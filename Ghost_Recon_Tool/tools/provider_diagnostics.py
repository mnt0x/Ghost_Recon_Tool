from __future__ import annotations

import argparse
import asyncio
import contextlib
import json
import os
import socket
import ssl
import sys
import time
from pathlib import Path
from typing import Any, Dict, List
from urllib.parse import urlparse

import aiohttp

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


PROVIDER_PROBES: List[Dict[str, Any]] = [
    {"provider": "crt.sh", "url": "https://crt.sh/?q=%25.example.com&output=json", "expect": "json"},
    {"provider": "subdomain_center", "url": "https://api.subdomain.center/?domain=example.com", "expect": "json"},
    {"provider": "dns_google", "url": "https://dns.google/resolve?name=example.com&type=A", "expect": "json"},
    {"provider": "commoncrawl_index", "url": "https://index.commoncrawl.org/collinfo.json", "expect": "json"},
    {"provider": "urlscan", "url": "https://urlscan.io/api/v1/search/?q=domain:example.com", "expect": "json"},
    {"provider": "internetdb_shodan", "url": "https://internetdb.shodan.io/8.8.8.8", "expect": "json"},
]


def _default_result(provider: str, url: str) -> Dict[str, Any]:
    return {
        "provider": provider,
        "url": url,
        "host": urlparse(url).hostname or "",
        "dns_ok": False,
        "tcp_ok": False,
        "tls_ok": False,
        "http_status": 0,
        "latency_ms": 0,
        "timeout_stage": "",
        "body_bytes": 0,
        "non_empty_body": False,
        "body_truncated": False,
        "parse_ok": False,
        "error_type": "",
        "retry_recovered": False,
        "proxy_env": bool(os.environ.get("HTTP_PROXY") or os.environ.get("HTTPS_PROXY") or os.environ.get("ALL_PROXY")),
        "attempts": 0,
    }


async def _dns_probe(host: str) -> tuple[bool, str, List[str]]:
    loop = asyncio.get_running_loop()
    try:
        infos = await loop.getaddrinfo(host, 443, type=socket.SOCK_STREAM)
        addrs = sorted({str(item[4][0]) for item in infos if item and len(item) >= 5 and item[4]})
        return True, "", addrs
    except socket.gaierror as exc:
        return False, type(exc).__name__, []
    except Exception as exc:
        return False, type(exc).__name__, []


async def _tcp_probe(host: str, port: int, timeout: float) -> tuple[bool, str]:
    try:
        fut = asyncio.open_connection(host, port, ssl=None)
        reader, writer = await asyncio.wait_for(fut, timeout=timeout)
        writer.close()
        await writer.wait_closed()
        return True, ""
    except asyncio.TimeoutError:
        return False, "connect"
    except Exception as exc:
        return False, type(exc).__name__


async def _tls_probe(host: str, port: int, timeout: float) -> tuple[bool, str]:
    ctx = ssl.create_default_context()
    try:
        fut = asyncio.open_connection(host, port, ssl=ctx, server_hostname=host)
        reader, writer = await asyncio.wait_for(fut, timeout=timeout)
        writer.close()
        await writer.wait_closed()
        return True, ""
    except asyncio.TimeoutError:
        return False, "tls"
    except ssl.SSLError as exc:
        return False, type(exc).__name__
    except Exception as exc:
        return False, type(exc).__name__


async def _http_attempt(
    session: aiohttp.ClientSession,
    url: str,
    expect: str,
    timeout_total: float,
) -> Dict[str, Any]:
    start = time.perf_counter()
    stage = "connect"
    result: Dict[str, Any] = {
        "http_status": 0,
        "latency_ms": 0,
        "timeout_stage": "",
        "body_bytes": 0,
        "non_empty_body": False,
        "body_truncated": False,
        "parse_ok": False,
        "error_type": "",
    }
    timeout = aiohttp.ClientTimeout(total=timeout_total, connect=min(8, timeout_total), sock_connect=min(8, timeout_total), sock_read=timeout_total)
    try:
        async with session.get(url, timeout=timeout, allow_redirects=True, headers={"User-Agent": "Mozilla/5.0"}) as resp:
            result["http_status"] = int(resp.status or 0)
            stage = "first_byte"
            body = await resp.read()
            result["latency_ms"] = int((time.perf_counter() - start) * 1000)
            result["body_bytes"] = len(body)
            result["non_empty_body"] = bool(body)
            content_length = resp.headers.get("Content-Length")
            if content_length:
                with contextlib.suppress(Exception):
                    result["body_truncated"] = len(body) < int(content_length)
            if expect == "json" and body:
                try:
                    json.loads(body.decode("utf-8", errors="replace"))
                    result["parse_ok"] = True
                except Exception as exc:
                    result["error_type"] = type(exc).__name__
                    result["timeout_stage"] = "parse"
            return result
    except asyncio.TimeoutError:
        result["latency_ms"] = int((time.perf_counter() - start) * 1000)
        result["timeout_stage"] = stage
        result["error_type"] = "TimeoutError"
        return result
    except aiohttp.ClientConnectorCertificateError as exc:
        result["latency_ms"] = int((time.perf_counter() - start) * 1000)
        result["timeout_stage"] = "tls"
        result["error_type"] = type(exc).__name__
        return result
    except aiohttp.ClientConnectorError as exc:
        result["latency_ms"] = int((time.perf_counter() - start) * 1000)
        result["timeout_stage"] = "connect"
        result["error_type"] = type(exc).__name__
        return result
    except Exception as exc:
        result["latency_ms"] = int((time.perf_counter() - start) * 1000)
        result["timeout_stage"] = stage
        result["error_type"] = type(exc).__name__
        return result


async def probe_provider(provider: str, url: str, *, expect: str = "json", retries: int = 1) -> Dict[str, Any]:
    host = urlparse(url).hostname or ""
    result = _default_result(provider, url)
    result["host"] = host
    dns_ok, dns_error, addrs = await _dns_probe(host)
    result["dns_ok"] = dns_ok
    if not dns_ok:
        result["error_type"] = dns_error or "DNSFailure"
        result["timeout_stage"] = "dns"
        return result
    result["dns_addresses"] = addrs
    tcp_ok, tcp_error = await _tcp_probe(host, 443, timeout=8)
    result["tcp_ok"] = tcp_ok
    if not tcp_ok:
        result["error_type"] = tcp_error or "TCPFailure"
        result["timeout_stage"] = "connect"
        return result
    tls_ok, tls_error = await _tls_probe(host, 443, timeout=10)
    result["tls_ok"] = tls_ok
    if not tls_ok:
        result["error_type"] = tls_error or "TLSFailure"
        result["timeout_stage"] = "tls"
        return result

    connector = aiohttp.TCPConnector(ssl=True, limit=2)
    async with aiohttp.ClientSession(connector=connector) as session:
        attempts = 0
        previous_failure = False
        for attempt in range(retries + 1):
            attempts += 1
            attempt_result = await _http_attempt(session, url, expect, timeout_total=20)
            result.update(attempt_result)
            result["attempts"] = attempts
            if result["http_status"] and result["non_empty_body"] and (result["parse_ok"] or expect != "json"):
                result["retry_recovered"] = previous_failure and attempt > 0
                return result
            previous_failure = True
            await asyncio.sleep(0.4 * (attempt + 1))
    return result


def render_provider_diagnostics_markdown(rows: List[Dict[str, Any]]) -> str:
    lines = [
        "# Provider Diagnostics",
        "",
        "| provider | dns_ok | tcp_ok | tls_ok | http_status | latency_ms | timeout_stage | body_bytes | non_empty_body | parse_ok | error_type | retry_recovered |",
        "|---|---|---|---|---:|---:|---|---:|---|---|---|---|",
    ]
    for row in rows:
        lines.append(
            f"| `{row.get('provider','')}` | `{row.get('dns_ok', False)}` | `{row.get('tcp_ok', False)}` | "
            f"`{row.get('tls_ok', False)}` | `{row.get('http_status', 0)}` | `{row.get('latency_ms', 0)}` | "
            f"`{row.get('timeout_stage', '')}` | `{row.get('body_bytes', 0)}` | `{row.get('non_empty_body', False)}` | "
            f"`{row.get('parse_ok', False)}` | `{row.get('error_type', '')}` | `{row.get('retry_recovered', False)}` |"
        )
    return "\n".join(lines) + "\n"


async def run_diagnostics() -> List[Dict[str, Any]]:
    return [await probe_provider(spec["provider"], spec["url"], expect=spec.get("expect", "json")) for spec in PROVIDER_PROBES]


async def _main() -> None:
    parser = argparse.ArgumentParser(description="Ghost Recon provider diagnostics")
    parser.add_argument("--out-dir", default="")
    args = parser.parse_args()

    rows = await run_diagnostics()
    payload = {"generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "rows": rows}
    text = json.dumps(payload, indent=2, ensure_ascii=False)
    print(text)
    if args.out_dir:
        out_dir = Path(args.out_dir)
        out_dir.mkdir(parents=True, exist_ok=True)
        (out_dir / "provider_diagnostics.json").write_text(text, encoding="utf-8")
        (out_dir / "provider_diagnostics.md").write_text(render_provider_diagnostics_markdown(rows), encoding="utf-8")


if __name__ == "__main__":
    asyncio.run(_main())
