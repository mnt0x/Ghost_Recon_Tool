#!/usr/bin/env python3
# Ghost Recon Tool - Passive Domain Reconnaissance
# ASCII logo:
#    ________  __  ___    ___      ____   ____  ________  ________  ______  __
#   / ___/ _ \/ / / / |  / _ \    / __/  / __ \/ ___/ _ \/ ___/ _ \/ __/ _ \/ /
#  /__  / , _/ /_/ /| | / , _/   _\ \   / /_/ / /__/ , _/ /__/ , _/ _// , _/ /
# /____/_/|_|\____/ |___/_/|_|  /___/   \____/\___/_/|_|\___/_/|_/___/_/|_/_/
# For authorized penetration testing and bug bounty engagements only.
# Author: mnt0x

import asyncio
import aiohttp
import json
import re
import os
import sys
import time
import socket
import random
import hashlib
import uuid
import base64
import ipaddress
import csv
import io
import zipfile
import gzip
import logging
import contextlib
import traceback as _traceback
import platform
import importlib.util
import copy
from html import escape as html_escape
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from dataclasses import dataclass, field, asdict
from typing import Optional, Dict, List, Any, Tuple, Callable, Awaitable, Iterator, Iterable
from urllib.parse import urlparse, quote, urlencode, urlunparse, urlsplit, urlunsplit, parse_qsl, unquote
import urllib.request
import urllib.error
import argparse
import ssl
import webbrowser
import threading
from aiohttp import web as aio_web
from collections import OrderedDict

# Windows UTF-8 terminal fix
if sys.platform == "win32":
    os.environ.setdefault("PYTHONIOENCODING", "utf-8")
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except AttributeError:
        pass

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich import print as rprint
from rich.live import Live
from rich.columns import Columns
from rich.markup import escape

from bs4 import BeautifulSoup
import tldextract
from jinja2 import Environment, FileSystemLoader, select_autoescape

from ghost_recon.core.policy import (
    ModuleMode,
    ScanPolicy,
    set_scan_context,
    reset_scan_context,
)
from ghost_recon.core.keystore import (
    KEY_ALIASES,
    PROVIDER_ENV_MAP,
    KeystoreWriteError,
    load_key_layers,
    load_keys as load_store_keys,
    normalize_keys as normalize_store_keys,
    provider_status as keystore_provider_status,
    save_keys as save_store_keys,
    source_to_required_credentials,
    summarize_services,
    validate_provider_value,
)
from ghost_recon.core.scan_manager import ScanManager
from ghost_recon.utils.http import (
    DEFAULT_HTTP_GUARD,
    HttpGuard,
    HttpConfig,
    configure_http_guard,
    get_http_guard,
    set_current_http_guard,
    reset_current_http_guard,
    set_current_scan_id,
    reset_current_scan_id,
    set_current_source,
    reset_current_source,
)
from ghost_recon.utils.domain import normalize_domain, is_valid_domain, normalize_hostname, looks_like_hostname
from ghost_recon.web.security import load_or_create_admin_token, constant_time_equals, token_fingerprint
from ghost_recon.config.settings import (
    RESULT_INDEX_TTL_SECONDS,
    ACTIVE_SCANS_MAX,
    ACTIVE_SCANS_TTL_SECONDS,
)
from ghost_recon.output.report_builder import build_canonical_report as _build_canonical_report_raw, build_full_static_report_context
from ghost_recon.sources.registry import SourceRegistry, SOURCE_CATALOG, list_sources as list_registered_sources
from ghost_recon.sources.commoncrawl import latest_commoncrawl_indexes
from ghost_recon.utils.normalize import DropReason, canonical_entity_id
from ghost_recon.utils.text import normalize_text, read_response_text as _read_response_text
from ghost_recon.sources.keyed import (
    parse_virustotal_subdomains,
    parse_securitytrails_subdomains,
    parse_chaos_subdomains,
    parse_fullhunt_subdomains,
    parse_censys_subdomains,
    parse_hunter_emails,
    parse_intelx_emails,
    parse_shodan_cve_ids,
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("ghost_recon")

_TLDEXTRACT_SNAPSHOT = tldextract.TLDExtract(cache_dir=None, suffix_list_urls=())
_TLDEXTRACT_FALLBACK_WARNED = False


def _safe_tld_extract(value: str):
    global _TLDEXTRACT_FALLBACK_WARNED
    try:
        return tldextract.extract(value)
    except Exception as exc:
        if not _TLDEXTRACT_FALLBACK_WARNED:
            log.warning(
                "tldextract cache unavailable; falling back to embedded suffix snapshot (%s: %s)",
                type(exc).__name__,
                exc,
            )
            _TLDEXTRACT_FALLBACK_WARNED = True
        return _TLDEXTRACT_SNAPSHOT(value)


class SensitiveLogFilter(logging.Filter):
    _token_re = re.compile(
        r"(?i)\b(api[_-]?key|token|secret|password|authorization)\b\s*[:=]\s*([^\s,;\"']+)"
    )

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            rendered = record.getMessage()
        except Exception:
            return True
        if not rendered:
            return True
        cleaned = self._token_re.sub(lambda m: f"{m.group(1)}=***REDACTED***", rendered)
        if cleaned != rendered:
            record.msg = cleaned
            record.args = ()
        return True


for _handler in logging.getLogger().handlers:
    _handler.addFilter(SensitiveLogFilter())

console = Console(
    force_terminal=True,
    legacy_windows=False,
    safe_box=True,
)

# Ã¢â€â‚¬Ã¢â€â‚¬ MODULE-LEVEL CACHES Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
_DOH_CACHE: Dict[Tuple[str, str], Tuple[list, float]] = {}
_DOH_CACHE_TTL = 300  # 5 minutes
_INDEX_TEXT_CACHE: Dict[str, Tuple[str, float]] = {}
_INDEX_TEXT_CACHE_TTL = 600  # 10 minutes
_COMMONCRAWL_INDEX_CACHE: Dict[str, Tuple[List[str], float]] = {}
_CLOUD_RANGES: Dict[str, List[Tuple[Any, str]]] = {}
_CLOUD_RANGES_LOADED = False
_IP_API_SEM: Optional[asyncio.Semaphore] = None  # rate limit: 3 concurrent (45 req/min free tier)


def _get_ip_api_sem() -> asyncio.Semaphore:
    global _IP_API_SEM
    if _IP_API_SEM is None:
        _IP_API_SEM = asyncio.Semaphore(3)
    return _IP_API_SEM


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _env_int(name: str, default: int) -> int:
    raw = str(os.environ.get(name, "") or "").strip()
    if not raw:
        return default
    try:
        return int(raw)
    except (TypeError, ValueError):
        return default


def _normalize_text_leaf(value: Any) -> Any:
    if isinstance(value, (str, bytes)) or value is None:
        return normalize_text(value)
    return value


def _normalize_text_tree(value: Any) -> Any:
    if isinstance(value, dict):
        root: dict[Any, Any] = {}
        stack: List[Tuple[Any, Any]] = [(value, root)]
        while stack:
            source, target = stack.pop()
            if isinstance(source, dict):
                for key, child in source.items():
                    if isinstance(child, dict):
                        nested: dict[Any, Any] = {}
                        target[key] = nested
                        stack.append((child, nested))
                    elif isinstance(child, (list, tuple)):
                        nested = []
                        target[key] = nested
                        stack.append((list(child), nested))
                    else:
                        target[key] = _normalize_text_leaf(child)
            else:
                for child in source:
                    if isinstance(child, dict):
                        nested = {}
                        target.append(nested)
                        stack.append((child, nested))
                    elif isinstance(child, (list, tuple)):
                        nested = []
                        target.append(nested)
                        stack.append((list(child), nested))
                    else:
                        target.append(_normalize_text_leaf(child))
        return root
    if isinstance(value, (list, tuple)):
        root_list: List[Any] = []
        stack: List[Tuple[Any, Any]] = [(list(value), root_list)]
        while stack:
            source, target = stack.pop()
            if isinstance(source, dict):
                for key, child in source.items():
                    if isinstance(child, dict):
                        nested: dict[Any, Any] = {}
                        target[key] = nested
                        stack.append((child, nested))
                    elif isinstance(child, (list, tuple)):
                        nested = []
                        target[key] = nested
                        stack.append((list(child), nested))
                    else:
                        target[key] = _normalize_text_leaf(child)
            else:
                for child in source:
                    if isinstance(child, dict):
                        nested = {}
                        target.append(nested)
                        stack.append((child, nested))
                    elif isinstance(child, (list, tuple)):
                        nested = []
                        target.append(nested)
                        stack.append((list(child), nested))
                    else:
                        target.append(_normalize_text_leaf(child))
        return root_list
    return _normalize_text_leaf(value)


def _redact_sensitive_leaf(value: Any, secret_values: List[str]) -> Any:
    if not isinstance(value, str):
        return value
    redacted = value
    for secret in secret_values:
        if secret and secret in redacted:
            redacted = redacted.replace(secret, "***REDACTED***")
    redacted = re.sub(
        r"(?i)(api[_-]?key|token|secret|password|authorization)\s*[:=]\s*([^\s,;\"']+)",
        r"\1=***REDACTED***",
        redacted,
    )
    return redacted


def _redact_sensitive_tree(value: Any, secrets: List[str]) -> Any:
    secret_values = [s for s in secrets if isinstance(s, str) and s]
    if isinstance(value, dict):
        root: dict[Any, Any] = {}
        stack: List[Tuple[Any, Any]] = [(value, root)]
        while stack:
            source, target = stack.pop()
            if isinstance(source, dict):
                for key, child in source.items():
                    if isinstance(child, dict):
                        nested: dict[Any, Any] = {}
                        target[key] = nested
                        stack.append((child, nested))
                    elif isinstance(child, list):
                        nested = []
                        target[key] = nested
                        stack.append((child, nested))
                    else:
                        target[key] = _redact_sensitive_leaf(child, secret_values)
            else:
                for child in source:
                    if isinstance(child, dict):
                        nested = {}
                        target.append(nested)
                        stack.append((child, nested))
                    elif isinstance(child, list):
                        nested = []
                        target.append(nested)
                        stack.append((child, nested))
                    else:
                        target.append(_redact_sensitive_leaf(child, secret_values))
        return root
    if isinstance(value, list):
        root_list: List[Any] = []
        stack: List[Tuple[Any, Any]] = [(value, root_list)]
        while stack:
            source, target = stack.pop()
            if isinstance(source, dict):
                for key, child in source.items():
                    if isinstance(child, dict):
                        nested: dict[Any, Any] = {}
                        target[key] = nested
                        stack.append((child, nested))
                    elif isinstance(child, list):
                        nested = []
                        target[key] = nested
                        stack.append((child, nested))
                    else:
                        target[key] = _redact_sensitive_leaf(child, secret_values)
            else:
                for child in source:
                    if isinstance(child, dict):
                        nested = {}
                        target.append(nested)
                        stack.append((child, nested))
                    elif isinstance(child, list):
                        nested = []
                        target.append(nested)
                        stack.append((child, nested))
                    else:
                        target.append(_redact_sensitive_leaf(child, secret_values))
        return root_list
    return _redact_sensitive_leaf(value, secret_values)


def _iter_json_bytes(value: Any):
    encoder = json.JSONEncoder(indent=2, default=str, ensure_ascii=False)
    for chunk in encoder.iterencode(value):
        if chunk:
            yield chunk.encode("utf-8")


def _safe_download_filename(scan_id: str, ext: str, suffix: str = "") -> str:
    safe_scan_id = re.sub(r"[^A-Za-z0-9._-]", "_", str(scan_id or "scan"))
    safe_scan_id = safe_scan_id.strip("._-") or "scan"
    safe_suffix = re.sub(r"[^A-Za-z0-9._-]", "_", str(suffix or ""))
    safe_suffix = f"_{safe_suffix}" if safe_suffix else ""
    safe_ext = re.sub(r"[^A-Za-z0-9]", "", str(ext or "txt")).lower() or "txt"
    return f"ghost_recon_{safe_scan_id}{safe_suffix}.{safe_ext}"


_SCAN_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$")


def _normalize_scan_id_value(scan_id: Any) -> str:
    candidate = str(scan_id or "").strip()
    return candidate if _SCAN_ID_RE.fullmatch(candidate) else ""


class ExpectedClientDisconnect(Exception):
    """Raised when an SSE client closes the connection normally."""


def _is_expected_client_disconnect(exc: BaseException) -> bool:
    if isinstance(exc, (ConnectionResetError, BrokenPipeError)):
        return True
    if isinstance(exc, RuntimeError):
        msg = str(exc).lower()
        return "cannot write to closing transport" in msg or "connection lost" in msg
    if isinstance(exc, OSError):
        return getattr(exc, "winerror", None) in {64, 10053, 10054} or getattr(exc, "errno", None) in {32, 54, 104}
    return False


def _install_windows_asyncio_disconnect_guard(loop: Optional[asyncio.AbstractEventLoop] = None) -> None:
    if sys.platform != "win32":
        return
    loop = loop or asyncio.get_running_loop()
    previous_handler = loop.get_exception_handler()

    def handler(loop_obj: asyncio.AbstractEventLoop, context: Dict[str, Any]) -> None:
        exc = context.get("exception")
        message = str(context.get("message", "") or "")
        lowered = message.lower()
        if _is_expected_client_disconnect(exc) or ("10054" in lowered and "connection" in lowered):
            logging.debug("Suppressed expected Windows client disconnect: %s", message or exc)
            return
        if previous_handler:
            previous_handler(loop_obj, context)
        else:
            loop_obj.default_exception_handler(context)

    loop.set_exception_handler(handler)


async def _sse_heartbeat_loop(
    *,
    emit_event: Callable[[str, Dict[str, Any]], Awaitable[None]],
    emit_comment: Callable[[str], Awaitable[None]],
    stop_event: asyncio.Event,
    get_scan_meta: Callable[[], Dict[str, str]],
    get_running_phase: Callable[[], str],
    ping_interval_seconds: float = 8.0,
    phase_tick_interval_seconds: float = 12.0,
    sleep_fn: Callable[[float], Awaitable[None]] = asyncio.sleep,
    time_fn: Callable[[], float] = time.time,
) -> None:
    """Emit periodic SSE heartbeat and running-phase ticks while scan is alive."""
    last_phase_tick = 0.0
    while not stop_event.is_set():
        scan_meta = get_scan_meta()
        now = float(time_fn())
        now_ms = int(now * 1000)
        await emit_event(
            "ping",
            {
                "ts": now_ms,
                "scan_id": scan_meta.get("scan_id", ""),
                "domain": scan_meta.get("domain", ""),
            },
        )
        await emit_comment(": keep-alive\n\n")

        phase_name = (get_running_phase() or "").strip()
        if phase_name and (now - last_phase_tick >= phase_tick_interval_seconds):
            await emit_event(
                "phase",
                {
                    "name": phase_name,
                    "status": "running",
                    "tick": True,
                    "ts": now_ms,
                    "scan_id": scan_meta.get("scan_id", ""),
                    "domain": scan_meta.get("domain", ""),
                },
            )
            last_phase_tick = now

        await sleep_fn(max(0.1, float(ping_interval_seconds)))

# Ã¢â€â‚¬Ã¢â€â‚¬ CREDENTIAL PATTERNS Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
CRED_PATTERNS = {
    "AWS_KEY":       re.compile(r'AKIA[0-9A-Z]{16}'),
    "Google_API":    re.compile(r'AIza[0-9A-Za-z\-_]{35}'),
    "Slack_Token":   re.compile(r'xox[baprs]-[0-9a-zA-Z\-]{10,48}'),
    "Stripe_Live":   re.compile(r'sk_live_[0-9a-zA-Z]{24,}'),
    "Stripe_Test":   re.compile(r'sk_test_[0-9a-zA-Z]{24,}'),
    "JWT":           re.compile(r'eyJ[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_=]+\.?[A-Za-z0-9\-_.+/=]*'),
    "Private_Key":   re.compile(r'-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----'),
    "Generic_Secret":re.compile(r'(?i)(?:password|passwd|secret|token|api_key|apikey)\s*[=:]\s*["\']([^"\']{8,})["\']'),
}

# Ã¢â€â‚¬Ã¢â€â‚¬ USER AGENTS Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Safari/537.36 OPR/102.0.0.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Android 14; Mobile; rv:121.0) Gecko/121.0 Firefox/121.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Vivaldi/6.5.3206.39",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36 Brave/1.61",
    "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0",
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
]

TIMEOUTS   = {"fast": 10, "balanced": 20, "deep": 45, "turbo": 8}
DELAYS     = {"fast": 0.1, "balanced": 0.5, "deep": 1.0, "turbo": 0.0}
SEMAPHORES = {"fast": 30, "balanced": 50, "deep": 45, "turbo": 100}

# Per-module hard timeouts (seconds) — prevents any single module from hanging forever
MODULE_TIMEOUTS: Dict[str, Dict[str, int]] = {
    "DNS Intelligence":         {"fast": 60,  "balanced": 60,  "deep": 60,  "turbo": 30},
    "Subdomain Enumeration":    {"fast": 300, "balanced": 720, "deep": 1800, "turbo": 120},
    "Email Discovery":          {"fast": 180, "balanced": 360, "deep": 600, "turbo": 120},
    "Technology Detection":     {"fast": 45,  "balanced": 60,  "deep": 90,  "turbo": 30},
    "WHOIS Intelligence":       {"fast": 30,  "balanced": 45,  "deep": 60,  "turbo": 20},
    "IP Intelligence":          {"fast": 90,  "balanced": 180, "deep": 300, "turbo": 60},
    "SSL Intelligence":         {"fast": 45,  "balanced": 60,  "deep": 90,  "turbo": 30},
    "Web Archive":              {"fast": 600, "balanced": 600, "deep": 1800, "turbo": 600},
    "Breach Intelligence":      {"fast": 45,  "balanced": 60,  "deep": 90,  "turbo": 30},
    "Reputation Intel":         {"fast": 45,  "balanced": 60,  "deep": 90,  "turbo": 30},
    "Cloud Assets":             {"fast": 60,  "balanced": 90,  "deep": 120, "turbo": 45},
    "Takeover Detection":       {"fast": 60,  "balanced": 90,  "deep": 120, "turbo": 45},
    "Typosquat Detection":      {"fast": 60,  "balanced": 120, "deep": 180, "turbo": 30},
    "Security Headers":         {"fast": 30,  "balanced": 45,  "deep": 60,  "turbo": 20},
    "Social Footprint":         {"fast": 45,  "balanced": 60,  "deep": 90,  "turbo": 30},
    "ASN Intelligence":         {"fast": 45,  "balanced": 60,  "deep": 90,  "turbo": 30},
    "Dork Intelligence":        {"fast": 120, "balanced": 180, "deep": 240, "turbo": 60},
    "Passive Artifact Intelligence": {"fast": 45, "balanced": 75, "deep": 120, "turbo": 30},
    "Vulnerability Intelligence":{"fast": 30, "balanced": 60,  "deep": 90,  "turbo": 20},
    "Risk Scoring":             {"fast": 15,  "balanced": 15,  "deep": 15,  "turbo": 10},
    "Correlations":             {"fast": 15,  "balanced": 15,  "deep": 15,  "turbo": 10},
}


# Per-source timeouts — caps each individual source within enumerate()/discover()
# Prevents one slow source from blocking the whole module's asyncio.wait_for
PER_SOURCE_TIMEOUT: Dict[str, int] = {"fast": 45, "balanced": 60, "deep": 90, "turbo": 30}
SLOW_SOURCE_TIMEOUT: Dict[str, int] = {"fast": 20, "balanced": 30, "deep": 45, "turbo": 15}
SLOW_SOURCES: frozenset = frozenset({
    "commoncrawl", "wayback", "wayback_subs", "wayback_contacts",
    "wayback_snapshots", "commoncrawl_mailto", "commoncrawl_index",
})
# Per-source timeout overrides (take precedence over SLOW_SOURCE_TIMEOUT)
SOURCE_OVERRIDE_TIMEOUTS: Dict[str, Dict[str, int]] = {
    # FIXED: crt.sh large wildcard searches now fail fast on server-side recovery conflicts, so keep deep timeout bounded.
    "crt.sh":              {"fast": 180, "balanced": 180, "deep": 120, "turbo": 180},
    "commoncrawl":          {"fast": 180, "balanced": 180, "deep": 300, "turbo": 180},
    "wayback":              {"fast": 45, "balanced": 60, "deep": 300, "turbo": 30},
    "wayback_subs":         {"fast": 45, "balanced": 60, "deep": 300, "turbo": 30},
    "wayback_host_hints":   {"fast": 45, "balanced": 60, "deep": 180, "turbo": 30},
    "wayback_contacts":     {"fast": 30, "balanced": 45, "deep": 90, "turbo": 20},
    "wayback_snapshots":    {"fast": 15, "balanced": 25, "deep": 60, "turbo": 15},
    "commoncrawl_index":    {"fast": 15, "balanced": 25, "deep": 60, "turbo": 15},
    "commoncrawl_mailto":   {"fast": 15, "balanced": 25, "deep": 60, "turbo": 15},
    "shrewdeye":            {"fast": 30, "balanced": 30, "deep": 30, "turbo": 20},
    "wayback_cdx":          {"fast": 45, "balanced": 60, "deep": 300, "turbo": 30},
    "wayback_cdx_full":     {"fast": 60, "balanced": 90, "deep": 600, "turbo": 45},
    "otx_passive_dns":      {"fast": 45, "balanced": 45, "deep": 45, "turbo": 45},
    "bufferover_dns":       {"fast": 20, "balanced": 20, "deep": 20, "turbo": 15},
    "github_code":          {"fast": 10, "balanced": 12, "deep": 15, "turbo": 10},
    "certspotter":          {"fast": 30, "balanced": 30, "deep": 60, "turbo": 30},
    # Subdomain sources prone to hanging
    "crobat":               {"fast": 30, "balanced": 30, "deep": 30, "turbo": 30},
    "columbus":             {"fast": 30, "balanced": 45, "deep": 60, "turbo": 30},
    "anubisdb":             {"fast": 120, "balanced": 120, "deep": 180, "turbo": 120},
    "jldc":                 {"fast": 120, "balanced": 120, "deep": 180, "turbo": 120},
    "subdomaincenter":      {"fast": 180, "balanced": 180, "deep": 300, "turbo": 180},
    "vt_unauth":            {"fast": 10, "balanced": 12, "deep": 15, "turbo":  8},
    "grep_app":             {"fast": 10, "balanced": 12, "deep": 15, "turbo":  8},
    "grep_app_subs":        {"fast": 10, "balanced": 12, "deep": 15, "turbo":  8},
    "otx":                  {"fast": 30, "balanced": 30, "deep": 60, "turbo": 30},
    "rapiddns":             {"fast": 30, "balanced": 30, "deep": 120, "turbo": 30},
    "circl_pdns":           {"fast": 30, "balanced": 30, "deep": 60, "turbo": 30},
    "urlscan_pages":        {"fast": 30, "balanced": 35, "deep": 90, "turbo": 30},
    "dnsrepo":              {"fast": 30, "balanced": 30, "deep": 60, "turbo": 30},
    "hackertarget":         {"fast": 30, "balanced": 30, "deep": 60, "turbo": 30},
    "hackertarget_dns":     {"fast": 30, "balanced": 30, "deep": 60, "turbo": 30},
    "hackertarget_subdomain": {"fast": 30, "balanced": 30, "deep": 60, "turbo": 30},
    "mnemonic_pdns":        {"fast": 30, "balanced": 30, "deep": 60, "turbo": 30},
    "digitorus":            {"fast": 10, "balanced": 10, "deep": 10, "turbo": 10},
    "sitedossier":          {"fast": 10, "balanced": 10, "deep": 10, "turbo": 10},
    "bevigil_free":         {"fast": 10, "balanced": 10, "deep": 10, "turbo": 10},
    "myssl":                {"fast": 30, "balanced": 30, "deep": 45, "turbo": 30},
    "sslmate_certs":        {"fast": 30, "balanced": 30, "deep": 60, "turbo": 30},
    "trickest":             {"fast": 45, "balanced": 45, "deep": 45, "turbo": 45},
    "ctsearch_google":      {"fast": 30, "balanced": 45, "deep": 60, "turbo": 30},
    "alienvault_pulse":     {"fast": 30, "balanced": 45, "deep": 45, "turbo": 30},
    "he_bgp":               {"fast": 10, "balanced": 10, "deep": 10, "turbo": 10},
    "dnsgrep":              {"fast": 10, "balanced": 10, "deep": 10, "turbo": 10},
}

MODULE_CLASSIFICATION: Dict[str, ModuleMode] = {
    "DNS Intelligence": ModuleMode.PASSIVE,
    "Subdomain Enumeration": ModuleMode.PASSIVE,
    "Email Discovery": ModuleMode.PASSIVE,
    "Technology Detection": ModuleMode.PASSIVE,
    "WHOIS Intelligence": ModuleMode.PASSIVE,
    "IP Intelligence": ModuleMode.PASSIVE,
    "SSL Intelligence": ModuleMode.PASSIVE,
    "Web Archive": ModuleMode.PASSIVE,
    "Breach Intelligence": ModuleMode.PASSIVE,
    "Reputation Intel": ModuleMode.PASSIVE,
    "Cloud Assets": ModuleMode.PASSIVE,
    "Takeover Detection": ModuleMode.ACTIVE,
    "Typosquat Detection": ModuleMode.PASSIVE,
    "Dork Intelligence": ModuleMode.PASSIVE,
    "Security Headers": ModuleMode.SEMI,
    "Social Footprint": ModuleMode.PASSIVE,
    "ASN Intelligence": ModuleMode.PASSIVE,
    "Passive Artifact Intelligence": ModuleMode.PASSIVE,
    "Vulnerability Intelligence": ModuleMode.PASSIVE,
    "Risk Scoring": ModuleMode.PASSIVE,
    "Correlations": ModuleMode.PASSIVE,
}

SOURCE_CONFIDENCE: Dict[str, float] = {
    "crt.sh": 0.95,
    "certspotter": 0.9,
    "wayback": 0.75,
    "commoncrawl": 0.72,
    "otx": 0.78,
    "urlscan": 0.82,
    "jldc": 0.68,
    "anubisdb": 0.68,
    "whois_html": 0.62,
    "pgp_keys": 0.66,
    "phonebook": 0.7,
    "github_code_emails": 0.74,
    "github_issues": 0.72,
    "ct_logs": 0.88,
    "paste_sites": 0.6,
    "wayback_snapshots": 0.79,
    "commoncrawl_index": 0.69,
    "commoncrawl_mailto": 0.71,
}

DEEP_MODE_OPTIONAL_SOURCES: tuple[str, ...] = (
    "c99",
    "commoncrawl",
    "commoncrawl_index",
    "commoncrawl_mailto",
    "grep_app",
    "netcraft",
    "sublist3r",
    "wayback_snapshots",
)

HOST_FAMILY_MAP: Dict[str, Tuple[List[str], int]] = {
    "remote_access": (["vpn", "remote", "ssh", "rdp", "citrix", "jump", "bastion"], 4),
    "identity_auth": (["sso", "sts", "auth", "login", "oauth", "openid", "mfa", "adfs"], 4),
    "email_infra": (["mail", "smtp", "imap", "pop3", "mx", "webmail", "exchange", "owa"], 3),
    "admin_panel": (["admin", "administrator", "portal", "manage", "control", "console", "dashboard"], 4),
    "api_endpoint": (["api", "rest", "graphql", "grpc", "swagger", "openapi", "gateway"], 3),
    "non_production": (["dev", "develop", "development", "staging", "stage", "test", "uat", "qa", "beta", "sandbox", "preprod", "preview"], 3),
    "internal_hint": (["internal", "intra", "corp", "partner", "legacy", "old"], 2),
    "devops": (["jenkins", "gitlab", "github", "jira", "confluence", "sonar", "nexus", "artifactory", "ci", "cd", "pipeline"], 3),
    "file_transfer": (["ftp", "sftp", "files", "upload", "download", "transfer"], 2),
    "backup": (["backup", "bak", "archive", "copy"], 2),
}

_TARGET_FAMILY_NOISE = {
    "as", "eu", "na", "oc", "sw", "uk", "us", "emea", "apac", "latam",
    "prod", "prd", "dev", "test", "stage", "staging", "ppe", "int", "internal",
    "eastus", "eastus2", "westus", "westus2", "centralus", "westeurope", "northeurope",
}


def _host_family_enrichment(host: str, apex: str) -> Tuple[List[str], int]:
    prefix = host[:-len(apex) - 1].lower() if host.endswith("." + apex) else host.lower()
    tags: List[str] = []
    score_bonus = 0
    for tag, (keywords, bonus) in HOST_FAMILY_MAP.items():
        if any(
            prefix == keyword
            or prefix.startswith(f"{keyword}.")
            or prefix.endswith(f".{keyword}")
            or f".{keyword}." in f".{prefix}."
            for keyword in keywords
        ):
            tags.append(tag)
            score_bonus += bonus
    return tags, score_bonus


def _normalized_target_family(host: str, apex: str) -> str:
    norm_host = normalize_hostname(host)
    if not norm_host or not norm_host.endswith("." + apex):
        return norm_host
    prefix = norm_host[:-len(apex) - 1]
    labels = [label for label in prefix.split(".") if label]
    if len(labels) <= 2:
        return prefix
    trimmed = list(labels)
    while len(trimmed) > 2 and (
        trimmed[0] in _TARGET_FAMILY_NOISE
        or (len(trimmed[0]) <= 3 and trimmed[0].isalpha())
        or re.fullmatch(r"[a-z]{2,3}\d?", trimmed[0], re.I)
    ):
        trimmed = trimmed[1:]
    return ".".join(trimmed)

# Ã¢â€â‚¬Ã¢â€â‚¬ DATACLASSES Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
@dataclass
class SubdomainRecord:
    name: str
    sources: list = field(default_factory=list)
    seen_in_sources: list = field(default_factory=list)
    ips: list = field(default_factory=list)
    resolved_ips: list = field(default_factory=list)
    ports: list = field(default_factory=list)
    cname: list = field(default_factory=list)
    takeover_status: str = "UNKNOWN"
    takeover_evidence: str = ""
    wildcard_candidate: bool = False
    cloud_provider: str = ""
    tags: list = field(default_factory=list)
    relevance_score: int = 0
    confidence: float = 0.0
    confidence_bucket: str = "medium_confidence"
    first_seen_source: str = ""
    passive_evidence_count: int = 0
    api_enriched: bool = False
    exclusive_source: bool = False
    first_seen: str = ""
    last_seen: str = ""
    source_attribution: list = field(default_factory=list)

@dataclass
class EmailRecord:
    email: str
    sources: list = field(default_factory=list)
    role: str = "generic"
    confidence: float = 0.0
    first_seen: str = ""
    last_seen: str = ""
    source_attribution: list = field(default_factory=list)

@dataclass
class TechnologyFinding:
    name: str
    category: str
    evidence: str
    confidence: str
    sources: list = field(default_factory=list)
    observation_recency: str = "current_passive"
    historical_only: bool = False
    current_passive: bool = True
    third_party_context: bool = False
    first_party: bool = True
    version: str = ""

@dataclass
class DNSRecord:
    type: str
    name: str
    value: str
    source: str = "doh"

@dataclass
class IPRecord:
    ip: str
    asn: str = ""
    org: str = ""
    country: str = ""
    city: str = ""
    rdns: str = ""
    cloud_provider: str = ""
    cdn: bool = False
    open_ports: list = field(default_factory=list)
    vulns: list = field(default_factory=list)
    cpes: list = field(default_factory=list)
    tags: list = field(default_factory=list)
    hostnames: list = field(default_factory=list)
    greynoise: dict = field(default_factory=dict)
    abuseipdb: dict = field(default_factory=dict)
    shared_hosting: list = field(default_factory=list)
    otx_data: dict = field(default_factory=dict)

@dataclass
class BreachRecord:
    name: str
    date: str = ""
    data_types: list = field(default_factory=list)
    description: str = ""
    source: str = ""

@dataclass
class TakeoverRecord:
    subdomain: str
    cname_chain: list = field(default_factory=list)
    provider: str = ""
    status: str = "INVESTIGATE"
    evidence: str = ""
    severity: str = "LOW"

@dataclass
class CloudAsset:
    asset_type: str
    name: str
    url: str = ""
    region: str = ""
    public: bool = False
    confidence: float = 0.0
    classification: str = "heuristic"  # evidenced | probable | heuristic
    source: str = ""

@dataclass
class WaybackURL:
    url: str
    timestamp: str = ""
    status_code: int = 0
    mime_type: str = ""

@dataclass
class SSLInfo:
    subject: str = ""
    issuer: str = ""
    not_before: str = ""
    not_after: str = ""
    san_entries: list = field(default_factory=list)
    expired: bool = False
    days_left: int = 0
    ct_sources: list = field(default_factory=list)
    observation_recency: str = "historical_only"
    historical_only: bool = True
    current_passive: bool = False
    third_party_context: bool = False
    first_party: bool = True
    ownership_confidence: float = 0.6
    source_scope: str = "first_party"

@dataclass
class ReconResult:
    domain: str
    scan_id: str
    mode: str
    scan_date: str = field(default_factory=_utcnow_iso)
    subdomains: list = field(default_factory=list)
    emails: list = field(default_factory=list)
    technologies: list = field(default_factory=list)
    dns_records: list = field(default_factory=list)
    ip_records: list = field(default_factory=list)
    ssl_info: list = field(default_factory=list)
    breach_records: list = field(default_factory=list)
    takeover_records: list = field(default_factory=list)
    cloud_assets: list = field(default_factory=list)
    wayback_urls: list = field(default_factory=list)
    archive_urls: list = field(default_factory=list)
    archive_summary: dict = field(default_factory=dict)
    whois_data: dict = field(default_factory=dict)
    reputation_data: dict = field(default_factory=dict)
    scores: dict = field(default_factory=dict)
    typosquats: list = field(default_factory=list)
    dorks: list = field(default_factory=list)
    security_headers: dict = field(default_factory=dict)
    social_footprint: dict = field(default_factory=dict)
    asn_intelligence: dict = field(default_factory=dict)
    vulnerabilities: list = field(default_factory=list)
    correlations: list = field(default_factory=list)
    interesting_endpoints: list = field(default_factory=list)
    potential_secrets: list = field(default_factory=list)
    developer_references: list = field(default_factory=list)
    high_value_targets: list = field(default_factory=list)
    asset_clusters: dict = field(default_factory=dict)
    email_pattern: dict = field(default_factory=dict)
    cve_intelligence: dict = field(default_factory=dict)
    source_metrics: dict = field(default_factory=dict)
    scan_context: dict = field(default_factory=dict)
    errors: list = field(default_factory=list)
    duration_seconds: float = 0.0
    email_security: dict = field(default_factory=dict)
    historical_ips: list = field(default_factory=list)
    raw_preservation: dict = field(default_factory=dict)

# Ã¢â€â‚¬Ã¢â€â‚¬ TECH SIGNATURES Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
TECH_SIGNATURES = {
    "Apache":       {"category": "web_server",   "patterns": [r"Apache[/ ][\d.]+", r"<address>Apache"]},
    "Nginx":        {"category": "web_server",   "patterns": [r"nginx[/ ][\d.]+", r"<hr><center>nginx"]},
    "IIS":          {"category": "web_server",   "patterns": [r"Microsoft-IIS[/ ][\d.]+", r"X-Powered-By: ASP\.NET"]},
    "LiteSpeed":    {"category": "web_server",   "patterns": [r"LiteSpeed"]},
    "Caddy":        {"category": "web_server",   "patterns": [r"Caddy"]},
    "OpenResty":    {"category": "web_server",   "patterns": [r"openresty[/ ][\d.]+"]},
    "Tomcat":       {"category": "web_server",   "patterns": [r"Apache Tomcat", r"Coyote"]},
    "Gunicorn":     {"category": "web_server",   "patterns": [r"gunicorn[/ ][\d.]+"]},
    "Cloudflare":   {"category": "cdn_waf",      "patterns": [r"cloudflare", r"CF-Cache-Status", r"cf-ray"]},
    "Akamai":       {"category": "cdn_waf",      "patterns": [r"akamai", r"AkamaiGHost", r"X-Check-Cacheable"]},
    "Fastly":       {"category": "cdn_waf",      "patterns": [r"Fastly", r"fastly-restarts"]},
    "CloudFront":   {"category": "cdn_waf",      "patterns": [r"CloudFront", r"X-Amz-Cf-Id"]},
    "Incapsula":    {"category": "cdn_waf",      "patterns": [r"incapsula", r"visid_incap_"]},
    "Sucuri":       {"category": "cdn_waf",      "patterns": [r"Sucuri", r"X-Sucuri-ID"]},
    "Imperva":      {"category": "cdn_waf",      "patterns": [r"Imperva", r"X-Iinfo"]},
    "F5-BIG-IP":    {"category": "cdn_waf",      "patterns": [r"BIG-IP", r"TS\w{8}="]},
    "ModSecurity":  {"category": "cdn_waf",      "patterns": [r"Mod_Security"]},
    "WordPress":    {"category": "cms",          "patterns": [r"/wp-content/", r"/wp-includes/", r"wp-json", r"WordPress"]},
    "Drupal":       {"category": "cms",          "patterns": [r"Drupal", r"/sites/default/files/"]},
    "Joomla":       {"category": "cms",          "patterns": [r"Joomla", r"/media/jui/"]},
    "Magento":      {"category": "cms",          "patterns": [r"Magento", r"mage/", r"Mage\.Cookies"]},
    "Shopify":      {"category": "cms",          "patterns": [r"cdn\.shopify\.com", r"shopify\.com/s/files"]},
    "Wix":          {"category": "cms",          "patterns": [r"wix\.com", r"X-Wix-"]},
    "Squarespace":  {"category": "cms",          "patterns": [r"Squarespace", r"squarespace\.com"]},
    "Ghost":        {"category": "cms",          "patterns": [r"ghost\.io", r"content/themes/ghost"]},
    "Webflow":      {"category": "cms",          "patterns": [r"Webflow", r"webflow\.com"]},
    "Next.js":      {"category": "framework",    "patterns": [r"__NEXT_DATA__", r"_next/static"]},
    "Nuxt.js":      {"category": "framework",    "patterns": [r"__NUXT__", r"_nuxt/"]},
    "Gatsby":       {"category": "framework",    "patterns": [r"___gatsby", r"gatsby-"]},
    "Hugo":         {"category": "framework",    "patterns": [r"Hugo"]},
    "React":        {"category": "js_framework", "patterns": [r"react\.js", r"ReactDOM", r"__REACT"]},
    "Angular":      {"category": "js_framework", "patterns": [r"ng-version", r"ng-app", r"\[ng-"]},
    "Vue":          {"category": "js_framework", "patterns": [r"vue\.js", r"__vue__", r"v-bind:"]},
    "Svelte":       {"category": "js_framework", "patterns": [r"__svelte"]},
    "jQuery":       {"category": "js_library",   "patterns": [r"jquery[.-][\d.]+\.js", r"jQuery v[\d.]+"]},
    "Bootstrap":    {"category": "css_framework", "patterns": [r"bootstrap\.min\.css", r"bootstrap\.js"]},
    "Tailwind":     {"category": "css_framework", "patterns": [r"tailwindcss", r"tailwind"]},
    "PHP":          {"category": "backend",      "patterns": [r"X-Powered-By: PHP", r"PHPSESSID"]},
    "Node.js":      {"category": "backend",      "patterns": [r"X-Powered-By: Express", r"Express"]},
    "Django":       {"category": "backend",      "patterns": [r"csrfmiddlewaretoken", r"django"]},
    "Flask":        {"category": "backend",      "patterns": [r"Werkzeug"]},
    "Laravel":      {"category": "backend",      "patterns": [r"laravel_session", r"XSRF-TOKEN"]},
    "Ruby-Rails":   {"category": "backend",      "patterns": [r"Phusion Passenger", r"_rails_"]},
    "ASP.NET":      {"category": "backend",      "patterns": [r"ASP\.NET", r"__VIEWSTATE", r"X-AspNet-Version"]},
    "Spring":       {"category": "backend",      "patterns": [r"X-Application-Context"]},
    "GA4":          {"category": "analytics",    "patterns": [r"G-[A-Z0-9]{10}", r"gtag\("]},
    "UA-Analytics": {"category": "analytics",    "patterns": [r"UA-\d{4,}-\d+"]},
    "GTM":          {"category": "tag_manager",  "patterns": [r"GTM-[A-Z0-9]+", r"googletagmanager\.com"]},
    "Hotjar":       {"category": "analytics",    "patterns": [r"hotjar", r"hjid"]},
    "Mixpanel":     {"category": "analytics",    "patterns": [r"mixpanel"]},
    "Segment":      {"category": "analytics",    "patterns": [r"segment\.com"]},
    "HubSpot":      {"category": "marketing",    "patterns": [r"hubspot\.com", r"hs-scripts\.com"]},
    "Intercom":     {"category": "marketing",    "patterns": [r"intercom\.com", r"intercomSettings"]},
    "Zendesk":      {"category": "marketing",    "patterns": [r"zendesk\.com", r"zopim"]},
    "Drift":        {"category": "marketing",    "patterns": [r"drift\.com"]},
    "Mailchimp":    {"category": "marketing",    "patterns": [r"mailchimp\.com", r"list-manage\.com"]},
    "Salesforce":   {"category": "crm",          "patterns": [r"salesforce\.com", r"force\.com"]},
    "Stripe":       {"category": "payments",     "patterns": [r"js\.stripe\.com", r"Stripe\("]},
    "PayPal":       {"category": "payments",     "patterns": [r"paypalobjects\.com"]},
    "AWS-S3":       {"category": "cloud",        "patterns": [r"s3\.amazonaws\.com", r"s3-[a-z]+-[0-9]+\.amazonaws"]},
    "Google-Cloud": {"category": "cloud",        "patterns": [r"storage\.googleapis\.com", r"appspot\.com"]},
    "Azure":        {"category": "cloud",        "patterns": [r"azurewebsites\.net", r"blob\.core\.windows"]},
    "Heroku":       {"category": "cloud",        "patterns": [r"herokuapp\.com"]},
    "Vercel":       {"category": "cloud",        "patterns": [r"vercel\.app", r"now\.sh"]},
    "Netlify":      {"category": "cloud",        "patterns": [r"netlify\.app", r"netlify\.com"]},
    "Okta":         {"category": "auth_sso",     "patterns": [r"okta\.com", r"oktacdn\.com"]},
    "Auth0":        {"category": "auth_sso",     "patterns": [r"auth0\.com", r"cdn\.auth0\.com"]},
    "Google-SSO":   {"category": "auth_sso",     "patterns": [r"accounts\.google\.com", r"gsi/client"]},
    "Azure-AD":     {"category": "auth_sso",     "patterns": [r"login\.microsoftonline\.com"]},
    "Sentry":       {"category": "monitoring",   "patterns": [r"sentry\.io", r"Sentry\.init"]},
    "Datadog":      {"category": "monitoring",   "patterns": [r"datadoghq\.com", r"DD_CLIENT_TOKEN"]},
    "New-Relic":    {"category": "monitoring",   "patterns": [r"newrelic\.com", r"NREUM"]},
    "Dynatrace":    {"category": "monitoring",   "patterns": [r"dynatrace\.com", r"dtrum"]},
    "Google-WS":    {"category": "email_infra",  "patterns": [r"aspmx\.l\.google", r"google\.com\."]},
    "M365":         {"category": "email_infra",  "patterns": [r"mail\.protection\.outlook", r"outlook\.com"]},
    "Proofpoint":   {"category": "email_sec",    "patterns": [r"pphosted\.com", r"proofpoint"]},
    "Mimecast":     {"category": "email_sec",    "patterns": [r"mimecast\.com"]},
    "Sendgrid":     {"category": "email_infra",  "patterns": [r"sendgrid\.net"]},
    "Mailgun":      {"category": "email_infra",  "patterns": [r"mailgun\.org"]},
    "Amazon-SES":   {"category": "email_infra",  "patterns": [r"amazonses\.com"]},
    "Atlassian":    {"category": "devops",       "patterns": [r"atlassian-domain-verification"]},
    "HackerOne":    {"category": "security",     "patterns": [r"hackerone\.com"]},
    "Bugcrowd":     {"category": "security",     "patterns": [r"bugcrowd\.com"]},
}

# Ã¢â€â‚¬Ã¢â€â‚¬ TAKEOVER FINGERPRINTS Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
TAKEOVER_FINGERPRINTS = {
    "github_pages":   {"cname": [".github.io", ".github.com"],              "content": ["There isn't a GitHub Pages site here", "For root URLs"],           "severity": "HIGH"},
    "heroku":         {"cname": [".herokudns.com", ".herokuapp.com"],        "content": ["No such app", "herokucdn.com/error-pages/no-such-app"],             "severity": "HIGH"},
    "shopify":        {"cname": [".myshopify.com", ".shopifycloud.com"],     "content": ["Sorry, this shop is currently unavailable"],                         "severity": "HIGH"},
    "tumblr":         {"cname": [".tumblr.com"],                             "content": ["Whatever you were looking for doesn't live here"],                    "severity": "HIGH"},
    "wordpress_com":  {"cname": [".wordpress.com"],                          "content": ["Do you want to register"],                                            "severity": "HIGH"},
    "ghost":          {"cname": [".ghost.io"],                               "content": ["The thing you were looking for is no longer here"],                   "severity": "HIGH"},
    "fastly":         {"cname": [".fastly.net", ".fastlylb.net"],            "content": ["Fastly error: unknown domain"],                                      "severity": "HIGH"},
    "pantheon":       {"cname": [".pantheonsite.io"],                        "content": ["404 error unknown site"],                                             "severity": "HIGH"},
    "azure_websites": {"cname": [".azurewebsites.net", ".trafficmanager.net"], "content": ["404 Web Site not found"],                                          "severity": "HIGH"},
    "aws_s3":         {"cname": [".s3.amazonaws.com", ".s3-website"],        "content": ["NoSuchBucket", "The specified bucket does not exist"],               "severity": "CRITICAL"},
    "aws_cloudfront": {"cname": [".cloudfront.net"],                         "content": ["Bad request", "ERROR: The request could not be satisfied"],          "severity": "HIGH"},
    "zendesk":        {"cname": [".zendesk.com"],                            "content": ["Help Center Closed"],                                                 "severity": "HIGH"},
    "sendgrid":       {"cname": [".sendgrid.net"],                           "content": ["The domain you are looking for is not configured"],                   "severity": "HIGH"},
    "hubspot":        {"cname": [".hubspot.net", ".hs-sites.com"],           "content": ["This page isn't available", "does not exist in our system"],         "severity": "HIGH"},
    "acquia":         {"cname": [".acquia-sites.com"],                       "content": ["If you are an Acquia Cloud customer"],                                "severity": "HIGH"},
    "netlify":        {"cname": [".netlify.app", ".netlify.com"],            "content": ["Not Found - Request ID"],                                             "severity": "HIGH"},
    "vercel":         {"cname": [".vercel.app", ".now.sh"],                  "content": ["The deployment could not be found", "DEPLOYMENT_NOT_FOUND"],         "severity": "HIGH"},
    "surge":          {"cname": [".surge.sh"],                               "content": ["project not found"],                                                  "severity": "HIGH"},
    "bitbucket":      {"cname": [".bitbucket.io"],                           "content": ["Repository not found"],                                               "severity": "HIGH"},
    "read_the_docs":  {"cname": [".readthedocs.io"],                         "content": ["unknown to Read the Docs"],                                           "severity": "HIGH"},
    "intercom":       {"cname": [".custom.intercom.help"],                   "content": ["This page is reserved for artistic dogs"],                            "severity": "HIGH"},
    "freshdesk":      {"cname": [".freshdesk.com"],                          "content": ["We couldn't find the site you're looking for"],                       "severity": "HIGH"},
    "uservoice":      {"cname": [".uservoice.com"],                          "content": ["This UserVoice subdomain is currently available"],                    "severity": "HIGH"},
    "helpscout":      {"cname": [".helpscoutdocs.com"],                      "content": ["No settings were found for this company"],                            "severity": "HIGH"},
    "fly_io":         {"cname": [".fly.dev"],                                "content": ["404 Not Found"],                                                      "severity": "MEDIUM"},
    "canny":          {"cname": [".canny.io"],                               "content": ["There is no such company"],                                           "severity": "HIGH"},
    "webflow":        {"cname": [".webflow.io"],                             "content": ["The page you are looking for doesn't exist"],                         "severity": "MEDIUM"},
    "wix":            {"cname": [".wixdns.net"],                             "content": ["Error ConnectYourDomain"],                                            "severity": "MEDIUM"},
    "squarespace":    {"cname": [".squarespace.com"],                        "content": ["No Such Account"],                                                    "severity": "MEDIUM"},
    "strikingly":     {"cname": [".strikingly.com"],                         "content": ["page not found"],                                                     "severity": "MEDIUM"},
    "tilda":          {"cname": [".tilda.ws"],                               "content": ["Please renew your subscription"],                                     "severity": "MEDIUM"},
    "feedpress":      {"cname": [".feedpress.me"],                           "content": ["The feed has not been found"],                                        "severity": "MEDIUM"},
    "unbounce":       {"cname": [".unbouncepages.com"],                      "content": ["The requested URL was not found"],                                    "severity": "MEDIUM"},
    "agilecrm":       {"cname": [".agilecrm.com"],                           "content": ["Sorry, this page is no longer available"],                            "severity": "MEDIUM"},
    "kajabi":         {"cname": [".kajabi.com"],                             "content": ["The page you were looking for doesn't exist"],                        "severity": "MEDIUM"},
    "desk_com":       {"cname": [".desk.com"],                               "content": ["Please try again or try Desk.com free"],                              "severity": "HIGH"},
    "statuspage":     {"cname": [".statuspage.io"],                          "content": ["You are being redirected"],                                           "severity": "MEDIUM"},
    "landingi":       {"cname": [".landingi.com"],                           "content": ["It looks like you're lost"],                                          "severity": "MEDIUM"},
    "cargo":          {"cname": [".cargocollective.com"],                    "content": ["If you're moving your domain away from Cargo"],                       "severity": "MEDIUM"},
    "launchrock":     {"cname": [".launchrock.com"],                         "content": ["It looks like you may have taken a wrong turn"],                      "severity": "MEDIUM"},
    "simplebooklet":  {"cname": [".simplebooklet.com"],                      "content": ["We can't find this flipbook"],                                        "severity": "MEDIUM"},
    "pingdom":              {"cname": [".pingdom.com"],                      "content": ["pingdom"],                                                 "severity": "LOW"},
    "uptimerobot":          {"cname": [".uptimerobot.com"],                  "content": ["page not found"],                                          "severity": "LOW"},
    "aws_elastic_beanstalk":{"cname": [".elasticbeanstalk.com"],             "content": ["NoSuchApplication", "404 Not Found"],                      "severity": "HIGH"},
    "aws_s3_website":       {"cname": [".s3-website-", ".s3-website."],      "content": ["NoSuchBucket", "403 Forbidden"],                           "severity": "CRITICAL"},
    "digitalocean_spaces":  {"cname": [".digitaloceanspaces.com"],           "content": ["NoSuchBucket"],                                            "severity": "HIGH"},
    "kinsta":               {"cname": [".kinsta.cloud"],                     "content": ["No Site For Domain"],                                      "severity": "HIGH"},
    "wpengine":             {"cname": [".wpengine.com"],                     "content": ["No Site Configured"],                                      "severity": "HIGH"},
    "flywheel":             {"cname": [".getflywheel.com"],                  "content": ["We're sorry"],                                             "severity": "MEDIUM"},
    "render":               {"cname": [".onrender.com"],                     "content": ["No web service found"],                                    "severity": "HIGH"},
    "railway":              {"cname": [".railway.app"],                      "content": ["Application not found"],                                   "severity": "HIGH"},
    "cyclic":               {"cname": [".cyclic.app"],                       "content": ["not found"],                                               "severity": "MEDIUM"},
    "gitbook":              {"cname": [".gitbook.io"],                       "content": ["We could not find what you were looking for"],              "severity": "HIGH"},
    "readme_io":            {"cname": [".readme.io"],                        "content": ["The page you're looking for"],                             "severity": "MEDIUM"},
    "aftership":            {"cname": [".aftership.com"],                    "content": ["Oops"],                                                    "severity": "MEDIUM"},
    "aha":                  {"cname": [".ideas.aha.io"],                     "content": ["There is no portal here"],                                 "severity": "MEDIUM"},
    "campaign_monitor":     {"cname": [".createsend.com"],                   "content": ["Double check the URL"],                                    "severity": "MEDIUM"},
    "acquia_alt":           {"cname": [".acquia-sites.com"],                 "content": ["The site you are looking for could not be found"],         "severity": "HIGH"},
    "frontify":             {"cname": [".frontify.com"],                     "content": ["Not Found"],                                               "severity": "MEDIUM"},
    "hatenablog":           {"cname": [".hatenablog.com"],                   "content": ["404 Blog is not found"],                                   "severity": "MEDIUM"},
    "short_io":             {"cname": [".short.vu"],                         "content": ["Link does not exist"],                                     "severity": "HIGH"},
    "smugmug":              {"cname": [".smugmug.com"],                      "content": ["SmugMug Error Page"],                                      "severity": "MEDIUM"},
    "myshopify_alt":        {"cname": [".myshopify.com"],                    "content": ["Sorry, this shop is currently unavailable"],               "severity": "HIGH"},
    "tictail":              {"cname": [".tictail.com"],                      "content": ["Building beautiful stores"],                               "severity": "LOW"},
    "cloudfront_alt":       {"cname": [".cloudfront.net"],                   "content": ["ERROR: The request could not be satisfied", "Bad request"], "severity": "HIGH"},
    "azure_cdn":            {"cname": [".azureedge.net"],                    "content": ["404 Not Found"],                                           "severity": "MEDIUM"},
    "pantheon_alt":         {"cname": [".pantheon.io"],                      "content": ["404 error unknown site"],                                  "severity": "HIGH"},
    "dokku":                {"cname": [".dokku.me"],                         "content": ["no such app"],                                             "severity": "MEDIUM"},
    "smartjob":             {"cname": [".smartjobboard.com"],                "content": ["This job board website is either expired"],                 "severity": "MEDIUM"},
    "proposify":            {"cname": [".proposify.biz"],                    "content": ["If you need immediate assistance"],                        "severity": "MEDIUM"},
    "bigcartel":            {"cname": [".bigcartel.com"],                    "content": ["Oops! We couldn\\'t find that page."],                     "severity": "LOW"},
    "gemfury":              {"cname": [".fury.io"],                          "content": ["404: This page could not be found."],                      "severity": "MEDIUM"},
}

# Ã¢â€â‚¬Ã¢â€â‚¬ WILDCARD PATTERNS Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
WILDCARD_PATS = [
    re.compile(r"^[a-f0-9]{32}\."),
    re.compile(r"^[a-f0-9]{20,}\."),
    re.compile(r"^\d{10,}\."),
    re.compile(r"^[a-z]{1,2}\d{8,}\."),
]

# Ã¢â€â‚¬Ã¢â€â‚¬ CLOUD BUCKET PATTERNS Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
CLOUD_BUCKET_PATTERNS = {
    "s3":     [r"https?://([a-z0-9][a-z0-9\-\.]{2,62})\.s3(?:[-.][\w-]+)?\.amazonaws\.com"],
    "gcs":    [r"https?://storage\.googleapis\.com/([a-z0-9\-_.]+)"],
    "azure":  [r"https?://([a-z0-9][a-z0-9\-]{2,62})\.blob\.core\.windows\.net"],
    "do":     [r"https?://([a-z0-9][a-z0-9\-\.]{2,62})\.digitaloceanspaces\.com"],
}

# Ã¢â€â‚¬Ã¢â€â‚¬ ROLE EMAIL PATTERNS Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
ROLE_EMAIL_PREFIXES = {
    "executive": ["ceo", "cto", "cfo", "ciso", "vp", "director", "chief", "founder", "president", "owner", "evp", "svp", "coo"],
    "security":  ["security", "infosec", "appsec", "soc", "abuse", "vuln", "bugbounty", "csirt", "pentest", "cert"],
    "admin":     ["admin", "webmaster", "postmaster", "hostmaster", "sysadmin", "devops", "noc", "ops", "administrator", "root"],
    "dev":       ["dev", "developer", "engineer", "sre", "platform", "backend", "frontend", "architect", "code", "api", "engineering", "git"],
    "hr":        ["hr", "recruit", "talent", "people", "careers", "hiring", "jobs", "recruiting"],
    "finance":   ["finance", "billing", "accounting", "payment", "invoice", "treasury"],
    "legal":     ["legal", "counsel", "compliance", "gdpr", "privacy", "dpo"],
    "sales":     ["sales", "business", "partner", "revenue", "crm", "bd", "bizdev", "partnerships"],
    "marketing": ["marketing", "brand", "pr", "press", "media", "comms", "social", "growth"],
    "support":   ["support", "help", "customer", "service", "success", "helpdesk", "care", "ticket"],
    "generic":   ["info", "contact", "hello", "team", "noreply", "no-reply", "donotreply", "mail", "office", "hi", "general"],
}

# Ã¢â€â‚¬Ã¢â€â‚¬ DNS INTELLIGENCE CONSTANTS Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
DKIM_SELECTORS = [
    # Generic / numeric
    "default", "selector1", "selector2", "selector3", "selector4",
    "k1", "k2", "k3", "s1", "s2", "s3",
    "key1", "key2", "key3", "key2048",
    "sig1", "sig2", "main", "primary", "secondary",
    "test", "prod", "staging", "dev",
    "m", "s", "mx",
    # Mail-related
    "mail", "mail1", "mail2", "smtp", "smtpout", "dkimout",
    "em", "em1", "em2", "em3", "mailer", "outbound", "inbound",
    "newsletter", "lists", "bounce", "noreply", "notify",
    "dkim", "email",
    # Google / Microsoft
    "google", "google1", "google2",
    "office365", "microsoft",
    # ESPs
    "sendgrid", "sendgrid1", "sendgrid2",
    "mailjet", "mailjet1",
    "mandrill",
    "sparkpost", "sp1",
    "mailchimp", "mc",
    "amazonses", "ses", "ses1",
    "postmark", "pm",
    "protonmail", "pm1",
    "mailgun", "mg1",
    # CRM / Marketing
    "salesforce", "sf1",
    "hubspot", "hs1",
    "zendesk", "zd1",
    "marketo", "mkto",
    "eloqua",
    "pardot",
    "intercom",
    "constant-contact",
    "campaign-monitor",
    "klaviyo",
    "sendinblue", "sib",
    "activecampaign",
    # Security gateways
    "mimecast", "mic1",
    "proofpoint", "pp",
    "ironport",
    "barracuda",
    # Other providers
    "zoho", "yandex",
    "fastmail", "fm1", "fm2",
    "tutanota",
    "smtp2go",
    "mailersend",
    "sparkmail",
    "moosend",
    "litmus",
    "returnpath",
    "brevo",
]

SRV_PREFIXES = [
    # VoIP / messaging
    "_sip._tcp", "_sip._udp",
    "_sips._tcp",
    "_xmpp-client._tcp", "_xmpp-server._tcp",
    "_jabber._tcp",
    "_turn._tcp", "_turn._udp",
    "_stun._tcp", "_stun._udp",
    "_turns._tcp",
    "_matrix._tcp",
    # Directory / Auth
    "_ldap._tcp", "_ldaps._tcp",
    "_kerberos._tcp", "_kerberos._udp",
    "_kpasswd._tcp", "_kpasswd._udp",
    # Email / Calendar
    "_autodiscover._tcp",
    "_imaps._tcp", "_imap._tcp",
    "_pop3s._tcp", "_pop3._tcp",
    "_submission._tcp",
    "_smtp._tcp",
    "_caldav._tcp", "_caldavs._tcp",
    "_carddav._tcp", "_carddavs._tcp",
    # Microsoft-specific
    "_msrpc._tcp",
    "_gc._tcp",
    "_kerberos._tcp.dc._msdcs",
    # Chat / collaboration
    "_chat._tcp",
    "_xmpp._tcp",
    "_irc._tcp",
    # Game / Other
    "_minecraft._tcp",
    "_teamspeak._udp",
    "_ftp._tcp",
    "_sftp._tcp",
    "_ssh._tcp",
    "_rdp._tcp",
    "_http._tcp",
    "_https._tcp",
    "_openvpn._udp",
    "_pptp._tcp",
    "_l2tp._udp",
]

SPF_PROVIDER_MAP = {
    "_spf.google.com":            "Google Workspace",
    "spf.protection.outlook.com": "Microsoft 365",
    "include.zoho.com":           "Zoho Mail",
    "sendgrid.net":               "SendGrid",
    "mailgun.org":                "Mailgun",
    "servers.mcsv.net":           "Mailchimp",
    "amazonses.com":              "Amazon SES",
    "_spf.salesforce.com":        "Salesforce",
    "spf.mandrillapp.com":        "Mandrill/Mailchimp",
    "mktomail.com":               "Marketo",
    "spf.mailjet.com":            "Mailjet",
    "spf.sendinblue.com":         "Sendinblue/Brevo",
    "spf.sparkpostmail.com":      "SparkPost",
    "postmarkapp.com":            "Postmark",
    "mimecast.com":               "Mimecast",
    "pphosted.com":               "Proofpoint",
    "spf.smtp2go.com":            "SMTP2Go",
    "mailersend.com":             "MailerSend",
    "yandex.ru":                  "Yandex Mail",
    "spf.messagelabs.com":        "Symantec Email Security",
    "barracudanetworks.com":      "Barracuda",
    "hubspot.com":                "HubSpot",
    "zendesk.com":                "Zendesk",
    "customer.io":                "Customer.io",
    "klaviyo.com":                "Klaviyo",
}

TXT_TOKEN_MAP = {
    # Search / Webmaster
    r"google-site-verification":         "Google Search Console",
    r"yandex-verification":              "Yandex Webmaster",
    r"yahoo-domain-verification":        "Yahoo Domain Verification",
    r"bing-site-auth":                   "Bing Webmaster",
    r"baidu-site-verification":          "Baidu Webmaster",
    # Microsoft / Office
    r"MS=ms":                            "Microsoft/Office 365",
    r"v=msoid":                          "Microsoft Online ID",
    # Atlassian / Dev tools
    r"atlassian-domain-verification":    "Atlassian (Jira/Confluence)",
    r"atlassian-sending-domain-verification": "Atlassian Email",
    r"github-challenge-":                "GitHub Pages",
    r"gitlab-labs-verification":         "GitLab",
    r"bitbucket-domain-verification":    "Bitbucket",
    r"jira-":                            "Jira",
    # Comms
    r"slack-domain-verification":        "Slack",
    r"zoom-domain-verification":         "Zoom",
    r"teams-domain-verification":        "Microsoft Teams",
    r"webex-domain-verification":        "Cisco Webex",
    # Payments / Finance
    r"stripe-verification":              "Stripe",
    r"square-domain-verification":       "Square",
    r"paypal-domain-verification":       "PayPal",
    # Auth / SSO
    r"miro-domain-verification":         "Miro",
    r"duo-domain-verification":          "Duo Security",
    r"okta-domain-verification":         "Okta",
    r"onelogin-domain-claim":            "OneLogin",
    r"sailpoint-site-verification":      "SailPoint",
    # Productivity
    r"apple-domain-verification":        "Apple",
    r"dropbox-domain-verification":      "Dropbox",
    r"box-domain-verification":          "Box",
    r"docusign":                         "DocuSign",
    r"adobe-idp-site-verification":      "Adobe",
    r"notion-domain-verification":       "Notion",
    r"airtable-domain-verification":     "Airtable",
    # Marketing
    r"facebook-domain-verification":     "Facebook/Meta",
    r"klaviyo-site-verification":        "Klaviyo",
    r"hubspot-domain-verification":      "HubSpot",
    r"pardot-domain-verification":       "Pardot",
    # Security / Trust
    r"have-i-been-pwned-validation":     "HIBP",
    r"cisco-site-verification":          "Cisco",
    r"keybase-site-verification":        "Keybase",
    r"brave-ledger-verification":        "Brave Browser",
    r"globalsign-smime-dv":              "GlobalSign S/MIME",
    r"spycloud-domain-verification":     "SpyCloud",
    # Mail security
    r"v=spf1":                           "SPF Record",
    r"v=DMARC1":                         "DMARC Policy",
    r"v=DKIM1":                          "DKIM Key",
    # Hosting
    r"loaderio-":                        "Loader.io (Load Testing)",
    r"wix-domain-verification":          "Wix",
    r"shopify-domain-verification":      "Shopify",
    r"bluehost-domain-verification":     "Bluehost",
    r"protonmail-verification=":         "ProtonMail",
    r"zoho-verification=":               "Zoho",
}

def categorize_email(email: str) -> str:
    l = email.split("@")[0].lower()
    exact_map = {
        "info": "info",
        "devops": "devops",
    }
    if l in exact_map:
        return exact_map[l]
    for role, keywords in ROLE_EMAIL_PREFIXES.items():
        if any(k in l for k in keywords):
            return role
    return "personal"


COMMON_PASSIVE_SUBDOMAIN_PREFIXES = [
    "vpn", "mail", "webmail", "remote", "gateway", "portal", "api",
    "dev", "staging", "test", "beta", "admin", "panel", "dashboard",
    "login", "sso", "smtp", "mx", "ftp", "sftp", "rdp", "citrix",
    "extranet", "intranet", "jira", "confluence", "gitlab", "git",
    "jenkins", "grafana", "kibana", "elastic", "db", "database",
    "backup", "cdn", "static", "assets", "media", "upload", "files",
    "docs", "support", "blog", "shop", "app", "mobile", "api-v2",
    "uat", "qa", "preprod", "sandbox", "demo", "partners", "b2b",
    "status", "monitor", "nagios", "proxy", "bastion", "jump",
    "vpn2", "vpn-gateway", "webvpn", "pulse", "dmz", "ws", "wss",
    "ns1", "ns2", "ns3", "mx1", "mx2", "smtp2", "mail2", "mail3",
    "imap", "pop3", "autodiscover", "autoconfig", "helpdesk",
    "crm", "erp", "hr", "finance", "accounting", "legal", "it",
    "security", "noc", "soc", "ops", "devops", "infra", "cloud",
    "prod", "production", "live", "www2", "web", "web2", "secure",
    "members", "member", "client", "clients", "customer", "partner",
]

# Ã¢â€â‚¬Ã¢â€â‚¬ HTTP HELPERS Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
def _headers(extra: dict = None) -> dict:
    h = {
        "User-Agent": random.choice(USER_AGENTS),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "gzip, deflate",
        "Connection": "keep-alive",
    }
    if extra:
        h.update(extra)
    return h


class _ResponseProxy:
    """Proxy aiohttp response object with robust text decoding."""

    def __init__(self, response: aiohttp.ClientResponse):
        self._response = response

    def __getattr__(self, item):
        return getattr(self._response, item)

    def __bool__(self) -> bool:
        return True

    async def text(self, *args, **kwargs):
        enc = kwargs.get("encoding", "utf-8")
        return await _read_response_text(self._response, fallback_encoding=enc)


async def _safe_get(session: aiohttp.ClientSession, url: str, timeout: int = 20, **kwargs) -> Optional[aiohttp.ClientResponse]:
    extra_h = kwargs.pop("headers", {})
    merged_h = _headers(extra_h if isinstance(extra_h, dict) else {})
    try:
        resp = await get_http_guard().get(
            session,
            url,
            timeout=timeout,
            headers=merged_h,
            allow_redirects=kwargs.pop("allow_redirects", True),
            **kwargs,
        )
        return _ResponseProxy(resp) if resp else None
    except (aiohttp.ClientError, asyncio.TimeoutError) as exc:
        log.debug("safe_get_failed url=%s err=%s", url, exc)
        return None


async def _safe_post(session: aiohttp.ClientSession, url: str, timeout: int = 20, **kwargs) -> Optional[aiohttp.ClientResponse]:
    extra_h = kwargs.pop("headers", {})
    merged_h = _headers(extra_h if isinstance(extra_h, dict) else {})
    try:
        resp = await get_http_guard().post(
            session,
            url,
            timeout=timeout,
            headers=merged_h,
            allow_redirects=kwargs.pop("allow_redirects", True),
            data=kwargs.pop("data", None),
            json=kwargs.pop("json", None),
            **kwargs,
        )
        return _ResponseProxy(resp) if resp else None
    except (aiohttp.ClientError, asyncio.TimeoutError) as exc:
        log.debug("safe_post_failed url=%s err=%s", url, exc)
        return None


async def _safe_get_text_cached(session: aiohttp.ClientSession, url: str, timeout: int = 20) -> str:
    now = time.time()
    cached = _INDEX_TEXT_CACHE.get(url)
    if cached and cached[1] > now:
        return cached[0]
    resp = await _safe_get(session, url, timeout=timeout)
    if not (resp and resp.status == 200):
        return ""
    text = await resp.text()
    _INDEX_TEXT_CACHE[url] = (text, now + _INDEX_TEXT_CACHE_TTL)
    return text


async def _commoncrawl_indexes(session: aiohttp.ClientSession, mode: str) -> List[str]:
    cache_key = str(mode or "balanced")
    now = time.time()
    cached = _COMMONCRAWL_INDEX_CACHE.get(cache_key)
    if cached and cached[1] > now:
        return list(cached[0])

    async def _fetch_json(url: str) -> Any:
        resp = await _safe_get(session, url, timeout=15)
        if not (resp and resp.status == 200):
            return None
        return await resp.json(content_type=None)

    indexes = await latest_commoncrawl_indexes(_fetch_json, mode=cache_key)
    _COMMONCRAWL_INDEX_CACHE[cache_key] = (list(indexes), now + 3600)
    return list(indexes)


def _github_auth_headers(token: str, *, accept: str = "application/vnd.github+json") -> Dict[str, str]:
    headers = {"Accept": accept}
    if token:
        headers["Authorization"] = f"token {token}"
    return headers


async def _json_request_with_retries(
    session: aiohttp.ClientSession,
    method: str,
    url: str,
    *,
    timeout: int,
    retries: int = 2,
    backoff: float = 0.75,
    headers: Optional[Dict[str, str]] = None,
    data: Any = None,
    json_body: Any = None,
    ssl: bool = True,
) -> tuple[Optional[Any], int]:
    caller = _safe_get if method.upper() == "GET" else _safe_post
    last_status = 0
    for attempt in range(retries + 1):
        resp = await caller(
            session,
            url,
            timeout=timeout,
            headers=headers or {},
            data=data,
            json=json_body,
            ssl=ssl,
        )
        if resp:
            last_status = int(resp.status or 0)
            if 200 <= last_status < 300:
                try:
                    return await resp.json(content_type=None), last_status
                except Exception:
                    try:
                        return json.loads(await resp.text()), last_status
                    except Exception:
                        return None, last_status
            if last_status not in {408, 429, 500, 502, 503, 504}:
                break
        if attempt < retries:
            await asyncio.sleep(backoff * float(2 ** attempt))
    return None, last_status


async def _text_request_with_retries(
    session: aiohttp.ClientSession,
    method: str,
    url: str,
    *,
    timeout: int,
    retries: int = 2,
    backoff: float = 0.75,
    headers: Optional[Dict[str, str]] = None,
    data: Any = None,
    json_body: Any = None,
    ssl: bool = True,
) -> tuple[str, int]:
    caller = _safe_get if method.upper() == "GET" else _safe_post
    last_status = 0
    for attempt in range(retries + 1):
        resp = await caller(
            session,
            url,
            timeout=timeout,
            headers=headers or {},
            data=data,
            json=json_body,
            ssl=ssl,
        )
        if resp:
            last_status = int(resp.status or 0)
            if 200 <= last_status < 300:
                try:
                    return await resp.text(), last_status
                except Exception:
                    return "", last_status
            if last_status not in {408, 429, 500, 502, 503, 504}:
                break
        if attempt < retries:
            await asyncio.sleep(backoff * float(2 ** attempt))
    return "", last_status


def _sse_summary(result: "ReconResult") -> dict:
    wayback = result.wayback_urls if isinstance(result.wayback_urls, dict) else {}
    # Prefer stored total_urls count (set by mine() before capping); fallback to summing list keys
    archive_urls = int(wayback.get("total_urls", 0) or 0)
    if archive_urls == 0:
        for key in ("interesting", "urls", "all", "all_urls"):
            val = wayback.get(key, [])
            if isinstance(val, list):
                archive_urls += len(val)
    vulns = len(result.vulnerabilities)
    takeovers = len(result.takeover_records)
    breaches = len(result.breach_records)
    cloud_assets = len(result.cloud_assets)
    ports = 0
    for row in (result.ip_records or []):
        if not isinstance(row, dict):
            continue
        raw_ports = row.get("open_ports") or row.get("ports") or []
        ports += len([p for p in raw_ports if isinstance(p, int) or str(p).isdigit()])
    return {
        "subdomains": len(result.subdomains),
        "emails": len(result.emails),
        "vulns": vulns,
        "ips": len(result.ip_records),
        "ports": ports,
        "cloud_assets": cloud_assets,
        "exposures": vulns + takeovers + breaches + cloud_assets,
        "takeovers": takeovers,
        "technologies": len(result.technologies),
        "breaches": breaches,
        "archive_urls": archive_urls,
        "certs": len(result.ssl_info),
        # Backward-compatible aliases for older frontends.
        "ip_records": len(result.ip_records),
        "vulnerabilities": vulns,
    }


async def _doh_query(session: aiohttp.ClientSession, name: str, qtype: str, timeout: int = 15) -> list:
    """Cached DoH query with multiple resolvers for brittle enterprise domains."""
    cache_key = (name.lower(), qtype.upper())
    now = time.time()
    if cache_key in _DOH_CACHE:
        records, expiry = _DOH_CACHE[cache_key]
        if now < expiry:
            return records
    endpoints = [
        (
            f"https://cloudflare-dns.com/dns-query?name={quote(name)}&type={qtype}",
            {"Accept": "application/dns-json", "User-Agent": random.choice(USER_AGENTS)},
        ),
        (
            f"https://dns.google/resolve?name={quote(name)}&type={qtype}",
            {"Accept": "application/dns-json", "User-Agent": random.choice(USER_AGENTS)},
        ),
        (
            f"https://mozilla.cloudflare-dns.com/dns-query?name={quote(name)}&type={qtype}",
            {"Accept": "application/dns-json", "User-Agent": random.choice(USER_AGENTS)},
        ),
        (
            f"https://doh.opendns.com/dns-query?name={quote(name)}&type={qtype}",
            {"Accept": "application/dns-json", "User-Agent": random.choice(USER_AGENTS)},
        ),
    ]
    for endpoint, headers in endpoints:
        try:
            resp = await _safe_get(
                session,
                endpoint,
                timeout=timeout,
                headers=headers,
            )
            if resp and resp.status == 200:
                data = await resp.json(content_type=None)
                answers = data.get("Answer", [])
                _DOH_CACHE[cache_key] = (answers, now + _DOH_CACHE_TTL)
                return answers
        except Exception:
            continue
    _DOH_CACHE[cache_key] = ([], now + 30)
    return []


async def _load_cloud_ranges(session: aiohttp.ClientSession):
    """Download and cache cloud provider IP ranges once."""
    global _CLOUD_RANGES, _CLOUD_RANGES_LOADED
    if _CLOUD_RANGES_LOADED:
        return
    # AWS
    try:
        resp = await _safe_get(session, "https://ip-ranges.amazonaws.com/ip-ranges.json", timeout=15)
        if resp and resp.status == 200:
            data = await resp.json(content_type=None)
            nets = []
            for p in data.get("prefixes", []):
                try:
                    nets.append((ipaddress.ip_network(p["ip_prefix"], strict=False), p.get("service", "AWS")))
                except Exception:
                    pass
            _CLOUD_RANGES["aws"] = nets
    except Exception:
        pass
    # Cloudflare
    try:
        resp = await _safe_get(session, "https://www.cloudflare.com/ips-v4", timeout=10)
        if resp and resp.status == 200:
            text = await resp.text()
            nets = []
            for line in text.splitlines():
                line = line.strip()
                if line:
                    try:
                        nets.append((ipaddress.ip_network(line, strict=False), "CDN"))
                    except Exception:
                        pass
            _CLOUD_RANGES["cloudflare"] = nets
    except Exception:
        pass
    # GCP
    try:
        resp = await _safe_get(session, "https://www.gstatic.com/ipranges/cloud.json", timeout=10)
        if resp and resp.status == 200:
            data = await resp.json(content_type=None)
            nets = []
            for p in data.get("prefixes", []):
                ipv4 = p.get("ipv4Prefix", "")
                if ipv4:
                    try:
                        nets.append((ipaddress.ip_network(ipv4, strict=False), "GCP"))
                    except Exception:
                        pass
            _CLOUD_RANGES["gcp"] = nets
    except Exception:
        pass
    # Azure
    try:
        azure_url = (
            "https://download.microsoft.com/download/7/1/D/"
            "71D86715-5596-4529-9B13-DA13A5DE5B63/ServiceTags_Public.json"
        )
        resp = await _safe_get(session, azure_url, timeout=20)
        if resp and resp.status == 200:
            data = await resp.json(content_type=None)
            nets = []
            for value in data.get("values", []):
                for prefix in value.get("properties", {}).get("addressPrefixes", []):
                    if ":" not in prefix:  # IPv4 only
                        try:
                            svc = value.get("name", "Azure")
                            nets.append((ipaddress.ip_network(prefix, strict=False), svc))
                        except Exception:
                            pass
            _CLOUD_RANGES["azure"] = nets
    except Exception:
        pass
    # Fastly
    try:
        resp = await _safe_get(session, "https://api.fastly.com/public-ip-list", timeout=10)
        if resp and resp.status == 200:
            data = await resp.json(content_type=None)
            nets = []
            for prefix in data.get("addresses", []):
                if ":" not in prefix:
                    try:
                        nets.append((ipaddress.ip_network(prefix, strict=False), "CDN"))
                    except Exception:
                        pass
            _CLOUD_RANGES["fastly"] = nets
    except Exception:
        pass
    _CLOUD_RANGES_LOADED = True


def _check_cloud_provider(ip_str: str) -> Tuple[str, str]:
    """Returns (provider_name, service_name) for a given IP."""
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        provider_map = {
            "aws": "AWS", "cloudflare": "Cloudflare", "gcp": "Google Cloud",
            "azure": "Azure", "fastly": "Fastly",
        }
        for key, nets in _CLOUD_RANGES.items():
            for net, svc in nets:
                if ip_obj in net:
                    return provider_map.get(key, key.upper()), svc
    except Exception:
        pass
    return "", ""


def _normalize_ip_literal(value: Any) -> str:
    raw = str(value or "").strip().rstrip(".")
    if not raw:
        return ""
    try:
        return str(ipaddress.ip_address(raw))
    except Exception:
        return ""


def _extract_ip_literals(values: Any) -> List[str]:
    out: List[str] = []
    if values is None:
        return out
    if isinstance(values, (list, tuple, set)):
        for item in values:
            out.extend(_extract_ip_literals(item))
        return out
    ip = _normalize_ip_literal(values)
    if ip:
        out.append(ip)
    return out

# Ã¢â€â‚¬Ã¢â€â‚¬ SUBDOMAIN ENUMERATOR Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
class SubdomainEnumerator:
    def __init__(
        self,
        domain: str,
        mode: str,
        session: aiohttp.ClientSession,
        api_keys: dict,
        debug_coverage: bool = False,
        source_registry: Optional[SourceRegistry] = None,
    ):
        self.domain = domain
        self.mode = mode
        self.session = session
        self.api_keys = api_keys
        self.debug_coverage = debug_coverage
        self.source_registry = source_registry or SourceRegistry(api_keys=api_keys)
        self.apex = normalize_hostname(domain)
        self.source_metrics: Dict[str, Dict[str, Any]] = {}
        self.dropped_items: List[Dict[str, Any]] = []
        self.source_errors: List[Dict[str, Any]] = []
        self._partial_results: Dict[str, SubdomainRecord] = {}
        self._normalized_candidates_seen: set[str] = set()
        self._rejected_noise_count: int = 0
        self._accepted_final_count: int = 0
        self.inventory_stats: Dict[str, Any] = {}
        self.timeout = max(TIMEOUTS[mode], 30)
        self._domain_re = re.compile(
            rf"(?:[a-zA-Z0-9_](?:[a-zA-Z0-9_\-]{{0,61}}[a-zA-Z0-9_])?\.)+{re.escape(domain)}",
            re.I
        )

    def _normalize_candidate_subs(self, values: Any) -> set:
        normalized = set()
        for raw in values or []:
            sub = self._normalize_in_scope_subdomain(raw)
            if sub:
                normalized.add(sub)
        return normalized

    def _normalize_ct_subdomain(self, value: Any) -> str:
        raw = str(value or "").strip().lower().rstrip(".")
        if raw.startswith("*."):
            tail = normalize_hostname(raw[2:])
            if tail and tail == self.apex:
                return f"*.{tail}"
        norm = normalize_hostname(raw.lstrip("*."))
        return norm.lower() if norm else ""

    def _candidate_host_tokens(self, raw: Any) -> List[str]:
        value = normalize_text(str(raw or "")).strip()
        if not value:
            return []
        tokens: List[str] = []

        def push(candidate: str) -> None:
            cand = str(candidate or "").strip().strip("[](){}<>\"'")
            if cand and cand not in tokens:
                tokens.append(cand)

        push(value)
        for part in re.split(r"[\s,;|]+", value):
            push(part)
            if "=" in part:
                push(part.split("=", 1)[-1])
            if "://" in part:
                try:
                    parsed = urlparse(part)
                    push(parsed.hostname or "")
                except Exception:
                    continue
        return tokens

    def _normalize_in_scope_subdomain(self, raw: Any) -> str:
        for token in self._candidate_host_tokens(raw):
            sub = normalize_hostname(token)
            if not sub or sub == self.apex:
                continue
            if not sub.endswith("." + self.apex):
                continue
            if not looks_like_hostname(sub):
                continue
            return sub
        return ""

    def _extract_host_candidate(self, raw: Any) -> str:
        for token in self._candidate_host_tokens(raw):
            host = self._normalize_in_scope_subdomain(token)
            if host:
                return host
            try:
                parsed = urlparse(token)
            except Exception:
                continue
            host = self._normalize_in_scope_subdomain(parsed.hostname or "")
            if host:
                return host
        return ""

    def _collect_scoped_hosts(self, payload: Any, *, preferred_keys: Optional[Tuple[str, ...]] = None) -> set:
        hits: set[str] = set()
        keys = tuple(preferred_keys or ())

        def walk(node: Any, depth: int = 0) -> None:
            if depth > 4 or node is None:
                return
            if isinstance(node, dict):
                for key, value in node.items():
                    if not keys or str(key) in keys:
                        host = self._extract_host_candidate(value)
                        if host:
                            hits.add(host)
                    walk(value, depth + 1)
                return
            if isinstance(node, (list, tuple, set)):
                for item in node:
                    walk(item, depth + 1)
                return
            host = self._extract_host_candidate(node)
            if host:
                hits.add(host)

        walk(payload)
        return hits

    def _extract(self, text: str) -> set:
        found = set(self._domain_re.findall(text))
        cleaned = set()
        for s in found:
            s = normalize_hostname(s)
            if s and (s.endswith("." + self.apex) or s == self.apex):
                cleaned.add(s)
        return cleaned

    def _metric_bucket(self, name: str) -> Dict[str, Any]:
        return self.source_metrics.setdefault(name, {
            "items_obtenidos": 0,
            "items_parseados": 0,
            "items_aceptados": 0,
            "items_descartados_por_dedupe": 0,
            "items_descartados_por_filtro": 0,
            "errores": 0,
            "latencia_ms": 0,
            "status": "ok",
        })

    def _source_quality_bucket(self, source_name: str) -> str:
        source = str(source_name or "").strip().lower()
        if source in {"crt.sh", "ct_logs", "ctsearch", "securitytrails", "virustotal", "fullhunt", "chaos", "censys", "whoisxml", "mnemonic_pdns"}:
            return "high_confidence"
        if source in {"jldc", "anubisdb", "commoncrawl"}:
            return "noisy"
        return "medium_confidence"

    def _source_confidence_weight(self, source_name: str) -> float:
        base = float(SOURCE_CONFIDENCE.get(source_name, 0.65) or 0.65)
        bucket = self._source_quality_bucket(source_name)
        if bucket == "high_confidence":
            base += 0.08
        elif bucket == "noisy":
            base -= 0.12
        return max(0.25, min(0.95, base))

    def _subdomain_confidence(self, rec: SubdomainRecord) -> tuple[float, str]:
        sources = [str(src) for src in (rec.sources or []) if str(src)]
        if not sources:
            return 0.35, "noisy"
        weighted = [self._source_confidence_weight(src) for src in sources]
        average = sum(weighted) / max(1, len(weighted))
        diversity_bonus = min(0.22, max(0, len(set(sources)) - 1) * 0.07)
        high_bonus = 0.06 if any(self._source_quality_bucket(src) == "high_confidence" for src in sources) else 0.0
        noisy_penalty = 0.06 if len(set(sources)) == 1 and self._source_quality_bucket(sources[0]) == "noisy" else 0.0
        score = round(max(0.2, min(0.99, average + diversity_bonus + high_bonus - noisy_penalty)), 3)
        if score >= 0.82:
            return score, "high_confidence"
        if score >= 0.58:
            return score, "medium_confidence"
        return score, "noisy"

    def _is_api_backed_source(self, source_name: str) -> bool:
        try:
            return bool((self.source_registry and self.source_registry.effective_status(source_name) == "ok") and self.source_registry.api_keys and source_to_required_credentials(source_name))
        except Exception:
            return bool(source_to_required_credentials(source_name))

    def _store_partial_results(self, results: Dict[str, SubdomainRecord]) -> None:
        # Keep best-known in-memory snapshot so orchestration can recover on module timeout.
        self._partial_results = dict(results)

    def get_partial_results(self) -> Dict[str, SubdomainRecord]:
        return dict(self._partial_results)

    async def _run_source(self, name: str, fn) -> set:
        metric = self._metric_bucket(name)
        t0 = time.perf_counter()
        tok = set_current_source(name)
        _timeout = SOURCE_OVERRIDE_TIMEOUTS.get(name, {}).get(self.mode) or (SLOW_SOURCE_TIMEOUT if name in SLOW_SOURCES else PER_SOURCE_TIMEOUT).get(self.mode, 60)
        try:
            data = await asyncio.wait_for(fn(), timeout=_timeout)
            items = data if isinstance(data, set) else set()
            metric["items_obtenidos"] = len(items)
            return items
        except (aiohttp.ClientError, asyncio.TimeoutError, ValueError) as exc:
            metric["errores"] += 1
            metric["status"] = "timeout" if isinstance(exc, asyncio.TimeoutError) else "fail"
            self.source_errors.append({
                "time": _utcnow_iso(),
                "module": "Subdomain Enumeration",
                "source": name,
                "kind": type(exc).__name__,
                "message_short": str(exc)[:160],
            })
            if self.debug_coverage:
                log.warning("sub_source_failed source=%s domain=%s err=%s", name, self.domain, exc)
            return set()
        except Exception as exc:
            metric["errores"] += 1
            metric["status"] = "fail"
            self.source_errors.append({
                "time": _utcnow_iso(),
                "module": "Subdomain Enumeration",
                "source": name,
                "kind": type(exc).__name__,
                "message_short": str(exc)[:160],
            })
            log.warning("sub_source_failed_unexpected source=%s domain=%s err=%s", name, self.domain, exc)
            return set()
        finally:
            reset_current_source(tok)
            metric["latencia_ms"] = int((time.perf_counter() - t0) * 1000)
            guard = get_http_guard()
            if self.debug_coverage and hasattr(guard, "source_state"):
                metric["runtime"] = guard.source_state(name)
    async def _crtsh(self) -> set:
        subs = set()
        domain = self.domain
        page_size = 5000
        max_pages = {"fast": 2, "balanced": 4, "deep": 10, "turbo": 2}.get(self.mode, 4)
        request_timeout = {"fast": 30, "balanced": 45, "deep": 90, "turbo": 25}.get(self.mode, 45)
        def parse_crtsh(data):
            found = set()
            for entry in (data if isinstance(data, list) else []):
                for fld in ("name_value", "common_name"):
                    val = entry.get(fld) or ""
                    if not isinstance(val, str):
                        continue
                    for line in re.split(r'[\n,]', val):
                        line = self._normalize_ct_subdomain(line)
                        if line == f"*.{domain}":
                            found.add(line)
                        elif line and line.endswith(domain) and looks_like_hostname(line):
                            found.add(line.lower())
            return found
        def parse_crtsh_html(text: str) -> set:
            found = set()
            if not text:
                return found
            for host in re.findall(r"(?i)(?:^|[^A-Z0-9_.-])([A-Z0-9][A-Z0-9_.-]*\." + re.escape(domain) + r")", text):
                norm = normalize_hostname(str(host).strip().lstrip("*."))
                if norm and norm.endswith(domain) and looks_like_hostname(norm):
                    found.add(norm.lower())
            return found
        def parse_crtsh_body(raw: str) -> list:
            text = str(raw or "").strip()
            if not text or text.startswith("<"):
                return []
            try:
                parsed = json.loads(text)
                return parsed if isinstance(parsed, list) else []
            except Exception:
                rows = []
                for ln in text.splitlines():
                    ln = ln.strip().rstrip(",")
                    if not ln or ln.startswith("[BEGIN_HEADERS]") or ln.startswith("[END_HEADERS]"):
                        continue
                    try:
                        obj = json.loads(ln)
                    except Exception:
                        continue
                    if isinstance(obj, dict):
                        rows.append(obj)
                return rows
        def is_terminal_crtsh_error(status: int, raw: str) -> bool:
            lowered = str(raw or "").lower()
            if status in {502, 503, 504}:
                return True
            return any(marker in lowered for marker in (
                "terminated by the crt.sh database server",
                "searches that would produce many results may never succeed",
                "server conn crashed?",
                "sorry, something went wrong",
                "unsupported use of '%'",
            ))
        # Prefer the fast single-shot JSON variant first. The heavier sorted/deduplicated views
        # often stall long enough to consume the whole source timeout before we reach a working query.
        json_specs = [
            {
                "base_url": f"https://crt.sh/?q=%25.{domain}&output=json",
                "use_listing_params": False,
                "max_pages": 1,
            },
            {
                "base_url": f"https://crt.sh/?q=%.{domain}&output=json",
                "use_listing_params": True,
                "max_pages": max_pages,
            },
            {
                "base_url": f"https://crt.sh/?Identity=%.{domain}&output=json",
                "use_listing_params": True,
                "max_pages": max_pages,
            },
            {
                "base_url": f"https://crt.sh/?q=%.{domain}&output=json&deduplicate=Y",
                "use_listing_params": True,
                "max_pages": max_pages,
            },
            {
                "base_url": f"https://crt.sh/?Identity=%.{domain}&output=json&deduplicate=Y",
                "use_listing_params": True,
                "max_pages": max_pages,
            },
            {
                "base_url": f"https://crt.sh/?q={domain}&output=json",
                "use_listing_params": False,
                "max_pages": 1,
            },
        ]
        html_urls = [
            f"https://crt.sh/?q=%.{domain}",
            f"https://crt.sh/?Identity=%.{domain}",
            f"https://crt.sh/?q={domain}",
        ]
        json_found_any = False
        for spec in json_specs:
            base_url = str(spec.get("base_url", "") or "")
            use_listing_params = bool(spec.get("use_listing_params", False))
            spec_max_pages = max(1, int(spec.get("max_pages", 1) or 1))
            offset = 0
            pages_seen = 0
            terminal_error = False
            base_prev = len(subs)
            while pages_seen < spec_max_pages:
                page_url = base_url
                if use_listing_params:
                    page_url += "&dir=^&sort=1&group=none"
                if offset and use_listing_params:
                    page_url += f"&offset={offset}"
                data, status = await _json_request_with_retries(
                    self.session,
                    "GET",
                    page_url,
                    timeout=request_timeout,
                    retries=3,
                    backoff=0.8,
                    headers={"User-Agent": "Mozilla/5.0"},
                    ssl=False,
                )
                rows = data if isinstance(data, list) else []
                raw = ""
                if not rows or status != 200:
                    resp = await _safe_get(
                        self.session,
                        page_url,
                        timeout=request_timeout,
                        headers={"User-Agent": "Mozilla/5.0"},
                        ssl=False,
                    )
                    if resp:
                        status = resp.status
                        raw = await resp.text()
                        rows = parse_crtsh_body(raw)
                if is_terminal_crtsh_error(status, raw):
                    terminal_error = True
                    break
                if not rows:
                    break
                subs.update(parse_crtsh(rows))
                pages_seen += 1
                row_count = len(rows)
                if row_count < page_size:
                    break
                offset += row_count
                await asyncio.sleep(0.35)
            if terminal_error:
                continue
            base_added = len(subs) - base_prev
            json_found_any = json_found_any or base_added > 0
            if base_added > 0:
                return subs
        if json_found_any:
            return subs
        for base_url in html_urls:
            offset = 0
            for _ in range(max_pages):
                html_url = f"{base_url}&dir=^&sort=1&group=none"
                if offset:
                    html_url += f"&offset={offset}"
                resp = await _safe_get(
                    self.session,
                    html_url,
                    timeout=request_timeout,
                    headers={"User-Agent": "Mozilla/5.0"},
                    ssl=False,
                )
                if not resp:
                    break
                text = await resp.text()
                if is_terminal_crtsh_error(resp.status, text):
                    break
                if resp.status != 200:
                    break
                found = parse_crtsh_html(text)
                if not found:
                    break
                prev = len(subs)
                subs.update(found)
                if len(subs) == prev:
                    break
                offset += page_size
                await asyncio.sleep(0.35)
        return subs

    async def _certspotter(self) -> set:
        subs = set()
        after_cursor = None
        max_pages = 20 if self.mode == "deep" else 10
        for _ in range(max_pages):
            try:
                url = (f"https://api.certspotter.com/v1/issuances?domain={self.domain}"
                       f"&include_subdomains=true&expand=dns_names")
                if after_cursor:
                    url += f"&after={quote(str(after_cursor), safe='')}"
                data, status = await _json_request_with_retries(
                    self.session,
                    "GET",
                    url,
                    timeout=max(self.timeout, 30),
                    retries=3,
                    backoff=1.0,
                    headers={"Accept": "application/json"},
                )
                if status != 200 or not isinstance(data, list):
                    break
                if not data:
                    break
                next_cursor = None
                for entry in data:
                    for name in entry.get("dns_names", []):
                        host = self._normalize_ct_subdomain(name)
                        if host == f"*.{self.domain}":
                            subs.add(host)
                        elif host and host.endswith(self.domain):
                            subs.add(host.lower())
                    entry_id = entry.get("id")
                    if entry_id is not None:
                        next_cursor = entry_id
                after_cursor = next_cursor
                if after_cursor is None:
                    break
                await asyncio.sleep(0.2)
            except Exception:
                break
        return subs

    async def _hackertarget(self) -> set:
        subs = set()
        page = 1
        seen_pages = set()
        timeout = max(self.timeout, 30)
        while True:
            url = f"https://api.hackertarget.com/hostsearch/?q={self.domain}&page={page}"
            text = ""
            for attempt in range(4):
                try:
                    resp = await _safe_get(self.session, url, timeout=timeout)
                    if resp and resp.status == 200:
                        text = await resp.text()
                        break
                except Exception:
                    pass
                if attempt < 3:
                    await asyncio.sleep(float(2**attempt))
            if not text:
                break
            lowered = text.lower()
            if "api count exceeded" in lowered or "error" in lowered:
                break
            found = self._extract(text)
            fingerprint = tuple(sorted(found))[:25]
            if not found or fingerprint in seen_pages:
                break
            seen_pages.add(fingerprint)
            prev = len(subs)
            subs.update(found)
            if len(subs) == prev:
                break
            page += 1
            await asyncio.sleep(0.35)
        return subs

    async def _rapiddns(self) -> set:
        subs = set()
        seen_pages = set()
        timeout = max(self.timeout, 30)
        max_pages = 20 if self.mode == "deep" else 5 if self.mode == "fast" else 10
        host_re = re.compile(rf'([a-z0-9][a-z0-9._-]*\.{re.escape(self.domain)})', re.I)
        for page in range(1, max_pages + 1):
            url = f"https://rapiddns.io/subdomain/{self.domain}?full=1&page={page}"
            text, status = await _text_request_with_retries(
                self.session,
                "GET",
                url,
                timeout=timeout,
                retries=3,
                backoff=1.0,
                headers={"User-Agent": "Mozilla/5.0", "Accept": "text/html,application/xhtml+xml"},
            )
            if status != 200 or not text.strip():
                break
            found = {
                normalize_hostname(host).lower()
                for host in host_re.findall(text)
                if normalize_hostname(host) and normalize_hostname(host).endswith(self.domain)
            }
            found.update(self._extract(text))
            fingerprint = tuple(sorted(found))[:25]
            if not found or fingerprint in seen_pages:
                break
            seen_pages.add(fingerprint)
            prev_len = len(subs)
            subs.update(found)
            has_next = (
                f"page={page + 1}" in text
                or 'rel="next"' in text.lower()
                or ">Next<" in text
            )
            if len(subs) == prev_len and not has_next:
                break
            if not has_next and len(found) < 10:
                break
            await asyncio.sleep(0.5)
        return subs

    # _threatcrowd removed — offline since 2022

    async def _alienvault_otx(self) -> set:
        subs = set()
        page = 1
        timeout = max(self.timeout, 30)
        headers = {"Accept": "application/json", "User-Agent": "Mozilla/5.0"}
        while True:
            url = (
                f"https://otx.alienvault.com/api/v1/indicators/domain/{self.domain}/passive_dns"
                f"?limit=500&page={page}"
            )
            data = None
            for attempt in range(4):
                try:
                    resp = await _safe_get(self.session, url, timeout=timeout, headers=headers)
                    if resp and resp.status == 200:
                        data = await resp.json(content_type=None)
                        break
                except Exception:
                    pass
                if attempt < 3:
                    await asyncio.sleep(float(2**attempt))
            if not isinstance(data, dict):
                break
            entries = data.get("passive_dns", []) or []
            if not entries:
                break
            prev = len(subs)
            for entry in entries:
                host = normalize_hostname(entry.get("hostname", "") or entry.get("host", ""))
                if host and host.endswith(self.domain):
                    subs.add(host.lower())
            if not data.get("has_next") or len(subs) == prev:
                break
            page += 1
            await asyncio.sleep(0.35)
        return subs

    async def _subdomaincenter(self) -> set:
        def _parse_items(payload: Any) -> tuple[set[str], bool]:
            items = []
            rate_limited = False
            if isinstance(payload, str):
                lowered = payload.lower()
                rate_limited = "rate limit" in lowered or "too many requests" in lowered
            elif isinstance(payload, list):
                items = payload
            elif isinstance(payload, dict):
                items = payload.get("subdomains", []) or payload.get("data", []) or []
                status_s = str(payload.get("status", "") or "").strip().lower()
                message_blob = json.dumps(payload, ensure_ascii=False).lower()
                rate_limited = (
                    status_s == "429"
                    or "rate limit" in message_blob
                    or "too many requests" in message_blob
                )
            found = set()
            for item in items:
                norm = normalize_hostname(str(item).strip().lstrip("*."))
                if norm and norm != self.apex and norm.endswith(self.domain):
                    found.add(norm.lower())
            return found, rate_limited
        subs = set()
        max_pages = {"fast": 2, "balanced": 4, "deep": 8, "turbo": 2}.get(self.mode, 4)
        request_timeout = {"fast": 20, "balanced": 30, "deep": 60, "turbo": 20}.get(self.mode, max(self.timeout, 30))
        page_delay = 22.0 if self.mode in {"balanced", "deep"} else 0.0
        headers = _headers({"Accept": "application/json"})
        source_budget = int(
            SOURCE_OVERRIDE_TIMEOUTS.get("subdomaincenter", {}).get(self.mode)
            or (SLOW_SOURCE_TIMEOUT if "subdomaincenter" in SLOW_SOURCES else PER_SOURCE_TIMEOUT).get(self.mode, 60)
        )
        started_at = time.perf_counter()
        safety_margin = 20.0

        # FIXED: use aiohttp JSON requests and honor subdomain.center's live 3/minute throttle so zstd responses and 429s do not zero this high-yield source.
        for page in range(1, max_pages + 1):
            if subs and (time.perf_counter() - started_at) >= max(5.0, float(source_budget) - safety_margin):
                return subs
            url = f"https://api.subdomain.center/?domain={self.domain}"
            if page > 1:
                url += f"&page={page}"
            max_attempts = 8 if page == 1 and self.mode in {"balanced", "deep"} else 4
            page_found_count = 0
            page_added = 0
            for attempt in range(max_attempts):
                data: Any = ""
                raw = ""
                status = 0
                retry_after = 0.0
                retryable_failure = False
                try:
                    resp = await _safe_get(
                        self.session,
                        url,
                        timeout=request_timeout,
                        headers=headers,
                    )
                    if resp:
                        status = int(resp.status or 0)
                        retry_after_hdr = str(resp.headers.get("Retry-After", "") or "").strip()
                        if retry_after_hdr.isdigit():
                            retry_after = float(retry_after_hdr)
                        try:
                            data = await resp.json(content_type=None)
                            raw = json.dumps(data, ensure_ascii=False) if isinstance(data, (list, dict)) else str(data or "")
                        except Exception:
                            raw = await resp.text()
                            data = raw
                except (aiohttp.ClientError, asyncio.TimeoutError):
                    retryable_failure = True
                    data = ""
                    raw = ""
                    status = 0
                except Exception:
                    data = ""
                    raw = ""
                    status = 0
                found, rate_limited = _parse_items(data)
                if not found and raw:
                    lowered_raw = raw.lower()
                    rate_limited = (
                        rate_limited
                        or status in {403, 429}
                        or "rate limit" in lowered_raw
                        or "too many requests" in lowered_raw
                    )
                    for host in re.findall(r'"([^"\s]+\.' + re.escape(self.domain) + r')"', raw, re.I):
                        norm = normalize_hostname(host)
                        if norm and norm != self.apex and norm.endswith(self.domain):
                            found.add(norm.lower())
                if found:
                    before = len(subs)
                    subs.update(found)
                    page_found_count = len(found)
                    page_added = len(subs) - before
                    break
                should_retry = retryable_failure or rate_limited
                if not should_retry:
                    return subs
                if attempt == max_attempts - 1:
                    return subs
                if subs and (time.perf_counter() - started_at) >= max(5.0, float(source_budget) - safety_margin):
                    return subs
                await asyncio.sleep(max(22.0 + float(attempt), retry_after))
            if not page_found_count or page_added == 0 or page_found_count < 500:
                return subs
            if page < max_pages and page_delay:
                if subs and (time.perf_counter() - started_at) >= max(5.0, float(source_budget) - safety_margin):
                    return subs
                await asyncio.sleep(page_delay)
        return subs

    async def _he_bgp(self) -> set:
        subs = set()
        try:
            text, status = await _text_request_with_retries(
                self.session,
                "GET",
                f"https://bgp.he.net/dns/{self.domain}#_dns",
                timeout=max(self.timeout, 60),
                retries=3,
                backoff=1.0,
                headers={"User-Agent": "Mozilla/5.0", "Accept": "text/html,application/xhtml+xml"},
            )
            if status == 200 and text:
                for host in re.findall(rf'([A-Za-z0-9._-]+\.{re.escape(self.domain)})', text, re.I):
                    norm = normalize_hostname(host)
                    if norm and norm.endswith(self.domain):
                        subs.add(norm.lower())
        except Exception:
            pass
        return subs

    async def _dnsgrep(self) -> set:
        subs = set()
        try:
            text, status = await _text_request_with_retries(
                self.session,
                "GET",
                f"https://www.dnsgrep.nl/subdomains/{self.domain}",
                timeout=max(self.timeout, 45),
                retries=3,
                backoff=1.0,
                headers={"User-Agent": "Mozilla/5.0", "Accept": "text/html,application/xhtml+xml"},
            )
            if status == 200 and text:
                for host in re.findall(rf'([A-Za-z0-9._-]+\.{re.escape(self.domain)})', text, re.I):
                    norm = normalize_hostname(host)
                    if norm and norm.endswith(self.domain):
                        subs.add(norm.lower())
        except Exception:
            pass
        return subs

    async def _myssl(self) -> set:
        try:
            data, status = await _json_request_with_retries(
                self.session,
                "GET",
                f"https://myssl.com/api/v1/discover_sub_domain?domain={self.domain}",
                timeout=max(self.timeout, 30),
                retries=3,
                backoff=1.0,
            )
            if status == 200 and isinstance(data, dict):
                return {
                    host.lower()
                    for item in data.get("data", [])
                    for host in [normalize_hostname(item.get("domain", ""))]
                    if host and host.endswith(self.domain)
                }
        except Exception:
            pass
        return set()

    async def _digitorus(self) -> set:
        try:
            text, status = await _text_request_with_retries(
                self.session,
                "GET",
                f"https://certificatedetails.com/{self.domain}",
                timeout=max(self.timeout, 45),
                retries=3,
                backoff=1.0,
                headers={"User-Agent": "Mozilla/5.0"},
            )
            if status == 200 and text:
                found = set(re.findall(r'[\w\-\.]+\.' + re.escape(self.domain), text))
                return {s.lower() for s in found}
        except Exception:
            pass
        return set()

    async def _bevigil_free(self) -> set:
        try:
            data, status = await _json_request_with_retries(
                self.session,
                "GET",
                f"https://osint.bevigil.com/api/{self.domain}/subdomains/",
                timeout=max(self.timeout, 45),
                retries=3,
                backoff=1.0,
                headers={"X-Access-Token": "", "Accept": "application/json"},
            )
            if status == 200 and isinstance(data, dict):
                return {s.lower() for s in data.get("subdomains", []) if s.endswith(self.domain)}
        except Exception:
            pass
        return set()

    async def _hackertarget_reverse(self) -> set:
        subs = set()
        seen_pages = set()
        for page in range(1, 51):
            try:
                text, status = await _text_request_with_retries(
                    self.session,
                    "GET",
                    f"https://api.hackertarget.com/hostsearch/?q={self.domain}&page={page}",
                    timeout=max(self.timeout, 60),
                    retries=3,
                    backoff=1.0,
                )
                if status != 200 or not text:
                    break
                lowered = text.lower()
                if "api count exceeded" in lowered or "error" in lowered:
                    break
                page_subs = set()
                for line in text.splitlines():
                    if "," in line:
                        host = normalize_hostname(line.split(",", 1)[0].strip().lower())
                        if host and host.endswith(self.domain):
                            page_subs.add(host)
                fingerprint = tuple(sorted(page_subs))[:50]
                if not page_subs or fingerprint in seen_pages:
                    break
                seen_pages.add(fingerprint)
                prev = len(subs)
                subs.update(page_subs)
                if len(subs) == prev:
                    break
                await asyncio.sleep(0.35)
            except Exception:
                break
        return subs

    async def _sitedossier(self) -> set:
        try:
            text, status = await _text_request_with_retries(
                self.session,
                "GET",
                f"https://www.sitedossier.com/parentdomain/{self.domain}",
                timeout=max(self.timeout, 60),
                retries=3,
                backoff=1.0,
                headers={"User-Agent": "Mozilla/5.0"},
            )
            if status == 200 and text:
                return {s.lower() for s in re.findall(r'[\w\-\.]+\.' + re.escape(self.domain), text)}
        except Exception:
            pass
        return set()

    async def _urlscan_subdomains(self) -> set:
        subs = set()
        seen_pages = set()
        search_after = ""
        max_pages = 20 if self.mode == "deep" else 8
        for _ in range(max_pages):
            try:
                url = f"https://urlscan.io/api/v1/search/?q=domain:{self.domain}&size=1000"
                if search_after:
                    url += f"&search_after={quote(search_after, safe=':,')}"
                data, status = await _json_request_with_retries(
                    self.session,
                    "GET",
                    url,
                    timeout=max(self.timeout, 60),
                    retries=3,
                    backoff=1.0,
                    headers={"Accept": "application/json"},
                )
                if status != 200 or not isinstance(data, dict):
                    break
                results = data.get("results", []) or []
                if not results:
                    break
                page_subs = set()
                for result in results:
                    p = result.get("page", {})
                    for field in ("domain", "apexDomain"):
                        host = normalize_hostname(str(p.get(field, "")).lower())
                        if host and host.endswith(self.domain):
                            page_subs.add(host)
                fingerprint = tuple(sorted(page_subs))[:50]
                if not page_subs or fingerprint in seen_pages:
                    break
                seen_pages.add(fingerprint)
                prev = len(subs)
                subs.update(page_subs)
                next_cursor = data.get("search_after") or data.get("next") or ""
                if isinstance(next_cursor, list):
                    next_cursor = ",".join(str(part) for part in next_cursor)
                search_after = str(next_cursor or "")
                if len(subs) == prev or not search_after:
                    break
                await asyncio.sleep(0.35)
            except Exception:
                break
        return subs

    async def _dnsbufferover(self) -> set:
        subs = set()
        try:
            data, _ = await _json_request_with_retries(
                self.session,
                "GET",
                f"https://dns.bufferover.run/dns?q=.{self.domain}",
                timeout=max(self.timeout, 30),
                retries=3,
                backoff=1.0,
                headers={"User-Agent": "Mozilla/5.0"},
            )
            if isinstance(data, dict):
                for bucket in ("FDNS_A", "FDNS_AAAA", "FDNS_CNAME", "RDNS"):
                    for entry in (data.get(bucket, []) or []):
                        host = self._extract_host_candidate(entry)
                        if host:
                            subs.add(host)
        except Exception:
            pass
        return subs

    async def _wayback_subdomains(self) -> set:
        try:
            from urllib.parse import urlparse
            url = (f"https://web.archive.org/cdx/search/cdx?url=*.{self.domain}"
                   f"&output=json&fl=original&collapse=urlkey&limit=100000")
            resp = await _safe_get(self.session, url, timeout=45)
            if resp and resp.status == 200:
                rows = await resp.json(content_type=None)
                subs = set()
                for row in rows[1:]:
                    try:
                        h = urlparse(row[0]).hostname or ""
                        h = h.lstrip("*.").lower()
                        if h and h.endswith(self.domain) and "." in h:
                            subs.add(h)
                    except Exception:
                        pass
                return subs
        except Exception:
            pass
        return set()

    async def _urlscan(self) -> set:
        subs = set()
        try:
            url = f"https://urlscan.io/api/v1/search/?q=domain:{self.domain}&size=200"
            resp = await _safe_get(self.session, url, timeout=self.timeout)
            if resp and resp.status == 200:
                data = await resp.json(content_type=None)
                for result in data.get("results", []):
                    page = result.get("page", {})
                    subs.update(self._collect_scoped_hosts(page, preferred_keys=("domain", "ptr", "url")))
                    subs.update(self._collect_scoped_hosts(result.get("task", {}), preferred_keys=("domain", "url")))
                    subs.update(self._extract(str(result)))
        except Exception:
            pass
        return subs

    async def _otx(self) -> set:
        subs = set()
        try:
            key = self.api_keys.get("otx", "")
            headers = {"X-OTX-API-KEY": key} if key else {}
            page = 1
            while True:
                url = (f"https://otx.alienvault.com/api/v1/indicators/domain/{self.domain}"
                       f"/passive_dns?limit=500&page={page}")
                data = None
                for attempt in range(4):
                    try:
                        resp = await _safe_get(self.session, url, timeout=max(self.timeout, 30), headers=headers)
                        if resp and resp.status == 200:
                            data = await resp.json(content_type=None)
                            break
                    except Exception:
                        pass
                    if attempt < 3:
                        await asyncio.sleep(float(2**attempt))
                if not isinstance(data, dict):
                    break
                entries = data.get("passive_dns", [])
                for entry in entries:
                    subs.update(self._collect_scoped_hosts(entry, preferred_keys=("hostname", "host", "address")))
                if not data.get("has_next", False) or not entries:
                    break
                page += 1
                await asyncio.sleep(0.3)
        except Exception:
            pass
        return subs
    async def _wayback_subs(self) -> set:
        subs = set()
        limit = {"fast": 50000, "balanced": 200000, "deep": 500000, "turbo": 25000}.get(self.mode, 100000)
        page_size = min(limit, 50000)
        offset = 0
        empty_pages = 0
        while True:
            try:
                cdx_url = (
                    "https://web.archive.org/cdx/search/cdx"
                    f"?url={quote(self.domain, safe='')}"
                    "&matchType=domain"
                    "&output=json"
                    "&fl=original"
                    "&collapse=urlkey"
                    f"&limit={page_size}"
                    f"&offset={offset}"
                )
                data, status = await _json_request_with_retries(
                    self.session,
                    "GET",
                    cdx_url,
                    timeout=max(self.timeout, 45),
                    retries=3,
                    backoff=1.0,
                    ssl=False,
                )
                if status != 200 or not isinstance(data, list):
                    break
                rows = data[1:] if data and isinstance(data[0], list) else data
                if not rows:
                    empty_pages += 1
                    if empty_pages >= 2:
                        break
                    offset += page_size
                    await asyncio.sleep(0.2)
                    continue
                empty_pages = 0
                prev = len(subs)
                for row in rows:
                    raw = row[0] if isinstance(row, list) and row else row
                    host = self._extract_host_candidate(raw)
                    if host:
                        subs.add(host.lower())
                offset += len(rows)
                if len(rows) < page_size or (len(subs) == prev and len(rows) < page_size):
                    break
                await asyncio.sleep(0.35)
            except Exception:
                break
        return subs

    async def _wayback_host_hints(self) -> set:
        subs = set()
        limit = {"fast": 6, "balanced": 12, "deep": 18, "turbo": 4}.get(self.mode, 10)
        cdx_timeout = {"fast": 8, "balanced": 12, "deep": 16, "turbo": 6}.get(self.mode, 10)
        fetch_timeout = {"fast": 6, "balanced": 8, "deep": 10, "turbo": 5}.get(self.mode, 8)
        query_specs = (
            (f"https://web.archive.org/cdx/search/cdx?url={self.domain}/*&output=json&fl=original,timestamp,statuscode,mimetype&filter=statuscode:200&limit={limit * 4}&collapse=urlkey", 4.0),
            (f"https://web.archive.org/cdx/search/cdx?url=www.{self.domain}/*&output=json&fl=original,timestamp,statuscode,mimetype&filter=statuscode:200&limit={limit * 3}&collapse=urlkey", 3.0),
            (f"https://web.archive.org/cdx/search/cdx?url=*.{self.domain}/*&output=json&fl=original,timestamp,statuscode,mimetype&filter=statuscode:200&limit={limit * 4}&collapse=urlkey", 1.0),
        )
        keyword_tokens = (
            "/login", "/auth", "/oauth", "/sso", "/vpn", "/remote", "/gateway", "/admin",
            "/owa", "/exchange", "/webmail", "/mail", "/citrix", "/mfa", "/sts",
        )
        try:
            scored_rows: Dict[Tuple[str, str], Dict[str, Any]] = {}
            for cdx, host_bias in query_specs:
                resp = await _safe_get(self.session, cdx, timeout=cdx_timeout, ssl=False)
                if not (resp and resp.status == 200):
                    continue
                data = await resp.json(content_type=None)
                for row in data[1:]:
                    if not (isinstance(row, list) and len(row) >= 4):
                        continue
                    original, timestamp, _, mime = row[:4]
                    original_s = str(original or "")
                    timestamp_s = str(timestamp or "")
                    mime_s = str(mime or "").lower()
                    if not original_s.startswith("http"):
                        continue
                    if mime_s and not any(tok in mime_s for tok in ("html", "text", "javascript", "json", "xml")):
                        continue
                    try:
                        parsed = urlparse(original_s)
                    except Exception:
                        continue
                    host = normalize_hostname(parsed.hostname or "")
                    if host:
                        subs.update(self._normalize_candidate_subs({host}))
                    path = (parsed.path or "/").lower()
                    lowered_url = original_s.lower()
                    score = host_bias
                    if host in {self.apex, f"www.{self.apex}"}:
                        score += 3.0
                    elif host.endswith("." + self.apex):
                        score += 1.5
                    if any(tok in lowered_url or tok in path for tok in keyword_tokens):
                        score += 8.0
                    if path in {"/", "/index.html", "/login"}:
                        score += 2.0
                    if path.count("/") <= 2:
                        score += 1.0
                    key = (original_s, timestamp_s)
                    current = scored_rows.get(key)
                    if current is None or float(current.get("score", 0.0)) < score:
                        scored_rows[key] = {"url": original_s, "timestamp": timestamp_s, "score": score}
            rows = [
                (row["url"], row["timestamp"])
                for row in sorted(
                    scored_rows.values(),
                    key=lambda item: (-float(item.get("score", 0.0)), str(item.get("timestamp", "")), str(item.get("url", ""))),
                )[:limit]
            ]
            sem = asyncio.Semaphore(6)

            async def fetch_extract(original_url: str, timestamp: str) -> set:
                async with sem:
                    archive_url = f"https://web.archive.org/web/{timestamp}if_/{original_url}"
                    try:
                        text = await _safe_get_text_cached(self.session, archive_url, timeout=fetch_timeout)
                    except Exception:
                        text = ""
                    return self._extract(text[:250000]) if text else set()

            if rows:
                batches = await asyncio.gather(*(fetch_extract(url, ts) for url, ts in rows), return_exceptions=True)
                for batch in batches:
                    if isinstance(batch, set):
                        subs.update(self._normalize_candidate_subs(batch))
        except Exception:
            pass
        return subs

    async def _commoncrawl(self) -> set:
        subs = set()
        indexes = await _commoncrawl_indexes(self.session, self.mode)
        for idx in indexes:
            url = (f"https://index.commoncrawl.org/{idx}-index?"
                   f"url=*.{self.domain}&output=json&limit=10000")
            text = ""
            for attempt in range(3):
                try:
                    text = await _safe_get_text_cached(self.session, url, timeout=max(self.timeout, 35))
                    if text:
                        break
                except Exception:
                    pass
                await asyncio.sleep(0.3 * (attempt + 1))
            if text:
                for line in text.splitlines():
                    try:
                        obj = json.loads(line)
                        raw_url = obj.get("url", "")
                        host = normalize_hostname(urlparse(raw_url).hostname or "")
                        if not host:
                            ext = _safe_tld_extract(raw_url)
                            if ext.subdomain and ext.domain and ext.suffix:
                                host = normalize_hostname(f"{ext.subdomain}.{ext.domain}.{ext.suffix}")
                        if host.endswith(self.domain) and host != self.domain and looks_like_hostname(host):
                            subs.add(host.lower())
                    except Exception:
                        pass
            await asyncio.sleep(0.15)
        return subs

    async def _securitytrails(self) -> set:
        return set()

    async def _virustotal_subs(self) -> set:
        subs = set()
        key = self.api_keys.get("virustotal", "")
        if not key:
            return subs
        max_pages = {"fast": 1, "balanced": 2, "deep": 3, "turbo": 1}.get(self.mode, 1)
        try:
            cursor = None
            for page in range(max_pages):
                _url = f"https://www.virustotal.com/api/v3/domains/{self.domain}/subdomains?limit=40"
                if cursor:
                    _url += f"&cursor={cursor}"
                resp = await _safe_get(self.session, _url, timeout=self.timeout,
                                        headers={"x-apikey": key})
                if resp and resp.status == 200:
                    data = await resp.json(content_type=None)
                    found = parse_virustotal_subdomains(data, self.domain)
                    subs.update(found)
                    # VirusTotal v3 uses cursor-based pagination
                    meta = data.get("meta", {}) if isinstance(data, dict) else {}
                    cursor = meta.get("cursor") if isinstance(meta, dict) else None
                    if not cursor or not found:
                        break
                    await asyncio.sleep(1.0)  # VT rate limit: 4 req/min public API
                else:
                    break
        except Exception:
            pass
        return subs

    async def _fullhunt(self) -> set:
        return set()

    async def _chaos(self) -> set:
        subs = set()
        key = self.api_keys.get("chaos", "")
        if not key:
            return subs
        try:
            url = f"https://dns.projectdiscovery.io/dns/{self.domain}/subdomains"
            resp = await _safe_get(self.session, url, timeout=self.timeout,
                                    headers={"Authorization": key})
            if resp and resp.status == 200:
                data = await resp.json(content_type=None)
                subs.update(parse_chaos_subdomains(data, self.domain))
        except Exception:
            pass
        return subs

    # _bufferover removed — discontinued

    async def _jldc(self) -> set:
        subs = set()
        url = f"https://jldc.me/anubis/subdomains/{self.domain}"
        data = None
        for attempt in range(3):
            data, _ = await _json_request_with_retries(
                self.session,
                "GET",
                url,
                timeout=max(self.timeout, 180 if self.mode == "deep" else 120),
                retries=3,
                backoff=1.0,
            )
            if isinstance(data, list) and data:
                break
            if attempt < 2:
                await asyncio.sleep(5.0)
        for sub in (data if isinstance(data, list) else []):
            sub = str(sub).strip().lower()
            if sub.endswith(self.domain):
                subs.add(sub)
        return subs

    async def _anubisdb(self) -> set:
        subs = set()
        url = f"https://jonlu.ca/anubis/subdomains/{self.domain}"
        data = None
        for attempt in range(3):
            data, _ = await _json_request_with_retries(
                self.session,
                "GET",
                url,
                timeout=max(self.timeout, 180 if self.mode == "deep" else 120),
                retries=3,
                backoff=1.0,
            )
            if isinstance(data, list) and data:
                break
            if attempt < 2:
                await asyncio.sleep(5.0)
        for sub in (data if isinstance(data, list) else []):
            sub = str(sub).strip().lower()
            if sub.endswith(self.domain):
                subs.add(sub)
        return subs

    async def _shrewdeye(self) -> set:
        subs = set()
        try:
            url = f"https://shrewdeye.app/domains/{self.domain}.json"
            resp = await _safe_get(self.session, url, timeout=self.timeout)
            if resp and resp.status == 200:
                data = await resp.json(content_type=None)
                items = data if isinstance(data, list) else data.get("domains", [])
                for sub in items:
                    sub = str(sub).strip().lower().lstrip("*.")
                    if sub.endswith(self.domain):
                        subs.add(sub)
        except Exception:
            pass
        return subs

    async def _sublist3r_api(self) -> set:
        subs = set()
        try:
            url = f"https://api.sublist3r.com/search.php?domain={self.domain}"
            resp = await _safe_get(self.session, url, timeout=self.timeout)
            if resp and resp.status == 200:
                data = await resp.json(content_type=None)
                for sub in (data if isinstance(data, list) else []):
                    sub = str(sub).strip().lower()
                    if sub.endswith(self.domain):
                        subs.add(sub)
        except Exception:
            pass
        return subs

    async def _wayback_cdx(self) -> set:
        subs = set()
        max_pages = {"fast": 1, "balanced": 2, "deep": 4, "turbo": 1}.get(self.mode, 2)
        cdx_urls = [
            f"https://web.archive.org/cdx/search/cdx?url=*.{self.domain}/*&output=text&fl=original&collapse=urlkey&limit=25000&showResumeKey=true",
            f"https://web.archive.org/cdx/search/cdx?url={self.domain}/*&output=text&fl=original&collapse=urlkey&limit=25000&showResumeKey=true",
        ]
        for base_url in cdx_urls:
            page_url = base_url
            for _ in range(max_pages):
                try:
                    text, status = await _text_request_with_retries(
                        self.session,
                        "GET",
                        page_url,
                        timeout=max(self.timeout, 60),
                        retries=3,
                        backoff=1.0,
                        ssl=False,
                    )
                except Exception:
                    break
                if status != 200 or not text:
                    break
                lines = text.splitlines()
                resume_key = ""
                if lines:
                    last_line = lines[-1].strip()
                    if last_line and not last_line.startswith(("http://", "https://")):
                        resume_key = last_line
                        lines = lines[:-1]
                        if lines and not lines[-1].strip():
                            lines = lines[:-1]
                prev = len(subs)
                # FIXED: use Wayback text+resume pagination because JSON CDX frequently truncates large wildcard host searches.
                for line in lines:
                    host = self._extract_host_candidate(line)
                    if host:
                        subs.add(host.lower())
                if not resume_key or len(subs) == prev:
                    break
                page_url = f"{base_url}&resumeKey={quote(resume_key, safe='')}"
                await asyncio.sleep(0.35)
        return subs

    async def _otx_passive_dns(self) -> set:
        subs = set()
        try:
            page = 1
            while True:
                url = (
                    f"https://otx.alienvault.com/api/v1/indicators/domain/{self.domain}/passive_dns"
                    f"?limit=500&page={page}"
                )
                data, _ = await _json_request_with_retries(
                    self.session,
                    "GET",
                    url,
                    timeout=max(self.timeout, 30),
                    retries=3,
                    backoff=1.0,
                )
                if not isinstance(data, dict):
                    break
                entries = data.get("passive_dns", []) or []
                for item in entries:
                    subs.update(self._collect_scoped_hosts(item, preferred_keys=("hostname", "host", "address")))
                if not entries or not data.get("has_next", False):
                    break
                page += 1
                await asyncio.sleep(0.35)
        except Exception:
            pass
        return subs

    async def _bufferover_dns(self) -> set:
        """dns.bufferover.run passive DNS endpoint."""
        subs = set()
        try:
            url = f"https://dns.bufferover.run/dns?q=.{self.domain}"
            data, _ = await _json_request_with_retries(
                self.session,
                "GET",
                url,
                timeout=max(self.timeout, 30),
                retries=3,
                backoff=1.0,
            )
            if isinstance(data, dict):
                for key in ("FDNS_A", "FDNS_AAAA", "FDNS_CNAME", "RDNS"):
                    for entry in (data.get(key, []) or []):
                        host = self._extract_host_candidate(entry)
                        if host:
                            subs.add(host)
        except Exception:
            pass
        return subs

    async def _riddler_io(self) -> set:
        """riddler.io subdomain search"""
        try:
            r = await _safe_get(self.session,
                f"https://riddler.io/search/exportcsv?q=pld:{self.domain}",
                timeout=10, headers={"User-Agent": "Mozilla/5.0"})
            if r and r.status == 200:
                text = await r.text()
                found = re.findall(r'[\w\-\.]+\.' + re.escape(self.domain), text)
                return {s.lower() for s in found if s.lower().endswith(self.domain)}
        except Exception:
            pass
        return set()

    async def _sslmate_certs(self) -> set:
        """SSLMate CertSpotter API — alternative CT log feed"""
        try:
            data, status = await _json_request_with_retries(
                self.session,
                "GET",
                f"https://api.certspotter.com/v1/issuances?domain={self.domain}&include_subdomains=true&expand=dns_names",
                timeout=max(self.timeout, 30),
                retries=3,
                backoff=1.0,
                headers={"Accept": "application/json"},
            )
            if status == 200 and isinstance(data, list):
                subs = set()
                for cert in data:
                    for name in cert.get("dns_names", []):
                        name = self._normalize_ct_subdomain(name)
                        if name == f"*.{self.domain}":
                            subs.add(name)
                        elif name and name.endswith(self.domain) and "." in name:
                            subs.add(name)
                return subs
        except Exception:
            pass
        return set()

    async def _wayback_cdx_full(self) -> set:
        subs = set()
        try:
            page_url = (
                f"https://web.archive.org/cdx/search/cdx?url=*.{self.domain}/*"
                "&output=text&fl=original&collapse=urlkey&limit=50000&showResumeKey=true"
            )
            max_pages = {"fast": 1, "balanced": 3, "deep": 8, "turbo": 1}.get(self.mode, 3)
            for _ in range(max_pages):
                text, status = await _text_request_with_retries(
                    self.session,
                    "GET",
                    page_url,
                    timeout=max(self.timeout, 180),
                    retries=3,
                    backoff=1.0,
                    ssl=False,
                )
                if status != 200 or not text:
                    break
                lines = text.splitlines()
                resume_key = ""
                if lines:
                    last_line = lines[-1].strip()
                    if last_line and not last_line.startswith(("http://", "https://")):
                        resume_key = last_line
                        lines = lines[:-1]
                        if lines and not lines[-1].strip():
                            lines = lines[:-1]
                prev = len(subs)
                # FIXED: use Wayback text+resume pagination because large JSON CDX responses were yielding zero hosts in deep mode.
                for raw_url in lines:
                    host = self._extract_host_candidate(raw_url)
                    if host:
                        subs.add(host)
                if not resume_key or len(subs) == prev:
                    break
                page_url = page_url.split("&resumeKey=", 1)[0] + f"&resumeKey={quote(resume_key, safe='')}"
                await asyncio.sleep(0.35)
        except Exception:
            pass
        return subs

    # _threatminer removed — offline

    async def _hackertarget_dns(self) -> set:
        subs = set()
        try:
            url = f"https://api.hackertarget.com/dnslookup/?q={self.domain}"
            resp = await _safe_get(self.session, url, timeout=self.timeout)
            if resp and resp.status == 200:
                text = await resp.text()
                subs.update(self._extract(text))
        except Exception:
            pass
        return subs

    # _rapiddns_pages removed — duplicates rapiddns

    async def _dnsdumpster(self) -> set:
        subs = set()
        try:
            jar = aiohttp.CookieJar(unsafe=True)
            base_headers = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.5",
                "Connection": "keep-alive",
            }
            # Step 1: GET to get CSRF token
            async with aiohttp.ClientSession(cookie_jar=jar) as sess:
                r1 = await _safe_get(
                    sess,
                    "https://dnsdumpster.com/",
                    headers=base_headers,
                    timeout=self.timeout,
                )
                if not r1 or r1.status != 200:
                    return subs
                html_text = await r1.text()
                # Extract CSRF from HTML form
                csrf_val = ""
                soup_tmp = BeautifulSoup(html_text, "html.parser")
                inp = soup_tmp.find("input", {"name": "csrfmiddlewaretoken"})
                if inp:
                    csrf_val = inp.get("value", "")
                # Also try to get from cookie jar
                if not csrf_val:
                    for cookie in jar:
                        if cookie.key == "csrftoken":
                            csrf_val = cookie.value
                            break
                if not csrf_val:
                    return subs
                # Step 2: POST with CSRF and cookie
                post_headers = {
                    **base_headers,
                    "Referer": "https://dnsdumpster.com/",
                    "Origin": "https://dnsdumpster.com",
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Cookie": f"csrftoken={csrf_val}",
                }
                post_data = f"csrfmiddlewaretoken={csrf_val}&targetip={self.domain}&user=free"
                r2 = await _safe_post(
                    sess,
                    "https://dnsdumpster.com/",
                    timeout=self.timeout,
                    data=post_data,
                    headers=post_headers,
                )
                if r2 and r2.status == 200:
                    text = await r2.text()
                    soup = BeautifulSoup(text, "html.parser")
                    # Parse hosts from table cells
                    for td in soup.find_all("td", class_=lambda c: c and "col-md-4" in c):
                        raw = td.get_text(separator=" ", strip=True)
                        # First word is the hostname
                        host = raw.split()[0].strip().lower().rstrip(".")
                        if host.endswith(self.domain) and host != self.domain:
                            subs.add(host)
                    # Also apply regex extraction on full response
                    subs.update(self._extract(text))
        except Exception:
            pass
        return subs

    async def _dnshistory(self) -> set:
        """Parse DNS history from dnshistory.org for historical subdomains."""
        subs = set()
        for page in [1, 2]:
            try:
                url = f"https://dnshistory.org/subdomains/{page}/{self.domain}"
                resp = await _safe_get(self.session, url, timeout=self.timeout)
                if resp and resp.status == 200:
                    text = await resp.text()
                    soup = BeautifulSoup(text, "html.parser")
                    # Parse all table cells and anchor tags for subdomains
                    for tag in soup.find_all(["td", "a"]):
                        t = tag.get_text(strip=True).lower()
                        if t.endswith("." + self.domain) and len(t) > len(self.domain) + 1:
                            subs.add(t)
                    subs.update(self._extract(text))
                await asyncio.sleep(0.5)
            except Exception:
                pass
        return subs

    async def _virustotal_unauth(self) -> set:
        subs = set()
        try:
            cursor = ""
            for _ in range(5):
                url = f"https://www.virustotal.com/ui/domains/{self.domain}/subdomains?limit=40"
                if cursor:
                    url += f"&cursor={cursor}"
                resp = await _safe_get(self.session, url, timeout=self.timeout,
                                       headers={"Accept": "application/json"})
                if resp and resp.status == 200:
                    data = await resp.json(content_type=None)
                    for item in data.get("data", []):
                        sub = item.get("id", "")
                        if sub.endswith(self.domain):
                            subs.add(sub.lower())
                    cursor = data.get("meta", {}).get("cursor", "")
                    if not cursor or not data.get("data"):
                        break
                else:
                    break
                await asyncio.sleep(0.5)
        except Exception:
            pass
        return subs

    async def _urlscan_paginated(self) -> set:
        subs = set()
        max_pages = 10 if self.mode == "deep" else 5
        try:
            search_after = None
            for _ in range(max_pages):
                url = f"https://urlscan.io/api/v1/search/?q=domain:{self.domain}&size=10000"
                if search_after:
                    url += f"&search_after={search_after}"
                resp = await _safe_get(self.session, url, timeout=self.timeout)
                if resp and resp.status == 200:
                    data = await resp.json(content_type=None)
                    results = data.get("results", [])
                    for r in results:
                        pg = r.get("page", {})
                        for key in ("domain", "ptr"):
                            val = pg.get(key, "")
                            if val and val.endswith(self.domain) and val != self.domain:
                                subs.add(val.lower())
                        subs.update(self._extract(str(pg)))
                    if len(results) < 100:
                        break
                    search_after = results[-1].get("sort", [None])[-1] if results else None
                    if not search_after:
                        break
                else:
                    break
                await asyncio.sleep(0.5)
        except Exception:
            pass
        return subs

    async def _github_code_subs(self) -> set:
        subs = set()
        key = self.api_keys.get("github_token", "")
        auth_h = {"Authorization": f"Bearer {key}"} if key else {}
        auth_h["Accept"] = "application/vnd.github.v3.text-match+json"
        queries = [f'"{self.domain}"', f'"site:{self.domain}"', f'"{self.domain}" subdomain']
        for query in queries:
            try:
                url = f"https://api.github.com/search/code?q={quote(query)}&per_page=100"
                resp = await _safe_get(self.session, url, timeout=self.timeout, headers=auth_h)
                if resp and resp.status == 200:
                    data = await resp.json(content_type=None)
                    for item in data.get("items", []):
                        for match in item.get("text_matches", []):
                            subs.update(self._extract(match.get("fragment", "")))
                await asyncio.sleep(1.5)
            except Exception:
                pass
        return subs

    async def _grep_app_subs(self) -> set:
        subs = set()
        try:
            url = f"https://grep.app/api/search?q={quote(self.domain)}&per_page=100"
            resp = await _safe_get(self.session, url, timeout=self.timeout)
            if resp and resp.status == 200:
                data = await resp.json(content_type=None)
                for hit in data.get("hits", {}).get("hits", []):
                    snippet = hit.get("content", {}).get("snippet", "")
                    raw_url = hit.get("file", {}).get("raw_url", "")
                    subs.update(self._extract(snippet))
                    subs.update(self._extract(raw_url))
        except Exception:
            pass
        return subs

    async def _zoomeye(self) -> set:
        subs = set()
        try:
            url = f"https://api.zoomeye.org/web/search?query=hostname:{self.domain}&page=1"
            resp = await _safe_get(self.session, url, timeout=self.timeout)
            if resp and resp.status == 200:
                data = await resp.json(content_type=None)
                for match in data.get("matches", []):
                    subs.update(self._extract(str(match)))
        except Exception:
            pass
        return subs

    async def _fofa(self) -> set:
        subs = set()
        try:
            query = base64.b64encode(f'domain="{self.domain}"'.encode()).decode()
            url = f"https://fofa.info/api/v1/search/all?qbase64={query}&fields=host,domain&size=10000"
            resp = await _safe_get(self.session, url, timeout=self.timeout)
            if resp and resp.status == 200:
                data = await resp.json(content_type=None)
                for item in data.get("results", []):
                    for val in item:
                        val = str(val).strip().lower().lstrip("*.")
                        if val.endswith(self.domain):
                            subs.add(val)
        except Exception:
            pass
        return subs

    async def _netcraft(self) -> set:
        subs = set()
        try:
            url = (f"https://searchdns.netcraft.com/?restriction=site+ends+with"
                   f"&host={self.domain}&position=limited")
            resp = await _safe_get(self.session, url, timeout=self.timeout,
                                   headers={"Referer": "https://www.netcraft.com"})
            if resp and resp.status == 200:
                text = await resp.text()
                subs.update(self._extract(text))
                soup = BeautifulSoup(text, "html.parser")
                for a in soup.find_all("a", href=True):
                    parsed = urlparse(a["href"])
                    host = (parsed.hostname or "").lower()
                    if host.endswith(self.domain):
                        subs.add(host)
        except Exception:
            pass
        return subs

    async def _leakix(self) -> set:
        subs = set()
        try:
            for url in (
                f"https://leakix.net/api/subdomains/{self.domain}",
                f"https://leakix.net/domain/{self.domain}",
            ):
                resp = await _safe_get(self.session, url, timeout=min(self.timeout, 12),
                                       headers={"Accept": "application/json"})
                if resp and resp.status == 200:
                    try:
                        data = await resp.json(content_type=None)
                        items = data if isinstance(data, list) else data.get("subdomains", []) or data.get("Events", [])
                        for event in items:
                            host = str(
                                event.get("host", "")
                                or event.get("subdomain", "")
                                or event.get("hostname", "")
                                or event
                            ).strip().lower()
                            host = normalize_hostname(host)
                            if host.endswith(self.domain):
                                subs.add(host)
                        if subs:
                            break
                    except Exception:
                        text = await resp.text()
                        subs.update(self._extract(text))
        except Exception:
            pass
        return subs

    async def _phonebook_subs(self) -> set:
        subs = set()
        try:
            form_data = aiohttp.FormData()
            form_data.add_field("term", self.domain)
            form_data.add_field("type", "2")
            form_data.add_field("page", "1")
            resp = await _safe_post(
                self.session,
                "https://phonebook.cz/search/",
                timeout=self.timeout,
                data=form_data,
                headers={"Referer": "https://phonebook.cz/"},
            )
            if resp and resp.status == 200:
                text = await resp.text()
                subs.update(self._extract(text))
        except Exception:
            pass
        return subs

    async def _binaryedge(self) -> set:
        return set()

    async def _riskiq(self) -> set:
        return set()

    async def _censys_subs(self) -> set:
        return set()

    async def _dnsrepo(self) -> set:
        subs = set()
        try:
            url = f"https://dnsrepo.noc.org/?domain={self.domain}"
            text, status = await _text_request_with_retries(
                self.session,
                "GET",
                url,
                timeout=max(self.timeout, 30),
                retries=3,
                backoff=1.0,
            )
            if status == 200 and text:
                subs.update(self._extract(text))
                soup = BeautifulSoup(text, "html.parser")
                for row in soup.find_all("tr"):
                    cells = row.find_all("td")
                    if cells:
                        val = cells[0].get_text(strip=True).lower()
                        if val.endswith(self.domain) and val != self.domain:
                            subs.add(val)
        except Exception:
            pass
        return subs

    async def _riddler(self) -> set:
        # riddler.io is offline — skip immediately
        return set()

    # _sonar_fdns removed — omnisint.io shut down

    async def _crobat(self) -> set:
        # crobat.app is offline — skip immediately
        return set()

    async def _ctsearch_entrust(self) -> set:
        subs = set()
        try:
            url = (f"https://ctsearch.entrust.com/api/v1/certificates"
                   f"?fields=subjectDN,subjectAltNames,dnsNames&domain={self.domain}&includeExpired=true"
                   f"&exactMatch=false&limit=5000")
            resp = await _safe_get(self.session, url, timeout=self.timeout)
            if resp and resp.status == 200:
                data = await resp.json(content_type=None)
                certs = data if isinstance(data, list) else data.get("certs", [])
                for cert in certs:
                    if not isinstance(cert, dict):
                        continue
                    subject_dn = cert.get("subjectDN", "")
                    for part in str(subject_dn).split(","):
                        part = part.strip()
                        if part.startswith("CN="):
                            cn = normalize_hostname(part[3:].strip().lstrip("*."))
                            if cn.endswith(self.domain) and cn != self.domain:
                                subs.add(cn.lower())
                    for key in ("subjectAltNames", "dnsNames", "san", "sans"):
                        for value in (cert.get(key, []) or []):
                            host = normalize_hostname(str(value).strip().lstrip("*."))
                            if host.endswith(self.domain) and host != self.domain:
                                subs.add(host)
        except Exception:
            pass
        return subs

    async def _bevigil(self) -> set:
        """Bevigil mobile OSINT Ã¢â‚¬â€ finds subdomains extracted from APKs."""
        subs = set()
        key = self.api_keys.get("bevigil", "")
        if not key:
            return subs
        try:
            url = f"https://osint.bevigil.com/api/{self.domain}/subdomains/"
            resp = await _safe_get(
                self.session, url, timeout=self.timeout,
                headers={"X-Access-Token": key}
            )
            if resp and resp.status == 200:
                data = await resp.json(content_type=None)
                for sub in data.get("subdomains", []):
                    sub = sub.strip().lower()
                    if sub.endswith(self.domain):
                        subs.add(sub)
        except Exception:
            pass
        return subs

    async def _threatbook(self) -> set:
        """ThreatBook subdomain intel."""
        return set()

    async def _columbus(self) -> set:
        subs = set()
        try:
            url = f"https://columbus.elmasy.com/api/lookup/{self.domain}"
            data, status = await _json_request_with_retries(
                self.session,
                "GET",
                url,
                timeout=max(self.timeout, 45),
                retries=3,
                backoff=1.0,
                headers={"Accept": "application/json"},
            )
            if status == 200 and isinstance(data, (list, dict)):
                items = data if isinstance(data, list) else data.get("subdomains", [])
                for sub in items:
                    sub = str(sub).strip().lower().lstrip("*.")
                    # Columbus returns just the subdomain prefix, not the full FQDN
                    if sub and not sub.endswith(self.domain):
                        sub = f"{sub}.{self.domain}"
                    if sub and sub.endswith(self.domain) and sub != self.domain:
                        subs.add(sub)
        except Exception:
            pass
        return subs

    async def _c99(self) -> set:
        subs = set()
        try:
            url = f"https://subdomainfinder.c99.nl/api.php?key=&domain={self.domain}"
            resp = await _safe_get(self.session, url, timeout=self.timeout)
            if resp and resp.status == 200:
                text = await resp.text()
                try:
                    data = await resp.json(content_type=None)
                    for sub in (data.get("subdomains", []) if isinstance(data, dict) else []):
                        sub = str(sub).strip().lower().lstrip("*.")
                        if sub.endswith(self.domain):
                            subs.add(sub)
                except Exception:
                    subs.update(self._extract(text))
        except Exception:
            pass
        return subs

    async def _whoisxml_subs(self) -> set:
        subs = set()
        try:
            url = (f"https://domains.whoisxmlapi.com/api/v1"
                   f"?apiKey=at_free&domainName={self.domain}&outputFormat=JSON")
            resp = await _safe_get(self.session, url, timeout=self.timeout)
            if resp and resp.status == 200:
                data = await resp.json(content_type=None)
                if isinstance(data, dict):
                    subs.update(self._collect_scoped_hosts(data))
                    for item in data.get("result", {}).get("list", []) or []:
                        sub = item.get("name", "") if isinstance(item, dict) else str(item)
                        sub = normalize_hostname(sub.strip().lower().lstrip("*."))
                        if sub.endswith(self.domain) and sub != self.domain:
                            subs.add(sub)
        except Exception:
            pass
        return subs

    async def _mnemonic_pdns(self) -> set:
        subs = set()
        try:
            url = f"https://api.mnemonic.no/pdns/v3/{self.domain}?limit=1000"
            data, status = await _json_request_with_retries(
                self.session,
                "GET",
                url,
                timeout=max(self.timeout, 30),
                retries=3,
                backoff=1.0,
            )
            if status == 200 and isinstance(data, dict):
                for rec in data.get("data", []):
                    query = rec.get("query", "")
                    if query and query.endswith(self.domain) and query != self.domain:
                        subs.add(query.rstrip(".").lower())
        except Exception:
            pass
        return subs

    async def _circl_passive_dns(self) -> set:
        subs = set()
        try:
            url = f"https://www.circl.lu/pdns/query/{self.domain}"
            headers = {"Accept": "application/json"}
            text, status = await _text_request_with_retries(
                self.session,
                "GET",
                url,
                timeout=max(self.timeout, 30),
                retries=3,
                backoff=1.0,
                headers=headers,
            )
            if status == 200 and text:
                entries = []
                try:
                    parsed = json.loads(text)
                except Exception:
                    parsed = None
                if isinstance(parsed, list):
                    entries.extend(item for item in parsed if isinstance(item, dict))
                elif isinstance(parsed, dict):
                    entries.append(parsed)
                else:
                    for line in text.strip().splitlines():
                        try:
                            entry = json.loads(line)
                        except Exception:
                            continue
                        if isinstance(entry, dict):
                            entries.append(entry)
                for entry in entries:
                    rrname = normalize_hostname(str(entry.get("rrname", "") or "").rstrip(".").lower())
                    if rrname and rrname.endswith(self.domain) and looks_like_hostname(rrname):
                        subs.add(rrname)
        except Exception:
            pass
        return subs

    async def _doh_wordlist_passive(self) -> set:
        subs = set()
        sem = asyncio.Semaphore(30)
        loop = asyncio.get_running_loop()

        async def lookup(prefix: str) -> None:
            hostname = f"{prefix}.{self.domain}"
            async with sem:
                try:
                    answers = await _doh_query(self.session, hostname, "A", timeout=5)
                except Exception:
                    answers = []
                if answers:
                    subs.add(hostname)
                    return
                try:
                    resolution = await asyncio.wait_for(
                        loop.getaddrinfo(hostname, None, family=socket.AF_UNSPEC, type=socket.SOCK_STREAM),
                        timeout=5,
                    )
                except Exception:
                    resolution = []
            if resolution:
                subs.add(hostname)

        await asyncio.gather(*(lookup(prefix) for prefix in COMMON_PASSIVE_SUBDOMAIN_PREFIXES), return_exceptions=True)
        return subs

    async def _hackertarget_reverseip_hosts(self, ips: List[str]) -> set:
        hosts = set()
        unique_ips = [ip for ip in dict.fromkeys(_normalize_ip_literal(value) for value in ips) if ip]
        if not unique_ips:
            return hosts
        sem = asyncio.Semaphore(20)

        async def lookup(ip: str) -> set:
            async with sem:
                try:
                    url = f"https://api.hackertarget.com/reverseiplookup/?q={ip}"
                    resp = await _safe_get(self.session, url, timeout=min(self.timeout, 12))
                    if not (resp and resp.status == 200):
                        return set()
                    text = await resp.text()
                except Exception:
                    return set()
            lowered = text.lower()
            if "api count exceeded" in lowered or "error detected" in lowered:
                return set()
            found = set()
            for line in text.splitlines():
                host = line.strip()
                if "," in host:
                    host = host.split(",", 1)[0].strip()
                host = normalize_hostname(host)
                if host and host.endswith("." + self.apex):
                    found.add(host)
            return found

        batches = await asyncio.gather(*(lookup(ip) for ip in unique_ips), return_exceptions=True)
        for batch in batches:
            if isinstance(batch, set):
                hosts.update(batch)
        return hosts

    async def _omnisint_subdomains(self) -> set:
        """Omnisint/ODIN free subdomain data"""
        subs = set()
        try:
            data, status = await _json_request_with_retries(
                self.session,
                "GET",
                f"https://sonar.omnisint.io/subdomains/{self.domain}",
                timeout=max(self.timeout, 30),
                retries=3,
                backoff=1.0,
                headers={"User-Agent": "Mozilla/5.0"},
            )
            if status == 200 and isinstance(data, list):
                for s in data:
                    if isinstance(s, str) and s.endswith(self.domain):
                        subs.add(normalize_hostname(s).lower())
            elif status in {404, 503}:
                subs.update(await self._crtsh())
        except Exception:
            pass
        return subs

    async def _trickest(self) -> set:
        subs = set()
        try:
            data, status = await _json_request_with_retries(
                self.session,
                "GET",
                f"https://dns.trickest.io/get?domain={self.domain}",
                timeout=max(self.timeout, 45),
                retries=3,
                backoff=1.0,
                headers={"Accept": "application/json"},
            )
            items = data if isinstance(data, list) else (data.get("subdomains", []) if isinstance(data, dict) else [])
            if status == 200:
                for item in items:
                    host = normalize_hostname(str(item).strip().lower().lstrip("*."))
                    if host and host.endswith(self.domain):
                        subs.add(host)
        except Exception:
            pass
        return subs

    async def _hackertarget_subdomain(self) -> set:
        subs = set()
        try:
            text, status = await _text_request_with_retries(
                self.session,
                "GET",
                f"https://api.hackertarget.com/subdomains/?q={self.domain}",
                timeout=max(self.timeout, 60),
                retries=3,
                backoff=1.0,
            )
            if status == 200 and text and "error" not in text.lower():
                for line in text.splitlines():
                    host = normalize_hostname(line.strip().lower().lstrip("*."))
                    if host and host.endswith(self.domain):
                        subs.add(host)
        except Exception:
            pass
        return subs

    async def _ctsearch_google(self) -> set:
        subs = set()
        try:
            urls = [
                (
                    "https://transparencyreport.google.com/transparencyreport/api/v3/"
                    f"httpsreport/ct/certsearch?include_subdomains=true&domain={self.domain}&token=&hl=en"
                ),
                f"https://transparencyreport.google.com/https/certificates?domain={quote(self.domain)}&hl=en",
            ]
            for url in urls:
                text, status = await _text_request_with_retries(
                    self.session,
                    "GET",
                    url,
                    timeout=max(self.timeout, 60),
                    retries=3,
                    backoff=1.0,
                    headers={"User-Agent": "Mozilla/5.0"},
                )
                if status != 200 or not text:
                    continue
                # FIXED: Google's legacy CT API path now returns 404 intermittently, so fall back to the live certificates page and extract any in-scope hosts embedded in the response.
                for host in re.findall(r'[\w\-\.]+\.' + re.escape(self.domain), text, re.I):
                    norm = normalize_hostname(str(host).strip().lower().lstrip("*."))
                    if norm and norm.endswith(self.domain):
                        subs.add(norm)
                if subs:
                    break
        except Exception:
            pass
        return subs

    async def _alienvault_pulse(self) -> set:
        subs = set()
        try:
            data, status = await _json_request_with_retries(
                self.session,
                "GET",
                f"https://otx.alienvault.com/api/v1/indicators/domain/{self.domain}/url_list?limit=500",
                timeout=max(self.timeout, 45),
                retries=3,
                backoff=1.0,
                headers={"Accept": "application/json", "User-Agent": "Mozilla/5.0"},
            )
            if status == 200 and isinstance(data, dict):
                for entry in data.get("url_list", []) or data.get("results", []) or []:
                    host = normalize_hostname(urlparse(str(entry.get("url", "") or "")).hostname or "")
                    if host and host.endswith(self.domain):
                        subs.add(host)
        except Exception:
            pass
        return subs

    async def _google_ct_subdomains(self) -> set:
        """Google Certificate Transparency via transparencyreport.google.com"""
        return await self._ctsearch_google()

    async def enumerate(self) -> Dict[str, SubdomainRecord]:
        # All modes: fast, balanced, deep, turbo
        seen_ts = _utcnow_iso()
        sources_map = {
            "crt.sh":         self._crtsh,
            "certspotter":    self._certspotter,
            "hackertarget":   self._hackertarget,
            "hackertarget_dns": self._hackertarget_dns,
            "hackertarget_subdomain": self._hackertarget_subdomain,
            "rapiddns":       self._rapiddns,
            "urlscan":        self._urlscan,
            "urlscan_pages":  self._urlscan_paginated,
            "otx":            self._otx,
            "jldc":           self._jldc,
            "anubisdb":       self._anubisdb,
            "shrewdeye":      self._shrewdeye,
            "vt_unauth":      self._virustotal_unauth,
            "grep_app":       self._grep_app_subs,
            "wayback_cdx":    self._wayback_cdx,
            "otx_passive_dns": self._otx_passive_dns,
            "bufferover_dns": self._bufferover_dns,
            "alienvault_otx":    self._alienvault_otx,
            "subdomaincenter":   self._subdomaincenter,
            "he_bgp":            self._he_bgp,
            "dnsgrep":           self._dnsgrep,
            "myssl":             self._myssl,
            "digitorus":         self._digitorus,
            "bevigil_free":      self._bevigil_free,
            "hackertarget_rev":  self._hackertarget_reverse,
            "sitedossier":       self._sitedossier,
            "urlscan_subs":      self._urlscan_subdomains,
            "dnsbufferover":     self._dnsbufferover,
            "sslmate_certs":     self._sslmate_certs,
            "google_ct":         self._google_ct_subdomains,
            "ctsearch_google":   self._ctsearch_google,
            "trickest":          self._trickest,
            "doh_wordlist":      self._doh_wordlist_passive,
        }
        if self.mode in ("balanced", "deep", "turbo"):
            sources_map.update({
                "circl_pdns":     self._circl_passive_dns,
                "wayback":        self._wayback_subs,
                "wayback_host_hints": self._wayback_host_hints,
                "github_code":    self._github_code_subs,
                "netcraft":       self._netcraft,
                "leakix":         self._leakix,
                "dnsdumpster":    self._dnsdumpster,
                "phonebook_subs": self._phonebook_subs,
                "dnsrepo":        self._dnsrepo,
                "bevigil":        self._bevigil,
                "ctsearch":       self._ctsearch_entrust,
                "columbus":       self._columbus,
                "c99":            self._c99,
                "whoisxml":       self._whoisxml_subs,
                "mnemonic_pdns":  self._mnemonic_pdns,
                "alienvault_pulse": self._alienvault_pulse,
            })
        if self.mode in ("balanced", "deep"):
            sources_map.update({
                "commoncrawl":    self._commoncrawl,
            })
        if self.mode == "deep":
            sources_map.update({
                "virustotal":     self._virustotal_subs,
                "chaos":          self._chaos,
                "wayback_cdx_full": self._wayback_cdx_full,
                "wayback_subdomains": self._wayback_subdomains,
            })

        runnable_sources, source_statuses = self.source_registry.filter_sources(sources_map)
        for source_name, st in source_statuses.items():
            if st != "ok":
                m = self._metric_bucket(source_name)
                m["status"] = st
        async def _run_named_source(name: str, fn):
            return name, await self._run_source(name, fn)

        results: Dict[str, SubdomainRecord] = {}

        def _consume_source_result(name: str, result: set) -> None:
            metric = self._metric_bucket(name)
            if metric.get("status") in {"", "ok"}:
                metric["status"] = "ok"
            count = len(result) if isinstance(result, set) else 0
            if count:
                console.print(f"[dim]  [+] {name} -> {count} subdomains[/dim]")
            for sub in result:
                metric["items_parseados"] += 1
                raw_sub = str(sub or "").strip().lower()
                is_ct_wildcard = (
                    name in {"crt.sh", "certspotter", "sslmate_certs"}
                    and raw_sub.startswith("*.")
                    and normalize_hostname(raw_sub[2:]) == self.apex
                )
                # FIXED: preserve CT wildcard SAN entries as passive scope indicators instead of collapsing them into the apex and silently discarding them.
                sub = raw_sub if is_ct_wildcard else normalize_hostname(raw_sub)
                if not sub or (sub == self.apex and not is_ct_wildcard):
                    metric["items_descartados_por_filtro"] += 1
                    self._rejected_noise_count += 1
                    self.dropped_items.append({"section": "subdomains", "source": name, "item": sub, "reason": DropReason.APEX_DOMAIN.value})
                    if self.debug_coverage:
                        log.debug("sub_discarded source=%s reason=empty_or_apex value=%r", name, sub)
                    continue
                if not sub.endswith("." + self.apex):
                    metric["items_descartados_por_filtro"] += 1
                    self._rejected_noise_count += 1
                    self.dropped_items.append({"section": "subdomains", "source": name, "item": sub, "reason": DropReason.OUT_OF_SCOPE.value})
                    if self.debug_coverage:
                        log.debug("sub_discarded source=%s reason=not_in_scope value=%r", name, sub)
                    continue
                if not is_ct_wildcard and not looks_like_hostname(sub):
                    metric["items_descartados_por_filtro"] += 1
                    self._rejected_noise_count += 1
                    self.dropped_items.append({"section": "subdomains", "source": name, "item": sub, "reason": DropReason.INVALID_HOSTNAME.value})
                    if self.debug_coverage:
                        log.debug("sub_discarded source=%s reason=invalid_hostname value=%r", name, sub)
                    continue
                if self.debug_coverage and name == "crt.sh":
                    log.debug("sub_accepted source=%s value=%r", name, sub)
                self._normalized_candidates_seen.add(sub)
                if sub not in results:
                    results[sub] = SubdomainRecord(name=sub)
                    metric["items_aceptados"] += 1
                else:
                    metric["items_descartados_por_dedupe"] += 1
                    self.dropped_items.append({"section": "subdomains", "source": name, "item": sub, "reason": DropReason.DEDUPE.value})
                    if self.debug_coverage and name == "crt.sh":
                        log.debug("sub_discarded source=%s reason=dedupe value=%r", name, sub)
                if name not in results[sub].sources:
                    results[sub].sources.append(name)
                    results[sub].seen_in_sources = list(results[sub].sources)
                    results[sub].source_attribution.append({
                        "entity_id": canonical_entity_id("subdomain", sub),
                        "source": name,
                        "confidence": self._source_confidence_weight(name),
                        "source_quality": self._source_quality_bucket(name),
                        "first_seen": seen_ts,
                        "last_seen": seen_ts,
                    })
                results[sub].first_seen_source = str((results[sub].source_attribution[0] or {}).get("source", name))
                results[sub].confidence, results[sub].confidence_bucket = self._subdomain_confidence(results[sub])
                results[sub].passive_evidence_count = len(results[sub].source_attribution)
                results[sub].api_enriched = any(self._is_api_backed_source(src) for src in (results[sub].sources or []))
                results[sub].exclusive_source = len(set(results[sub].sources or [])) == 1
                results[sub].resolved_ips = list(results[sub].ips or [])
                if not results[sub].first_seen:
                    results[sub].first_seen = seen_ts
                results[sub].last_seen = seen_ts
            self._store_partial_results(results)

        priority_sources = ("subdomaincenter", "crt.sh")
        for source_name in priority_sources:
            fn = runnable_sources.pop(source_name, None)
            if fn is None:
                continue
            try:
                _, result = await _run_named_source(source_name, fn)
            except Exception:
                continue
            _consume_source_result(source_name, result if isinstance(result, set) else set())

        tasks = [asyncio.create_task(_run_named_source(name, fn)) for name, fn in runnable_sources.items()]
        for task in asyncio.as_completed(tasks):
            try:
                name, result = await task
            except Exception:
                continue
            _consume_source_result(name, result if isinstance(result, set) else set())

        results.pop(self.domain, None)

        def merge_recovered_hosts(source_name: str, hosts: set[str], *, confidence: float, tags: List[str]) -> int:
            added = 0
            for host in sorted(self._normalize_candidate_subs(hosts)):
                rec = results.get(host)
                if rec is None:
                    rec = SubdomainRecord(name=host)
                    results[host] = rec
                    added += 1
                if source_name not in rec.sources:
                    rec.sources.append(source_name)
                    rec.seen_in_sources = list(rec.sources)
                    rec.source_attribution.append({
                        "entity_id": canonical_entity_id("subdomain", host),
                        "source": source_name,
                        "confidence": confidence,
                        "source_quality": self._source_quality_bucket(source_name),
                        "first_seen": seen_ts,
                        "last_seen": seen_ts,
                    })
                rec.tags = list(dict.fromkeys((rec.tags or []) + list(tags)))
                self._normalized_candidates_seen.add(host)
                rec.first_seen_source = str((rec.source_attribution[0] or {}).get("source", source_name))
                rec.confidence, rec.confidence_bucket = self._subdomain_confidence(rec)
                rec.passive_evidence_count = len(rec.source_attribution)
                rec.api_enriched = any(self._is_api_backed_source(src) for src in (rec.sources or []))
                rec.exclusive_source = len(set(rec.sources or [])) == 1
                rec.resolved_ips = list(rec.ips or [])
                if not rec.first_seen:
                    rec.first_seen = seen_ts
                rec.last_seen = seen_ts
            if added:
                metric = self._metric_bucket(source_name)
                metric["items_obtenidos"] += added
                metric["items_parseados"] += added
                metric["items_aceptados"] += added
                metric["status"] = "derived_ok"
            return added

        # Wildcard candidate detection from naming patterns
        for rec in results.values():
            for pat in WILDCARD_PATS:
                rel = rec.name[: -len(self.domain) - 1]
                if pat.match(rel + "."):
                    rec.wildcard_candidate = True
                    break

        self._store_partial_results(results)

        # DoH resolution for each unique subdomain
        sem = asyncio.Semaphore(50)
        shodan_sem = asyncio.Semaphore(10)

        async def _shodan_idb(ip: str) -> dict:
            async with shodan_sem:
                for attempt in range(3):
                    try:
                        resp = await _safe_get(
                            self.session,
                            f"https://internetdb.shodan.io/{ip}",
                            timeout=max(self.timeout, 30),
                            ssl=False,
                        )
                        if resp and resp.status == 200:
                            data = await resp.json(content_type=None)
                            if isinstance(data, dict):
                                return data
                        if resp and resp.status not in {429, 500, 502, 503, 504}:
                            break
                    except Exception:
                        pass
                    if attempt < 2:
                        await asyncio.sleep(float(2 ** attempt))
            return {}

        async def resolve_sub(sub: str, rec: SubdomainRecord):
            recovered = {
                "cname_recovery": set(),
                "internetdb_host_hint": set(),
            }
            async with sem:
                a_answers = await _doh_query(self.session, sub, "A", self.timeout)
                raw_answers = [str(a.get("data", "")).strip().rstrip(".") for a in a_answers if str(a.get("data", "")).strip()]
                ips: List[str] = []
                cname_hints: List[str] = []
                for raw in raw_answers:
                    ip = _normalize_ip_literal(raw)
                    if ip:
                        ips.append(ip)
                    elif looks_like_hostname(raw):
                        host = normalize_hostname(raw)
                        if host:
                            cname_hints.append(host)
                if ips:
                    rec.ips = sorted(set(ips))
                    # Enrich first IP with Shodan InternetDB
                    if self.mode in ("balanced", "deep"):
                        first_ip = ips[0]
                        idb = await _shodan_idb(first_ip)
                        if idb:
                            rec.ports = idb.get("ports") or []
                            recovered["internetdb_host_hint"].update(self._normalize_candidate_subs(idb.get("hostnames", []) or []))
                if cname_hints:
                    rec.cname = sorted(set((rec.cname or []) + cname_hints))
                    recovered["cname_recovery"].update(self._normalize_candidate_subs(cname_hints))
                cname_answers = await _doh_query(self.session, sub, "CNAME", self.timeout)
                if cname_answers:
                    cname_values = [normalize_hostname(str(c.get("data", "")).rstrip(".")) for c in cname_answers]
                    cname_values = [c for c in cname_values if c]
                    rec.cname = sorted(set((rec.cname or []) + cname_values))
                    recovered["cname_recovery"].update(self._normalize_candidate_subs(cname_values))
            for bucket in recovered.values():
                bucket.discard(sub)
            return recovered

        # Cap DoH resolution to avoid outer timeout for large domains (e.g. microsoft.com ~8000 subs)
        _max_resolve = {"fast": 200, "balanced": 500, "deep": 1000, "turbo": 100}.get(self.mode, 200)
        resolve_candidates = list(results.items())[:_max_resolve]
        resolve_budget = {"fast": 20, "balanced": 60, "deep": 300, "turbo": 12}.get(self.mode, 45)
        try:
            resolve_results = []
            for start in range(0, len(resolve_candidates), 10):
                chunk = resolve_candidates[start:start + 10]
                chunk_results = await asyncio.wait_for(
                    asyncio.gather(*(resolve_sub(sub, rec) for sub, rec in chunk), return_exceptions=True),
                    timeout=resolve_budget,
                )
                resolve_results.extend(chunk_results)
                if start + 10 < len(resolve_candidates):
                    await asyncio.sleep(0.5)
        except asyncio.TimeoutError:
            self.source_errors.append({
                "time": _utcnow_iso(),
                "module": "Subdomain Enumeration",
                "source": "subdomain_resolver",
                "kind": "TimeoutError",
                "message_short": f"DoH enrichment budget exceeded ({resolve_budget}s); continuing with partial enrichment",
            })
            resolve_results = []
        for item in resolve_results:
            if not isinstance(item, dict):
                continue
            merge_recovered_hosts(
                "cname_recovery",
                set(item.get("cname_recovery", set()) or set()),
                confidence=0.74,
                tags=["dns", "cname"],
            )
            merge_recovered_hosts(
                "internetdb_host_hint",
                set(item.get("internetdb_host_hint", set()) or set()),
                confidence=0.72,
                tags=["passive_ip", "internetdb"],
            )

        reverse_ip_hosts = await self._hackertarget_reverseip_hosts([
            ip
            for rec in results.values()
            for ip in (rec.ips or [])
        ])
        merge_recovered_hosts(
            "hackertarget_reverseip",
            reverse_ip_hosts,
            confidence=0.76,
            tags=["reverse_ip", "passive_ip"],
        )

        # Wildcard detection: if >30 subs resolve to same IP
        all_ips = [ip for rec in results.values() for ip in rec.ips]
        if all_ips:
            ip_counts = Counter(all_ips)
            most_common_ip, most_common_count = ip_counts.most_common(1)[0]
            if most_common_count > 30:
                for rec in results.values():
                    if most_common_ip in rec.ips:
                        rec.wildcard_candidate = True

        # Ã¢â€â‚¬Ã¢â€â‚¬ Subdomain tagging & relevance scoring Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
        for sub_name, rec in results.items():
            prefix = sub_name[:-len(self.domain)-1].lower() if sub_name.endswith("." + self.domain) else sub_name.lower()
            tags, score_bonus = _host_family_enrichment(sub_name, self.domain)
            score = 5
            if tags:
                rec.tags = list(dict.fromkeys(tags))
                score += score_bonus
                if "identity_auth" in tags:
                    score += 2
                if "internal_hint" in tags:
                    score += 1
            # More sources = more confidence = higher relevance
            score += min(len(rec.sources), 5)
            source_conf = min(1.0, round(0.2 + (0.12 * len(rec.sources)) + (0.15 if rec.ips else 0), 2))
            rec.confidence = max(rec.confidence, source_conf)
            unique_sources = len(set(rec.sources or []))
            premium_sources = len([src for src in (rec.sources or []) if self._is_api_backed_source(src)])
            noisy_only = bool(rec.sources) and all(self._source_quality_bucket(src) == "noisy" for src in (rec.sources or []))
            if unique_sources >= 2:
                score += 1
            if unique_sources >= 4:
                score += 1
            if premium_sources:
                score += min(2, premium_sources)
            if any(self._source_quality_bucket(src) == "high_confidence" for src in (rec.sources or [])):
                score += 1
            if rec.confidence >= 0.82:
                rec.confidence_bucket = "high_confidence"
            elif rec.confidence < 0.58:
                rec.confidence_bucket = "noisy"
            # IPs resolved = active
            if rec.ips:
                score += 2
            elif any(src in {"archive_host_hint", "artifact_host_hint", "dork_host_hint", "wayback_host_hints"} for src in (rec.sources or [])):
                score += 1
            # Open dangerous ports
            dangerous_ports = {21, 23, 25, 445, 3306, 5432, 6379, 9200, 27017, 2375, 11211}
            if any(p in dangerous_ports for p in rec.ports):
                score += 3
            if rec.wildcard_candidate:
                score -= 2
            if noisy_only and unique_sources == 1:
                score -= 2
            if rec.api_enriched and rec.ips:
                score += 1
            rec.passive_evidence_count = max(rec.passive_evidence_count, len(rec.source_attribution or []))
            rec.exclusive_source = unique_sources == 1
            rec.seen_in_sources = list(dict.fromkeys(rec.sources or []))
            rec.resolved_ips = list(dict.fromkeys(rec.ips or []))
            rec.relevance_score = max(0, min(score, 10))
            # Cloud provider from CNAME
            if rec.cname:
                cname_str = " ".join(rec.cname).lower()
                if "amazonaws.com" in cname_str:
                    rec.cloud_provider = "AWS"
                elif "azure" in cname_str or "windows.net" in cname_str:
                    rec.cloud_provider = "Azure"
                elif "googleusercontent.com" in cname_str or "appspot.com" in cname_str:
                    rec.cloud_provider = "GCP"
                elif "cloudflare" in cname_str:
                    rec.cloud_provider = "Cloudflare"
                elif "netlify" in cname_str:
                    rec.cloud_provider = "Netlify"
                elif "vercel" in cname_str or "now.sh" in cname_str:
                    rec.cloud_provider = "Vercel"
                elif "heroku" in cname_str:
                    rec.cloud_provider = "Heroku"

        # Sort by relevance score descending
        sorted_results = dict(sorted(results.items(), key=lambda x: x[1].relevance_score, reverse=True))
        # Mode-aware cap: keep deep scans broad without unbounded memory growth.
        cap = {"fast": 3000, "balanced": 12000, "deep": 25000, "turbo": 2000}.get(self.mode, 5000)
        if len(sorted_results) > cap:
            sorted_results = dict(list(sorted_results.items())[:cap])
        raw_discovered_count = 0
        for metric in self.source_metrics.values():
            if isinstance(metric, dict):
                raw_discovered_count += int(metric.get("items_obtenidos", metric.get("items_parseados", 0)) or 0)
        bucket_counts = {"high_confidence": 0, "medium_confidence": 0, "noisy": 0}
        for rec in sorted_results.values():
            bucket = str(rec.confidence_bucket or "medium_confidence")
            bucket_counts[bucket if bucket in bucket_counts else "medium_confidence"] += 1
        self.inventory_stats = {
            "raw_discovered_count": int(raw_discovered_count),
            "unique_normalized_count": len(self._normalized_candidates_seen),
            "accepted_final_count": len(sorted_results),
            "rejected_noise_count": int(self._rejected_noise_count),
            "wildcard_suspected_count": len([rec for rec in sorted_results.values() if bool(rec.wildcard_candidate)]),
            "high_confidence_count": int(bucket_counts.get("high_confidence", 0)),
            "medium_confidence_count": int(bucket_counts.get("medium_confidence", 0)),
            "noisy_count": int(bucket_counts.get("noisy", 0)),
            "confidence_buckets": bucket_counts,
        }
        summary_parts = []
        for name, metric in sorted(self.source_metrics.items()):
            accepted = int(metric.get("items_aceptados", 0) or 0)
            status = str(metric.get("status", "") or "unknown")
            if accepted > 0 or status not in {"ok", "derived_ok"}:
                summary_parts.append(f"{name}: {accepted} ({status})")
        if summary_parts:
            log.info("[SOURCE SUMMARY] %s", ", ".join(summary_parts))
        self._store_partial_results(sorted_results)

        return sorted_results


# Ã¢â€â‚¬Ã¢â€â‚¬ EMAIL DISCOVERY Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
class EmailDiscovery:
    _email_re = re.compile(
        r"(?<![A-Za-z0-9._%+\-])[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@"
        r"(?:[A-Za-z0-9-]{1,63}\.)+[A-Za-z0-9-]{2,63}(?![A-Za-z0-9._%+\-])"
    )
    _obfus_re = re.compile(
        r"[a-zA-Z0-9._%+\-]+\s*(?:\[\s*at\s*\]|\(\s*at\s*\)|\s+at\s+)\s*"
        r"[a-zA-Z0-9.\-]+\s*(?:\[\s*dot\s*\]|\(\s*dot\s*\)|\s+dot\s+)\s*[a-zA-Z0-9\-]{2,63}",
        re.I
    )

    def __init__(
        self,
        domain: str,
        mode: str,
        session: aiohttp.ClientSession,
        api_keys: dict,
        policy: Optional[ScanPolicy] = None,
        debug_coverage: bool = False,
        source_registry: Optional[SourceRegistry] = None,
    ):
        self.domain = domain
        self.mode = mode
        self.session = session
        self.api_keys = api_keys
        self.policy = policy or ScanPolicy()
        self.debug_coverage = debug_coverage
        self.source_registry = source_registry or SourceRegistry(api_keys=api_keys)
        self.apex = normalize_hostname(domain)
        self.source_metrics: Dict[str, Dict[str, Any]] = {}
        self.dropped_items: List[Dict[str, Any]] = []
        self.source_errors: List[Dict[str, Any]] = []
        self.timeout = TIMEOUTS[mode]
        self.email_evidence: Dict[str, Dict[str, List[Dict[str, Any]]]] = {}
        self._archive_candidates_cache: Optional[List[Dict[str, Any]]] = None
        self._partial_results: Dict[str, EmailRecord] = {}
        self._domain_email_re = re.compile(
            r'\b[A-Za-z0-9._%+\-]+@' + re.escape(domain) + r'\b', re.I
        )

    def _store_partial_results(self, results: Dict[str, EmailRecord]) -> None:
        self._partial_results = dict(results)

    def get_partial_results(self) -> Dict[str, EmailRecord]:
        return dict(self._partial_results)

    def _metric_bucket(self, name: str) -> Dict[str, Any]:
        return self.source_metrics.setdefault(name, {
            "items_obtenidos": 0,
            "items_parseados": 0,
            "items_aceptados": 0,
            "items_descartados_por_dedupe": 0,
            "items_descartados_por_filtro": 0,
            "errores": 0,
            "latencia_ms": 0,
            "status": "ok",
        })

    def _normalize_email(self, value: str) -> str:
        e = (value or "").strip().strip(".,;:<>\"'()[]{}").lower()
        if e.startswith("mailto:"):
            e = e[7:].strip().lower()
        if "@" not in e:
            return ""
        local, _, domain = e.rpartition("@")
        host = normalize_hostname(domain)
        if not local or not host:
            return ""
        if not re.match(r"^[a-z0-9.!#$%&'*+/=?^_`{|}~-]{1,64}$", local):
            return ""
        if not (host == self.apex or host.endswith("." + self.apex)):
            return ""
        if not looks_like_hostname(host):
            return ""
        return f"{local}@{host}"

    def _clean_emails(self, raw: set) -> set:
        out = set()
        for e in raw:
            normalized = self._normalize_email(e)
            if normalized:
                out.add(normalized)
        return out

    def _deobfuscate(self, text: str) -> list:
        emails = []
        for m in self._obfus_re.finditer(text):
            raw = m.group(0)
            e = re.sub(r"\s*(?:\[\s*at\s*\]|\(\s*at\s*\)|\s+at\s+)\s*", "@", raw, flags=re.I)
            e = re.sub(r"\s*(?:\[\s*dot\s*\]|\(\s*dot\s*\)|\s+dot\s+)\s*", ".", e, flags=re.I)
            normalized = self._normalize_email(e)
            if normalized:
                emails.append(normalized)
        return emails

    def _record_email_evidence(
        self,
        source: str,
        email: str,
        ref_url: str,
        *,
        fetched_at: str,
        first_seen: str = "",
        last_seen: str = "",
        evidence_type: str = "index",
    ) -> None:
        if not email:
            return
        by_source = self.email_evidence.setdefault(source, {})
        refs = by_source.setdefault(email, [])
        refs.append({
            "entity_id": canonical_entity_id("email", email),
            "source": source,
            "ref_url": ref_url,
            "evidence_type": evidence_type,
            "fetched_at": fetched_at,
            "first_seen": first_seen or fetched_at,
            "last_seen": last_seen or fetched_at,
        })

    async def _archive_candidate_urls(self) -> List[Dict[str, Any]]:
        if self._archive_candidates_cache is not None:
            return self._archive_candidates_cache
        out: List[Dict[str, Any]] = []
        # Assumption: candidate pages focused on contact/about maximize email yield in passive-only mode.
        hint_re = re.compile(r"(contact|about|team|staff|people|support|legal|privacy|security|press|careers)", re.I)
        try:
            cdx_url = (
                f"https://web.archive.org/cdx/search/cdx?url=*.{self.domain}/*"
                f"&output=json&fl=original,timestamp,statuscode,mimetype&collapse=urlkey&limit=1200"
            )
            resp = await _safe_get(self.session, cdx_url, timeout=max(self.timeout, 35))
            if resp and resp.status == 200:
                data = await resp.json(content_type=None)
                for row in data[1:]:
                    if not isinstance(row, list) or len(row) < 4:
                        continue
                    raw_url = str(row[0] or "").strip()
                    ts = str(row[1] or "").strip()
                    code = str(row[2] or "").strip()
                    mime = str(row[3] or "").lower().strip()
                    if not raw_url or not code.startswith("2"):
                        continue
                    if not (hint_re.search(raw_url) or "mailto:" in raw_url.lower()):
                        continue
                    if "html" not in mime and "text" not in mime and "json" not in mime and mime:
                        continue
                    out.append({
                        "source": "wayback_cdx",
                        "url": raw_url,
                        "timestamp": ts,
                        "ref_url": cdx_url,
                    })
        except Exception:
            pass
        try:
            cc_indexes = await _commoncrawl_indexes(self.session, "deep" if self.mode in ("deep", "turbo") else self.mode)
            for idx in cc_indexes:
                cc_url = (
                    f"https://index.commoncrawl.org/{idx}-index?"
                    f"url=*.{self.domain}/*&output=json&limit=600&fl=url,timestamp,status,filename,offset,length"
                )
                text = ""
                for attempt in range(3):
                    try:
                        text = await _safe_get_text_cached(self.session, cc_url, timeout=max(self.timeout, 35))
                        if text:
                            break
                    except Exception:
                        pass
                    await asyncio.sleep(0.25 * (attempt + 1))
                if not text:
                    continue
                for line in text.splitlines():
                    try:
                        obj = json.loads(line)
                    except Exception:
                        continue
                    raw_url = str(obj.get("url", "") or "").strip()
                    if not raw_url:
                        continue
                    if not (hint_re.search(raw_url) or "mailto:" in raw_url.lower()):
                        continue
                    out.append({
                        "source": "commoncrawl_index",
                        "url": raw_url,
                        "timestamp": str(obj.get("timestamp", "") or "").strip(),
                        "ref_url": cc_url,
                        "filename": str(obj.get("filename", "") or "").strip(),
                        "offset": str(obj.get("offset", "") or "").strip(),
                        "length": str(obj.get("length", "") or "").strip(),
                    })
            await asyncio.sleep(0.2)
        except Exception:
            pass
        # Preserve diversity but cap for runtime safety.
        dedup = {}
        for item in out:
            k = (item.get("source", ""), item.get("url", ""))
            if k not in dedup:
                dedup[k] = item
        self._archive_candidates_cache = list(dedup.values())[:900]
        return self._archive_candidates_cache

    async def _from_wayback_snapshots(self) -> set:
        emails = set()
        fetched_at = _utcnow_iso()
        candidates = await self._archive_candidate_urls()
        wayback_candidates = [c for c in candidates if c.get("source") == "wayback_cdx"]
        max_fetch = 40 if self.mode in ("deep", "turbo") else 20
        for cand in wayback_candidates[:max_fetch]:
            raw_url = str(cand.get("url", "") or "")
            ts = str(cand.get("timestamp", "") or "")
            if not raw_url or not ts:
                continue
            archive_url = f"https://web.archive.org/web/{ts}id_/{raw_url}"
            try:
                resp = await _safe_get(self.session, archive_url, timeout=max(self.timeout, 20))
                if not (resp and resp.status == 200):
                    continue
                text = await resp.text()
                observed = set(self._email_re.findall(text))
                observed.update(self._deobfuscate(text))
                for m in re.finditer(r"mailto:([^\s\"'<>?]+)", text, re.I):
                    observed.add(m.group(1).strip().lower())
                for e in observed:
                    norm = self._normalize_email(e)
                    if not norm:
                        continue
                    emails.add(norm)
                    self._record_email_evidence(
                        "wayback_snapshots",
                        norm,
                        archive_url,
                        fetched_at=fetched_at,
                        first_seen=ts,
                        last_seen=ts,
                        evidence_type="snapshot",
                    )
                await asyncio.sleep(0.15)
            except Exception:
                continue
        return self._clean_emails(emails)

    async def _from_commoncrawl_index_emails(self) -> set:
        emails = set()
        fetched_at = _utcnow_iso()
        candidates = await self._archive_candidate_urls()
        cc_candidates = [c for c in candidates if c.get("source") == "commoncrawl_index"]
        for cand in cc_candidates:
            raw_url = str(cand.get("url", "") or "")
            if not raw_url:
                continue
            # CommonCrawl index-only evidence (no direct target fetch).
            for e in self._email_re.findall(raw_url):
                norm = self._normalize_email(e)
                if not norm:
                    continue
                emails.add(norm)
                self._record_email_evidence(
                    "commoncrawl_index",
                    norm,
                    str(cand.get("ref_url", "")) or raw_url,
                    fetched_at=fetched_at,
                    first_seen=str(cand.get("timestamp", "")),
                    last_seen=str(cand.get("timestamp", "")),
                    evidence_type="index_url",
                )
            mailto_match = re.match(r"mailto:(.+)", raw_url, re.I)
            if mailto_match:
                norm = self._normalize_email(mailto_match.group(1).strip().lower())
                if norm:
                    emails.add(norm)
                    self._record_email_evidence(
                        "commoncrawl_index",
                        norm,
                        str(cand.get("ref_url", "")) or raw_url,
                        fetched_at=fetched_at,
                        first_seen=str(cand.get("timestamp", "")),
                        last_seen=str(cand.get("timestamp", "")),
                        evidence_type="mailto_index",
                    )
        return self._clean_emails(emails)

    async def _run_source(self, name: str, fn) -> set:
        metric = self._metric_bucket(name)
        t0 = time.perf_counter()
        tok = set_current_source(name)
        _timeout = SOURCE_OVERRIDE_TIMEOUTS.get(name, {}).get(self.mode) or (SLOW_SOURCE_TIMEOUT if name in SLOW_SOURCES else PER_SOURCE_TIMEOUT).get(self.mode, 60)
        try:
            data = await asyncio.wait_for(fn(), timeout=_timeout)
            items = data if isinstance(data, set) else set()
            metric["items_obtenidos"] = len(items)
            return items
        except (aiohttp.ClientError, asyncio.TimeoutError, ValueError) as exc:
            metric["errores"] += 1
            metric["status"] = "timeout" if isinstance(exc, asyncio.TimeoutError) else "fail"
            self.source_errors.append({
                "time": _utcnow_iso(),
                "module": "Email Discovery",
                "source": name,
                "kind": type(exc).__name__,
                "message_short": str(exc)[:160],
            })
            if self.debug_coverage:
                log.warning("email_source_failed source=%s domain=%s err=%s", name, self.domain, exc)
            return set()
        except Exception as exc:
            metric["errores"] += 1
            metric["status"] = "fail"
            self.source_errors.append({
                "time": _utcnow_iso(),
                "module": "Email Discovery",
                "source": name,
                "kind": type(exc).__name__,
                "message_short": str(exc)[:160],
            })
            log.warning("email_source_failed_unexpected source=%s domain=%s err=%s", name, self.domain, exc)
            return set()
        finally:
            reset_current_source(tok)
            metric["latencia_ms"] = int((time.perf_counter() - t0) * 1000)
            guard = get_http_guard()
            if self.debug_coverage and hasattr(guard, "source_state"):
                metric["runtime"] = guard.source_state(name)
    async def _from_ct_logs(self) -> set:
        emails = set()
        try:
            url = f"https://crt.sh/?q=%25.{self.domain}&output=json"
            resp = await _safe_get(self.session, url, timeout=self.timeout)
            if resp and resp.status == 200:
                data = await resp.json(content_type=None)
                for entry in data:
                    for fld in ("name_value", "common_name"):
                        val = entry.get(fld) or ""
                        if not isinstance(val, str):
                            continue
                        emails.update(self._email_re.findall(val))
        except Exception:
            pass
        return self._clean_emails(emails)

    async def _from_whois_html(self) -> set:
        emails = set()
        try:
            for base in [f"https://www.whois.com/whois/{self.domain}",
                         f"https://who.is/whois/{self.domain}"]:
                resp = await _safe_get(self.session, base, timeout=self.timeout)
                if resp and resp.status == 200:
                    text = await resp.text()
                    emails.update(self._email_re.findall(text))
                    emails.update(self._deobfuscate(text))
                    if emails:
                        break
        except Exception:
            pass
        return self._clean_emails(emails)

    async def _from_hunter(self) -> set:
        return set()

    async def _from_emailformat(self) -> set:
        emails = set()
        try:
            url = f"https://www.email-format.com/d/{self.domain}/"
            resp = await _safe_get(self.session, url, timeout=self.timeout)
            if resp and resp.status == 200:
                text = await resp.text()
                emails.update(self._email_re.findall(text))
        except Exception:
            pass
        return self._clean_emails(emails)

    async def _from_target_page(self) -> set:
        """Fetch emails from archived homepage snapshots via Wayback Machine (passive)."""
        emails = set()
        for target_path in [f"https://{self.domain}/", f"https://www.{self.domain}/"]:
            cdx_url = (
                "https://web.archive.org/cdx/search/cdx"
                f"?url={target_path}&output=json&limit=1&fl=timestamp"
                "&filter=statuscode:200&from=20220101"
            )
            try:
                resp = await _safe_get(self.session, cdx_url, timeout=self.timeout)
                if not (resp and resp.status == 200):
                    continue
                data = await resp.json(content_type=None)
                rows = data[1:] if isinstance(data, list) and len(data) > 1 else []
                if not rows:
                    continue
                ts = rows[0][0] if rows[0] else ""
                if not ts:
                    continue
                archive_url = f"https://web.archive.org/web/{ts}id_/{target_path}"
                resp2 = await _safe_get(self.session, archive_url, timeout=max(self.timeout, 20))
                if resp2 and resp2.status == 200:
                    text = await resp2.text()
                    emails.update(self._email_re.findall(text))
                    emails.update(self._deobfuscate(text))
                    for m in re.finditer(r"mailto:([^\s\"'<>?]+)", text, re.I):
                        addr = m.group(1).strip().lower()
                        if "@" in addr:
                            emails.add(addr)
                    if emails:
                        break
            except Exception:
                continue
        return self._clean_emails(emails)
    async def _from_securitytxt(self) -> set:
        """Fetch emails from archived security.txt via Wayback Machine (passive)."""
        emails = set()
        for sec_path in [
            f"https://{self.domain}/.well-known/security.txt",
            f"https://{self.domain}/security.txt",
        ]:
            cdx_url = (
                "https://web.archive.org/cdx/search/cdx"
                f"?url={sec_path}&output=json&limit=1&fl=timestamp"
                "&filter=statuscode:200"
            )
            try:
                resp = await _safe_get(self.session, cdx_url, timeout=self.timeout)
                if not (resp and resp.status == 200):
                    continue
                data = await resp.json(content_type=None)
                rows = data[1:] if isinstance(data, list) and len(data) > 1 else []
                if not rows:
                    continue
                ts = rows[0][0] if rows[0] else ""
                if not ts:
                    continue
                archive_url = f"https://web.archive.org/web/{ts}id_/{sec_path}"
                resp2 = await _safe_get(self.session, archive_url, timeout=max(self.timeout, 20))
                if resp2 and resp2.status == 200:
                    text = await resp2.text()
                    for m in re.finditer(r"Contact:\s*(.+)", text, re.I):
                        val = m.group(1).strip()
                        emails.update(self._email_re.findall(val))
                    if emails:
                        break
            except Exception:
                continue
        return self._clean_emails(emails)

    async def _from_pgp_keyserver(self) -> set:
        emails = set()
        for base_url in [
            f"https://keyserver.ubuntu.com/pks/lookup?op=index&search={self.domain}&fingerprint=on&options=mr",
            f"https://keys.openpgp.org/search?q={self.domain}",
        ]:
            try:
                resp = await _safe_get(self.session, base_url, timeout=self.timeout)
                if resp and resp.status == 200:
                    text = await resp.text()
                    emails.update(self._email_re.findall(text))
            except Exception:
                pass
        return self._clean_emails(emails)

    async def _from_github_code(self) -> set:
        emails = set()
        key = self.api_keys.get("github_token", "")
        headers = _github_auth_headers(key, accept="application/vnd.github.v3.text-match+json")
        try:
            url = f"https://api.github.com/search/code?q=%40{self.domain}&per_page=100"
            resp = await _safe_get(self.session, url, timeout=self.timeout, headers=headers)
            if resp and resp.status == 200:
                data = await resp.json(content_type=None)
                for item in data.get("items", []):
                    for match in item.get("text_matches", []):
                        emails.update(self._email_re.findall(match.get("fragment", "")))
        except Exception:
            pass
        return self._clean_emails(emails)

    async def _from_github_commits(self) -> set:
        emails = set()
        key = self.api_keys.get("github_token", "")
        headers = _github_auth_headers(key, accept="application/vnd.github.cloak-preview+json")
        try:
            queries = [
                f"{self.domain} author-email:*@{self.domain}",
                f"\"{self.domain}\" author-email:*@{self.domain}",
                f"{self.domain.split('.')[0]} {self.domain} author-email:*@{self.domain}",
            ]
            for query in queries:
                url = f"https://api.github.com/search/commits?q={quote(query)}&per_page=100"
                data, status = await _json_request_with_retries(
                    self.session,
                    "GET",
                    url,
                    timeout=max(self.timeout, 30),
                    retries=3,
                    backoff=1.0,
                    headers=headers,
                )
                if status != 200 or not isinstance(data, dict):
                    continue
                for item in data.get("items", []):
                    commit = item.get("commit", {}) if isinstance(item, dict) else {}
                    for actor_key in ("author", "committer"):
                        actor = commit.get(actor_key, {}) if isinstance(commit.get(actor_key), dict) else {}
                        author_email = self._normalize_email(actor.get("email", ""))
                        if author_email and author_email.endswith("@" + self.domain):
                            emails.add(author_email)
                            self._record_email_evidence(
                                "github_commits",
                                author_email,
                                str((item.get("html_url") or item.get("url") or "")).strip(),
                                fetched_at=_utcnow_iso(),
                                evidence_type="commit_author",
                            )
                    text_blob = json.dumps(item, default=str, ensure_ascii=False)
                    emails.update(self._domain_email_re.findall(text_blob))
                await asyncio.sleep(0.35)
        except Exception:
            pass
        return self._clean_emails(emails)

    async def _from_wayback_mailto(self) -> set:
        emails = set()
        fetched_at = _utcnow_iso()
        url = (
            f"https://web.archive.org/cdx/search/cdx?url=mailto:*@{self.domain}"
            "&output=json&fl=original&limit=10000"
        )
        try:
            data, status = await _json_request_with_retries(
                self.session,
                "GET",
                url,
                timeout=max(self.timeout, 30),
                retries=3,
                backoff=1.0,
                ssl=False,
            )
            if status == 200 and isinstance(data, list):
                for row in data[1:]:
                    value = row[0] if isinstance(row, list) and row else row
                    raw = str(value or "").strip()
                    for match in re.findall(r"[A-Za-z0-9._%+\-]+@" + re.escape(self.domain), raw, re.I):
                        norm = self._normalize_email(match)
                        if not norm:
                            continue
                        emails.add(norm)
                        self._record_email_evidence(
                            "wayback_mailto",
                            norm,
                            raw,
                            fetched_at=fetched_at,
                            evidence_type="archive_mailto",
                        )
        except Exception:
            pass
        return self._clean_emails(emails)

    async def _from_wayback_contacts(self) -> set:
        emails = set()
        fetched_at = _utcnow_iso()
        for path in ["/contact", "/about", "/about-us", "/team", "/people", "/staff", "/contact-us"]:
            try:
                cdx_url = (
                    "https://web.archive.org/cdx/search/cdx"
                    f"?url={self.domain}{path}&output=json&limit=1&fl=timestamp,original"
                    "&filter=statuscode:200"
                )
                resp = await _safe_get(self.session, cdx_url, timeout=max(self.timeout, 20))
                if not (resp and resp.status == 200):
                    continue
                data = await resp.json(content_type=None)
                rows = data[1:] if isinstance(data, list) and len(data) > 1 else []
                if not rows:
                    continue
                row = rows[0] if isinstance(rows[0], list) else []
                ts = str(row[0] or "").strip() if row else ""
                orig = str(row[1] or "").strip() if len(row) > 1 else ""
                if not ts or not orig:
                    continue
                archive_url = f"https://web.archive.org/web/{ts}id_/{orig}"
                resp2 = await _safe_get(self.session, archive_url, timeout=max(self.timeout, 20))
                if not (resp2 and resp2.status == 200):
                    continue
                text = await resp2.text()
                observed = set(self._email_re.findall(text))
                observed.update(self._deobfuscate(text))
                for match in re.finditer(r"mailto:([^\s\"'<>?]+)", text, re.I):
                    observed.add(match.group(1).strip().lower())
                for e in observed:
                    norm = self._normalize_email(e)
                    if not norm:
                        continue
                    emails.add(norm)
                    self._record_email_evidence(
                        "wayback_contacts",
                        norm,
                        archive_url,
                        fetched_at=fetched_at,
                        first_seen=ts,
                        last_seen=ts,
                        evidence_type="contact_snapshot",
                    )
                if emails:
                    break
            except Exception:
                pass
        return self._clean_emails(emails)

    async def _from_skymem(self) -> set:
        emails = set()
        try:
            url = f"https://www.skymem.info/srch?q={self.domain}"
            resp = await _safe_get(self.session, url, timeout=self.timeout)
            if resp and resp.status == 200:
                text = await resp.text()
                emails.update(self._email_re.findall(text))
        except Exception:
            pass
        return self._clean_emails(emails)

    async def _from_phonebook(self) -> set:
        emails = set()
        try:
            page = 1
            while True:
                url = f"https://phonebook.cz/search?term={quote(self.domain)}&type=email&page={page}"
                text = ""
                for attempt in range(4):
                    try:
                        resp = await _safe_get(
                            self.session,
                            url,
                            timeout=max(self.timeout, 30),
                            headers={"Referer": "https://phonebook.cz/", "User-Agent": "Mozilla/5.0"},
                        )
                        if resp and resp.status == 200:
                            text = await resp.text()
                            break
                    except Exception:
                        pass
                    if attempt < 3:
                        await asyncio.sleep(float(2**attempt))
                if not text:
                    break
                found = set(self._email_re.findall(text))
                prev = len(emails)
                emails.update(found)
                if not found or len(emails) == prev:
                    break
                page += 1
                await asyncio.sleep(0.35)
        except Exception:
            pass
        return self._clean_emails(emails)

    async def _from_intelx(self) -> set:
        return set()

    async def _from_github_issues(self) -> set:
        emails = set()
        key = self.api_keys.get("github_token", "")
        headers = _github_auth_headers(key, accept="application/vnd.github.v3.text-match+json")
        try:
            url = f"https://api.github.com/search/issues?q={self.domain}&per_page=100"
            resp = await _safe_get(self.session, url, timeout=self.timeout, headers=headers)
            if resp and resp.status == 200:
                data = await resp.json(content_type=None)
                for item in data.get("items", []):
                    body = item.get("body", "") or ""
                    emails.update(self._email_re.findall(body))
                    for match in item.get("text_matches", []):
                        emails.update(self._email_re.findall(match.get("fragment", "")))
        except Exception:
            pass
        return self._clean_emails(emails)

    async def _from_paste_sites(self) -> set:
        emails = set()
        try:
            url = f"https://psbdmp.ws/api/search/{self.domain}"
            resp = await _safe_get(self.session, url, timeout=self.timeout)
            if resp and resp.status == 200:
                data = await resp.json(content_type=None)
                items = data if isinstance(data, list) else data.get("data", [])
                for item in items:
                    content = item.get("text", item.get("content", "")) if isinstance(item, dict) else str(item)
                    emails.update(self._email_re.findall(content))
        except Exception:
            pass
        return self._clean_emails(emails)

    async def _from_commoncrawl_mailto(self) -> set:
        emails = set()
        fetched_at = _utcnow_iso()
        hint_re = re.compile(r"(contact|about|team|staff|people|support|legal|privacy|security|press|careers)", re.I)
        processed_pages = 0

        async def _fetch_commoncrawl_record_text(record: Dict[str, Any]) -> str:
            filename = str(record.get("filename", "") or "").strip().lstrip("/")
            offset_raw = str(record.get("offset", "") or "").strip()
            length_raw = str(record.get("length", "") or "").strip()
            if not filename or not offset_raw.isdigit() or not length_raw.isdigit():
                return ""
            offset = int(offset_raw)
            length = int(length_raw)
            if offset < 0 or length <= 0:
                return ""
            record_url = f"https://data.commoncrawl.org/{filename}"
            range_end = offset + length - 1
            payload = b""
            for attempt in range(4):
                try:
                    resp = await _safe_get(
                        self.session,
                        record_url,
                        timeout=max(self.timeout, 30),
                        headers={"Range": f"bytes={offset}-{range_end}"},
                    )
                    if resp and resp.status in {200, 206}:
                        payload = await resp.read()
                        if payload:
                            break
                except Exception:
                    pass
                if attempt < 3:
                    await asyncio.sleep(float(2 ** attempt))
            if not payload:
                return ""
            try:
                decoded = gzip.decompress(payload)
            except OSError:
                decoded = payload
            body = decoded
            warc_split = body.find(b"\r\n\r\n")
            if warc_split != -1:
                body = body[warc_split + 4:]
            if body.startswith(b"HTTP/"):
                http_split = body.find(b"\r\n\r\n")
                if http_split != -1:
                    body = body[http_split + 4:]
            return body.decode("utf-8", errors="replace")

        try:
            cc_indexes = await _commoncrawl_indexes(self.session, "deep" if self.mode in ("deep", "turbo") else self.mode)
            for idx in cc_indexes:
                base_url = (
                    f"https://index.commoncrawl.org/{idx}-index"
                    f"?url=*.{self.domain}/*&output=json&limit=1000"
                    "&fl=url,timestamp,status,mime,filename,offset,length"
                )
                meta_url = f"{base_url}&showNumPages=true"
                meta, _ = await _json_request_with_retries(
                    self.session,
                    "GET",
                    meta_url,
                    timeout=max(self.timeout, 30),
                    retries=3,
                    backoff=1.0,
                )
                pages = 1
                if isinstance(meta, dict):
                    pages = max(1, int(meta.get("pages", 1) or 1))
                for page in range(pages):
                    url = f"{base_url}&page={page}"
                    text = ""
                    for attempt in range(4):
                        try:
                            text = await _safe_get_text_cached(self.session, url, timeout=max(self.timeout, 30))
                            if text:
                                break
                        except Exception:
                            pass
                        if attempt < 3:
                            await asyncio.sleep(float(2**attempt))
                    if not text:
                        continue
                    for line in text.splitlines():
                        try:
                            obj = json.loads(line)
                            raw_url = str(obj.get("url", "") or "").strip()
                            mime = str(obj.get("mime", "") or "").lower()
                            status = str(obj.get("status", "") or "")
                            if not raw_url or not status.startswith("2"):
                                continue
                            if not hint_re.search(raw_url):
                                continue
                            if mime and "html" not in mime and "text" not in mime:
                                continue
                            page_text = await _fetch_commoncrawl_record_text(obj)
                            if not page_text:
                                continue
                            processed_pages += 1
                            observed = set(self._email_re.findall(page_text))
                            observed.update(self._deobfuscate(page_text))
                            for match in re.finditer(r"mailto:([^\s\"'<>?]+)", page_text, re.I):
                                observed.add(match.group(1).strip().lower())
                            for email in observed:
                                norm = self._normalize_email(email)
                                if not norm:
                                    continue
                                emails.add(norm)
                                self._record_email_evidence(
                                    "commoncrawl_mailto",
                                    norm,
                                    raw_url,
                                    fetched_at=fetched_at,
                                    first_seen=str(obj.get("timestamp", "") or ""),
                                    last_seen=str(obj.get("timestamp", "") or ""),
                                    evidence_type="mailto_page",
                                )
                            await asyncio.sleep(0.15)
                        except Exception:
                            pass
                    await asyncio.sleep(0.2)
        except Exception:
            pass
        if processed_pages:
            log.debug("commoncrawl_mailto processed_pages=%d domain=%s emails=%d", processed_pages, self.domain, len(emails))
        return self._clean_emails(emails)

    async def discover(self) -> Dict[str, EmailRecord]:
        seen_ts = _utcnow_iso()
        sources_map = {
            "ct_logs":      self._from_ct_logs,
            "whois_html":   self._from_whois_html,
            "target_page":  self._from_target_page,
            "security_txt": self._from_securitytxt,
            "pgp_keys":     self._from_pgp_keyserver,
            "skymem":       self._from_skymem,
            "phonebook":    self._from_phonebook,
        }
        if self.mode in ("balanced", "deep", "turbo"):
            sources_map["email_format"]       = self._from_emailformat
            sources_map["github_code_emails"] = self._from_github_code
            sources_map["github_commits"]     = self._from_github_commits
            sources_map["github_issues"]      = self._from_github_issues
            sources_map["wayback_contacts"]   = self._from_wayback_contacts
            sources_map["wayback_mailto"]     = self._from_wayback_mailto
            sources_map["commoncrawl_mailto"] = self._from_commoncrawl_mailto
            sources_map["wayback_snapshots"]  = self._from_wayback_snapshots
            sources_map["commoncrawl_index"]  = self._from_commoncrawl_index_emails
            sources_map["paste_sites"]        = self._from_paste_sites
        runnable_sources, source_statuses = self.source_registry.filter_sources(sources_map)
        for source_name, st in source_statuses.items():
            if st != "ok":
                m = self._metric_bucket(source_name)
                m["status"] = st
        tasks = {name: asyncio.create_task(self._run_source(name, fn)) for name, fn in runnable_sources.items()}
        results: Dict[str, EmailRecord] = {}

        done = await asyncio.gather(*tasks.values(), return_exceptions=True)
        for name, result in zip(tasks.keys(), done):
            metric = self._metric_bucket(name)
            if metric.get("status") in {"", "ok"}:
                metric["status"] = "ok"
            if isinstance(result, Exception):
                metric["errores"] += 1
                continue
            for email in result:
                metric["items_parseados"] += 1
                normalized = self._normalize_email(email)
                if not normalized:
                    metric["items_descartados_por_filtro"] += 1
                    self.dropped_items.append({"section": "emails", "source": name, "item": str(email), "reason": DropReason.INVALID_EMAIL.value})
                    if self.debug_coverage:
                        log.debug("email_discarded source=%s reason=invalid email=%r", name, email)
                    continue
                email = normalized
                if email not in results:
                    results[email] = EmailRecord(
                        email=email,
                        role=categorize_email(email),
                    )
                    metric["items_aceptados"] += 1
                else:
                    metric["items_descartados_por_dedupe"] += 1
                    self.dropped_items.append({"section": "emails", "source": name, "item": email, "reason": DropReason.DEDUPE.value})
                if name not in results[email].sources:
                    results[email].sources.append(name)
                    refs = self.email_evidence.get(name, {}).get(email, [])
                    if refs:
                        for ref in refs:
                            ref_conf = SOURCE_CONFIDENCE.get(name, 0.62)
                            results[email].source_attribution.append({
                                "entity_id": canonical_entity_id("email", email),
                                "source": name,
                                "confidence": ref_conf,
                                "first_seen": ref.get("first_seen", seen_ts) or seen_ts,
                                "last_seen": ref.get("last_seen", seen_ts) or seen_ts,
                                "ref_url": ref.get("ref_url", ""),
                                "fetched_at": ref.get("fetched_at", seen_ts),
                                "evidence_type": ref.get("evidence_type", "index"),
                            })
                    else:
                        results[email].source_attribution.append({
                            "entity_id": canonical_entity_id("email", email),
                            "source": name,
                            "confidence": SOURCE_CONFIDENCE.get(name, 0.62),
                            "first_seen": seen_ts,
                            "last_seen": seen_ts,
                        })
                conf_samples = [float(SOURCE_CONFIDENCE.get(src, 0.62)) for src in results[email].sources]
                diversity_bonus = min(0.2, max(0, len(results[email].sources) - 1) * 0.04)
                base_conf = sum(conf_samples) / max(1, len(conf_samples))
                freshness_bonus = 0.0
                first_seen_vals = [a.get("first_seen", "") for a in results[email].source_attribution if isinstance(a, dict)]
                last_seen_vals = [a.get("last_seen", "") for a in results[email].source_attribution if isinstance(a, dict)]
                first_seen_vals = [v for v in first_seen_vals if v]
                last_seen_vals = [v for v in last_seen_vals if v]
                if last_seen_vals:
                    recent_marker = max(last_seen_vals)
                    if recent_marker[:4].isdigit() and int(recent_marker[:4]) >= datetime.now(timezone.utc).year - 1:
                        freshness_bonus = 0.03
                results[email].confidence = round(min(0.99, base_conf + diversity_bonus + freshness_bonus), 3)
                if not results[email].first_seen:
                    results[email].first_seen = min(first_seen_vals) if first_seen_vals else seen_ts
                results[email].last_seen = max(last_seen_vals) if last_seen_vals else seen_ts
            self._store_partial_results(results)

        return results

    @staticmethod
    def detect_email_pattern(emails: list, domain: str) -> dict:
        """Detect naming convention from collected emails without inventing addresses."""
        import re as _re
        personal_emails = [
            e.get("email", e) if isinstance(e, dict) else e
            for e in emails
            if not any(role in (e.get("email", e) if isinstance(e, dict) else e).split("@")[0].lower()
                       for role in ["info", "contact", "hello", "support", "admin", "help", "sales", "hr", "legal"])
        ]
        if not personal_emails:
            return {}
        patterns = [
            (r'^([a-z]{2,})\.([a-z]{2,})@', 'dot'),           # firstname.lastname
            (r'^([a-z])\.([a-z]{2,})@', 'initial_last'),       # f.lastname
            (r'^([a-z]{2,})\.([a-z])@', 'first_initial'),      # firstname.l
            (r'^([a-z]+)_([a-z]+)@', 'firstname_lastname'),
            (r'^([a-z]{1,2})([a-z]+)@', 'initials+lastname'),
            (r'^([a-z]+)@', 'firstname'),
        ]
        pattern_counts: Dict[str, int] = {}
        for email in personal_emails[:20]:
            local = (email.split("@")[0]).lower()
            for pat, name in patterns:
                if _re.match(pat, local + "@"):
                    pattern_counts[name] = pattern_counts.get(name, 0) + 1
                    break
        if not pattern_counts:
            return {}
        detected = max(pattern_counts, key=lambda x: pattern_counts[x])
        confidence = int(100 * pattern_counts[detected] / max(len(personal_emails[:20]), 1))
        return {
            "pattern": detected,
            "confidence": confidence,
            "sample_count": len(personal_emails),
        }


# Ã¢â€â‚¬Ã¢â€â‚¬ TECHNOLOGY DETECTOR Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
class TechnologyDetector:
    def __init__(
        self,
        domain,
        mode,
        session,
        dns_records,
        wayback_urls=None,
        policy: Optional[ScanPolicy] = None,
        subdomains: Optional[List[Dict[str, Any]]] = None,
        ssl_info: Optional[List[Dict[str, Any]]] = None,
    ):
        self.domain = domain
        self.mode = mode
        self.session = session
        self.dns_records = dns_records
        self.wayback_urls = wayback_urls if isinstance(wayback_urls, dict) else {}
        self.timeout = TIMEOUTS[mode]
        self.policy = policy or ScanPolicy()
        self.subdomains = subdomains or []
        self.ssl_info = ssl_info or []

    async def _fetch_target(self):
        data = {"headers": {}, "html": "", "headers_server": "", "status": 0}
        # Skip direct target requests in passive-only mode
        if self.policy.passive_only and not self.policy.allow_target_requests:
            return data
        urls = [f"https://{self.domain}", f"https://www.{self.domain}"]
        if self.policy.allow_insecure_http_fallback:
            urls.append(f"http://{self.domain}")
        for url in urls:
            try:
                resp = await _safe_get(self.session, url, timeout=self.timeout)
                if resp:
                    data["status"] = resp.status
                    data["headers"] = dict(resp.headers)
                    data["headers_server"] = resp.headers.get("Server", "")
                    try:
                        text = await resp.text(errors="replace")
                        data["html"] = text[:80000]
                    except Exception:
                        pass
                    break
            except Exception:
                pass
        return data

    def _build_dns_text(self):
        result = {"dns_mx": "", "dns_txt": "", "dns_ns": "", "dns_cname": ""}
        for rec in self.dns_records:
            rtype = rec.get("type", "") if isinstance(rec, dict) else rec.type
            rval = rec.get("value", "") if isinstance(rec, dict) else rec.value
            if rtype == "MX":
                result["dns_mx"] += rval + " "
            elif rtype == "TXT":
                result["dns_txt"] += rval + " "
            elif rtype == "NS":
                result["dns_ns"] += rval + " "
            elif rtype == "CNAME":
                result["dns_cname"] += rval + " "
        return result

    def _dns_based_tech_detection(self, dns_text: dict) -> list:
        """Detect technologies from SPF includes and CNAME patterns."""
        findings = []
        seen = set()
        txt = dns_text.get("dns_txt", "").lower()
        cname = dns_text.get("dns_cname", "").lower()

        # SPF include-based vendor detection
        spf_vendors = [
            ("salesforce.com",      "Salesforce",       "crm"),
            ("hubspot.com",         "HubSpot",          "marketing"),
            ("zendesk.com",         "Zendesk",          "support"),
            ("mailchimp.com",       "Mailchimp",        "email_marketing"),
            ("marketo.com",         "Marketo",          "marketing"),
            ("intercom.io",         "Intercom",         "support"),
            ("intercom.com",        "Intercom",         "support"),
            ("stripe.com",          "Stripe",           "payments"),
            ("twilio.com",          "Twilio",           "communications"),
            ("okta.com",            "Okta",             "auth_sso"),
            ("auth0.com",           "Auth0",            "auth_sso"),
            ("cloudflare.com",      "Cloudflare",       "cdn_waf"),
            ("fastly.com",          "Fastly",           "cdn"),
            ("shopify.com",         "Shopify",          "ecommerce"),
            ("docusign.com",        "DocuSign",         "legal"),
            ("zoom.us",             "Zoom",             "communications"),
            ("slack.com",           "Slack",            "communications"),
            ("atlassian.net",       "Atlassian",        "devops"),
            ("github.com",          "GitHub",           "devops"),
            ("gitlab.com",          "GitLab",           "devops"),
            ("jira",                "Jira",             "devops"),
            ("datadog",             "Datadog",          "monitoring"),
            ("newrelic.com",        "New Relic",        "monitoring"),
            ("sentry.io",           "Sentry",           "monitoring"),
            ("amazonaws.com",       "Amazon SES",       "email_infra"),
            ("sendgrid.com",        "SendGrid",         "email_infra"),
            ("mailgun.com",         "Mailgun",          "email_infra"),
            ("google.com",          "Google Workspace", "email_infra"),
            ("googlemail.com",      "Google Workspace", "email_infra"),
            ("outlook.com",         "Microsoft 365",    "email_infra"),
            ("hotmail.com",         "Microsoft 365",    "email_infra"),
            ("protection.outlook",  "Microsoft 365",    "email_infra"),
            ("proofpoint.com",      "Proofpoint",       "email_security"),
            ("mimecast.com",        "Mimecast",         "email_security"),
            ("barracuda",           "Barracuda",        "email_security"),
        ]
        for keyword, name, category in spf_vendors:
            if keyword in txt and name.lower() not in seen:
                seen.add(name.lower())
                findings.append(TechnologyFinding(
                    name=name, category=category,
                    evidence=f"SPF include: {keyword}",
                    confidence="high", sources=["dns_analysis"]
                ))

        # MX-based detection
        mx = dns_text.get("dns_mx", "").lower()
        mx_vendors = [
            ("google.com",         "Google Workspace", "email_infra"),
            ("googlemail.com",     "Google Workspace", "email_infra"),
            ("outlook.com",        "Microsoft 365",    "email_infra"),
            ("protection.outlook", "Microsoft 365",    "email_infra"),
            ("mimecast.com",       "Mimecast",         "email_security"),
            ("proofpoint.com",     "Proofpoint",       "email_security"),
            ("pphosted.com",       "Proofpoint",       "email_security"),
            ("amazonses.com",      "Amazon SES",       "email_infra"),
            ("mailgun.org",        "Mailgun",          "email_infra"),
            ("sendgrid.net",       "SendGrid",         "email_infra"),
            ("zoho.com",           "Zoho Mail",        "email_infra"),
        ]
        for keyword, name, category in mx_vendors:
            if keyword in mx and name.lower() not in seen:
                seen.add(name.lower())
                findings.append(TechnologyFinding(
                    name=name, category=category,
                    evidence=f"MX record: {keyword}",
                    confidence="high", sources=["dns_analysis"]
                ))

        # CNAME-based CDN detection
        cname_vendors = [
            ("cloudflare.net",      "Cloudflare",           "cdn_waf"),
            ("cloudflare.com",      "Cloudflare",           "cdn_waf"),
            ("akamaiedge.net",      "Akamai",               "cdn_waf"),
            ("edgekey.net",         "Akamai",               "cdn_waf"),
            ("edgesuite.net",       "Akamai",               "cdn_waf"),
            ("akamai.net",          "Akamai",               "cdn_waf"),
            ("llnwd.net",           "Limelight Networks",   "cdn"),
            ("fastly.net",          "Fastly",               "cdn"),
            ("cloudfront.net",      "AWS CloudFront",       "cdn"),
            ("azureedge.net",       "Azure CDN",            "cdn"),
            ("azurefd.net",         "Azure Front Door",     "cdn"),
            ("trafficmanager.net",  "Azure Traffic Manager","cdn"),
            ("github.io",           "GitHub Pages",         "hosting"),
            ("netlify.app",         "Netlify",              "hosting"),
            ("netlify.com",         "Netlify",              "hosting"),
            ("vercel.app",          "Vercel",               "hosting"),
            ("vercel.com",          "Vercel",               "hosting"),
            ("heroku.com",          "Heroku",               "hosting"),
            ("wpengine.com",        "WP Engine",            "hosting"),
            ("pantheon.io",         "Pantheon",             "hosting"),
            ("kinsta.cloud",        "Kinsta",               "hosting"),
            ("ghost.io",            "Ghost",                "cms"),
            ("wixdns.net",          "Wix",                  "cms"),
            ("squarespace.com",     "Squarespace",          "cms"),
            ("myshopify.com",       "Shopify",              "ecommerce"),
            ("zendesk.com",         "Zendesk",              "support"),
        ]
        for keyword, name, category in cname_vendors:
            if keyword in cname and name.lower() not in seen:
                seen.add(name.lower())
                findings.append(TechnologyFinding(
                    name=name, category=category,
                    evidence=f"CNAME: *.{keyword}",
                    confidence="high", sources=["dns_analysis"]
                ))

        # TXT record fingerprints
        txt_vendors = [
            ("google-site-verification",        "Google Workspace",     "email_infra"),
            ("atlassian-domain-verification",   "Atlassian",            "devops"),
            ("docusign=",                        "DocuSign",             "legal"),
            ("stripe-verification=",             "Stripe",               "payments"),
            ("ms=",                              "Microsoft 365",        "email_infra"),
        ]
        for keyword, name, category in txt_vendors:
            if keyword in txt and name.lower() not in seen:
                seen.add(name.lower())
                findings.append(TechnologyFinding(
                    name=name, category=category,
                    evidence=f"TXT record: {keyword}",
                    confidence="medium", sources=["dns_analysis"]
                ))

        # Additional SPF include patterns
        spf_extra = [
            ("include:_spf.google.com",         "Google Workspace",     "email_infra"),
            ("include:amazonses.com",            "AWS SES",              "email_infra"),
            ("include:sendgrid.net",             "SendGrid",             "email_infra"),
            ("include:mailgun.org",              "Mailgun",              "email_infra"),
            ("include:protection.outlook.com",   "Microsoft 365",        "email_infra"),
            ("include:spf.protection.outlook.com","Exchange Online",     "email_infra"),
            ("include:_spf.salesforce.com",      "Salesforce",           "crm"),
            ("include:spf.mandrillapp.com",      "Mandrill",             "email_infra"),
            ("include:mail.zendesk.com",         "Zendesk",              "support"),
            ("include:servers.mcsv.net",         "Mailchimp",            "email_marketing"),
            ("include:spf.hubspot.com",          "HubSpot",              "marketing"),
            ("include:smtp.freshdesk.com",       "Freshdesk",            "support"),
        ]
        for keyword, name, category in spf_extra:
            if keyword in txt and name.lower() not in seen:
                seen.add(name.lower())
                findings.append(TechnologyFinding(
                    name=name, category=category,
                    evidence=f"SPF include: {keyword}",
                    confidence="high", sources=["dns_analysis"]
                ))

        # NS record-based DNS provider detection
        ns = dns_text.get("dns_ns", "").lower()
        ns_vendors = [
            ("cloudflare.com",      "Cloudflare DNS",   "dns"),
            ("awsdns",              "AWS Route53",      "dns"),
            ("azure-dns",           "Azure DNS",        "dns"),
            ("googledomains.com",   "Google DNS",       "dns"),
            ("dnsimple.com",        "DNSimple",         "dns"),
        ]
        for keyword, name, category in ns_vendors:
            if keyword in ns and name.lower() not in seen:
                seen.add(name.lower())
                findings.append(TechnologyFinding(
                    name=name, category=category,
                    evidence=f"NS record: {keyword}",
                    confidence="high", sources=["dns_analysis"]
                ))

        return findings

    def _match_tech(self, name, sig, target_data, dns_text):
        http_text = (
            target_data.get("html", "") +
            " ".join(f"{k}: {v}" for k, v in target_data.get("headers", {}).items()) +
            target_data.get("headers_server", "")
        )
        dns_combined = (
            dns_text.get("dns_mx", "") +
            dns_text.get("dns_txt", "") +
            dns_text.get("dns_ns", "") +
            dns_text.get("dns_cname", "")
        )
        all_text = http_text + dns_combined
        for pattern in sig["patterns"]:
            m = re.search(pattern, all_text, re.I)
            if m:
                evidence = m.group(0)[:120]
                # Determine source: was match in HTTP response or DNS?
                if re.search(pattern, http_text, re.I):
                    source = "header_analysis"
                else:
                    source = "dns_analysis"
                # Extract version number from evidence or headers
                version = ""
                version_m = re.search(r"[/ ](\d+\.\d+[\.\d]*)", evidence)
                if not version_m:
                    # Try Server and X-Powered-By headers directly
                    for hdr_key in ("Server", "X-Powered-By"):
                        hdr_val = target_data.get("headers", {}).get(hdr_key, "")
                        if hdr_val:
                            hm = re.search(r"[/ ](\d+\.\d+[\.\d]*)", hdr_val)
                            if hm:
                                version_m = hm
                                break
                if version_m:
                    version = version_m.group(1)
                return TechnologyFinding(
                    name=name,
                    category=sig["category"],
                    evidence=evidence,
                    confidence="high",
                    sources=[source],
                    version=version,
                )
        return None

    def _cname_based_tech_detection(self, subdomains: list) -> list:
        """Detect CDN/hosting technologies from subdomain CNAME records."""
        cname_tech_map = {
            'akamaiedge.net': ('Akamai CDN', 'cdn'),
            'edgekey.net':    ('Akamai CDN', 'cdn'),
            'cloudflare.net': ('Cloudflare', 'cdn'),
            'fastly.net':     ('Fastly CDN', 'cdn'),
            'cloudfront.net': ('AWS CloudFront', 'cdn'),
            'azureedge.net':  ('Azure CDN', 'cdn'),
            'trafficmanager.net': ('Azure Traffic Manager', 'cloud'),
            'github.io':      ('GitHub Pages', 'hosting'),
            'netlify.app':    ('Netlify', 'hosting'),
            'vercel.app':     ('Vercel', 'hosting'),
            'heroku.com':     ('Heroku', 'hosting'),
            'herokuapp.com':  ('Heroku', 'hosting'),
            'squarespace.com':('Squarespace', 'cms'),
            'shopify.com':    ('Shopify', 'ecommerce'),
            'myshopify.com':  ('Shopify', 'ecommerce'),
            'pantheonsite.io':('Pantheon', 'hosting'),
            'wpengine.com':   ('WP Engine', 'cms'),
            'zendesk.com':    ('Zendesk', 'marketing'),
            'freshdesk.com':  ('Freshdesk', 'marketing'),
            'hubspot.com':    ('HubSpot', 'marketing'),
            'pardot.com':     ('Salesforce Pardot', 'marketing'),
            'marketo.net':    ('Marketo', 'marketing'),
        }
        findings = []
        seen = set()
        for sub in subdomains:
            cnames = sub.get('cname', []) if isinstance(sub, dict) else []
            for cname_val in (cnames or []):
                cname_lower = str(cname_val or '').lower().rstrip('.')
                for suffix, (tech_name, tech_cat) in cname_tech_map.items():
                    if cname_lower.endswith(suffix) and tech_name.lower() not in seen:
                        seen.add(tech_name.lower())
                        findings.append(TechnologyFinding(
                            name=tech_name,
                            category=tech_cat,
                            evidence=f'CNAME: {cname_val}',
                            confidence='high',
                            sources=['cname_analysis'],
                            observation_recency='current_passive',
                            historical_only=False,
                            current_passive=True,
                        ))
        return findings

    def _ssl_based_tech_detection(self, ssl_info: list) -> list:
        findings = []
        seen = set()
        ssl_tech_map = {
            "shopify.com": ("Shopify", "ecommerce"),
            "github.io": ("GitHub Pages", "hosting"),
            "herokuapp.com": ("Heroku", "hosting"),
            "fastly.net": ("Fastly", "cdn"),
            "cloudfront.net": ("AWS CloudFront", "cdn"),
            "pantheonsite.io": ("Pantheon", "hosting"),
        }
        for cert in ssl_info or []:
            if not isinstance(cert, dict):
                continue
            haystacks = [
                str(cert.get("subject", "") or ""),
                str(cert.get("common_name", "") or ""),
                " ".join(str(v or "") for v in (cert.get("san_entries") or [])),
                str(cert.get("issuer", "") or ""),
            ]
            combined = " ".join(haystacks).lower()
            for token, (tech_name, tech_cat) in ssl_tech_map.items():
                if token in combined and tech_name.lower() not in seen:
                    seen.add(tech_name.lower())
                    findings.append(TechnologyFinding(
                        name=tech_name,
                        category=tech_cat,
                        evidence=f"SSL certificate contains {token}",
                        confidence="medium",
                        sources=["ssl_certificate"],
                    ))
        return findings

    def _archive_based_tech_detection(self) -> list:
        archive = self.wayback_urls if isinstance(self.wayback_urls, dict) else {}
        if not archive:
            return []
        findings = []
        seen = set()
        archive_text_parts = []
        for key in ("api_endpoints", "admin_paths", "sensitive_files", "js_files", "titles", "meta_generators"):
            value = archive.get(key, [])
            if isinstance(value, list):
                archive_text_parts.extend(str(v) for v in value[:200])
        for row in archive.get("page_tech_hints", []) or []:
            if isinstance(row, dict):
                archive_text_parts.extend([
                    str(row.get("evidence", "") or ""),
                    str(row.get("title", "") or ""),
                    str(row.get("generator", "") or ""),
                    " ".join(str(s) for s in (row.get("script_urls", []) or [])[:20]),
                ])
        archive_text = "\n".join(archive_text_parts)
        if not archive_text.strip():
            return []

        def add(name: str, category: str, evidence: str, confidence: str = "medium") -> None:
            key = name.lower()
            if key in seen:
                return
            seen.add(key)
            findings.append(TechnologyFinding(
                name=name,
                category=category,
                evidence=normalize_text(evidence[:180]),
                confidence=confidence,
                sources=["archival_passive"],
                observation_recency="archival_passive",
                historical_only=True,
                current_passive=False,
                third_party_context=False,
                first_party=True,
            ))

        archival_patterns = [
            ("AngularJS", "js_framework", [r"angular(?:\.min)?\.js", r"angular\.module\(", r"ng-app", r"ng-controller"], "medium"),
            ("Angular", "js_framework", [r"ng-version", r"angular(?:\.min)?\.js"], "medium"),
            ("React", "js_framework", [r"react(?:\.production)?(?:\.min)?\.js", r"react-dom", r"__REACT"], "medium"),
            ("Vue", "js_framework", [r"vue(?:\.runtime)?(?:\.min)?\.js", r"__vue__"], "medium"),
            ("Next.js", "framework", [r"_next/static", r"__NEXT_DATA__"], "medium"),
            ("Nuxt.js", "framework", [r"_nuxt/", r"__NUXT__"], "medium"),
            ("WordPress", "cms", [r"/wp-content/", r"/wp-includes/", r"meta[^>]+wordpress", r"wp-json"], "medium"),
            ("Drupal", "cms", [r"/sites/default/files/", r"meta[^>]+drupal"], "medium"),
            ("Joomla", "cms", [r"/media/jui/", r"meta[^>]+joomla"], "medium"),
            ("Magento", "cms", [r"/skin/frontend/", r"mage/cookies", r"magento"], "medium"),
            ("Bootstrap", "css_framework", [r"bootstrap(?:\.min)?\.(?:css|js)"], "low"),
            ("jQuery", "js_library", [r"jquery(?:[-.]\d[\d.]*)?\.js"], "low"),
            ("Swagger UI", "api_docs", [r"swagger-ui", r"/swagger", r"/openapi"], "medium"),
            ("GraphQL", "api", [r"/graphql", r"/gql"], "medium"),
            ("Jenkins", "devops", [r"/jenkins", r"jenkins(?:[-.]|$)"], "medium"),
        ]
        for name, category, patterns, confidence in archival_patterns:
            for pattern in patterns:
                match = re.search(pattern, archive_text, re.I)
                if match:
                    add(name, category, match.group(0), confidence)
                    break

        for name, sig in TECH_SIGNATURES.items():
            if name.lower() in seen:
                continue
            for pattern in sig["patterns"]:
                match = re.search(pattern, archive_text, re.I)
                if match:
                    add(name, sig["category"], match.group(0), "low")
                    break
        return findings

    async def _urlscan_tech(self) -> list:
        """Fetch tech stack from URLScan.io indexed results (fully passive)."""
        findings = []
        try:
            url = f"https://urlscan.io/api/v1/search/?q=domain:{self.domain}&size=3"
            resp = await _safe_get(self.session, url, timeout=self.timeout)
            if resp and resp.status == 200:
                data = await resp.json(content_type=None)
                seen = set()
                for result in (data.get("results") or [])[:3]:
                    # Tech from verdicts tags
                    tags = (result.get("verdicts", {}).get("overall", {}).get("tags") or [])
                    for tag in tags:
                        t = str(tag).strip()
                        if t and t.lower() not in seen and len(t) > 1:
                            seen.add(t.lower())
                            findings.append(TechnologyFinding(
                                name=t, category="urlscan_tag",
                                evidence=f"URLScan tag: {t}", confidence="medium",
                                sources=["urlscan"]
                            ))
                    # Tech from page.domain/server
                    page = result.get("page") or {}
                    server = page.get("server") or ""
                    if server and server.lower() not in seen:
                        seen.add(server.lower())
                        findings.append(TechnologyFinding(
                            name=server, category="web_server",
                            evidence=f"URLScan Server header: {server}", confidence="high",
                            sources=["urlscan"]
                        ))
        except Exception:
            pass
        return findings

    async def _urlscan_wappalyzer(self) -> list:
        """Fetch Wappalyzer tech data from URLScan result UUID (fully passive)."""
        findings = []
        try:
            search_url = f"https://urlscan.io/api/v1/search/?q=domain:{self.domain}&size=1"
            resp = await _safe_get(self.session, search_url, timeout=self.timeout)
            if not resp or resp.status != 200:
                return findings
            data = await resp.json(content_type=None)
            results = data.get("results") or []
            if not results:
                return findings
            uuid = (results[0].get("task") or {}).get("uuid") or ""
            if not uuid:
                return findings
            result_url = f"https://urlscan.io/api/v1/result/{uuid}/"
            resp2 = await _safe_get(self.session, result_url, timeout=self.timeout)
            if not resp2 or resp2.status != 200:
                return findings
            result_data = await resp2.json(content_type=None)
            wappa = ((result_data.get("meta") or {}).get("processors") or {}).get("wappa") or {}
            wappa_items = wappa.get("data") or []
            seen = set()
            for item in wappa_items:
                name = str(item.get("app") or item.get("name") or "").strip()
                if not name or name.lower() in seen:
                    continue
                seen.add(name.lower())
                cats = [c.get("name", "") for c in (item.get("categories") or []) if isinstance(c, dict)]
                category = cats[0].lower().replace(" ", "_") if cats else "framework"
                confidence_raw = item.get("confidence") or 0
                try:
                    conf_val = int(confidence_raw)
                except (TypeError, ValueError):
                    conf_val = 0
                confidence = "high" if conf_val >= 75 else "medium" if conf_val >= 40 else "low"
                findings.append(TechnologyFinding(
                    name=name,
                    category=category,
                    evidence=f"URLScan Wappalyzer: {name}" + (f" ({', '.join(cats)})" if cats else ""),
                    confidence=confidence,
                    sources=["urlscan_wappalyzer"],
                ))
        except Exception:
            pass
        return findings

    async def detect(self):
        target_data = await self._fetch_target()
        dns_text = self._build_dns_text()
        findings = []
        seen_names = set()
        for name, sig in TECH_SIGNATURES.items():
            finding = self._match_tech(name, sig, target_data, dns_text)
            if finding:
                findings.append(finding)
                seen_names.add(name.lower())
        # DNS-based technology detection (SPF includes, MX, CNAME)
        dns_findings = self._dns_based_tech_detection(dns_text)
        for f in dns_findings:
            if f.name.lower() not in seen_names:
                findings.append(f)
                seen_names.add(f.name.lower())
        # Passive URLScan tech enrichment (tags + server header)
        urlscan_findings = await self._urlscan_tech()
        for f in urlscan_findings:
            if f.name.lower() not in seen_names:
                findings.append(f)
                seen_names.add(f.name.lower())
        # Passive URLScan Wappalyzer enrichment (full tech fingerprint)
        wappa_findings = await self._urlscan_wappalyzer()
        for f in wappa_findings:
            if f.name.lower() not in seen_names:
                findings.append(f)
                seen_names.add(f.name.lower())
        cname_findings = self._cname_based_tech_detection(self.subdomains)
        for f in cname_findings:
            if f.name.lower() not in seen_names:
                findings.append(f)
                seen_names.add(f.name.lower())
        ssl_findings = self._ssl_based_tech_detection(self.ssl_info)
        for f in ssl_findings:
            if f.name.lower() not in seen_names:
                findings.append(f)
                seen_names.add(f.name.lower())
        archival_findings = self._archive_based_tech_detection()
        for f in archival_findings:
            if f.name.lower() not in seen_names:
                findings.append(f)
                seen_names.add(f.name.lower())
        return findings


# Ã¢â€â‚¬Ã¢â€â‚¬ DNS INTELLIGENCE Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
class DNSIntelligence:
    DOH_ENDPOINTS = [
        "https://cloudflare-dns.com/dns-query",
        "https://dns.google/resolve",
    ]
    RECORD_TYPES = ["A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA", "CAA", "DNSKEY", "DS"]
    DOH_QUERY_TIMEOUTS = {"fast": 4, "balanced": 5, "deep": 15, "turbo": 3}
    QUERY_BUDGETS = {"fast": 16, "balanced": 28, "deep": 42, "turbo": 12}
    DKIM_SELECTOR_CAP = {"fast": 10, "balanced": 18, "deep": 30, "turbo": 8}
    SRV_PREFIX_CAP = {"fast": 8, "balanced": 12, "deep": 18, "turbo": 6}

    def __init__(self, domain, mode, session):
        self.domain = domain
        self.mode = mode
        self.session = session
        self.timeout = TIMEOUTS[mode]
        self._partial_records: List[DNSRecord] = []
        self.stats: Dict[str, Any] = {
            "queries_total": 0,
            "queries_done": 0,
            "timed_out": False,
            "status": "ok",
        }

    def _store_partial(self, records: List[DNSRecord]) -> None:
        dedup: Dict[Tuple[str, str, str], DNSRecord] = {}
        for rec in records:
            if not isinstance(rec, DNSRecord):
                continue
            key = (str(rec.type), str(rec.name), str(rec.value))
            dedup[key] = rec
        self._partial_records = list(dedup.values())

    def get_partial_records(self) -> List[DNSRecord]:
        return list(self._partial_records)

    async def _query_doh(self, qname, qtype):
        per_try_timeout = self.DOH_QUERY_TIMEOUTS.get(self.mode, 5)
        for endpoint in self.DOH_ENDPOINTS:
            try:
                params = {"name": qname, "type": qtype}
                resp = await _safe_get(
                    self.session,
                    endpoint,
                    timeout=per_try_timeout,
                    params=params,
                    headers={"Accept": "application/dns-json", "User-Agent": random.choice(USER_AGENTS)},
                )
                if resp and resp.status == 200:
                    data = await resp.json(content_type=None)
                    answers = data.get("Answer", [])
                    records = []
                    for ans in answers:
                        rdata = str(ans.get("data", "")).strip()
                        records.append(DNSRecord(type=qtype, name=qname, value=rdata, source="doh"))
                    return records
            except Exception:
                continue
        return []

    async def _query_dkim_selectors(self) -> list:
        records = []
        sem = asyncio.Semaphore(20)
        selectors = DKIM_SELECTORS[: self.DKIM_SELECTOR_CAP.get(self.mode, 18)]
        async def check_selector(sel):
            async with sem:
                qname = f"{sel}._domainkey.{self.domain}"
                answers = await self._query_doh(qname, "TXT")
                if answers:
                    return answers
                return []
        tasks = [check_selector(s) for s in selectors]
        batches = await asyncio.gather(*tasks, return_exceptions=True)
        for batch in batches:
            if isinstance(batch, list):
                records.extend(batch)
        return records

    async def _query_srv_records(self) -> list:
        records = []
        prefixes = SRV_PREFIXES[: self.SRV_PREFIX_CAP.get(self.mode, 12)]
        tasks = [self._query_doh(f"{srv}.{self.domain}", "SRV") for srv in prefixes]
        batches = await asyncio.gather(*tasks, return_exceptions=True)
        for batch in batches:
            if isinstance(batch, list):
                records.extend(batch)
        return records

    def _parse_spf(self, spf_val: str) -> dict:
        includes = re.findall(r"include:([^\s]+)", spf_val)
        ip4s = re.findall(r"ip4:([^\s]+)", spf_val)
        ip6s = re.findall(r"ip6:([^\s]+)", spf_val)
        all_mech = re.search(r"[~\-+?]all", spf_val)
        providers = []
        for inc in includes:
            for spf_domain, provider in SPF_PROVIDER_MAP.items():
                if spf_domain in inc:
                    providers.append(provider)
        return {
            "raw": spf_val,
            "includes": includes, "ip4": ip4s, "ip6": ip6s,
            "all_mechanism": all_mech.group(0) if all_mech else "",
            "providers": providers,
        }

    async def _parse_dmarc(self) -> dict:
        answers = await self._query_doh(f"_dmarc.{self.domain}", "TXT")
        for ans in answers:
            val = ans.value if hasattr(ans, "value") else ans.get("data", "")
            if "v=DMARC1" in val:
                tags = {m.group(1): m.group(2).strip() for m in re.finditer(r"(\w+)=([^;]+)", val)}
                p = tags.get("p", "none")
                return {
                    "raw": val, "policy": p,
                    "subdomain_policy": tags.get("sp", ""),
                    "rua": tags.get("rua", ""), "ruf": tags.get("ruf", ""),
                    "pct": tags.get("pct", "100"),
                    "strength": "strong" if p == "reject" else "medium" if p == "quarantine" else "weak",
                }
        return {}

    def _email_security_grade(self, all_records: list) -> str:
        """Compute email security letter grade A-F from SPF/DMARC/DKIM findings."""
        spf_raw = ""
        dmarc_policy = ""
        dkim_found = False
        for rec in all_records:
            rtype = rec.type if hasattr(rec, "type") else rec.get("type", "")
            rval = rec.value if hasattr(rec, "value") else rec.get("value", "")
            if rtype == "TXT" and "v=spf1" in str(rval):
                spf_raw = str(rval)
            if rtype == "TXT" and "v=DMARC1" in str(rval):
                m = re.search(r"\bp=(\w+)", str(rval), re.I)
                if m:
                    dmarc_policy = m.group(1).lower()
            if rtype in ("DKIM", "TXT") and "v=DKIM1" in str(rval):
                dkim_found = True
        spf_all = ""
        if spf_raw:
            m = re.search(r"([~\-+?])all", spf_raw)
            if m:
                spf_all = m.group(1)
        has_spf = bool(spf_raw)
        spf_strict = spf_all == "-"
        spf_permissive = spf_all == "+"
        if dmarc_policy == "reject" and spf_strict and dkim_found:
            return "A"
        if dmarc_policy == "reject" and (spf_strict or dkim_found):
            return "B"
        if dmarc_policy == "quarantine":
            return "B"
        if spf_permissive:
            return "D"
        if dmarc_policy == "none":
            return "C"
        if has_spf and not dmarc_policy:
            return "C"
        if not has_spf and not dmarc_policy:
            return "F"
        return "C"

    def _identify_txt_tokens(self, txt_records: list) -> list:
        tokens = []
        for rec in txt_records:
            val = rec.value if hasattr(rec, "value") else rec.get("value", "")
            for pattern, service in TXT_TOKEN_MAP.items():
                if re.search(pattern, val, re.I):
                    tokens.append({"service": service, "value": val[:120]})
                    break
        return tokens

    async def query(self):
        record_types = self.RECORD_TYPES if self.mode != "fast" else ["A", "AAAA", "CNAME", "MX", "NS", "TXT"]
        tasks: Dict[str, asyncio.Task[Any]] = {}
        for rtype in record_types:
            key = f"apex_{rtype}"
            tasks[key] = asyncio.create_task(self._query_doh(self.domain, rtype))
        tasks["www_a"] = asyncio.create_task(self._query_doh(f"www.{self.domain}", "A"))
        tasks["mail_a"] = asyncio.create_task(self._query_doh(f"mail.{self.domain}", "A"))
        tasks["dmarc_txt"] = asyncio.create_task(self._query_doh(f"_dmarc.{self.domain}", "TXT"))
        if self.mode in ("balanced", "deep"):
            tasks["srv_records"] = asyncio.create_task(self._query_srv_records())
            tasks["dkim_selectors"] = asyncio.create_task(self._query_dkim_selectors())

        self.stats["queries_total"] = len(tasks)
        budget = self.QUERY_BUDGETS.get(self.mode, 25)
        start = time.perf_counter()
        pending = set(tasks.values())
        results_nested: List[Any] = []
        while pending:
            remaining = budget - (time.perf_counter() - start)
            if remaining <= 0:
                self.stats["timed_out"] = True
                self.stats["status"] = "timeout_partial"
                break
            done, pending = await asyncio.wait(
                pending,
                timeout=min(1.5, max(0.1, remaining)),
                return_when=asyncio.FIRST_COMPLETED,
            )
            if not done:
                continue
            for task in done:
                try:
                    results_nested.append(task.result())
                except Exception as exc:
                    results_nested.append(exc)
                self.stats["queries_done"] = int(self.stats.get("queries_done", 0)) + 1

        for task in pending:
            task.cancel()
        for task in pending:
            with contextlib.suppress(asyncio.CancelledError):
                await task

        all_records = []
        seen = set()
        spf_extra = []
        for batch in results_nested:
            if isinstance(batch, Exception):
                continue
            for rec in (batch if isinstance(batch, list) else []):
                if not hasattr(rec, "type"):
                    continue
                # Parse SPF providers from TXT
                if rec.type == "TXT" and rec.value.startswith("v=spf1"):
                    spf_data = self._parse_spf(rec.value)
                    spf_extra.append(DNSRecord(
                        type="SPF_PARSED", name=rec.name,
                        value=json.dumps(spf_data), source="doh"
                    ))
                key = (rec.type, rec.name, rec.value)
                if key not in seen:
                    seen.add(key)
                    all_records.append(rec)
        all_records.extend(spf_extra)

        # Add TXT token identification as metadata records
        txt_recs = [r for r in all_records if r.type == "TXT"]
        tokens = self._identify_txt_tokens(txt_recs)
        for tok in tokens:
            all_records.append(DNSRecord(
                type="TXT_TOKEN", name=self.domain,
                value=f"{tok['service']}: {tok['value'][:80]}", source="doh"
            ))
        # Compute and store email security grade
        email_grade = self._email_security_grade(all_records)
        all_records.append(DNSRecord(
            type="EMAIL_SECURITY_GRADE", name=self.domain,
            value=email_grade, source="computed"
        ))
        self._store_partial(all_records)
        if self.stats.get("status") == "ok" and self.stats.get("timed_out"):
            self.stats["status"] = "timeout_partial"
        return all_records


# Ã¢â€â‚¬Ã¢â€â‚¬ WHOIS INTELLIGENCE Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
class WhoisIntelligence:
    def __init__(self, domain, mode, session):
        self.domain = domain
        self.mode = mode
        self.session = session
        self.timeout = TIMEOUTS[mode]


    async def _whois_fallback(self):
        try:
            ext = _safe_tld_extract(self.domain)
            apex = f"{ext.domain}.{ext.suffix}"
            url = f"https://who.is/whois/{apex}"
            resp = await _safe_get(self.session, url, timeout=self.timeout)
            if resp and resp.status == 200:
                text = await resp.text()
                result = {}
                patterns = {
                    "registrar": r"Registrar:\s*(.+)",
                    "created": r"Creation Date:\s*(.+)",
                    "expires": r"Registry Expiry Date:\s*(.+)",
                    "updated": r"Updated Date:\s*(.+)",
                }
                for key, pat in patterns.items():
                    m = re.search(pat, text, re.I)
                    if m:
                        result[key] = m.group(1).strip()
                result["emails"] = sorted({
                    e.strip().lower()
                    for e in re.findall(r"[A-Za-z0-9._%+\-]+@" + re.escape(apex), text, re.I)
                })
                ns_matches = re.findall(r"Name Server:\s*(.+)", text, re.I)
                result["nameservers"] = [ns.strip().lower() for ns in ns_matches]
                result["source"] = "who.is"
                return result
        except Exception:
            pass
        return {}

    async def _whoiscom_fallback(self):
        """Secondary fallback via whois.com using direct aiohttp."""
        try:
            ext = _safe_tld_extract(self.domain)
            apex = f"{ext.domain}.{ext.suffix}"
            url = f"https://www.whois.com/whois/{apex}"
            conn = aiohttp.TCPConnector(ssl=False)
            timeout = aiohttp.ClientTimeout(total=20)
            async with aiohttp.ClientSession(connector=conn, timeout=timeout) as s:
                async with s.get(url, headers={"User-Agent": "Mozilla/5.0"}) as resp:
                    if resp.status == 200:
                        text = await resp.text()
                        result = {}
                        patterns = {
                            "registrar": r"Registrar:\s*(.+)",
                            "created": r"Creation Date:\s*(.+)",
                            "expires": r"(?:Registrar Registration Expiration Date|Registry Expiry Date):\s*(.+)",
                            "updated": r"Updated Date:\s*(.+)",
                            "registrant": r"Registrant Organization:\s*(.+)",
                        }
                        for key, pat in patterns.items():
                            m = re.search(pat, text, re.I)
                            if m:
                                result[key] = m.group(1).strip()
                        result["emails"] = sorted({
                            e.strip().lower()
                            for e in re.findall(r"[A-Za-z0-9._%+\-]+@" + re.escape(apex), text, re.I)
                        })
                        ns_matches = re.findall(r"Name Server:\s*(.+)", text, re.I)
                        result["nameservers"] = [ns.strip().lower() for ns in ns_matches[:8]]
                        result["source"] = "whois.com"
                        if any(v for k, v in result.items() if k not in ("nameservers", "source")):
                            return result
        except Exception:
            pass
        return {}

    async def _rdap_iana(self):
        """IANA RDAP bootstrap for broader TLD coverage."""
        try:
            ext = _safe_tld_extract(self.domain)
            apex = f"{ext.domain}.{ext.suffix}"
            # Try IANA RDAP bootstrap
            for rdap_url in [f"https://rdap.org/domain/{apex}", f"https://rdap.iana.org/domain/{apex}"]:
                resp = await _safe_get(self.session, rdap_url, timeout=15)
                if resp and resp.status == 200:
                    data = await resp.json(content_type=None)
                    result = {
                        "registrar": "", "created": "", "expires": "",
                        "updated": "", "status": [], "nameservers": [],
                        "registrant": "", "source": "rdap"
                    }
                    for event in data.get("events", []):
                        action = event.get("eventAction", "")
                        date = event.get("eventDate", "")
                        if action == "registration":
                            result["created"] = date
                        elif action == "expiration":
                            result["expires"] = date
                        elif action == "last changed":
                            result["updated"] = date
                    for entity in data.get("entities", []):
                        roles = entity.get("roles", [])
                        vcard = entity.get("vcardArray", [])
                        if "registrar" in roles and vcard:
                            for vcard_item in (vcard[1] if len(vcard) > 1 else []):
                                if vcard_item[0] == "fn":
                                    result["registrar"] = vcard_item[3]
                        if vcard:
                            for vcard_item in (vcard[1] if len(vcard) > 1 else []):
                                if vcard_item[0] == "email" and len(vcard_item) > 3 and isinstance(vcard_item[3], str):
                                    result.setdefault("emails", [])
                                    result["emails"].append(vcard_item[3].strip().lower())
                    result["nameservers"] = [
                        ns.get("ldhName", "").lower() for ns in data.get("nameservers", [])
                    ]
                    result["status"] = [
                        s.get("status", "") if isinstance(s, dict) else str(s)
                        for s in data.get("status", [])
                    ]
                    if isinstance(result.get("emails"), list):
                        result["emails"] = sorted({e for e in result["emails"] if "@" in str(e)})
                    if any(v for k, v in result.items() if k not in ("status", "nameservers", "source") and v):
                        return result
        except Exception:
            pass
        return {}

    async def lookup(self):
        rdap_data, fallback_data, whoiscom_data = await asyncio.gather(
            self._rdap_iana(), self._whois_fallback(), self._whoiscom_fallback(),
            return_exceptions=True
        )
        if isinstance(rdap_data, Exception):
            rdap_data = {}
        if isinstance(fallback_data, Exception):
            fallback_data = {}
        if isinstance(whoiscom_data, Exception):
            whoiscom_data = {}
        # Merge: rdap wins over scraped data for structured fields
        merged = {**whoiscom_data, **fallback_data, **{k: v for k, v in rdap_data.items() if v}}
        # Normalize date aliases
        if merged.get("created") and not merged.get("registration_date"):
            merged["registration_date"] = merged["created"]
        if merged.get("created") and not merged.get("creation_date"):
            merged["creation_date"] = merged["created"]
        if merged.get("expires") and not merged.get("expiration_date"):
            merged["expiration_date"] = merged["expires"]
        # Compute domain_age_days
        if merged.get("creation_date") and not merged.get("domain_age_days"):
            try:
                _m = re.search(r'\d{4}-\d{2}-\d{2}', str(merged["creation_date"]))
                if _m:
                    _dt = datetime.strptime(_m.group(), "%Y-%m-%d")
                    merged["domain_age_days"] = (datetime.now(timezone.utc).replace(tzinfo=None) - _dt).days
            except Exception:
                pass
        # Normalize name_servers alias
        if merged.get("nameservers") and not merged.get("name_servers"):
            merged["name_servers"] = merged["nameservers"]
        if isinstance(merged.get("emails"), list):
            merged["emails"] = sorted({str(e).strip().lower() for e in merged.get("emails", []) if "@" in str(e)})
        return merged


# Ã¢â€â‚¬Ã¢â€â‚¬ IP INTELLIGENCE Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
class IPIntelligence:  # noqa: E302
    CLOUD_KEYWORDS = {
        "AWS": ["amazonaws", "amazon"],
        "Google Cloud": ["google", "googlecloud"],
        "Azure": ["microsoft", "azure"],
        "Cloudflare": ["cloudflare"],
        "Fastly": ["fastly"],
        "Akamai": ["akamai"],
        "DigitalOcean": ["digitalocean"],
        "Hetzner": ["hetzner"],
        "OVH": ["ovh"],
        "Linode": ["linode"],
        "Vultr": ["vultr"],
    }
    CDN_PROVIDERS = {"Cloudflare", "Fastly", "Akamai"}

    def __init__(
        self,
        domain,
        mode,
        session,
        dns_records,
        api_keys: dict = None,
        policy: Optional[ScanPolicy] = None,
        subdomains: Optional[List[Dict[str, Any]]] = None,
    ):
        self.domain = domain
        self.mode = mode
        self.session = session
        self.dns_records = dns_records
        self.api_keys = api_keys or {}
        self.policy = policy or ScanPolicy()
        self.subdomains = subdomains or []
        self.timeout = TIMEOUTS[mode]

    def _collect_ips(self):
        ips = set()
        for rec in self.dns_records:
            rtype = rec.get("type") if isinstance(rec, dict) else rec.type
            rval = rec.get("value") if isinstance(rec, dict) else rec.value
            if rtype in ("A", "AAAA"):
                ip = _normalize_ip_literal(rval)
                if ip:
                    ips.add(ip)
        for sub in self.subdomains:
            if not isinstance(sub, dict):
                continue
            sub_ips = _extract_ip_literals(sub.get("ips") or sub.get("ip_addresses") or sub.get("resolved_ips") or [])
            for ip in sub_ips:
                ips.add(ip)
        return ips

    async def _lookup_ip(self, ip):
        rec = IPRecord(ip=ip)
        try:
            resp = await _safe_get(self.session, f"https://ipinfo.io/{ip}/json", timeout=self.timeout)
            if resp and resp.status == 200:
                data = await resp.json(content_type=None)
                org = data.get("org", "")
                parts = org.split(" ", 1)
                rec.asn = parts[0] if parts else ""
                rec.org = parts[1] if len(parts) > 1 else ""
                rec.country = data.get("country", "")
                rec.city = data.get("city", "")
                rec.rdns = data.get("hostname", "")
        except Exception:
            try:
                policy = getattr(self, "policy", None)
                if policy and policy.allow_insecure_http_fallback:
                    async with _get_ip_api_sem():
                        resp = await _safe_get(
                            self.session,
                            f"http://ip-api.com/json/{ip}?fields=status,country,city,isp,org,as,reverse",
                            timeout=self.timeout
                        )
                        await asyncio.sleep(1.5)  # inside sem: throttle to ≤3 req/1.5s = 45/min
                    if resp and resp.status == 200:
                        data = await resp.json(content_type=None)
                        if data.get("status") == "success":
                            rec.asn = data.get("as", "")
                            rec.org = data.get("org", "") or data.get("isp", "")
                            rec.country = data.get("country", "")
                            rec.city = data.get("city", "")
                            rec.rdns = data.get("reverse", "")
            except Exception:
                pass
        org_lower = rec.org.lower()
        for provider, keywords in self.CLOUD_KEYWORDS.items():
            if any(kw in org_lower for kw in keywords):
                rec.cloud_provider = provider
                break
        # Augment with cloud IP-range detection (more authoritative)
        cloud_prov, cloud_svc = _check_cloud_provider(ip)
        if cloud_prov:
            rec.cloud_provider = cloud_prov
        rec.cdn = rec.cloud_provider in self.CDN_PROVIDERS
        return rec

    async def _shodan_internetdb(self, ip: str) -> dict:
        for attempt in range(3):
            try:
                resp = await _safe_get(self.session, f"https://internetdb.shodan.io/{ip}", timeout=30, ssl=False)
                if resp is None:
                    if attempt < 2:
                        await asyncio.sleep(float(2 ** attempt))
                    continue
                if resp.status in (429, 503):
                    if attempt < 2:
                        await asyncio.sleep(float(2 ** attempt))
                    continue
                if resp.status == 200:
                    data = await resp.json(content_type=None)
                    if isinstance(data, dict):
                        return data
            except Exception:
                if attempt < 2:
                    await asyncio.sleep(float(2 ** attempt))
        return {}

    async def _bgpview_ip(self, ip: str) -> dict:
        try:
            resp = await _safe_get(self.session, f"https://api.bgpview.io/ip/{ip}", timeout=10)
            if resp and resp.status == 200:
                data = await resp.json(content_type=None)
                asns = data.get("data", {}).get("asns", [])
                if asns:
                    return {
                        "asn": asns[0].get("asn", ""),
                        "asn_name": asns[0].get("name", ""),
                        "asn_desc": asns[0].get("description", ""),
                        "rir": data.get("data", {}).get("rir_allocation", {}).get("rir_name", ""),
                    }
        except Exception:
            pass
        return {}

    async def _greynoise(self, ip: str) -> dict:
        try:
            resp = await _safe_get(self.session, f"https://api.greynoise.io/v3/community/{ip}", timeout=10)
            if resp and resp.status == 200:
                data = await resp.json(content_type=None)
                return {
                    "noise": data.get("noise", False),
                    "riot": data.get("riot", False),
                    "classification": data.get("classification", ""),
                    "name": data.get("name", ""),
                }
        except Exception:
            pass
        return {}

    async def _otx_ip(self, ip: str) -> dict:
        try:
            url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general"
            resp = await _safe_get(self.session, url, timeout=10)
            if resp and resp.status == 200:
                data = await resp.json(content_type=None)
                return {
                    "pulse_count": data.get("pulse_info", {}).get("count", 0),
                    "reputation": data.get("reputation", 0),
                    "country": data.get("country_name", ""),
                }
        except Exception:
            pass
        return {}

    async def _abuseipdb(self, ip: str) -> dict:
        return {}

    async def _reverse_dns_doh(self, ip: str) -> str:
        """Reverse DNS lookup via DoH."""
        try:
            parts = ip.split(".")
            if len(parts) == 4:
                reversed_ip = ".".join(reversed(parts))
                answers = await _doh_query(
                    self.session, f"{reversed_ip}.in-addr.arpa", "PTR", timeout=8
                )
                if answers:
                    return answers[0].get("data", "").rstrip(".")
        except Exception:
            pass
        return ""

    async def _hackertarget_reverse_ip(self, ip: str) -> list:
        """Find other domains hosted on the same IP via hackertarget reverse IP lookup."""
        try:
            url = f"https://api.hackertarget.com/reverseiplookup/?q={ip}"
            resp = await _safe_get(self.session, url, timeout=12)
            if resp and resp.status == 200:
                text = await resp.text()
                if "API count exceeded" in text or "error detected" in text.lower():
                    return []
                domains = [
                    line.strip() for line in text.splitlines()
                    if line.strip() and "." in line and not line.startswith("error")
                ]
                return domains[:25]
        except Exception:
            pass
        return []

    async def _enrich_ip_full(self, ip: str) -> IPRecord:
        rec = await self._lookup_ip(ip)
        # Run all enrichments concurrently
        shodan_task = asyncio.create_task(self._shodan_internetdb(ip))
        bgp_task    = asyncio.create_task(self._bgpview_ip(ip))
        gn_task     = asyncio.create_task(self._greynoise(ip))
        abuse_task  = asyncio.create_task(self._abuseipdb(ip))
        rdns_task   = asyncio.create_task(self._reverse_dns_doh(ip))
        otx_task    = asyncio.create_task(self._otx_ip(ip))
        shodan_data, bgp_data, gn_data, abuse_data, rdns, otx_data = await asyncio.gather(
            shodan_task, bgp_task, gn_task, abuse_task, rdns_task, otx_task,
            return_exceptions=True
        )
        # Shodan InternetDB — use 'or []' to handle explicit null fields
        if isinstance(shodan_data, dict) and shodan_data:
            hostnames = shodan_data.get("hostnames") or []
            if hostnames and not rec.rdns:
                rec.rdns = hostnames[0]
            rec.hostnames  = hostnames
            rec.open_ports = shodan_data.get("ports") or []
            rec.vulns      = shodan_data.get("vulns") or []
            rec.cpes       = shodan_data.get("cpes")  or []
            rec.tags       = shodan_data.get("tags")  or []
        # BGPView
        if isinstance(bgp_data, dict) and bgp_data and not rec.asn:
            rec.asn = str(bgp_data.get("asn", ""))
            rec.org = bgp_data.get("asn_name", "") or bgp_data.get("asn_desc", "") or rec.org
        # GreyNoise
        if isinstance(gn_data, dict) and (gn_data.get("noise") or gn_data.get("classification")):
            rec.greynoise = gn_data
        # AbuseIPDB
        if isinstance(abuse_data, dict) and abuse_data:
            rec.abuseipdb = abuse_data
        # Reverse DNS (DoH)
        if isinstance(rdns, str) and rdns and not rec.rdns:
            rec.rdns = rdns
        # OTX AlienVault
        if isinstance(otx_data, dict) and otx_data:
            rec.otx_data = otx_data
        # Reverse IP lookup: other domains on same server (balanced/deep only)
        if self.mode in ("balanced", "deep"):
            try:
                shared = await self._hackertarget_reverse_ip(ip)
                if shared:
                    rec.shared_hosting = shared
            except Exception:
                pass
        return rec

    async def enrich_specific(self, ips: List[str]):
        ip_list = [ip for ip in (_normalize_ip_literal(v) for v in ips) if ip]
        if not ip_list:
            return []
        deduped = list(dict.fromkeys(ip_list))
        sem = asyncio.Semaphore(min(SEMAPHORES[self.mode], 20))
        results: List[IPRecord] = []

        async def limited(ip: str):
            async with sem:
                return await self._enrich_ip_full(ip)

        for start in range(0, len(deduped), 20):
            chunk = deduped[start:start + 20]
            chunk_results = await asyncio.gather(*(limited(ip) for ip in chunk), return_exceptions=True)
            results.extend(r for r in chunk_results if isinstance(r, IPRecord))
            if start + 20 < len(deduped):
                await asyncio.sleep(0.2)
        return results

    async def enrich(self):
        return await self.enrich_specific(list(self._collect_ips()))


# Ã¢â€â‚¬Ã¢â€â‚¬ SSL INTELLIGENCE Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
class SSLIntelligence:
    def __init__(self, domain, mode, session):
        self.domain = domain
        self.mode = mode
        self.session = session
        self.timeout = TIMEOUTS[mode]

    @staticmethod
    def _parse_dt(raw: str) -> Optional[datetime]:
        value = str(raw or "").strip()
        if not value:
            return None
        try:
            dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except Exception:
            return None

    def _is_first_party_host(self, host: str) -> bool:
        norm = normalize_hostname(host or "").lstrip("*.")
        return bool(norm and (norm == self.domain or norm.endswith("." + self.domain)))

    def _is_provider_edge_cert(self, cert: SSLInfo) -> bool:
        provider_tokens = (
            "cloudfront", "cloudflare", "fastly", "akamai", "edgekey", "edgesuite",
            "imperva", "incapsula", "cloudinary", "azureedge", "azurefd", "cdn77",
            "stackpath", "netlify", "vercel", "heroku", "github.io",
        )
        material = " ".join([
            str(cert.subject or ""),
            str(cert.issuer or ""),
            " ".join(str(s or "") for s in (cert.san_entries or [])[:50]),
        ]).lower()
        return any(tok in material for tok in provider_tokens)

    def _annotate_cert(self, cert: SSLInfo) -> SSLInfo:
        hosts = set()
        if cert.subject:
            hosts.add(normalize_hostname(cert.subject).lstrip("*."))
        for san in cert.san_entries or []:
            norm = normalize_hostname(str(san or "")).lstrip("*.")
            if norm:
                hosts.add(norm)
        first_party_hosts = [host for host in hosts if self._is_first_party_host(host)]
        provider_edge = self._is_provider_edge_cert(cert)
        cert.first_party = bool(first_party_hosts)
        cert.third_party_context = bool(provider_edge and (not cert.first_party or len(first_party_hosts) <= max(1, len(hosts) // 2)))
        cert.source_scope = "third_party" if cert.third_party_context else "first_party"
        cert.ownership_confidence = 0.92 if cert.first_party and not cert.third_party_context else 0.38 if cert.third_party_context else 0.62
        if "hsts_preload" in (cert.ct_sources or []):
            cert.current_passive = True
            cert.historical_only = False
            cert.observation_recency = "current_passive"
            return cert
        cert.current_passive = False
        cert.historical_only = True
        cert.observation_recency = "historical_only"
        not_after_dt = self._parse_dt(cert.not_after)
        now = datetime.now(timezone.utc)
        if not_after_dt and not_after_dt >= now and (not_after_dt - now).days <= 45:
            cert.observation_recency = "recent_passive"
        return cert

    async def _crtsh_certs(self):
        certs = []
        try:
            url = f"https://crt.sh/?q=%25.{self.domain}&output=json"
            resp = await _safe_get(self.session, url, timeout=self.timeout)
            if resp and resp.status == 200:
                data = await resp.json(content_type=None)
                seen = set()
                for entry in data[:300]:
                    cn = entry.get("common_name", "")
                    issuer = entry.get("issuer_name", "")
                    not_before = entry.get("not_before", "")
                    not_after = entry.get("not_after", "")
                    sans_raw = entry.get("name_value", "")
                    sans = [s.strip().lstrip("*.") for s in sans_raw.splitlines() if s.strip()]
                    key = cn + not_before
                    if key in seen:
                        continue
                    seen.add(key)
                    expired = False
                    days_left = 0
                    try:
                        exp_dt = datetime.fromisoformat(not_after.replace("Z", "+00:00"))
                        now = datetime.now(exp_dt.tzinfo)
                        days_left = (exp_dt - now).days
                        expired = days_left < 0
                    except Exception:
                        pass
                    certs.append(SSLInfo(
                        subject=cn,
                        issuer=issuer,
                        not_before=not_before,
                        not_after=not_after,
                        san_entries=sans,
                        expired=expired,
                        days_left=days_left,
                        ct_sources=["crt.sh"]
                    ))
        except Exception:
            pass
        return certs

    async def _certspotter_certs(self):
        certs = []
        try:
            url = (f"https://api.certspotter.com/v1/issuances?domain={self.domain}"
                   f"&include_subdomains=true&expand=dns_names&expand=issuer&expand=cert")
            resp = await _safe_get(self.session, url, timeout=self.timeout)
            if resp and resp.status == 200:
                data = await resp.json(content_type=None)
                for entry in data[:100]:
                    dns_names = entry.get("dns_names", [])
                    issuer = entry.get("issuer", {})
                    issuer_str = issuer.get("friendly_name", "") if isinstance(issuer, dict) else str(issuer)
                    not_before = entry.get("not_before", "")
                    not_after = entry.get("not_after", "")
                    cn = dns_names[0] if dns_names else ""
                    days_left = 0
                    expired = False
                    try:
                        exp_dt = datetime.fromisoformat(not_after.replace("Z", "+00:00"))
                        now = datetime.now(exp_dt.tzinfo)
                        days_left = (exp_dt - now).days
                        expired = days_left < 0
                    except Exception:
                        pass
                    certs.append(SSLInfo(
                        subject=cn,
                        issuer=issuer_str,
                        not_before=not_before,
                        not_after=not_after,
                        san_entries=[n.lstrip("*.") for n in dns_names],
                        expired=expired,
                        days_left=days_left,
                        ct_sources=["certspotter"]
                    ))
        except Exception:
            pass
        return certs

    async def _hsts_preload(self) -> dict:
        try:
            ext = _safe_tld_extract(self.domain)
            apex = f"{ext.domain}.{ext.suffix}"
            resp = await _safe_get(self.session, f"https://hstspreload.org/api/v2/status?domain={apex}", timeout=10)
            if resp and resp.status == 200:
                data = await resp.json(content_type=None)
                return {
                    "status": data.get("status", "unknown"),
                    "include_subdomains": data.get("includeSubDomains", False),
                }
        except Exception:
            pass
        return {}

    async def query(self):
        tasks = [self._crtsh_certs()]
        if self.mode in ("balanced", "deep"):
            tasks.append(self._certspotter_certs())
            tasks.append(self._hsts_preload())
        results = await asyncio.gather(*tasks, return_exceptions=True)
        all_certs = []
        for batch in results:
            if isinstance(batch, list):
                all_certs.extend(batch)
            elif isinstance(batch, dict) and batch:
                # HSTS preload result Ã¢â‚¬â€ embed as a synthetic SSLInfo
                all_certs.append(SSLInfo(
                    subject=f"HSTS:{batch.get('status','unknown')}",
                    issuer="hstspreload.org",
                    ct_sources=["hsts_preload"]
                ))
        dedup: Dict[tuple, SSLInfo] = {}
        for cert in all_certs:
            if not isinstance(cert, SSLInfo):
                continue
            norm_subject = normalize_hostname(cert.subject or "").lstrip("*.")
            san_norm = sorted({
                normalize_hostname(str(s or "")).lstrip("*.")
                for s in (cert.san_entries or [])
                if normalize_hostname(str(s or "")).lstrip("*.")
            })
            if norm_subject:
                cert.subject = norm_subject
            cert.san_entries = san_norm
            key = (cert.subject, cert.not_after, tuple(cert.san_entries))
            prev = dedup.get(key)
            if not prev:
                dedup[key] = cert
                continue
            merged_sources = sorted(set((prev.ct_sources or []) + (cert.ct_sources or [])))
            prev.ct_sources = merged_sources
            prev.days_left = max(int(prev.days_left or 0), int(cert.days_left or 0))
            prev.expired = bool(prev.expired and cert.expired)
        out = []
        for cert in dedup.values():
            annotated = self._annotate_cert(cert)
            # Keep cert if: it has a subject matching the target domain, or it's an HSTS entry,
            # or it's a CDN edge cert, or any SAN matches the target domain
            if "hsts_preload" in (annotated.ct_sources or []):
                out.append(annotated)
                continue
            if annotated.first_party or annotated.third_party_context:
                out.append(annotated)
                continue
            # Also keep if subject or any SAN contains target domain (catch wildcard certs)
            check_material = " ".join([
                str(annotated.subject or ""),
                " ".join(str(s) for s in (annotated.san_entries or [])),
            ]).lower()
            if self.domain.lower() in check_material:
                out.append(annotated)
        return out


# Ã¢â€â‚¬Ã¢â€â‚¬ WEB ARCHIVE INTELLIGENCE Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
class WebArchiveIntelligence:
    def __init__(self, domain, mode, session):
        self.domain = domain
        self.mode = mode
        self.session = session
        self.timeout = max(TIMEOUTS[mode], 30)
        self._partial_results: Dict[str, Any] = {
            "all": [],
            "all_urls": [],
            "total_urls": 0,
            "total_retrieved": 0,
            "interesting": [],
            "api_endpoints": [],
            "admin_paths": [],
            "sensitive_files": [],
            "js_files": [],
            "documents": [],
            "js_secrets": [],
            "js_endpoints": [],
            "query_params": [],
            "top_paths": [],
            "sensitive_path_hits": [],
            "titles": [],
            "meta_generators": [],
            "page_tech_hints": [],
            "robots_disallow": [],
            "historical_robots": [],
            "sitemap_urls": [],
            "historical_sitemaps": [],
            "interesting_paths": [],
        }

    def _store_partial_results(self, payload: Dict[str, Any]) -> None:
        current = dict(self._partial_results)
        candidate_all = payload.get("all")
        candidate_all_urls = payload.get("all_urls") if isinstance(payload.get("all_urls"), list) else candidate_all
        try:
            current_total = int(current.get("total_urls", 0) or 0)
        except Exception:
            current_total = 0
        try:
            candidate_total = int(payload.get("total_urls", len(candidate_all) if isinstance(candidate_all, list) else 0) or 0)
        except Exception:
            candidate_total = len(candidate_all) if isinstance(candidate_all, list) else 0
        try:
            candidate_retrieved = int(payload.get("total_retrieved", candidate_total) or 0)
        except Exception:
            candidate_retrieved = candidate_total
        for key, value in (payload or {}).items():
            if key in {"all", "all_urls", "total_urls", "total_retrieved"}:
                continue
            current[key] = copy.deepcopy(value)
        if isinstance(candidate_all, list) and candidate_total >= current_total:
            current["all"] = copy.deepcopy(candidate_all)
            current["all_urls"] = copy.deepcopy(candidate_all_urls if isinstance(candidate_all_urls, list) else candidate_all)
            current["total_urls"] = candidate_total
            current["total_retrieved"] = candidate_retrieved
        self._partial_results = current

    def get_partial_results(self) -> Dict[str, Any]:
        return copy.deepcopy(self._partial_results)

    def _archive_snapshot_payload(self, urls: List[Any]) -> Dict[str, Any]:
        deduped = self._dedupe_wayback_urls(urls)
        serialized = [
            {
                "url": getattr(u, "url", str(u)),
                "timestamp": getattr(u, "timestamp", ""),
                "status_code": getattr(u, "status_code", 0),
                "mime_type": getattr(u, "mime_type", ""),
            }
            for u in deduped
        ]
        total = len(serialized)
        return {
            "all": serialized,
            "all_urls": serialized,
            "total_urls": total,
            "total_retrieved": total,
        }

    def _sanitize_archive_url(self, raw_url: str) -> str:
        raw = normalize_text(str(raw_url or "")).strip()
        if not raw:
            return ""
        lowered = raw.lower()
        # FIXED: preserve archived path/query fidelity so high-volume CDX sources keep distinct public URLs instead of collapsing them during archive dedupe.
        if any(tok in lowered for tok in ("&lt;", "&gt;", "</a", "<a ", "<div", "</div")):
            return ""
        try:
            parsed = urlparse(raw)
        except Exception:
            return ""
        scheme = parsed.scheme.lower()
        if scheme not in {"http", "https"}:
            return ""
        host = normalize_hostname(parsed.hostname or "")
        if not host or not (host == self.domain or host.endswith("." + self.domain)):
            return ""
        netloc = host if not parsed.port else f"{host}:{parsed.port}"
        path = parsed.path or "/"
        if not path.startswith("/"):
            path = "/" + path
        return urlunparse((scheme, netloc, path, "", parsed.query or "", ""))

    def _dedupe_wayback_urls(self, urls: list) -> list:
        dedup: Dict[str, WaybackURL] = {}
        for wu in urls:
            raw = wu.url if hasattr(wu, "url") else str(wu)
            clean = self._sanitize_archive_url(raw)
            if not clean:
                continue
            if clean not in dedup:
                dedup[clean] = WaybackURL(
                    url=clean,
                    timestamp=getattr(wu, "timestamp", ""),
                    status_code=getattr(wu, "status_code", 0),
                    mime_type=getattr(wu, "mime_type", ""),
                )
        return list(dedup.values())

    async def _wayback(self):
        page_limit = 500000
        cdx_timeout = max(self.timeout, 1200 if self.mode == "deep" else 600)
        primary_cdx_urls = [
            f"https://web.archive.org/cdx/search/cdx?url=*.{self.domain}/*"
            f"&output=json&fl=original&collapse=urlkey&limit={page_limit}",
        ]
        fallback_cdx_urls = [
            f"https://web.archive.org/cdx/search/cdx?url=*.{self.domain}/*"
            f"&output=text&fl=original&collapse=urlkey&limit={page_limit}",
            f"https://web.archive.org/cdx/search/cdx?url={self.domain}/*"
            f"&output=json&fl=original&collapse=urlkey&limit={page_limit}",
            f"https://web.archive.org/cdx/search/cdx?url={self.domain}/*"
            f"&output=text&fl=original&collapse=urlkey&limit={page_limit}",
        ]

        async def _fetch_commoncrawl_cdx() -> list:
            out = []
            seen_urls = set()
            try:
                idx_ids = await _commoncrawl_indexes(self.session, "deep" if self.mode == "deep" else self.mode)
                # FIXED: reuse the latest-index helper here so archive CDX queries do not accidentally reverse into stale CommonCrawl indexes.
                indexes = [f"https://index.commoncrawl.org/{idx}-index" for idx in idx_ids[:5]]
            except Exception:
                indexes = [
                    "https://index.commoncrawl.org/CC-MAIN-2026-12-index",
                    "https://index.commoncrawl.org/CC-MAIN-2026-08-index",
                ]

            async def _fetch_one_cc_index(idx_url: str) -> list:
                batch = []
                for pattern in (f"*.{self.domain}/*", f"{self.domain}/*"):
                    url = f"{idx_url}?url={pattern}&output=json&fl=url&limit=100000"
                    try:
                        text, status = await _text_request_with_retries(
                            self.session,
                            "GET",
                            url,
                            timeout=max(self.timeout, 180),
                            retries=2,
                            backoff=1.0,
                            ssl=False,
                        )
                    except Exception:
                        continue
                    if status != 200 or not text:
                        continue
                    for line in text.splitlines():
                        try:
                            obj = json.loads(line)
                        except Exception:
                            continue
                        clean = self._sanitize_archive_url(obj.get("url", ""))
                        if clean and clean not in seen_urls:
                            seen_urls.add(clean)
                            batch.append(WaybackURL(url=clean))
                return batch

            try:
                batches = await asyncio.gather(*(_fetch_one_cc_index(idx) for idx in indexes), return_exceptions=True)
                for batch in batches:
                    if not isinstance(batch, list):
                        continue
                    out.extend(batch)
            except Exception:
                pass
            return out

        async def _fetch_arquivo_pt() -> list:
            out = []
            seen_local = set()
            url = (
                f"https://arquivo.pt/wayback/cdx?url=*.{self.domain}/*"
                f"&output=json&collapse=urlkey&limit=100000"
            )
            try:
                text, status = await _text_request_with_retries(
                    self.session,
                    "GET",
                    url,
                    timeout=max(self.timeout, 120),
                    retries=2,
                    backoff=1.0,
                    ssl=False,
                )
                if status == 200 and text:
                    for line in text.splitlines():
                        line = line.strip()
                        if not line:
                            continue
                        candidate = ""
                        try:
                            obj = json.loads(line)
                        except Exception:
                            continue
                        if isinstance(obj, dict):
                            candidate = str(obj.get("url", "") or "")
                        elif isinstance(obj, list) and obj:
                            candidate = str(obj[0])
                        clean = self._sanitize_archive_url(candidate)
                        if clean and clean not in seen_local:
                            seen_local.add(clean)
                            out.append(WaybackURL(url=clean))
            except Exception:
                pass
            return out

        async def _fetch_json_archive(url: str, *, timeout: int, retries: int = 3, backoff: float = 1.0) -> list:
            out = []
            seen_urls = set()
            try:
                data, status = await _json_request_with_retries(
                    self.session,
                    "GET",
                    url,
                    timeout=timeout,
                    retries=retries,
                    backoff=backoff,
                    headers={"User-Agent": "Mozilla/5.0", "Accept": "application/json"},
                    ssl=False,
                )
                if status != 200 or not isinstance(data, list):
                    return out
                for row in data[1:] if data and isinstance(data[0], list) else data:
                    candidate = row[0] if isinstance(row, list) and row else row.get("original", "") if isinstance(row, dict) else ""
                    clean = self._sanitize_archive_url(candidate)
                    if not clean or clean in seen_urls:
                        continue
                    seen_urls.add(clean)
                    out.append(WaybackURL(url=clean))
            except Exception:
                return out
            return out

        def _rewrite_cdx_url(
            raw_url: str,
            *,
            output: Optional[str] = None,
            limit: Optional[int] = None,
            resume_key: str = "",
            show_resume: bool = False,
        ) -> str:
            parsed = urlsplit(raw_url)
            params = []
            seen_keys = set()
            for key, value in parse_qsl(parsed.query, keep_blank_values=True):
                lk = key.lower()
                if lk in {"offset", "showresumekey", "resumekey"}:
                    continue
                if lk == "output" and output is not None:
                    value = output
                elif lk == "limit" and limit is not None:
                    value = str(limit)
                params.append((key, value))
                seen_keys.add(lk)
            if output is not None and "output" not in seen_keys:
                params.append(("output", output))
            if limit is not None and "limit" not in seen_keys:
                params.append(("limit", str(limit)))
            if show_resume:
                params.append(("showResumeKey", "true"))
            if resume_key:
                params.append(("resumeKey", resume_key))
            return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, urlencode(params, doseq=True), parsed.fragment))

        def _add_text_rows(text: str, seen_urls: set, out: list) -> tuple[int, str]:
            page_rows = 0
            resume_key = ""
            lines = text.splitlines()
            if lines:
                last_line = lines[-1].strip()
                if last_line and not last_line.startswith(("http://", "https://")):
                    resume_key = last_line
                    lines = lines[:-1]
                    if lines and not lines[-1].strip():
                        lines = lines[:-1]
            for line in lines:
                clean = self._sanitize_archive_url(line)
                if not clean or clean in seen_urls:
                    continue
                seen_urls.add(clean)
                out.append(WaybackURL(url=clean))
                page_rows += 1
            return page_rows, resume_key

        def _add_json_rows(data: Any, seen_urls: set, out: list) -> int:
            page_rows = 0
            if not (isinstance(data, list) and len(data) >= 2):
                return 0
            for row in data[1:]:
                if not (isinstance(row, list) and row and isinstance(row[0], str)):
                    continue
                clean = self._sanitize_archive_url(row[0])
                if not clean or clean in seen_urls:
                    continue
                seen_urls.add(clean)
                out.append(WaybackURL(url=clean))
                page_rows += 1
            return page_rows

        async def _fetch_cdx(cdx_url: str) -> list:
            out = []
            seen_urls = set()
            text_mode = "&output=text" in cdx_url
            first_page_empty_retries = 2
            used_resume_fallback = False
            max_resume_pages = {"fast": 2, "balanced": 6, "deep": 12, "turbo": 1}.get(self.mode, 4)
            resume_pages_fetched = 0
            page_url = cdx_url
            empty_first_page_attempts = 0
            if self.mode in {"balanced", "deep"} and not text_mode:
                # FIXED: prefer Wayback text+resume pagination in balanced/deep mode because large JSON CDX queries truncate or stall on high-volume domains.
                page_url = _rewrite_cdx_url(cdx_url, output="text", limit=50000, show_resume=True)
                text_mode = True
                used_resume_fallback = True
            while True:
                page_rows = 0
                status = 0
                resume_key = ""
                try:
                    if text_mode:
                        text, status = await _text_request_with_retries(
                            self.session,
                            "GET",
                            page_url,
                            timeout=cdx_timeout,
                            retries=3,
                            backoff=1.0,
                            ssl=False,
                        )
                        if status == 200 and text:
                            page_rows, resume_key = _add_text_rows(text, seen_urls, out)
                    else:
                        data, status = await _json_request_with_retries(
                            self.session,
                            "GET",
                            page_url,
                            timeout=cdx_timeout,
                            retries=3,
                            backoff=1.0,
                            ssl=False,
                        )
                        if status == 200:
                            page_rows = _add_json_rows(data, seen_urls, out)
                except Exception:
                    status = 0

                if status == 200 and page_rows > 0:
                    if used_resume_fallback:
                        resume_pages_fetched += 1
                    if resume_key:
                        if used_resume_fallback and resume_pages_fetched >= max_resume_pages:
                            break
                        page_url = _rewrite_cdx_url(page_url, output="text", limit=50000, resume_key=resume_key, show_resume=True)
                        text_mode = True
                        used_resume_fallback = True
                        await asyncio.sleep(0.35)
                        continue
                    break

                if not used_resume_fallback and (status in {0, 408, 429, 500, 502, 503, 504} or (status == 200 and page_rows == 0)):
                    used_resume_fallback = True
                    page_url = _rewrite_cdx_url(cdx_url, output="text", limit=50000, show_resume=True)
                    text_mode = True
                    empty_first_page_attempts = 0
                    await asyncio.sleep(1.0)
                    continue

                if page_rows == 0 and not out and empty_first_page_attempts < first_page_empty_retries:
                    empty_first_page_attempts += 1
                    await asyncio.sleep(3.0)
                    continue
                break
            return out

        ukwa_url = (
            f"https://www.webarchive.org.uk/wayback/archive/cdx?url=*.{self.domain}/*"
            f"&output=json&fl=original&limit=50000"
        )
        tasks = [asyncio.create_task(_fetch_cdx(cdx_url)) for cdx_url in primary_cdx_urls]
        tasks.extend(asyncio.create_task(_fetch_cdx(cdx_url)) for cdx_url in fallback_cdx_urls)
        tasks.append(asyncio.create_task(_fetch_commoncrawl_cdx()))
        tasks.append(asyncio.create_task(_fetch_arquivo_pt()))
        tasks.append(asyncio.create_task(_fetch_json_archive(ukwa_url, timeout=max(self.timeout, 60), retries=3)))
        timeout_budget = {"fast": 300, "balanced": 900, "deep": 1500, "turbo": 240}.get(self.mode, 900)
        # FIXED: amazon.com archive = 0 — preserve completed CDX batches when one long-running archive branch exceeds the shared wait budget.
        urls = []
        try:
            for done_task in asyncio.as_completed(tasks, timeout=timeout_budget):
                try:
                    batch = await done_task
                except Exception:
                    continue
                if isinstance(batch, list) and batch:
                    urls.extend(batch)
                    self._store_partial_results(self._archive_snapshot_payload(urls))
        except asyncio.TimeoutError:
            pass
        finally:
            for task in tasks:
                if not task.done():
                    task.cancel()
            if tasks:
                await asyncio.gather(*tasks, return_exceptions=True)
        return self._dedupe_wayback_urls(urls)

    async def _commoncrawl(self):
        urls = []
        try:
            limit = 100000
            indexes = await _commoncrawl_indexes(self.session, "deep" if self.mode == "deep" else self.mode)
            seen = set()
            for idx in indexes:
                for pattern in (f"*.{self.domain}/*", f"{self.domain}/*"):
                    url = (f"https://index.commoncrawl.org/{idx}-index?"
                           f"url={pattern}&output=json&limit={limit}&fl=url,timestamp,status")
                    text = await _safe_get_text_cached(self.session, url, timeout=max(self.timeout, 180))
                    if not text:
                        continue
                    for line in text.splitlines():
                        try:
                            obj = json.loads(line)
                            clean = self._sanitize_archive_url(obj.get("url", ""))
                            if not clean or clean in seen:
                                continue
                            seen.add(clean)
                            urls.append(WaybackURL(
                                url=clean,
                                timestamp=obj.get("timestamp", ""),
                                status_code=int(obj.get("status", 0)) if str(obj.get("status", "")).isdigit() else 0
                            ))
                        except Exception:
                            pass
        except Exception:
            pass
        return urls

    def _interesting_urls(self, urls):
        interesting_patterns = [
            r"\.env", r"\.git", r"admin", r"backup", r"\.bak",
            r"config", r"debug", r"test", r"dev", r"staging",
            r"api/", r"swagger", r"graphql", r"phpinfo", r"wp-admin",
            r"login", r"dashboard", r"internal", r"secret", r"password",
            r"\.sql", r"\.xml", r"\.json", r"\.yaml", r"\.yml",
            r"\.log", r"\.csv", r"\.xls", r"\.pdf"
        ]
        flagged = []
        for wu in urls:
            if not getattr(wu, "url", ""):
                continue
            for pat in interesting_patterns:
                if re.search(pat, wu.url, re.I):
                    flagged.append(wu)
                    break
        return flagged

    @staticmethod
    def _archive_url_profile(raw_url: str):
        raw = str(raw_url or "").strip()
        path = "/"
        host = ""
        try:
            parsed = urlparse(raw if raw.startswith("http") else f"https://placeholder{raw}")
            host = normalize_hostname(parsed.hostname or "")
            path = (parsed.path or path).strip() or "/"
        except Exception:
            path = raw.split("?", 1)[0].strip() or "/"
        clean_path = path.split("?", 1)[0] or "/"
        lowered = f"{host}{clean_path}".lower()
        ext = Path(clean_path).suffix.lower()
        return clean_path, lowered, ext

    @classmethod
    def _is_low_value_archive_url(cls, raw_url: str) -> bool:
        path, lowered, ext = cls._archive_url_profile(raw_url)
        if any(token in lowered for token in (
            "/api", "/graphql", "/gql", "/admin", "/auth", "/oauth", "/login", "/sso",
            "/console", "/manager", "/portal", "/internal", "/debug", "/metrics",
            "/health", "/actuator", "/swagger", "/openapi", "/webhook", "/gateway",
            "config", "settings", "backup", "dump", "secret", "token", "password",
            "credential", ".env", ".bak", ".old", ".sql", ".db", ".dump", ".log",
            ".zip", ".tar", ".gz", ".map",
        )):
            return False
        if ext in {".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".css", ".woff", ".woff2"}:
            return True
        if any(path.startswith(prefix) for prefix in ("/static/", "/assets/", "/images/", "/fonts/")):
            return True
        if path in {"", "/", "/index.html", "/favicon.ico"}:
            return True
        return False

    @classmethod
    def _has_interesting_archive_signal(cls, raw_url: str) -> bool:
        if cls._is_low_value_archive_url(raw_url):
            return False
        _, lowered, ext = cls._archive_url_profile(raw_url)
        if ext in {".env", ".bak", ".old", ".backup", ".sql", ".db", ".dump", ".log", ".zip", ".tar", ".gz", ".tgz", ".map"}:
            return True
        return any(token in lowered for token in (
            "/download", "/upload", "/export", "/import", "/backup", "/logs",
            "/config", "/settings", "/debug", "/metrics", "/health", "/actuator",
            "/console", "/manager", "/portal", "/internal", "/private",
            "/repo", "/artifact", "/build", "/jenkins",
        ))

    async def _robots_txt_history(self) -> list:
        paths = []
        try:
            url = f"https://web.archive.org/cdx/search/cdx?url={self.domain}/robots.txt&output=json&limit=5&fl=timestamp"
            resp = await _safe_get(self.session, url, timeout=self.timeout)
            if resp and resp.status == 200:
                data = await resp.json(content_type=None)
                for row in data[1:]:
                    ts = row[0] if row else ""
                    archive_url = f"https://web.archive.org/web/{ts}/{self.domain}/robots.txt"
                    r2 = await _safe_get(self.session, archive_url, timeout=self.timeout)
                    if r2 and r2.status == 200:
                        text = await r2.text()
                        for m in re.finditer(r"Disallow:\s*(.+)", text, re.I):
                            paths.append(m.group(1).strip())
        except Exception:
            pass
        return list(set(paths))

    async def _sitemap_history(self) -> list:
        urls = []
        try:
            url = f"https://web.archive.org/cdx/search/cdx?url={self.domain}/sitemap.xml&output=json&limit=3&fl=timestamp"
            resp = await _safe_get(self.session, url, timeout=self.timeout)
            if resp and resp.status == 200:
                data = await resp.json(content_type=None)
                for row in data[1:4]:
                    ts = row[0] if row else ""
                    archive_url = f"https://web.archive.org/web/{ts}/{self.domain}/sitemap.xml"
                    r2 = await _safe_get(self.session, archive_url, timeout=self.timeout)
                    if r2 and r2.status == 200:
                        text = await r2.text()
                        urls.extend(re.findall(r"<loc>([^<]+)</loc>", text))
        except Exception:
            pass
        return list(dict.fromkeys(urls))[:300]

    def _categorize_urls(self, urls: list) -> dict:
        """Categorize archived URLs into api_endpoints, admin_paths, sensitive_files, js_files, documents."""
        api_re = re.compile(
            r'/(api|v\d+|rest|graphql|gql|rpc|ws|webhook|endpoint|swagger|openapi|gateway|soap)(/|$)'
            r'|//(?:api|gateway|rest|graphql|gql|ws)\.',
            re.I
        )
        admin_re = re.compile(
            r'/(admin|administrator|dashboard|panel|manage|wp-admin|cpanel|phpmyadmin|'
            r'control|backend|cms|console|manager|portal|superuser|staff|backoffice|'
            r'siteadmin|controlpanel|webadmin|adm|myadmin|login|signin|sign-in|sso|auth|oauth)(/|$|\?)',
            re.I
        )
        sensitive_re = re.compile(
            r'\.(env|git|sql|bak|backup|config|cfg|yml|yaml|ini|htaccess|htpasswd|'
            r'pem|key|pfx|p12|crt|csr|private|shadow|passwd|aws|credentials|'
            r'dockercfg|npmrc|netrc|pyc|DS_Store)$'
            r'|/(phpinfo|phpmyadmin|\.git/config|\.git/HEAD|\.svn/|\.hg/|'
            r'wp-config\.php|config\.php|database\.yml|secrets\.yml|'
            r'__pycache__|dump\.sql|backup\.tar|backup\.zip|robots\.txt|sitemap\.xml|'
            r'\.well-known/security\.txt|openapi\.json|swagger\.json)',
            re.I
        )
        js_re = re.compile(r'\.(js|jsx|mjs|ts|tsx|map)(\?|$)', re.I)
        doc_re = re.compile(r'\.(pdf|docx?|xlsx?|pptx?|csv|txt|odt|ods|rtf)(\?|$)', re.I)

        api_eps, admin_ps, sens_fs, js_fs, doc_fs, interesting_ps = [], [], [], [], [], []
        seen: dict[str, set] = {
            "api": set(), "admin": set(), "sens": set(), "js": set(), "doc": set(), "interesting": set()
        }

        for wu in urls:
            raw = wu.url if hasattr(wu, "url") else str(wu)
            ts = getattr(wu, "timestamp", "") or ""
            no_qs = raw.split('?')[0]
            lower = no_qs.lower()

            matched = False
            if api_re.search(lower) and raw not in seen["api"]:
                seen["api"].add(raw)
                api_eps.append(raw)
                matched = True
            if admin_re.search(lower) and raw not in seen["admin"]:
                seen["admin"].add(raw)
                admin_ps.append(raw)
                matched = True
            if sensitive_re.search(lower) and raw not in seen["sens"]:
                seen["sens"].add(raw)
                sens_fs.append(raw)
                matched = True
            if js_re.search(lower) and raw not in seen["js"]:
                seen["js"].add(raw)
                js_fs.append(raw)
                matched = True
            if doc_re.search(lower) and raw not in seen["doc"]:
                seen["doc"].add(raw)
                doc_fs.append(raw)
                matched = True
            if not matched and self._has_interesting_archive_signal(raw) and raw not in seen["interesting"]:
                seen["interesting"].add(raw)
                interesting_ps.append({"url": raw, "path": no_qs, "timestamp": ts})

        return {
            "api_endpoints": api_eps[:500],
            "admin_paths": admin_ps[:200],
            "sensitive_files": sens_fs[:500],
            "js_files": js_fs[:1000],
            "documents": doc_fs[:500],
            "interesting_paths": interesting_ps[:2000],
        }

    def _top_paths(self, urls: list) -> list:
        counts: Counter = Counter()
        for wu in urls:
            raw = wu.url if hasattr(wu, "url") else str(wu)
            try:
                parsed = urlparse(raw)
                path = (parsed.path or "/").strip()
            except Exception:
                path = "/"
            if not path:
                path = "/"
            if len(path) > 160:
                path = path[:160]
            counts[path] += 1
        return [{"path": p, "count": c} for p, c in counts.most_common(30)]

    def _archive_query_params(self, urls: list) -> list:
        counts: Counter = Counter()
        high_risk_keys = {
            "access_token", "api_key", "auth", "callback", "code", "key", "password",
            "redirect", "redirect_uri", "return", "returnto", "secret", "state", "token",
        }
        medium_risk_keys = {"continue", "email", "file", "next", "url", "user", "username"}
        low_risk_keys = {"id"}
        for wu in urls:
            raw = wu.url if hasattr(wu, "url") else str(wu)
            try:
                for key, _ in parse_qsl(urlparse(raw).query or "", keep_blank_values=True):
                    norm_key = normalize_text(str(key or "")).strip().lower()
                    if not norm_key or len(norm_key) > 40 or not re.fullmatch(r"[a-z0-9_.-]+", norm_key):
                        continue
                    counts[norm_key] += 1
            except Exception:
                continue
        ranked = sorted(
            counts.items(),
            key=lambda item: (
                0 if item[0] in high_risk_keys else 1 if item[0] in medium_risk_keys else 2 if item[0] in low_risk_keys else 3,
                -item[1],
                item[0],
            ),
        )
        return [
            {
                "name": key,
                "count": count,
                "suspicious": key in high_risk_keys or key in medium_risk_keys or key in low_risk_keys,
            }
            for key, count in ranked[:40]
        ]

    def _archive_api_profiles(self, urls: list) -> list:
        seen = set()
        profiles = []
        for wu in urls:
            raw = wu.url if hasattr(wu, "url") else str(wu)
            try:
                parsed = urlparse(raw)
            except Exception:
                continue
            path = parsed.path or "/"
            if not re.search(r"/api/|/v\d+/|/graphql|/rest|/swagger|/openapi", path, re.I):
                continue
            key = (normalize_hostname(parsed.hostname or ""), path)
            if key in seen:
                continue
            seen.add(key)
            profiles.append({
                "url": raw,
                "path": path,
                "host": normalize_hostname(parsed.hostname or ""),
                "query_params": sorted({k.lower() for k, _ in parse_qsl(parsed.query or "", keep_blank_values=True) if k})[:10],
            })
            if len(profiles) >= 80:
                break
        return profiles

    def _sensitive_path_hits(self, urls: list) -> list:
        patterns = [
            ("env", r"\.env"),
            ("backup", r"\.(bak|backup|old|swp)$"),
            ("admin", r"/(admin|dashboard|panel|cpanel)"),
            ("api", r"/(api|graphql|swagger|openapi|gql|rest)"),
            ("secrets", r"(token|secret|password|credential|key=)"),
        ]
        hits = []
        for wu in urls:
            raw = wu.url if hasattr(wu, "url") else str(wu)
            for tag, pat in patterns:
                if re.search(pat, raw, re.I):
                    hits.append({
                        "url": raw,
                        "tag": tag,
                        "severity": "LOW" if tag in {"admin", "api"} else "MEDIUM",
                        "classification": "hint",
                        "evidence": "path_pattern_from_archive_index",
                        "source": "wayback/commoncrawl_index",
                    })
                    break
        return hits[:120]

    def _archive_candidate_score(self, raw_url: str, *, kind: str) -> float:
        lowered = str(raw_url or "").lower()
        try:
            parsed = urlparse(raw_url)
            path = (parsed.path or "/").lower()
            host = normalize_hostname(parsed.hostname or "")
        except Exception:
            path = lowered
            host = ""
        score = 0.0
        if host == self.domain:
            score += 3.5
        elif host == f"www.{self.domain}":
            score += 3.0
        elif host.endswith("." + self.domain):
            score += 2.0
        if kind == "js":
            if any(tok in path for tok in ("app", "main", "api", "auth", "admin", "graphql", "openapi", "swagger")):
                score += 5.2
            if any(tok in path for tok in ("bundle", "chunk")):
                score += 4.1
            if "vendor" in path:
                score += 2.2
            if lowered.endswith(".map"):
                score += 2.5
            if "swagger" in path or "openapi" in path:
                score += 2.0
            if any(tok in path for tok in ("/static/", "/dist/", "/lib/", "/vendor/")):
                score -= 0.8
        else:
            if path in {"/", "/index.html"}:
                score += 2.0
            if any(tok in path for tok in ("/login", "/auth", "/oauth", "/sso", "/admin", "/api", "/graphql", "/dashboard", "/portal", "/console", "/swagger", "/openapi", "/robots.txt", "/sitemap.xml")):
                score += 6.0
            if any(ext in path for ext in (".json", ".yaml", ".yml", ".env", ".xml")):
                score += 2.0
        score -= min(2.5, path.count("/") * 0.15)
        return score

    def _select_archived_urls(self, urls: list, *, kind: str, limit: int) -> list:
        scored = []
        seen = set()
        for wu in urls:
            raw = getattr(wu, "url", "")
            ts = getattr(wu, "timestamp", "")
            if not raw or (raw, ts) in seen:
                continue
            seen.add((raw, ts))
            if kind == "js":
                if not re.search(r"\.(js|mjs|jsx|ts|tsx|map)(\?|$)", raw, re.I):
                    continue
            else:
                if re.search(r"\.(js|mjs|css|png|jpg|jpeg|gif|svg|woff2?|pdf|zip|tar|gz)(\?|$)", raw, re.I):
                    continue
            scored.append((self._archive_candidate_score(raw, kind=kind), raw, ts))
        scored.sort(key=lambda item: (-item[0], str(item[2]), str(item[1])))
        return [(raw, ts) for _, raw, ts in scored[:limit]]

    @staticmethod
    def _mask_secret_value(value: str) -> str:
        raw = str(value or "").strip()
        if len(raw) <= 8:
            return "*" * len(raw)
        return f"{raw[:4]}...{raw[-4:]}"

    def _extract_js_artifacts(self, text: str, original_url: str, archive_url: str) -> tuple[list, list]:
        if not text:
            return [], []
        secrets = []
        seen_secret_keys = set()
        for secret_type, pattern in CRED_PATTERNS.items():
            for match in pattern.finditer(text):
                value = match.group(1) if pattern.groups else match.group(0)
                value = str(value or "").strip()
                if not value:
                    continue
                key = (secret_type, value)
                if key in seen_secret_keys:
                    continue
                seen_secret_keys.add(key)
                conf = 0.93 if secret_type in {"AWS_KEY", "Google_API", "Slack_Token", "Stripe_Live", "Private_Key"} else 0.72
                secrets.append({
                    "secret_type": secret_type,
                    "match_preview": self._mask_secret_value(value),
                    "location": original_url,
                    "archive_url": archive_url,
                    "source": "wayback_js",
                    "classification": "potential_secret",
                    "confidence": conf,
                    "evidence": normalize_text(match.group(0)[:160]),
                })

        endpoint_re = re.compile(
            r'(?:"|\')('
            r'(?:https?://[A-Za-z0-9._:-]+(?:/[^"\']{0,180})?)'
            r'|(?:/(?:api|graphql|gql|admin|internal|debug|auth|oauth|login|v\d+)[^"\']{0,180})'
            r')(?:"|\')',
            re.I,
        )
        endpoints = []
        seen_endpoint_keys = set()
        for match in endpoint_re.finditer(text):
            candidate = str(match.group(1) or "").strip()
            if not candidate:
                continue
            category = "api"
            lowered = candidate.lower()
            if any(tok in lowered for tok in ("/admin", "/login", "/oauth", "/auth")):
                category = "auth"
            elif any(tok in lowered for tok in ("/debug", "/internal")):
                category = "internal"
            elif "graphql" in lowered or "/gql" in lowered:
                category = "graphql"
            host = ""
            path = candidate
            if candidate.startswith("http"):
                try:
                    parsed = urlparse(candidate)
                    host = normalize_hostname(parsed.hostname or "")
                    if host and not (host == self.domain or host.endswith("." + self.domain)):
                        continue
                    path = parsed.path or "/"
                except Exception:
                    continue
            key = (host or self.domain, path)
            if key in seen_endpoint_keys:
                continue
            seen_endpoint_keys.add(key)
            endpoints.append({
                "url": candidate,
                "host": host or self.domain,
                "path": path,
                "category": category,
                "source": "wayback_js",
                "classification": "passive",
                "confidence": 0.7 if candidate.startswith("http") else 0.62,
                "evidence": normalize_text(original_url[:180]),
            })
        return secrets[:20], endpoints[:40]

    def _extract_page_artifacts(self, html: str, original_url: str, archive_url: str) -> dict:
        if not html:
            return {}
        title = ""
        generator = ""
        script_urls: List[str] = []
        tech_hints: List[Dict[str, Any]] = []
        try:
            soup = BeautifulSoup(html[:250000], "html.parser")
            if soup.title and soup.title.string:
                title = normalize_text(soup.title.string)[:160]
            gen = soup.find("meta", attrs={"name": re.compile(r"generator", re.I)})
            if gen:
                generator = normalize_text(gen.get("content", ""))[:160]
            for script in soup.find_all("script", src=True):
                src = normalize_text(script.get("src", ""))
                if src:
                    script_urls.append(src[:180])
            hint_text = "\n".join([title, generator, " ".join(script_urls), html[:40000]])
            for name, sig in TECH_SIGNATURES.items():
                for pattern in sig["patterns"]:
                    match = re.search(pattern, hint_text, re.I)
                    if match:
                        tech_hints.append({
                            "name": name,
                            "category": sig["category"],
                            "evidence": normalize_text(match.group(0)[:160]),
                            "confidence": "medium" if generator or script_urls else "low",
                            "source": "wayback_html",
                            "url": original_url,
                            "archive_url": archive_url,
                            "observation_recency": "archival_passive",
                            "historical_only": True,
                            "current_passive": False,
                            "first_party": True,
                        })
                        break
        except Exception:
            return {}
        return {
            "title": title,
            "generator": generator,
            "script_urls": script_urls[:30],
            "tech_hints": tech_hints[:20],
        }

    async def _inspect_archived_js(self, urls: list) -> tuple[list, list]:
        js_limit = {"fast": 3, "balanced": 7, "deep": 14, "turbo": 2}.get(self.mode, 3)
        candidates = self._select_archived_urls(urls, kind="js", limit=js_limit)
        if not candidates:
            return [], []

        async def _fetch_and_extract(original_url: str, timestamp: str) -> tuple[list, list]:
            archive_url = f"https://web.archive.org/web/{timestamp}if_/{original_url}"
            try:
                text = await _safe_get_text_cached(self.session, archive_url, timeout=min(self.timeout, 20))
                if not text:
                    return [], []
                return self._extract_js_artifacts(text[:250000], original_url, archive_url)
            except Exception:
                return [], []

        batches = await asyncio.gather(*[_fetch_and_extract(url, ts) for url, ts in candidates], return_exceptions=True)
        secrets = []
        endpoints = []
        seen_secret = set()
        seen_endpoint = set()
        for batch in batches:
            if not (isinstance(batch, tuple) and len(batch) == 2):
                continue
            sec_rows, ep_rows = batch
            for row in sec_rows:
                key = (row.get("secret_type", ""), row.get("match_preview", ""), row.get("location", ""))
                if key in seen_secret:
                    continue
                seen_secret.add(key)
                secrets.append(row)
            for row in ep_rows:
                key = (row.get("host", ""), row.get("path", ""))
                if key in seen_endpoint:
                    continue
                seen_endpoint.add(key)
                endpoints.append(row)
        return secrets[:50], endpoints[:80]

    async def _inspect_archived_pages(self, urls: list) -> dict:
        page_limit = {"fast": 2, "balanced": 5, "deep": 10, "turbo": 2}.get(self.mode, 2)
        candidates = self._select_archived_urls(urls, kind="page", limit=page_limit)
        if not candidates:
            return {"titles": [], "meta_generators": [], "page_tech_hints": []}

        async def _fetch_page(original_url: str, timestamp: str) -> dict:
            archive_url = f"https://web.archive.org/web/{timestamp}if_/{original_url}"
            try:
                text = await _safe_get_text_cached(self.session, archive_url, timeout=min(self.timeout, 20))
                if not text:
                    return {}
                return self._extract_page_artifacts(text, original_url, archive_url)
            except Exception:
                return {}

        results = await asyncio.gather(*[_fetch_page(url, ts) for url, ts in candidates], return_exceptions=True)
        titles: List[str] = []
        generators: List[str] = []
        tech_hints: List[Dict[str, Any]] = []
        seen_titles = set()
        seen_gens = set()
        seen_hints = set()
        for item in results:
            if not isinstance(item, dict):
                continue
            title = str(item.get("title", "") or "")
            if title and title not in seen_titles:
                seen_titles.add(title)
                titles.append(title)
            generator = str(item.get("generator", "") or "")
            if generator and generator not in seen_gens:
                seen_gens.add(generator)
                generators.append(generator)
            for hint in item.get("tech_hints", []) or []:
                key = (hint.get("name", ""), hint.get("evidence", ""))
                if key in seen_hints:
                    continue
                seen_hints.add(key)
                tech_hints.append(hint)
        return {
            "titles": titles[:20],
            "meta_generators": generators[:10],
            "page_tech_hints": tech_hints[:40],
        }

    async def mine(self):
        tasks: List[asyncio.Task] = []

        async def _named(role: str, coro):
            return role, await coro

        def _add(role: str, coro) -> None:
            tasks.append(asyncio.create_task(_named(role, coro)))

        _add("wayback", self._wayback())
        if self.mode in ("balanced", "deep"):
            _add("commoncrawl", self._commoncrawl())
            _add("robots", self._robots_txt_history())
            _add("sitemap", self._sitemap_history())
        all_urls = []
        robots_paths = []
        sitemap_urls = []
        for task in asyncio.as_completed(tasks):
            try:
                role, batch = await task
            except Exception:
                continue
            if not isinstance(batch, list):
                continue
            if role == "robots":
                robots_paths = batch
                self._store_partial_results({
                    "robots_disallow": robots_paths,
                    "historical_robots": [f"https://web.archive.org/web/*/{self.domain}/robots.txt"] if robots_paths else [],
                })
                continue
            if role == "sitemap":
                sitemap_urls = batch
                self._store_partial_results({
                    "sitemap_urls": sitemap_urls[:100],
                    "historical_sitemaps": [f"https://web.archive.org/web/*/{self.domain}/sitemap.xml"] if sitemap_urls else [],
                })
                continue
            all_urls.extend(batch)
            self._store_partial_results(self._archive_snapshot_payload(all_urls))
        all_urls = self._dedupe_wayback_urls(all_urls)
        self._store_partial_results(self._archive_snapshot_payload(all_urls))
        interesting = self._interesting_urls(all_urls)
        categories = self._categorize_urls(all_urls)
        top_paths = self._top_paths(all_urls)
        query_params = self._archive_query_params(all_urls)
        api_profiles = self._archive_api_profiles(all_urls)
        sensitive_path_hits = self._sensitive_path_hits(all_urls)
        self._store_partial_results({
            "api_endpoints": categories["api_endpoints"],
            "admin_paths": categories["admin_paths"],
            "sensitive_files": categories["sensitive_files"],
            "js_files": categories["js_files"],
            "documents": categories["documents"],
            "query_params": query_params,
            "top_paths": top_paths,
            "sensitive_path_hits": sensitive_path_hits,
        })
        js_secrets, js_endpoints = await self._inspect_archived_js(all_urls)
        page_artifacts = await self._inspect_archived_pages(all_urls)
        # Serialize WaybackURL objects to dicts for template/JSON compatibility
        def _wu_to_dict(wu):
            if isinstance(wu, dict):
                return wu
            return {"url": getattr(wu, "url", str(wu)), "timestamp": getattr(wu, "timestamp", ""),
                    "status_code": getattr(wu, "status_code", 0), "mime_type": getattr(wu, "mime_type", "")}
        actual_total = len(all_urls)
        all_dicts = [_wu_to_dict(u) for u in all_urls]
        interesting_dicts = [_wu_to_dict(u) for u in interesting[:320]]
        interesting_paths = categories.get("interesting_paths", []) or []
        result = {
            "all": all_dicts,
            "all_urls": all_dicts,
            "total_urls": actual_total,
            "total_retrieved": actual_total,
            "interesting": interesting_dicts,
            "api_endpoints": categories["api_endpoints"],
            "api_endpoint_profiles": api_profiles,
            "admin_paths": categories["admin_paths"],
            "sensitive_files": categories["sensitive_files"],
            "js_files": categories["js_files"],
            "documents": categories["documents"],
            "js_secrets": js_secrets,
            "js_endpoints": js_endpoints,
            "query_params": query_params,
            "top_paths": top_paths,
            "sensitive_path_hits": sensitive_path_hits,
            "titles": page_artifacts.get("titles", []),
            "meta_generators": page_artifacts.get("meta_generators", []),
            "page_tech_hints": page_artifacts.get("page_tech_hints", []),
            "robots_disallow": robots_paths,
            "historical_robots": [f"https://web.archive.org/web/*/{self.domain}/robots.txt"] if robots_paths else [],
            "sitemap_urls": sitemap_urls[:100],
            "historical_sitemaps": [f"https://web.archive.org/web/*/{self.domain}/sitemap.xml"] if sitemap_urls else [],
            "interesting_paths": interesting_paths,
        }
        self._store_partial_results(result)
        return result



# -- DORK INTELLIGENCE ----------------------------------------------------------
class DorkIntelligence:
    """Passive dork intelligence: GitHub, Wayback CDX patterns, URLScan, Pastebin."""

    def __init__(self, domain, mode, session, api_keys):
        self.domain = domain
        self.mode = mode
        self.session = session
        self.api_keys = api_keys
        self.timeout = max(TIMEOUTS[mode], 30)

    def _template_findings(self) -> list:
        # Query ideas are not evidence and must not be persisted as findings.
        return []

    def _sanitize_finding(self, finding: dict) -> dict:
        return {
            "source": str(finding.get("source", "") or ""),
            "category": str(finding.get("category", "") or ""),
            "url": str(finding.get("url", "") or ""),
            "repo": str(finding.get("repo", "") or ""),
            "file": str(finding.get("file", "") or ""),
            "snippet": str(finding.get("snippet", "") or ""),
            "severity": str(finding.get("severity", "LOW") or "LOW").upper(),
        }

    async def _github_search(self) -> list:
        findings = []
        key = self.api_keys.get("github_token", "")
        if not key:
            return []  # GitHub code search requires auth since Feb 2023
        headers = _github_auth_headers(key, accept="application/vnd.github.v3.text-match+json")
        dork_queries = [
            (f'site:github.com "{self.domain}" password', "github_exposure", "HIGH"),
            (f'site:github.com "{self.domain}" secret', "github_exposure", "HIGH"),
            (f'site:github.com "{self.domain}" api_key', "github_exposure", "HIGH"),
            (f'site:github.com "{self.domain}" token', "github_exposure", "MEDIUM"),
            (f'"{self.domain}" .env', "config_files", "CRITICAL"),
            (f'"@{self.domain}"', "email_exposure", "LOW"),
            (f'"{self.domain}" private_key', "credentials", "CRITICAL"),
            (f'"{self.domain}" database_url', "credentials", "CRITICAL"),
        ]
        max_q = 4 if self.mode == "fast" else 8
        delay = 7 if not key else 2
        from urllib.parse import quote as _quote
        for query, category, severity in dork_queries[:max_q]:
            try:
                url = f"https://api.github.com/search/code?q={_quote(query)}&per_page=5"
                resp = await _safe_get(self.session, url, timeout=15, headers=headers)
                if resp and resp.status == 200:
                    data = await resp.json(content_type=None)
                    for item in (data.get("items") or [])[:3]:
                        repo = (item.get("repository") or {}).get("full_name", "")
                        html_url = item.get("html_url", "")
                        file_name = item.get("name", "")
                        snippet = ""
                        for match in (item.get("text_matches") or [])[:1]:
                            snippet = str(match.get("fragment", ""))[:300]
                        findings.append({
                            "source": "github",
                            "category": category,
                            "query": query,
                            "url": html_url,
                            "repo": repo,
                            "file": file_name,
                            "snippet": snippet[:300],
                            "severity": severity,
                        })
                await asyncio.sleep(delay)
            except Exception:
                pass
        return findings

    async def _wayback_patterns(self) -> list:
        findings = []
        patterns = [
            (f"url={self.domain}/*.env",      "env_files",       "CRITICAL"),
            (f"url={self.domain}/*.sql",      "database_dumps",  "CRITICAL"),
            (f"url={self.domain}/.git/*",     "git_exposure",    "CRITICAL"),
            (f"url={self.domain}/*password*", "credentials",     "CRITICAL"),
            (f"url={self.domain}/*backup*",   "backups",         "HIGH"),
            (f"url={self.domain}/*.bak",      "backups",         "HIGH"),
            (f"url={self.domain}/*.xls*",     "spreadsheets",    "MEDIUM"),
            (f"url={self.domain}/*config*",   "config_files",    "HIGH"),
            (f"url={self.domain}/*.log",      "logs",            "MEDIUM"),
            (f"url={self.domain}/*/admin*",   "admin_panels",    "MEDIUM"),
            (f"url={self.domain}/*.htpasswd", "auth_exposure",   "CRITICAL"),
            (f"url={self.domain}/wp-config*", "config_files",    "CRITICAL"),
            (f"url={self.domain}/*/api/*",    "api_endpoints",   "LOW"),
            (f"url={self.domain}/*.pdf",      "documents",       "LOW"),
        ]
        # Limit patterns in fast/turbo modes to reduce total dork time
        max_patterns = {"fast": 5, "balanced": 8, "deep": 14, "turbo": 3}.get(self.mode, 5)
        pat_timeout = {"fast": 15, "balanced": 20, "deep": 25, "turbo": 8}.get(self.mode, 15)
        for pattern, category, severity in patterns[:max_patterns]:
            try:
                cdx_url = (
                    f"https://web.archive.org/cdx/search/cdx?{pattern}"
                    f"&output=json&limit=10&fl=original,timestamp"
                )
                resp = await _safe_get(self.session, cdx_url, timeout=pat_timeout, ssl=False)
                if resp and resp.status == 200:
                    data = await resp.json(content_type=None)
                    for row in (data[1:] if data and len(data) > 1 else []):
                        if isinstance(row, list) and row and isinstance(row[0], str):
                            orig_url = row[0]
                            ts = row[1] if len(row) > 1 else ""
                            ts_display = f"{ts[:4]}-{ts[4:6]}-{ts[6:8]}" if len(ts) >= 8 else ts
                            findings.append({
                                "source": "wayback",
                                "category": category,
                                "query": pattern,
                                "url": orig_url,
                                "repo": "",
                                "file": orig_url.split("/")[-1] if orig_url else "",
                                "snippet": f"Archived in Wayback Machine ({ts_display})",
                                "severity": severity,
                            })
            except Exception:
                pass
        return findings

    async def _urlscan_dorks(self) -> list:
        findings = []
        try:
            from urllib.parse import quote as _quote
            # Specific filenames to avoid false positives (e.g. /en-us matching filename:config)
            queries = [
                (f"domain:{self.domain} filename:.env",          "config_exposure",  "CRITICAL", r"\.env$"),
                (f"domain:{self.domain} filename:wp-config.php", "config_exposure",  "CRITICAL", r"wp-config\.php"),
                (f"domain:{self.domain} filename:config.php",    "config_files",     "HIGH",     r"config\.php"),
                (f"domain:{self.domain} filename:database.yml",  "config_files",     "HIGH",     r"database\.yml"),
                (f"domain:{self.domain} filename:backup.sql",    "backups",          "HIGH",     r"backup.*\.sql"),
                (f"domain:{self.domain} filename:id_rsa",        "credentials",      "CRITICAL", r"id_rsa"),
                (f"domain:{self.domain} filename:.git",          "git_exposure",     "CRITICAL", r"\.git"),
                (f"domain:{self.domain} filename:credentials",   "credentials",      "CRITICAL", r"credential"),
            ]
            max_q = 3 if self.mode == "fast" else 6 if self.mode == "balanced" else 8
            seen_urls: set = set()
            for query, category, severity, url_pattern in queries[:max_q]:
                url = f"https://urlscan.io/api/v1/search/?q={_quote(query)}&size=5"
                resp = await _safe_get(self.session, url, timeout=15)
                if resp and resp.status == 200:
                    data = await resp.json(content_type=None)
                    for result in (data.get("results") or [])[:3]:
                        page = result.get("page") or {}
                        scan_url = page.get("url", "")
                        title = page.get("title", "")
                        scan_time = (result.get("task") or {}).get("time", "")
                        # Validate: URL must match the filename pattern (avoid false positives)
                        if not scan_url or scan_url in seen_urls:
                            continue
                        if not re.search(url_pattern, scan_url, re.I):
                            continue
                        seen_urls.add(scan_url)
                        findings.append({
                            "source": "urlscan",
                            "category": category,
                            "query": query,
                            "url": scan_url,
                            "repo": "",
                            "file": scan_url.split("/")[-1] if scan_url else "",
                            "snippet": f"URLScan scan ({scan_time[:10]}): {title[:100]}",
                            "severity": severity,
                        })
        except Exception:
            pass
        return findings

    async def _pastebin_dorks(self) -> list:
        findings = []
        try:
            url = f"https://psbdmp.ws/api/v3/search/{self.domain}"
            resp = await _safe_get(self.session, url, timeout=self.timeout)
            if resp and resp.status == 200:
                data = await resp.json(content_type=None)
                for item in (data.get("data") or [])[:5]:
                    paste_id = item.get("id", "")
                    paste_url = f"https://pastebin.com/{paste_id}" if paste_id else ""
                    tags = ", ".join(item.get("tags") or [])
                    findings.append({
                        "source": "pastebin",
                        "category": "paste_exposure",
                        "query": self.domain,
                        "url": paste_url,
                        "repo": "",
                        "file": "",
                        "snippet": f"Paste tags: {tags}" if tags else f"Domain in paste {paste_id}",
                        "severity": "MEDIUM",
                    })
        except Exception:
            pass
        return findings

    async def search(self) -> list:
        tasks = [self._wayback_patterns(), self._urlscan_dorks(), self._pastebin_dorks(), self._github_search()]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        all_findings = self._template_findings()
        seen_keys = set()
        for batch in results:
            if isinstance(batch, list):
                for f in batch:
                    if not isinstance(f, dict):
                        continue
                    clean = self._sanitize_finding(f)
                    url = clean.get("url", "")
                    key = url or f"{clean.get('source','')}:{clean.get('category','')}:{clean.get('file','')}"
                    if key and key not in seen_keys:
                        seen_keys.add(key)
                        all_findings.append(clean)
        sev_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        all_findings.sort(key=lambda x: sev_rank.get(x.get("severity", "low"), 9))
        return all_findings


# Ã¢â€â‚¬Ã¢â€â‚¬ BREACH INTELLIGENCE Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
class PassiveArtifactIntelligence:
    """Derive bug-bounty-focused passive artifacts from existing OSINT evidence."""

    def __init__(self, domain, mode, wayback_urls, dorks, subdomains, ip_records, cloud_assets, asn_intelligence, dns_records=None):
        self.domain = domain
        self.mode = mode
        self.wayback_urls = wayback_urls if isinstance(wayback_urls, dict) else {}
        self.dorks = dorks if isinstance(dorks, list) else []
        self.subdomains = subdomains if isinstance(subdomains, list) else []
        self.ip_records = ip_records if isinstance(ip_records, list) else []
        self.cloud_assets = cloud_assets if isinstance(cloud_assets, list) else []
        self.asn_intelligence = asn_intelligence if isinstance(asn_intelligence, dict) else {}
        self.dns_records = dns_records if isinstance(dns_records, list) else []

    def _host_context(self, raw_url: str = "", host: str = "", historical: bool = True) -> dict:
        norm_host = normalize_hostname(host or "")
        parsed_path = ""
        if raw_url and raw_url.startswith("http"):
            try:
                parsed = urlparse(raw_url)
                norm_host = normalize_hostname(parsed.hostname or "") or norm_host
                parsed_path = parsed.path or "/"
            except Exception:
                pass
        elif raw_url and looks_like_hostname(str(raw_url)):
            norm_host = normalize_hostname(str(raw_url)) or norm_host
        first_party = bool(norm_host and (norm_host == self.domain or norm_host.endswith("." + self.domain)))
        return {
            "host": norm_host or self.domain,
            "path": parsed_path or raw_url or "/",
            "first_party": first_party,
            "third_party_context": not first_party,
            "historical_only": bool(historical),
            "current_passive": not historical,
            "observation_recency": "historical_only" if historical else "current_passive",
        }

    @staticmethod
    def _semantic_path_key(path: str) -> str:
        raw = str(path or "/").strip() or "/"
        raw = re.sub(r"/\d{2,}", "/:id", raw)
        raw = re.sub(r"/[0-9a-f]{8,}", "/:id", raw, flags=re.I)
        raw = re.sub(r"/{2,}", "/", raw)
        return raw[:180]

    @staticmethod
    def _artifact_url_profile(raw_url: str):
        raw = str(raw_url or "").strip()
        path = "/"
        host = ""
        try:
            parsed = urlparse(raw if raw.startswith("http") else raw if raw.startswith("/") else f"https://{raw}")
            host = normalize_hostname(parsed.hostname or "")
            path = (parsed.path or path).strip() or "/"
        except Exception:
            path = raw.split("?", 1)[0].strip() or "/"
        clean_path = path.split("?", 1)[0] or "/"
        filename = Path(clean_path).name.lower()
        ext = Path(filename).suffix.lower()
        lowered = f"{host}{clean_path}".lower()
        return clean_path, filename, ext, lowered

    @classmethod
    def _is_low_value_artifact_url(cls, raw_url: str) -> bool:
        path, _, ext, lowered = cls._artifact_url_profile(raw_url)
        if any(token in lowered for token in (
            "/api", "/graphql", "/gql", "/admin", "/auth", "/oauth", "/login", "/sso",
            "/console", "/manager", "/portal", "/internal", "/debug", "/metrics",
            "/health", "/actuator", "/swagger", "/openapi", "/webhook", "/gateway",
            "config", "settings", "backup", "dump", "secret", "token", "password",
            "credential", ".env", ".bak", ".old", ".sql", ".db", ".dump", ".log",
            ".zip", ".tar", ".gz", ".map",
        )):
            return False
        if ext in {".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".css", ".woff", ".woff2"}:
            return True
        if any(path.startswith(prefix) for prefix in ("/static/", "/assets/", "/images/", "/fonts/")):
            return True
        if path in {"", "/", "/index.html", "/favicon.ico"}:
            return True
        return False

    @classmethod
    def _is_generic_frontend_bundle(cls, raw_url: str) -> bool:
        _, filename, _, lowered = cls._artifact_url_profile(raw_url)
        if not filename:
            return False
        if filename.endswith(".map"):
            return False
        return bool(re.search(r"(bundle|chunk|vendor|runtime|app\.[0-9a-f]{6,}|main\.[0-9a-f]{6,})", filename, re.I)) or "/static/" in lowered or "/assets/" in lowered

    def _endpoint_profile(self, raw_url: str) -> Optional[dict]:
        if not raw_url:
            return None
        if self._is_low_value_artifact_url(raw_url):
            return None
        try:
            parsed = urlparse(raw_url if raw_url.startswith("http") else f"https://{self.domain}{raw_url}")
        except Exception:
            return None
        host = normalize_hostname(parsed.hostname or "") or self.domain
        if host and not (host == self.domain or host.endswith("." + self.domain)):
            return None
        path = parsed.path or "/"
        query_keys = [k.lower() for k, _ in parse_qsl(parsed.query or "", keep_blank_values=True)]
        lowered = f"{host}{path}".lower()
        is_meaningful_well_known = False
        if path.startswith("/.well-known/"):
            meaningful_well_known = (
                "/.well-known/openid-configuration",
                "/.well-known/oauth-authorization-server",
                "/.well-known/assetlinks.json",
                "/.well-known/apple-app-site-association",
                "/.well-known/change-password",
                "/.well-known/security.txt",
            )
            if not any(path.startswith(prefix) for prefix in meaningful_well_known):
                return None
            is_meaningful_well_known = True
        reasons = []
        category = "endpoint"
        if is_meaningful_well_known:
            category = "metadata"
            reasons.append("well_known_surface")
            if path.startswith("/.well-known/security.txt"):
                reasons.append("security_contact_surface")
            elif path.startswith("/.well-known/openid-configuration") or path.startswith("/.well-known/oauth-authorization-server"):
                category = "auth"
                reasons.append("auth_metadata_surface")
        if any(tok in lowered for tok in ("/admin", "/panel", "/console", "/manager", "/jenkins")):
            category = "admin"
            reasons.append("admin_surface")
        if any(tok in lowered for tok in ("/auth", "/oauth", "/login", "/sso", "/callback")):
            category = "auth"
            reasons.append("auth_flow")
        if "graphql" in lowered or "/gql" in lowered:
            category = "graphql"
            reasons.append("graphql_surface")
        if any(tok in lowered for tok in ("/api", "/rest", "/swagger", "/openapi", "/webhook", "/gateway")):
            category = "api" if category == "endpoint" else category
            reasons.append("api_surface")
        if any(tok in lowered for tok in ("/internal", "/debug", "/metrics", "/health", "/actuator")):
            category = "internal" if category == "endpoint" else category
            reasons.append("internal_surface")
        if any(tok in lowered for tok in ("/upload", "/download", "/export", "/import", "/backup", "/logs", "/config", "/test", "/staging")):
            reasons.append("operational_surface")
        ext = Path(path).suffix.lower()
        if ext in {".json", ".yml", ".yaml", ".env", ".bak", ".old", ".zip", ".sql", ".tar", ".gz"}:
            reasons.append("interesting_file_extension")
        if any(q in {"token", "key", "secret", "redirect_uri", "client_id", "state", "code", "file", "upload", "download"} for q in query_keys):
            reasons.append("sensitive_query_parameter")
        if not reasons:
            return None
        priority = 18
        priority += 18 if category in {"admin", "auth", "graphql"} else 12 if category == "api" else 8
        priority += 10 if "interesting_file_extension" in reasons else 0
        priority += 6 if "sensitive_query_parameter" in reasons else 0
        return {
            "host": host,
            "path": path,
            "category": category,
            "reasons": reasons,
            "priority_score": min(priority, 100),
        }

    def _interesting_endpoints(self) -> list:
        rows = []
        seen = set()

        def add_endpoint(raw_url: str, source: str, confidence: float, evidence: str, historical: bool = True, classification: str = "passive") -> None:
            profile = self._endpoint_profile(raw_url)
            if not profile:
                return
            ctx = self._host_context(raw_url, profile["host"], historical=historical)
            key = (ctx["host"], self._semantic_path_key(profile["path"]), profile["category"])
            if key in seen:
                return
            seen.add(key)
            rows.append({
                "url": raw_url if raw_url.startswith("http") else f"https://{ctx['host']}{profile['path']}",
                "host": ctx["host"],
                "path": profile["path"],
                "category": profile["category"],
                "source": source,
                "classification": classification,
                "confidence": round(max(0.25, min(float(confidence or 0.6), 0.99)), 3),
                "evidence": normalize_text(evidence[:180]),
                "reasons": profile["reasons"][:5],
                "first_party": ctx["first_party"],
                "third_party_context": ctx["third_party_context"],
                "historical_only": ctx["historical_only"],
                "current_passive": ctx["current_passive"],
                "observation_recency": ctx["observation_recency"],
                "priority_score": int(profile["priority_score"]),
                "related_asset": ctx["host"],
            })

        for key in ("api_endpoints", "admin_paths", "sensitive_files", "sitemap_urls"):
            for url in self.wayback_urls.get(key, []) or []:
                add_endpoint(str(url), "wayback_archive", 0.68 if key == "sitemap_urls" else 0.78, key, historical=True, classification="passive")
        for row in self.wayback_urls.get("interesting", []) or []:
            if isinstance(row, dict):
                raw_url = str(row.get("url", "") or "")
                if not raw_url:
                    continue
                add_endpoint(
                    raw_url,
                    str(row.get("source", "wayback_archive")),
                    0.64,
                    str(row.get("reason", row.get("mime_type", "interesting_archive_url"))),
                    historical=True,
                    classification="passive",
                )
        for row in self.wayback_urls.get("js_endpoints", []) or []:
            if isinstance(row, dict):
                add_endpoint(
                    str(row.get("url", "")),
                    str(row.get("source", "wayback_js")),
                    float(row.get("confidence", 0.62) or 0.62),
                    str(row.get("evidence", "archived_js")),
                    historical=bool(row.get("historical_only", True)),
                    classification=str(row.get("classification", "passive") or "passive"),
                )
        for hit in self.wayback_urls.get("sensitive_path_hits", []) or []:
            if isinstance(hit, dict):
                add_endpoint(
                    str(hit.get("url", "")),
                    str(hit.get("source", "wayback/commoncrawl_index")),
                    0.55,
                    str(hit.get("tag", "archive_hint")),
                    historical=True,
                    classification="heuristic",
                )
        for url in self.wayback_urls.get("robots_disallow", []) or []:
            add_endpoint(f"https://{self.domain}{url}", "wayback_robots", 0.66, "robots_txt_history", historical=True, classification="passive")
        for url in (self.wayback_urls.get("documents", []) or [])[:60]:
            raw = str(url or "")
            if re.search(r"/(swagger|openapi|graphql|api-docs|docs|admin|jenkins|build|artifact|console)", raw, re.I):
                add_endpoint(raw, "wayback_archive", 0.71, "developer_document_surface", historical=True, classification="probable")
        for finding in self.dorks:
            if not isinstance(finding, dict):
                continue
            location = str(finding.get("url", "") or "")
            if not location:
                continue
            add_endpoint(
                location,
                str(finding.get("source", "dorks")),
                0.59,
                str(finding.get("snippet", "dork_reference")),
                historical=False,
                classification="probable",
            )

        rows.sort(key=lambda item: (-int(item.get("priority_score", 0)), -float(item.get("confidence", 0.0)), str(item.get("host", ""))))
        return rows[:140]

    def _secret_level(self, secret_type: str, location: str, source: str, evidence: str, preview: str, confidence: float) -> tuple[str, float]:
        combined = " ".join([str(secret_type or ""), str(location or ""), str(evidence or ""), str(preview or "")]).lower()
        strong_types = {"aws_key", "google_api", "slack_token", "stripe_live", "private_key"}
        weak_markers = ("help", "support", "docs", "documentation", "faq", "credential", "credentials")
        verification_markers = ("google-site-verification", "facebook-domain-verification", "ms=", "amazonses", "apple-domain-verification", "atlassian-domain-verification")
        if any(tok in combined for tok in verification_markers):
            return "weak_artifact", 0.22
        if secret_type.lower() in strong_types:
            return "strong_passive_exposure", max(0.84, confidence)
        if ".git" in combined and source != "wayback_js":
            return "weak_artifact", min(confidence, 0.38)
        if any(tok in combined for tok in weak_markers) and "akia" not in combined and "private key" not in combined:
            return "weak_artifact", min(confidence, 0.34)
        if re.search(r"(token|secret|api[_-]?key|password)\s*[:=]", combined, re.I):
            return "probable_secret_exposure", max(0.72, confidence)
        if "config" in combined or any(ext in combined for ext in (".env", ".yml", ".yaml", ".bak", ".sql")):
            return "suspicious_secret_reference", max(0.58, confidence)
        return "suspicious_secret_reference", max(0.46, min(confidence, 0.68))

    def _potential_secrets(self) -> list:
        rows = []
        seen = set()

        def add_secret(secret_type: str, location: str, source: str, confidence: float, evidence: str, preview: str = "", historical: bool = True) -> None:
            classification, norm_conf = self._secret_level(secret_type, location, source, evidence, preview, confidence)
            ctx = self._host_context(location, historical=historical)
            key = (secret_type, ctx["host"], self._semantic_path_key(ctx["path"]), classification)
            if key in seen:
                return
            seen.add(key)
            rows.append({
                "secret_type": secret_type,
                "location": location,
                "source": source,
                "classification": classification,
                "confidence": round(max(0.15, min(float(norm_conf or 0.5), 0.99)), 3),
                "evidence": normalize_text(evidence[:180]),
                "match_preview": preview[:80],
                "first_party": ctx["first_party"],
                "third_party_context": ctx["third_party_context"],
                "historical_only": ctx["historical_only"],
                "current_passive": ctx["current_passive"],
                "observation_recency": ctx["observation_recency"],
            })

        for row in self.wayback_urls.get("js_secrets", []) or []:
            if isinstance(row, dict):
                add_secret(
                    str(row.get("secret_type", "Generic_Secret") or "Generic_Secret"),
                    str(row.get("location", "") or row.get("archive_url", "")),
                    str(row.get("source", "wayback_js")),
                    float(row.get("confidence", 0.72) or 0.72),
                    str(row.get("evidence", "")),
                    str(row.get("match_preview", "")),
                    historical=True,
                )
        for hit in self.wayback_urls.get("sensitive_path_hits", []) or []:
            if not isinstance(hit, dict):
                continue
            tag = str(hit.get("tag", "") or "").lower()
            raw_url = str(hit.get("url", "") or "")
            if not raw_url or tag not in {"env", "config", "backup", "sql_dump", "credential_file", "secret"}:
                continue
            add_secret(
                tag,
                raw_url,
                str(hit.get("source", "wayback/commoncrawl_index")),
                0.56,
                str(hit.get("evidence", "archived_sensitive_path_hint")),
                preview=tag,
                historical=True,
            )
        for finding in self.dorks:
            if not isinstance(finding, dict):
                continue
            category = str(finding.get("category", "") or "")
            if category not in {"credentials", "api_keys", "config_exposure", "git_exposure", "auth_exposure", "config_files", "git_hint"}:
                continue
            severity = str(finding.get("severity", "LOW") or "LOW").upper()
            conf = 0.78 if severity == "CRITICAL" else 0.64 if severity == "HIGH" else 0.5
            add_secret(
                category,
                str(finding.get("url", "")),
                str(finding.get("source", "dorks")),
                conf,
                str(finding.get("snippet", "dork_match")),
                historical=False,
            )

        rows.sort(key=lambda item: (-float(item.get("confidence", 0.0)), str(item.get("classification", "")), str(item.get("secret_type", ""))))
        return rows[:90]

    def _developer_references(self) -> list:
        refs = []
        seen = set()

        def add_ref(source: str, category: str, location: str, evidence: str, confidence: float, repo: str = "", file_name: str = "", historical: bool = True, classification: str = "passive") -> None:
            ctx = self._host_context(location, historical=historical)
            key = (source, category, location or repo, file_name)
            if key in seen:
                return
            seen.add(key)
            refs.append({
                "source": source,
                "category": category,
                "location": location,
                "repo": repo,
                "file": file_name,
                "classification": classification,
                "confidence": round(max(0.2, min(float(confidence or 0.6), 0.99)), 3),
                "evidence": normalize_text(evidence[:180]),
                "first_party": ctx["first_party"],
                "third_party_context": ctx["third_party_context"],
                "historical_only": ctx["historical_only"],
                "current_passive": ctx["current_passive"],
                "observation_recency": ctx["observation_recency"],
            })

        for finding in self.dorks:
            if not isinstance(finding, dict):
                continue
            source = str(finding.get("source", "") or "")
            if source not in {"github", "pastebin", "urlscan"}:
                continue
            add_ref(
                source,
                str(finding.get("category", "") or "reference"),
                str(finding.get("url", "") or finding.get("repo", "")),
                str(finding.get("snippet", "")),
                0.76 if source == "github" else 0.58,
                repo=str(finding.get("repo", "") or ""),
                file_name=str(finding.get("file", "") or ""),
                historical=False,
                classification="probable" if source == "github" else "passive",
            )
        for url in (self.wayback_urls.get("js_files", []) or [])[:80]:
            raw = str(url or "")
            filename = Path(urlparse(raw).path or "").name
            if not filename:
                continue
            if filename.endswith(".map"):
                add_ref("wayback_archive", "source_map", raw, filename, 0.74, file_name=filename, historical=True)
                continue
            if self._is_generic_frontend_bundle(raw):
                continue
            if re.search(r"(\.map$|manifest|config|sourcemap)", filename, re.I):
                add_ref("wayback_archive", "developer_surface", raw, filename, 0.68, file_name=filename, historical=True)
        for url in (self.wayback_urls.get("api_endpoints", []) or [])[:80]:
            raw = str(url or "")
            if re.search(r"/(swagger|openapi|graphql|docs|console|admin|jenkins|build|artifact|repo)", raw, re.I):
                add_ref("wayback_archive", "developer_surface", raw, "archived_developer_surface", 0.68, historical=True)
        for row in (self.wayback_urls.get("interesting", []) or [])[:120]:
            if not isinstance(row, dict):
                continue
            raw = str(row.get("url", "") or "")
            if not raw:
                continue
            if re.search(r"(\.map$|package(-lock)?\.json|composer\.json|pom\.xml|build\.gradle|yarn\.lock|pnpm-lock\.yaml|requirements\.txt|swagger|openapi|graphql|jenkins|artifact)", raw, re.I):
                add_ref(
                    "wayback_archive",
                    "developer_surface",
                    raw,
                    str(row.get("mime_type", "interesting_archive_url")),
                    0.66,
                    file_name=Path(urlparse(raw).path or "").name,
                    historical=True,
                    classification="passive",
                )
        provider_patterns = {
            "google-site-verification": "google_workspace",
            "atlassian-domain-verification": "atlassian",
            "facebook-domain-verification": "facebook",
            "amazonses": "aws_ses",
            "spf1": "email_provider",
        }
        for rec in self.dns_records:
            value = ""
            rtype = ""
            if isinstance(rec, dict):
                value = str(rec.get("value", "") or "")
                rtype = str(rec.get("type", "") or "")
            else:
                value = str(getattr(rec, "value", "") or "")
                rtype = str(getattr(rec, "type", "") or "")
            if rtype != "TXT" or not value:
                continue
            lower = value.lower()
            for token, category in provider_patterns.items():
                if token in lower:
                    add_ref("dns_txt", category, self.domain, value, 0.66, historical=False, classification="passive")
                    break
        refs.sort(key=lambda item: (-float(item.get("confidence", 0.0)), item.get("source", ""), item.get("category", "")))
        return refs[:90]

    def _high_value_targets(self, endpoints: list, secrets: list, developer_refs: list) -> list:
        endpoint_hosts = Counter()
        for row in endpoints:
            host = str((row or {}).get("host", "") or "")
            if host:
                endpoint_hosts[host] += int(row.get("priority_score", 0) or 0)
        secret_hosts = Counter()
        for row in secrets:
            loc = str((row or {}).get("location", "") or "")
            try:
                host = normalize_hostname(urlparse(loc).hostname or "")
            except Exception:
                host = ""
            if host:
                secret_hosts[host] += 18 if row.get("classification") == "strong_passive_exposure" else 10 if row.get("classification") == "probable_secret_exposure" else 4
        dev_hosts = Counter()
        for row in developer_refs:
            loc = str((row or {}).get("location", "") or "")
            try:
                host = normalize_hostname(urlparse(loc).hostname or "")
            except Exception:
                host = ""
            if host and (host == self.domain or host.endswith("." + self.domain)):
                dev_hosts[host] += 8
        infra_hosts = Counter()
        for row in self.ip_records:
            if not isinstance(row, dict):
                continue
            ports = [int(p) for p in (row.get("open_ports", []) or []) if isinstance(p, int) or str(p).isdigit()]
            cpes = [str(v) for v in (row.get("cpes", []) or []) if str(v).strip()]
            if not ports and not cpes:
                continue
            related_hosts = []
            for sub in self.subdomains:
                if not isinstance(sub, dict):
                    continue
                host = str(sub.get("name", "") or "").strip().lower()
                if host and row.get("ip") in (sub.get("ips", []) or []):
                    related_hosts.append(host)
            for host in related_hosts:
                infra_hosts[host] += min(16, (len(ports) * 4) + (4 if cpes else 0))

        targets = []
        for sub in self.subdomains:
            if not isinstance(sub, dict):
                continue
            host = str(sub.get("name", "") or "").strip().lower()
            if not host:
                continue
            score = 0
            reasons = []
            corroboration = set()
            tags = [str(t or "").lower() for t in (sub.get("tags", []) or [])]
            if any(tag in tags for tag in ("admin_panel", "api_endpoint", "devops", "identity_auth", "remote_access")):
                score += 22
                reasons.append("sensitive_subdomain_tag")
                corroboration.add("tag")
            if any(tok in host for tok in ("admin", "auth", "api", "dev", "staging", "vpn", "sso", "oauth", "graphql", "gateway", "mail", "sts", "mfa", "exchange", "owa", "citrix", "sandbox", "preprod")):
                score += 10
                reasons.append("host_keyword_signal")
            if sub.get("takeover_status") in {"VULNERABLE", "POTENTIAL", "LIKELY_VULNERABLE"}:
                score += 35
                reasons.append("takeover_signal")
                corroboration.add("takeover")
            if endpoint_hosts.get(host):
                score += min(38, endpoint_hosts[host] // 4)
                reasons.append("interesting_endpoints")
                corroboration.add("endpoint")
            if secret_hosts.get(host):
                score += min(24, secret_hosts[host])
                reasons.append("potential_secret_reference")
                corroboration.add("secret")
            if dev_hosts.get(host):
                score += min(20, dev_hosts[host])
                reasons.append("developer_reference")
                corroboration.add("devref")
            if infra_hosts.get(host):
                score += min(12, infra_hosts[host])
                reasons.append("infra_signal")
                corroboration.add("infra")
            if sub.get("ips"):
                score += 4
                reasons.append("resolves_publicly")
                corroboration.add("resolution")
            if any(host == str((c or {}).get("subdomain", "") or "").lower() for c in self.cloud_assets):
                score += 10
                reasons.append("cloud_mapping")
                corroboration.add("cloud")
            if dev_hosts.get(host) and "developer_reference" not in reasons:
                score += 6
                reasons.append("developer_reference")
                corroboration.add("devref")
            artifact_backed = bool(corroboration.intersection({"endpoint", "secret", "devref", "takeover"}))
            if artifact_backed:
                score += 8
                reasons.append("multi_signal_convergence")
            weak_only = corroboration.issubset({"resolution", "tag", "cloud"}) and "takeover" not in corroboration and "endpoint" not in corroboration and "secret" not in corroboration and "devref" not in corroboration and "infra" not in corroboration
            if not artifact_backed and corroboration.issubset({"tag", "infra", "resolution", "cloud"}) and "takeover" not in corroboration and score < 40:
                continue
            if score < 18 or len(corroboration) < 2 or weak_only:
                continue
            targets.append({
                "host": host,
                "score": min(100, score),
                "classification": "probable" if score >= 58 else "passive",
                "confidence": 0.82 if score >= 70 else 0.72 if score >= 52 else 0.6,
                "reasons": reasons[:5],
                "sources": list(sub.get("sources", []) or [])[:5],
                "first_party": True,
                "third_party_context": False,
                "historical_only": False,
                "current_passive": True,
                "observation_recency": "current_passive",
            })
        targets.sort(
            key=lambda item: (
                -int(any(reason in {"interesting_endpoints", "potential_secret_reference", "developer_reference", "takeover_signal"} for reason in (item.get("reasons", []) or []))),
                -int("sensitive_subdomain_tag" in (item.get("reasons", []) or [])),
                -int(item.get("score", 0)),
                item.get("host", ""),
            )
        )
        diversified = []
        family_counts = Counter()
        for item in targets:
            host = str(item.get("host", "") or "")
            family_key = _normalized_target_family(host, self.domain) or host
            strong_story = any(
                reason in {"interesting_endpoints", "potential_secret_reference", "developer_reference", "takeover_signal", "multi_signal_convergence"}
                for reason in (item.get("reasons", []) or [])
            )
            family_cap = 2 if strong_story else 1
            if family_counts[family_key] >= family_cap:
                continue
            family_counts[family_key] += 1
            diversified.append(item)
            if len(diversified) >= 40:
                break
        return diversified

    def _asset_clusters(self) -> dict:
        by_ip: Dict[str, set] = {}
        for sub in self.subdomains:
            if not isinstance(sub, dict):
                continue
            host = str(sub.get("name", "") or "")
            for ip in (sub.get("ips", []) or []):
                ip_s = str(ip or "")
                if ip_s:
                    by_ip.setdefault(ip_s, set()).add(host)

        asn_map: Dict[str, Dict[str, Any]] = {}
        for rec in self.ip_records:
            if not isinstance(rec, dict):
                continue
            asn = str(rec.get("asn", "") or "")
            if not asn:
                continue
            bucket = asn_map.setdefault(asn, {"asn": asn, "org": str(rec.get("org", "") or ""), "ips": set(), "providers": set()})
            if rec.get("ip"):
                bucket["ips"].add(str(rec.get("ip")))
            if rec.get("provider"):
                bucket["providers"].add(str(rec.get("provider")))
            if rec.get("org"):
                bucket["org"] = str(rec.get("org"))

        ip_clusters = [{"ip": ip, "assets": sorted(list(hosts))[:10], "asset_count": len(hosts)} for ip, hosts in by_ip.items() if len(hosts) >= 2]
        ip_clusters.sort(key=lambda item: (-int(item.get("asset_count", 0)), item.get("ip", "")))
        asn_clusters = []
        for row in asn_map.values():
            asn_clusters.append({
                "asn": row["asn"],
                "org": row["org"],
                "ips": sorted(list(row["ips"]))[:10],
                "ip_count": len(row["ips"]),
                "providers": sorted(list(row["providers"]))[:5],
            })
        asn_clusters.sort(key=lambda item: (-int(item.get("ip_count", 0)), item.get("asn", "")))
        providers = []
        for row in asn_clusters[:20]:
            if row.get("providers"):
                providers.append({"asn": row["asn"], "org": row["org"], "providers": row["providers"]})
        return {
            "by_ip": ip_clusters[:30],
            "by_asn": asn_clusters[:30],
            "providers": providers[:20],
        }

    async def analyze(self) -> dict:
        endpoints = self._interesting_endpoints()
        secrets = self._potential_secrets()
        developer_refs = self._developer_references()
        high_value_targets = self._high_value_targets(endpoints, secrets, developer_refs)
        asset_clusters = self._asset_clusters()
        return {
            "interesting_endpoints": endpoints,
            "potential_secrets": secrets,
            "developer_references": developer_refs,
            "high_value_targets": high_value_targets,
            "asset_clusters": asset_clusters,
        }


class BreachIntelligence:
    def __init__(self, domain, mode, session, api_keys):
        self.domain = domain
        self.mode = mode
        self.session = session
        self.api_keys = api_keys
        self.timeout = TIMEOUTS[mode]

    async def _hibp(self):
        return []

    async def _dehashed_public(self):
        breaches = []
        try:
            url = f"https://api.dehashed.com/search?query=domain:{self.domain}&size=10"
            resp = await _safe_get(self.session, url, timeout=self.timeout)
            if resp and resp.status == 200:
                data = await resp.json(content_type=None)
                total = data.get("total", 0)
                if total > 0:
                    breaches.append(BreachRecord(
                        name="DeHashed",
                        description=f"{total} records found in dehashed.com for {self.domain}",
                        source="dehashed"
                    ))
        except Exception:
            pass
        return breaches

    async def _hibp_domain(self):
        """HIBP breach search by domain (no key required for domain lookup)."""
        breaches = []
        try:
            url = f"https://haveibeenpwned.com/api/v3/breaches?domain={self.domain}"
            headers = {"User-Agent": "ghost-recon-tool"}
            resp = await _safe_get(self.session, url, timeout=self.timeout, headers=headers)
            if resp and resp.status == 200:
                data = await resp.json(content_type=None)
                for item in data:
                    breaches.append(BreachRecord(
                        name=item.get("Name", ""),
                        date=item.get("BreachDate", ""),
                        data_types=item.get("DataClasses", []),
                        description=item.get("Description", "")[:200]
                    ))
        except Exception:
            pass
        return breaches

    async def _check_breachdirectory(self, email: str) -> dict:
        """Check BreachDirectory for a specific email."""
        return {}

    async def _github_dorks(self):
        """Search GitHub for exposed credentials related to the domain."""
        breaches = []
        key = self.api_keys.get("github_token", "")
        headers = {"Authorization": f"Bearer {key}", "Accept": "application/vnd.github.v3.text-match+json"} if key else {"Accept": "application/vnd.github.v3.text-match+json"}
        dork_queries = [
            f'"{self.domain}" password',
            f'"{self.domain}" secret',
            f'"{self.domain}" api_key',
            f'"{self.domain}" token',
            f'"@{self.domain}"',
        ]
        for query in dork_queries:
            try:
                url = f"https://api.github.com/search/code?q={quote(query)}&per_page=30"
                resp = await _safe_get(self.session, url, timeout=self.timeout, headers=headers)
                if resp and resp.status == 200:
                    data = await resp.json(content_type=None)
                    for item in data.get("items", []):
                        for match in item.get("text_matches", []):
                            fragment = match.get("fragment", "")
                            for cred_name, cred_re in CRED_PATTERNS.items():
                                if cred_re.search(fragment):
                                    repo = item.get("repository", {}).get("full_name", "")
                                    html_url = item.get("html_url", "")
                                    breaches.append(BreachRecord(
                                        name=f"GitHub Exposure: {cred_name}",
                                        date=datetime.now(timezone.utc).strftime("%Y-%m-%d"),
                                        data_types=[cred_name],
                                        description=f"Potential {cred_name} found in {repo}: {html_url}"
                                    ))
                await asyncio.sleep(2)
            except Exception:
                pass
        return breaches

    async def check(self):
        tasks = [self._dehashed_public(), self._hibp_domain()]
        if self.mode in ("balanced", "deep", "turbo"):
            tasks.append(self._github_dorks())
        results = await asyncio.gather(*tasks, return_exceptions=True)
        all_breaches = []
        seen_names = set()
        for batch in results:
            if isinstance(batch, list):
                for b in batch:
                    key = (b.name if hasattr(b, "name") else b.get("name", ""))
                    if key and key not in seen_names:
                        seen_names.add(key)
                        all_breaches.append(b)
        return all_breaches


# Ã¢â€â‚¬Ã¢â€â‚¬ REPUTATION INTELLIGENCE Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
class ReputationIntelligence:
    def __init__(self, domain, mode, session, api_keys):
        self.domain = domain
        self.mode = mode
        self.session = session
        self.api_keys = api_keys
        self.timeout = TIMEOUTS[mode]

    async def _virustotal(self):
        key = self.api_keys.get("virustotal", "")
        if not key:
            return {}
        try:
            url = f"https://www.virustotal.com/api/v3/domains/{self.domain}"
            resp = await _safe_get(self.session, url, timeout=self.timeout,
                                   headers={"x-apikey": key})
            if resp and resp.status == 200:
                data = await resp.json(content_type=None)
                stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                votes = data.get("data", {}).get("attributes", {}).get("total_votes", {})
                return {
                    "source": "virustotal",
                    "malicious": stats.get("malicious", 0),
                    "suspicious": stats.get("suspicious", 0),
                    "harmless": stats.get("harmless", 0),
                    "undetected": stats.get("undetected", 0),
                    "reputation": data.get("data", {}).get("attributes", {}).get("reputation", 0),
                    "votes_harmless": votes.get("harmless", 0),
                    "votes_malicious": votes.get("malicious", 0),
                }
        except Exception:
            pass
        return {}

    async def _otx(self):
        key = self.api_keys.get("otx", "")
        headers = {"X-OTX-API-KEY": key} if key else {}
        try:
            url = f"https://otx.alienvault.com/api/v1/indicators/domain/{self.domain}/general"
            resp = await _safe_get(self.session, url, timeout=self.timeout, headers=headers)
            if resp and resp.status == 200:
                data = await resp.json(content_type=None)
                return {
                    "source": "otx",
                    "pulse_count": data.get("pulse_info", {}).get("count", 0),
                    "malware_families": [
                        m.get("display_name", "") for m in
                        data.get("pulse_info", {}).get("related", {}).get("malware_families", [])
                    ][:5],
                    "industries": data.get("pulse_info", {}).get("related", {}).get("industries", [])[:5],
                }
        except Exception:
            pass
        return {}

    async def _urlscan(self):
        try:
            url = f"https://urlscan.io/api/v1/search/?q=domain:{self.domain}&size=5"
            resp = await _safe_get(self.session, url, timeout=self.timeout)
            if resp and resp.status == 200:
                data = await resp.json(content_type=None)
                results = data.get("results", [])
                malicious = sum(1 for r in results if r.get("verdicts", {}).get("overall", {}).get("malicious", False))
                return {
                    "source": "urlscan",
                    "total_scans": data.get("total", 0),
                    "malicious_scans": malicious,
                    "recent_scans": len(results),
                }
        except Exception:
            pass
        return {}

    async def _virustotal_unauth(self):
        try:
            url = f"https://www.virustotal.com/ui/domains/{self.domain}"
            resp = await _safe_get(self.session, url, timeout=self.timeout,
                                   headers={"Accept": "application/json"})
            if resp and resp.status == 200:
                data = await resp.json(content_type=None)
                attrs = data.get("data", {}).get("attributes", {})
                stats = attrs.get("last_analysis_stats", {})
                return {
                    "source": "virustotal_ui",
                    "malicious": stats.get("malicious", 0),
                    "suspicious": stats.get("suspicious", 0),
                    "harmless": stats.get("harmless", 0),
                    "reputation": attrs.get("reputation", 0),
                    "categories": attrs.get("categories", {}),
                }
        except Exception:
            pass
        return {}

    async def _phishtank(self):
        try:
            form_data = aiohttp.FormData()
            form_data.add_field("url", f"https://{self.domain}")
            form_data.add_field("format", "json")
            form_data.add_field("app_key", "")
            resp = await _safe_post(
                self.session,
                "https://checkurl.phishtank.com/checkurl/",
                timeout=self.timeout,
                data=form_data,
            )
            if resp and resp.status == 200:
                data = await resp.json(content_type=None)
                results = data.get("results", {})
                return {
                    "source": "phishtank",
                    "in_database": results.get("in_database", False),
                    "verified": results.get("verified", False),
                    "valid": results.get("valid", False),
                }
        except Exception:
            pass
        return {}

    async def _spamhaus_dbl(self):
        try:
            ext = _safe_tld_extract(self.domain)
            apex = f"{ext.domain}.{ext.suffix}"
            answers = await _doh_query(self.session, f"{apex}.dbl.spamhaus.org", "A", timeout=10)
            if answers:
                ip = answers[0].get("data", "")
                classification = {
                    "127.0.1.2": "spammed_domain",
                    "127.0.1.4": "phishing_domain",
                    "127.0.1.5": "malware_domain",
                }.get(ip, "listed")
                return {"source": "spamhaus_dbl", "listed": True, "classification": classification}
            return {"source": "spamhaus_dbl", "listed": False}
        except Exception:
            pass
        return {}

    async def _surbl(self):
        try:
            ext = _safe_tld_extract(self.domain)
            apex = f"{ext.domain}.{ext.suffix}"
            answers = await _doh_query(self.session, f"{apex}.multi.surbl.org", "A", timeout=10)
            if answers:
                result_ip = answers[0].get("data", "")
                # SURBL return codes: https://surbl.org/faq
                classification = {
                    "127.0.0.2": "phishing",
                    "127.0.0.4": "malware",
                    "127.0.0.8": "spam",
                    "127.0.0.16": "abuse",
                }.get(result_ip, "listed")
                return {"source": "surbl", "listed": True,
                        "classification": classification, "result_ip": result_ip}
            return {"source": "surbl", "listed": False}
        except Exception:
            pass
        return {}

    async def _talos(self):
        try:
            url = f"https://talosintelligence.com/sb_api/remote_lookup?query={self.domain}"
            resp = await _safe_get(self.session, url, timeout=self.timeout,
                                   headers={"Accept": "application/json"})
            if resp and resp.status == 200:
                data = await resp.json(content_type=None)
                return {
                    "source": "talos",
                    "reputation_category": data.get("category", {}).get("description", ""),
                    "email_score": data.get("email_score_name", ""),
                    "web_score": data.get("web_score_name", ""),
                }
        except Exception:
            pass
        return {}

    async def _github_org(self):
        try:
            ext = tldextract.extract(self.domain)
            org_name = ext.domain
            key = self.api_keys.get("github_token", "")
            headers = _github_auth_headers(key)
            resp = await _safe_get(self.session, f"https://api.github.com/orgs/{org_name}",
                                   timeout=self.timeout, headers=headers)
            if resp and resp.status == 200:
                data = await resp.json(content_type=None)
                org_info = {
                    "source": "github_org",
                    "org_name": org_name,
                    "url": data.get("html_url", ""),
                    "public_repos": data.get("public_repos", 0),
                    "followers": data.get("followers", 0),
                    "description": data.get("description", ""),
                    "blog": data.get("blog", ""),
                    "email": data.get("email", ""),
                    "location": data.get("location", ""),
                    "created_at": data.get("created_at", ""),
                }
                # Also fetch top repos
                repos_resp = await _safe_get(
                    self.session,
                    f"https://api.github.com/orgs/{org_name}/repos?per_page=100&type=public&sort=pushed",
                    timeout=self.timeout, headers=headers
                )
                if repos_resp and repos_resp.status == 200:
                    repos_data = await repos_resp.json(content_type=None)
                    org_info["repos"] = [
                        {
                            "name": r.get("name", ""),
                            "language": r.get("language", ""),
                            "stars": r.get("stargazers_count", 0),
                            "forks": r.get("forks_count", 0),
                            "last_push": r.get("pushed_at", ""),
                            "topics": r.get("topics", []),
                            "description": (r.get("description") or "")[:100],
                        }
                        for r in repos_data
                    ]
                return org_info
        except Exception:
            pass
        return {}

    async def _urlhaus_host(self):
        try:
            payload = {"host": self.domain}
            resp = await _safe_post(
                self.session,
                "https://urlhaus-api.abuse.ch/v1/host/",
                timeout=self.timeout,
                json=payload,
                headers={"Accept": "application/json"},
            )
            if resp and resp.status == 200:
                data = await resp.json(content_type=None)
                urls = data.get("urls", []) if isinstance(data, dict) else []
                return {
                    "source": "urlhaus",
                    "confidence": 0.8 if urls else 0.35,
                    "url_count": len(urls),
                    "status": data.get("query_status", "unknown"),
                }
        except Exception:
            pass
        return {}

    async def _pulsedive(self):
        try:
            url = f"https://pulsedive.com/api/info.php?indicator={quote(self.domain)}&pretty=1"
            resp = await _safe_get(self.session, url, timeout=self.timeout)
            if resp and resp.status == 200:
                data = await resp.json(content_type=None)
                risk = data.get("risk", "") if isinstance(data, dict) else ""
                related = data.get("related", []) if isinstance(data, dict) else []
                return {
                    "source": "pulsedive",
                    "risk": risk,
                    "indicator_type": data.get("type", "") if isinstance(data, dict) else "",
                    "related_count": len(related),
                    "summary": str((data.get("summary", "") if isinstance(data, dict) else "") or "")[:200],
                }
        except Exception:
            pass
        return {}

    async def _threatfox_domain(self):
        try:
            payload = {"query": "search_ioc", "search_term": self.domain}
            resp = await _safe_post(
                self.session,
                "https://threatfox-api.abuse.ch/api/v1/",
                timeout=self.timeout,
                json=payload,
                headers={"Accept": "application/json"},
            )
            if resp and resp.status == 200:
                data = await resp.json(content_type=None)
                items = data.get("data", []) if isinstance(data, dict) else []
                return {
                    "source": "threatfox",
                    "confidence": 0.85 if items else 0.3,
                    "ioc_count": len(items),
                    "malware_families": sorted({i.get("malware", "") for i in items if i.get("malware")})[:8],
                }
        except Exception:
            pass
        return {}

    async def _crtsh_recent(self):
        try:
            url = f"https://crt.sh/?q=%25.{self.domain}&output=json"
            resp = await _safe_get(self.session, url, timeout=self.timeout)
            if resp and resp.status == 200:
                data = await resp.json(content_type=None)
                if isinstance(data, list):
                    issuers = []
                    for entry in data[:150]:
                        issuer = (entry.get("issuer_name", "") or "").strip()
                        if issuer:
                            issuers.append(issuer)
                    uniq_issuers = sorted(set(issuers))
                    return {
                        "source": "crtsh_recent",
                        "confidence": 0.7,
                        "cert_observations": len(data),
                        "issuer_count": len(uniq_issuers),
                        "top_issuers": uniq_issuers[:5],
                    }
        except Exception:
            pass
        return {}

    async def check(self):
        tasks = [
            self._otx(), self._urlscan(), self._virustotal_unauth(),
            self._spamhaus_dbl(), self._surbl(), self._github_org(),
            self._urlhaus_host(), self._threatfox_domain(), self._crtsh_recent(), self._pulsedive(),
        ]
        if self.api_keys.get("virustotal"):
            tasks.append(self._virustotal())
        if self.mode in ("balanced", "deep"):
            tasks.append(self._phishtank())
            tasks.append(self._talos())
        results = await asyncio.gather(*tasks, return_exceptions=True)
        reputation = {}
        for r in results:
            if isinstance(r, dict) and r.get("source"):
                source = r.get("source", "unknown")
                reputation[source] = r
        return reputation


# Ã¢â€â‚¬Ã¢â€â‚¬ CLOUD ASSET INTELLIGENCE Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
class CloudIntelligence:
    S3_REGIONS = ["us-east-1", "us-west-2", "eu-west-1", "ap-southeast-1", "ap-northeast-1"]
    _CNAME_CLOUD_MAP = [
        ("s3.amazonaws.com",            "AWS S3",               "Object Storage",   "s3"),
        ("s3-website",                  "AWS S3",               "Object Storage",   "s3"),
        ("elasticbeanstalk.com",        "AWS Elastic Beanstalk","PaaS",             "aws_beanstalk"),
        ("blob.core.windows.net",       "Azure Blob",           "Object Storage",   "azure_blob"),
        ("azurewebsites.net",           "Azure App Service",    "PaaS",             "azure_webapp"),
        ("azurestaticapps.net",         "Azure Static Apps",    "Hosting",          "azure_static"),
        ("storage.googleapis.com",      "Google Cloud Storage", "Object Storage",   "gcs"),
        ("r2.dev",                      "Cloudflare R2",        "Object Storage",   "cloudflare_r2"),
        ("vercel.app",                  "Vercel",               "Hosting",          "vercel"),
        ("netlify.app",                 "Netlify",              "Hosting",          "netlify"),
        ("firebaseapp.com",             "Firebase",             "PaaS",             "firebase"),
        ("web.app",                     "Firebase",             "Hosting",          "firebase"),
        ("herokuapp.com",               "Heroku",               "PaaS",             "heroku"),
        ("digitaloceanspaces.com",      "DigitalOcean Spaces",  "Object Storage",   "do_spaces"),
        ("kinsta.cloud",                "Kinsta",               "Hosting",          "kinsta"),
        ("wpengine.com",                "WP Engine",            "Hosting",          "wpengine"),
        ("pages.dev",                   "Cloudflare Pages",     "Hosting",          "cloudflare_pages"),
    ]

    def __init__(self, domain, mode, session, api_keys=None, policy: Optional[ScanPolicy] = None, subdomains=None):
        self.domain = domain
        self.mode = mode
        self.session = session
        self.api_keys = api_keys or {}
        self.policy = policy or ScanPolicy()
        self.timeout = TIMEOUTS[mode]
        self._subdomains = subdomains or []
        try:
            ext = _safe_tld_extract(domain)
            if ext.domain and ext.suffix:
                self.apex = f"{ext.domain}.{ext.suffix}"
                self.name = ext.domain
            else:
                raise ValueError("tldextract_empty")
        except Exception:
            # Fallback: never fail scan startup due to suffix cache/lock/network issues.
            norm = normalize_domain(domain)
            parts = [p for p in norm.split(".") if p]
            if len(parts) >= 2:
                self.apex = ".".join(parts[-2:])
                self.name = parts[-2]
            else:
                self.apex = norm
                self.name = parts[0] if parts else norm

    def _bucket_candidates(self):
        candidates = []
        base = self.name
        prefixes = [
            "", "www.", "static.", "assets.", "media.", "cdn.", "files.", "data.",
            "backup.", "dev.", "staging.", "api.", "img.", "images.", "uploads.",
            "downloads.", "content.", "public.", "private.", "archive.", "logs.",
            "storage.", "resources.", "dist.", "build.", "release.", "prod.",
            "test.", "qa.", "uat.", "demo.", "docs.", "reports.", "export.",
            "attachments.", "videos.", "audio.", "scripts.", "css.", "fonts.",
        ]
        for pfx in prefixes:
            bucket_name = f"{pfx}{base}".strip(".")
            for region in (self.S3_REGIONS if self.mode == "deep" else self.S3_REGIONS[:2]):
                candidates.append({
                    "type": "s3",
                    "name": bucket_name,
                    "url": f"https://{bucket_name}.s3.{region}.amazonaws.com",
                    "region": region
                })
            candidates.append({
                "type": "gcs",
                "name": bucket_name,
                "url": f"https://storage.googleapis.com/{bucket_name}",
                "region": "global"
            })
            candidates.append({
                "type": "azure",
                "name": bucket_name.replace(".", "").replace("-", ""),
                "url": f"https://{bucket_name.replace('.','').replace('-','')}.blob.core.windows.net",
                "region": "azure"
            })
        return candidates[:60] if self.mode != "deep" else candidates

    async def _check_bucket(self, candidate):
        try:
            resp = await _safe_get(
                self.session,
                candidate["url"],
                timeout=self.timeout,
                headers=_headers(),
                allow_redirects=False,
            )
            status = resp.status
            if status in (200, 403, 301, 302):
                body = await resp.text()
                public = status == 200 and "ListBucketResult" in body
                return CloudAsset(
                    asset_type=candidate["type"],
                    name=candidate["name"],
                    url=candidate["url"],
                    region=candidate["region"],
                    public=public,
                    confidence=0.93 if public else 0.82,
                    classification="evidenced",
                    source="bucket_http_probe",
                )
        except Exception:
            pass
        return None

    async def _grayhatwarfare(self) -> list:
        assets = []
        try:
            url = f"https://buckets.grayhatwarfare.com/api/v2/buckets?keywords={self.apex}&limit=100&page=1"
            resp = await _safe_get(self.session, url, timeout=self.timeout)
            if resp and resp.status == 200:
                data = await resp.json(content_type=None)
                for bucket in data.get("buckets", []):
                    assets.append(CloudAsset(
                        asset_type=bucket.get("type", "bucket"),
                        name=bucket.get("bucket", ""),
                        url=bucket.get("url", ""),
                        region="",
                        public=bucket.get("keywords", "") != "",
                        confidence=0.9,
                        classification="evidenced",
                        source="grayhatwarfare",
                    ))
        except Exception:
            pass
        return assets

    async def _docker_hub(self) -> list:
        assets = []
        try:
            url = f"https://hub.docker.com/v2/search/repositories/?query={self.apex}&page_size=25"
            resp = await _safe_get(self.session, url, timeout=self.timeout)
            if resp and resp.status == 200:
                data = await resp.json(content_type=None)
                for repo in data.get("results", []):
                    assets.append(CloudAsset(
                        asset_type="docker_image",
                        name=repo.get("repo_name", ""),
                        url=f"https://hub.docker.com/r/{repo.get('repo_name','')}",
                        region="docker.io",
                        public=True,
                        confidence=0.55,
                        classification="probable",
                        source="docker_hub",
                    ))
        except Exception:
            pass
        return assets

    async def _check_doh_bucket(self, hostname: str, asset_type: str) -> Optional[CloudAsset]:
        """Check bucket existence via DoH only (no direct HTTP to bucket)."""
        try:
            answers = await _doh_query(self.session, hostname, "A", timeout=8)
            if answers:
                return CloudAsset(
                    asset_type=asset_type,
                    name=hostname.split(".")[0],
                    url=f"https://{hostname}",
                    region="",
                    public=False,
                    confidence=0.45,
                    classification="heuristic",
                    source="doh_permutations",
                )
        except Exception:
            pass
        return None

    async def _check_cloud_doh_permutations(self) -> list:
        assets = []
        base_perms = [self.name, self.apex.replace(".", "-")]
        base_perms = [p for p in dict.fromkeys(base_perms) if p]
        # Add common bucket name suffix variants
        extra_suffixes = ["-backup", "-data", "-assets", "-uploads"]
        perms = list(base_perms)
        for p in base_perms:
            for sfx in extra_suffixes:
                variant = f"{p}{sfx}"
                if variant not in perms:
                    perms.append(variant)
        checks = []
        for p in perms:
            checks.append(self._check_doh_bucket(f"{p}.s3.amazonaws.com", "s3"))
            checks.append(self._check_doh_bucket(f"{p}.blob.core.windows.net", "azure_blob"))
            checks.append(self._check_doh_bucket(f"{p}.storage.googleapis.com", "gcs"))
            checks.append(self._check_doh_bucket(f"{p}.firebaseio.com", "firebase"))
            checks.append(self._check_doh_bucket(f"{p}.web.app", "firebase"))
        results = await asyncio.gather(*checks, return_exceptions=True)
        for r in results:
            if isinstance(r, CloudAsset):
                assets.append(r)
        return assets

    def _from_subdomain_cnames(self) -> list:
        """Detect cloud assets from subdomain CNAME records (passive, no HTTP)."""
        assets = []
        seen_urls = set()
        for sub in (self._subdomains or []):
            if not isinstance(sub, dict):
                continue
            sub_name = str(sub.get("name", "") or "")
            cnames = sub.get("cname", []) or []
            if isinstance(cnames, str):
                cnames = [cnames]
            for cv in cnames:
                cv_lower = str(cv or "").lower().rstrip(".")
                for cname_pattern, provider, service, asset_type in self._CNAME_CLOUD_MAP:
                    if cname_pattern in cv_lower:
                        url = f"https://{sub_name}"
                        if url not in seen_urls:
                            seen_urls.add(url)
                            assets.append(CloudAsset(
                                asset_type=asset_type,
                                name=sub_name,
                                url=url,
                                region="",
                                public=False,
                                confidence=0.75,
                                classification="probable",
                                source="subdomain_cname_analysis",
                            ))
                        break
        return assets

    async def discover(self):
        candidates = self._bucket_candidates()
        sem = asyncio.Semaphore(SEMAPHORES[self.mode])
        async def limited(c):
            async with sem:
                return await self._check_bucket(c)
        # Passive default: do not probe cloud buckets directly unless explicitly allowed.
        allow_active_bucket_probe = (not self.policy.passive_only) and self.policy.allow_target_requests
        tasks = [limited(c) for c in candidates] if allow_active_bucket_probe else []
        cname_cloud_assets = self._from_subdomain_cnames()
        extra_tasks = [
            self._grayhatwarfare(),
            self._docker_hub(),
            self._check_cloud_doh_permutations(),
        ]
        all_tasks = tasks + extra_tasks
        results = await asyncio.gather(*all_tasks, return_exceptions=True)
        found = list(cname_cloud_assets)
        for r in results:
            if isinstance(r, CloudAsset):
                found.append(r)
            elif isinstance(r, list):
                found.extend([x for x in r if isinstance(x, CloudAsset)])
        merged: Dict[tuple, CloudAsset] = {}
        for asset in found:
            key = (
                str(asset.asset_type or "").strip().lower(),
                str(asset.name or "").strip().lower(),
                str(asset.url or "").strip().lower(),
            )
            prev = merged.get(key)
            if not prev:
                merged[key] = asset
                continue
            prev.public = bool(prev.public or asset.public)
            prev.confidence = round(max(float(prev.confidence or 0), float(asset.confidence or 0)), 3)
            rank = {"heuristic": 0, "probable": 1, "evidenced": 2}
            if rank.get(str(asset.classification or "heuristic"), 0) > rank.get(str(prev.classification or "heuristic"), 0):
                prev.classification = asset.classification
            prev.source = ",".join(sorted(set(
                [s for s in str(prev.source or "").split(",") if s] +
                [s for s in str(asset.source or "").split(",") if s]
            )))
        assets = list(merged.values())
        evidence_rank = {"heuristic": 0, "probable": 1, "evidenced": 2}
        assets.sort(
            key=lambda asset: (
                -evidence_rank.get(str(asset.classification or "heuristic"), 0),
                -float(asset.confidence or 0.0),
                str(asset.name or ""),
            )
        )
        evidenced = [asset for asset in assets if str(asset.classification or "heuristic") in {"probable", "evidenced"}]
        heuristics = [asset for asset in assets if str(asset.classification or "heuristic") == "heuristic"]
        if len(heuristics) > 6:
            heuristics = heuristics[:6]
        return evidenced + heuristics


# Ã¢â€â‚¬Ã¢â€â‚¬ TYPOSQUAT DETECTOR Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
class TyposquatDetector:
    COMMON_TLDS = [
        "com", "net", "org", "io", "co", "us", "info", "biz", "online", "site",
        "app", "dev", "xyz", "tech", "cloud", "store", "shop", "ai", "me", "cc",
        "tv", "in", "uk", "de", "fr", "cn", "ru", "ca", "au", "br",
    ]
    HOMOGLYPHS = {
        "a": ["à", "á", "â", "ä", "@", "4"],
        "e": ["è", "é", "ê", "ë", "3"],
        "i": ["ì", "í", "î", "ï", "1", "l"],
        "o": ["ò", "ó", "ô", "ö", "0"],
        "u": ["ù", "ú", "û", "ü"],
        "s": ["$","5"],
        "g": ["9"],
        "b": ["6"],
        "l": ["1","i"],
    }

    def __init__(self, domain: str, mode: str, session: aiohttp.ClientSession):
        self.domain = domain
        self.mode = mode
        self.session = session
        ext = _safe_tld_extract(domain)
        self.name = ext.domain
        self.tld = ext.suffix

    def _generate_variants(self) -> set:
        variants = set()
        name = self.name
        tld = self.tld

        # Missing character
        for i in range(len(name)):
            v = name[:i] + name[i+1:]
            if len(v) >= 3:
                variants.add(f"{v}.{tld}")

        # Transposed adjacent characters
        for i in range(len(name) - 1):
            v = name[:i] + name[i+1] + name[i] + name[i+2:]
            variants.add(f"{v}.{tld}")

        # Doubled character
        for i in range(len(name)):
            v = name[:i] + name[i] + name[i] + name[i+1:]
            variants.add(f"{v}.{tld}")

        # Inserted character (keyboard neighbors simplified)
        keyboard_adj = {"a":"qs","b":"vn","c":"xv","d":"sf","e":"wr","f":"dg","g":"fh",
                        "h":"gj","i":"uo","j":"hk","k":"jl","l":"k","m":"n","n":"mb",
                        "o":"ip","p":"o","q":"aw","r":"et","s":"ad","t":"ry","u":"yi",
                        "v":"cb","w":"qe","x":"zc","y":"ut","z":"x"}
        for i in range(len(name)):
            for adj in keyboard_adj.get(name[i], ""):
                v = name[:i] + adj + name[i+1:]
                variants.add(f"{v}.{tld}")

        # TLD swaps
        for alt_tld in self.COMMON_TLDS:
            if alt_tld != tld:
                variants.add(f"{name}.{alt_tld}")

        # Combosquatting (common prefixes/suffixes Ã¢â‚¬â€ phishing / impersonation patterns)
        for affix in [
            "app", "api", "login", "secure", "my", "web", "mail", "get", "go",
            "portal", "auth", "account", "support", "help", "shop", "store",
            "pay", "checkout", "verify", "confirm", "update", "signin", "sign-in",
            "online", "official", "real", "safe", "team", "service", "services",
            "customer", "users", "admin", "dashboard",
        ]:
            variants.add(f"{affix}{name}.{tld}")
            variants.add(f"{name}{affix}.{tld}")
            variants.add(f"{affix}-{name}.{tld}")
            variants.add(f"{name}-{affix}.{tld}")

        # Bitsquatting (1-bit error in each character)
        for i in range(len(name)):
            for bit in range(8):
                flipped = chr(ord(name[i]) ^ (1 << bit))
                if flipped.isalnum() or flipped == "-":
                    v = name[:i] + flipped + name[i+1:]
                    if v != name:
                        variants.add(f"{v}.{tld}")

        # Remove self
        variants.discard(self.domain)
        return variants

    def _classify_variant(self, variant: str) -> str:
        """Classify what kind of typosquat technique generated this variant."""
        orig = self.name
        vname = variant.split(".")[0] if "." in variant else variant
        # TLD swap
        if vname == orig:
            return "tld-swap"
        # Combosquat
        affixes = [
            "app","api","login","secure","my","web","mail","get","go",
            "portal","auth","account","support","help","shop","store",
            "pay","checkout","verify","confirm","update","signin","sign-in",
            "online","official","real","safe","team","service","services",
            "customer","users","admin","dashboard",
        ]
        for a in affixes:
            if vname == f"{a}{orig}" or vname == f"{orig}{a}" or \
               vname == f"{a}-{orig}" or vname == f"{orig}-{a}":
                return "combosquat"
        if len(vname) == len(orig) - 1:
            return "missing-char"
        if len(vname) == len(orig) + 1:
            return "doubled-char"
        if len(vname) == len(orig):
            return "substitution"
        return "other"

    async def _check_active(self, variant: str) -> Optional[dict]:
        DOH_ENDPOINTS = [
            "https://cloudflare-dns.com/dns-query",
            "https://dns.google/resolve",
        ]
        for endpoint in DOH_ENDPOINTS:
            try:
                timeout = aiohttp.ClientTimeout(total=4)
                async with self.session.get(
                    endpoint,
                    params={"name": variant, "type": "A"},
                    headers={"Accept": "application/dns-json"},
                    timeout=timeout,
                    ssl=False,
                ) as resp:
                    if resp.status != 200:
                        break
                    data = await resp.json(content_type=None)
                    if data.get("Status", -1) != 0:
                        return None
                    answers = data.get("Answer", [])
                    ips = [str(a.get("data", "")).strip() for a in answers
                           if a.get("type") == 1 and a.get("data", "").strip()]
                    if not ips:
                        return None
                    vtype = self._classify_variant(variant)
                    return {
                        "domain": variant,
                        "ips": ips,
                        "ip": ips[0],
                        "active": True,
                        "status": "ACTIVE",
                        "type": vtype,
                    }
            except Exception:
                continue
        return None

    async def detect(self) -> list:
        variants = self._generate_variants()
        max_variants = {"fast": 200, "balanced": 400, "deep": 800, "turbo": 100}.get(self.mode, 200)
        variants = list(variants)[:max_variants]
        sem = asyncio.Semaphore(30)
        async def limited(v):
            async with sem:
                return await self._check_active(v)
        tasks = [limited(v) for v in variants]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        active = [r for r in results if isinstance(r, dict) and r.get("active")]
        return sorted(active, key=lambda x: x["domain"])


# Ã¢â€â‚¬Ã¢â€â‚¬ SECURITY HEADERS ANALYZER Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
class SecurityHeadersAnalyzer:
    SECURITY_HEADERS = {
        "strict-transport-security":    {"weight": 25, "name": "HSTS"},
        "content-security-policy":      {"weight": 25, "name": "CSP"},
        "x-frame-options":              {"weight": 15, "name": "X-Frame-Options"},
        "x-content-type-options":       {"weight": 10, "name": "X-Content-Type-Options"},
        "referrer-policy":              {"weight": 10, "name": "Referrer-Policy"},
        "permissions-policy":           {"weight": 10, "name": "Permissions-Policy"},
        "x-xss-protection":             {"weight": 5,  "name": "X-XSS-Protection"},
    }

    def __init__(self, domain: str, mode: str, session: aiohttp.ClientSession, policy: Optional[ScanPolicy] = None):
        self.domain = domain
        self.mode = mode
        self.session = session
        self.timeout = TIMEOUTS[mode]
        self.policy = policy or ScanPolicy()

    async def analyze(self) -> dict:
        if getattr(self.policy, 'passive_only', False):
            return {}
        result = {
            "score": 0,
            "grade": "F",
            "headers_present": [],
            "headers_missing": [],
            "details": {},
            "url_checked": "",
        }
        for scheme in (f"https://{self.domain}", f"https://www.{self.domain}"):
            try:
                resp = await _safe_get(self.session, scheme, timeout=self.timeout)
                if resp:
                    result["url_checked"] = scheme
                    resp_headers = {k.lower(): v for k, v in resp.headers.items()}
                    score = 0
                    for hdr, meta in self.SECURITY_HEADERS.items():
                        val = resp_headers.get(hdr, "")
                        if val:
                            result["headers_present"].append(meta["name"])
                            score += meta["weight"]
                            result["details"][meta["name"]] = val[:200]
                        else:
                            result["headers_missing"].append(meta["name"])
                    result["score"] = score
                    # Grade
                    if score >= 90:   result["grade"] = "A+"
                    elif score >= 75: result["grade"] = "A"
                    elif score >= 60: result["grade"] = "B"
                    elif score >= 45: result["grade"] = "C"
                    elif score >= 30: result["grade"] = "D"
                    else:             result["grade"] = "F"
                    # Extra: check HTTPS redirect
                    result["https_enforced"] = "strict-transport-security" in resp_headers
                    # Extra: cookies with Secure/HttpOnly
                    set_cookie = resp_headers.get("set-cookie", "")
                    result["cookies_secure"] = "secure" in set_cookie.lower() if set_cookie else None
                    break
            except Exception:
                continue
        return result


# Ã¢â€â‚¬Ã¢â€â‚¬ SOCIAL FOOTPRINT DETECTOR Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
class SocialFootprintDetector:
    def __init__(self, domain: str, mode: str, session: aiohttp.ClientSession, api_keys: dict):
        self.domain = domain
        self.mode = mode
        self.session = session
        self.api_keys = api_keys
        self.timeout = TIMEOUTS[mode]
        ext = _safe_tld_extract(domain)
        self.brand = ext.domain

    async def _bing_search(self, query: str) -> list:
        """Search Bing for URLs matching query."""
        return []

    async def _itunes_app(self) -> list:
        """Find iOS apps via iTunes search."""
        apps = []
        try:
            url = f"https://itunes.apple.com/search?term={quote(self.brand)}&entity=software&limit=5"
            resp = await _safe_get(self.session, url, timeout=self.timeout)
            if resp and resp.status == 200:
                data = await resp.json(content_type=None)
                for item in data.get("results", []):
                    apps.append({
                        "name": item.get("trackName", ""),
                        "url": item.get("trackViewUrl", ""),
                        "bundle_id": item.get("bundleId", ""),
                        "developer": item.get("artistName", ""),
                        "icon": item.get("artworkUrl60", ""),
                    })
        except Exception:
            pass
        return apps

    async def _find_social(self, platform: str, url_pattern: str) -> Optional[str]:
        results = await self._bing_search(f'site:{url_pattern} "{self.brand}"')
        for r in results:
            if url_pattern in r and self.brand.lower() in r.lower():
                return r
        return None

    async def _github_org(self) -> dict:
        """Free GitHub API org lookup — no key needed for public orgs."""
        result: dict = {}
        try:
            url = f"https://api.github.com/orgs/{self.brand}"
            resp = await _safe_get(self.session, url, timeout=10,
                                   headers={"Accept": "application/vnd.github+json"})
            if resp and resp.status == 200:
                data = await resp.json(content_type=None)
                result = {
                    "url": data.get("html_url", ""),
                    "name": data.get("name", "") or data.get("login", ""),
                    "description": data.get("description", ""),
                    "public_repos": data.get("public_repos", 0),
                    "followers": data.get("followers", 0),
                    "location": data.get("location", ""),
                    "blog": data.get("blog", ""),
                    "avatar_url": data.get("avatar_url", ""),
                    "type": "org",
                }
        except Exception:
            pass
        return result

    async def _github_repos(self) -> list:
        """Fetch public repos for an org — valuable for secret/config exposure."""
        repos = []
        try:
            url = f"https://api.github.com/orgs/{self.brand}/repos?per_page=100&sort=updated"
            resp = await _safe_get(self.session, url, timeout=15,
                                   headers={"Accept": "application/vnd.github+json"})
            if resp and resp.status == 200:
                data = await resp.json(content_type=None)
                for repo in (data if isinstance(data, list) else [])[:50]:
                    repos.append({
                        "name": repo.get("name", ""),
                        "url": repo.get("html_url", ""),
                        "description": repo.get("description", ""),
                        "stars": repo.get("stargazers_count", 0),
                        "language": repo.get("language", ""),
                        "updated": repo.get("updated_at", ""),
                        "is_fork": repo.get("fork", False),
                    })
        except Exception:
            pass
        return repos

    async def _urlscan_social(self) -> dict:
        """Use URLScan.io to find social profiles — free no-key lookup."""
        found: dict = {}
        try:
            url = f"https://urlscan.io/api/v1/search/?q=domain:{self.domain}&size=10"
            resp = await _safe_get(self.session, url, timeout=10,
                                   headers={"Accept": "application/json"})
            if resp and resp.status == 200:
                data = await resp.json(content_type=None)
                for result in (data.get("results", []) or [])[:10]:
                    page = result.get("page", {})
                    links = result.get("links", []) or []
                    for link in links:
                        href = str(link.get("href", "") or "")
                        for platform, pattern in [
                            ("linkedin", "linkedin.com/company/"),
                            ("twitter", "twitter.com/"),
                            ("github", "github.com/"),
                            ("facebook", "facebook.com/"),
                            ("youtube", "youtube.com/"),
                        ]:
                            if pattern in href and platform not in found:
                                found[platform] = href
        except Exception:
            pass
        return found

    async def _npm_packages(self) -> list:
        """Check npm registry for org packages."""
        pkgs = []
        try:
            url = f"https://registry.npmjs.org/-/org/{self.brand}/package"
            resp = await _safe_get(self.session, url, timeout=8)
            if resp and resp.status == 200:
                data = await resp.json(content_type=None)
                for name in list((data or {}).keys())[:20]:
                    pkgs.append({"name": name, "url": f"https://www.npmjs.com/package/{name}"})
        except Exception:
            pass
        return pkgs

    async def detect(self) -> dict:
        # Run free lookups concurrently
        bing_tasks = {
            "linkedin":   self._find_social("linkedin", "linkedin.com/company"),
            "twitter":    self._find_social("twitter/x", "twitter.com"),
            "crunchbase": self._find_social("crunchbase", "crunchbase.com"),
            "facebook":   self._find_social("facebook", "facebook.com"),
            "youtube":    self._find_social("youtube", "youtube.com"),
        }
        free_tasks_results = await asyncio.gather(
            asyncio.gather(*bing_tasks.values(), return_exceptions=True),
            self._github_org(),
            self._github_repos(),
            self._urlscan_social(),
            self._itunes_app(),
            self._npm_packages(),
            return_exceptions=True,
        )

        bing_results, github_org, github_repos, urlscan_social, ios_apps, npm_pkgs = (
            free_tasks_results if not isinstance(free_tasks_results, Exception) else ([], {}, [], {}, [], [])
        )

        # Merge Bing results
        social: dict = {}
        if isinstance(bing_results, (list, tuple)):
            for platform, result in zip(bing_tasks.keys(), bing_results):
                if isinstance(result, str) and result:
                    social[platform] = result

        # Overlay URLScan discoveries (free, no key required)
        if isinstance(urlscan_social, dict):
            for platform, url in urlscan_social.items():
                if url and platform not in social:
                    social[platform] = url

        # GitHub org URL (always available for public orgs)
        if isinstance(github_org, dict) and github_org.get("url"):
            social.setdefault("github", github_org["url"])
        if isinstance(github_org, dict):
            blog = str(github_org.get("blog", "") or "").strip()
            if blog and ("linkedin.com" in blog or "twitter.com" in blog or "x.com" in blog or "youtube.com" in blog):
                if "linkedin.com" in blog:
                    social.setdefault("linkedin", blog)
                elif "youtube.com" in blog:
                    social.setdefault("youtube", blog)
                else:
                    social.setdefault("twitter", blog)

        return {
            "profiles": social,
            "github_org": github_org if isinstance(github_org, dict) else {},
            "github_repos": github_repos if isinstance(github_repos, list) else [],
            "ios_apps": ios_apps if isinstance(ios_apps, list) else [],
            "npm_packages": npm_pkgs if isinstance(npm_pkgs, list) else [],
            "brand": self.brand,
        }


# Ã¢â€â‚¬Ã¢â€â‚¬ ASN INTELLIGENCE Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
class ASNIntelligence:
    def __init__(self, domain: str, mode: str, session: aiohttp.ClientSession, ip_records: list):
        self.domain = domain
        self.mode = mode
        self.session = session
        self.ip_records = ip_records
        self.timeout = TIMEOUTS[mode]

    async def _bgpview_asn(self, asn_num: str) -> dict:
        try:
            asn_clean = asn_num.upper().lstrip("AS")
            resp = await _safe_get(self.session, f"https://api.bgpview.io/asn/{asn_clean}", timeout=10)
            if resp and resp.status == 200:
                data = await resp.json(content_type=None)
                d = data.get("data", {})
                return {
                    "asn": asn_num,
                    "name": d.get("name", ""),
                    "description": d.get("description_short", ""),
                    "country": d.get("country_code", ""),
                    "rir": d.get("rir_allocation", {}).get("rir_name", "") if d.get("rir_allocation") else "",
                }
        except Exception:
            pass
        return {}

    async def _bgpview_prefixes(self, asn_num: str) -> list:
        try:
            asn_clean = asn_num.upper().lstrip("AS")
            resp = await _safe_get(self.session, f"https://api.bgpview.io/asn/{asn_clean}/prefixes", timeout=10)
            if resp and resp.status == 200:
                data = await resp.json(content_type=None)
                prefixes = data.get("data", {}).get("ipv4_prefixes", [])
                return [{"prefix": p.get("prefix",""), "name": p.get("name",""), "country": p.get("country_code","")} for p in prefixes[:20]]
        except Exception:
            pass
        return []

    async def _bgpview_ip_asn(self, ip: str) -> str:
        """Resolve IP → ASN via bgpview when ip_records lack asn field."""
        try:
            resp = await _safe_get(self.session, f"https://api.bgpview.io/ip/{ip}", timeout=8)
            if resp and resp.status == 200:
                data = await resp.json(content_type=None)
                asns = data.get("data", {}).get("asns", [])
                if asns:
                    return f"AS{asns[0].get('asn', '')}"
        except Exception:
            pass
        return ""

    async def _ipinfo_asn(self, ip: str) -> tuple[str, dict]:
        info: dict = {}
        try:
            resp = await _safe_get(self.session, f"https://ipinfo.io/{ip}/json", timeout=8)
            if resp and resp.status == 200:
                data = await resp.json(content_type=None)
                org = str(data.get("org", "") or "").strip()
                asn_str = org.split()[0] if org else ""
                if asn_str.startswith("AS"):
                    info = {
                        "asn": asn_str,
                        "name": org.partition(" ")[2].strip(),
                        "country": data.get("country", ""),
                        "region": data.get("region", ""),
                        "city": data.get("city", ""),
                    }
                    return asn_str, info
        except Exception:
            pass
        return "", {}

    async def enrich(self) -> dict:
        seen_asns: set = set()
        seen_ips: list = []
        observed_by_asn: Dict[str, Dict[str, Any]] = {}

        for rec in self.ip_records:
            asn = rec.get("asn", "") if isinstance(rec, dict) else getattr(rec, "asn", "")
            ip = rec.get("ip", "") if isinstance(rec, dict) else getattr(rec, "ip", "")
            if asn:
                asn_norm = str(asn).upper()
                if not asn_norm.startswith("AS"):
                    asn_norm = f"AS{asn_norm}"
                seen_asns.add(asn_norm)
                bucket = observed_by_asn.setdefault(asn_norm, {
                    "asn": asn_norm,
                    "name": str((rec.get("org", "") if isinstance(rec, dict) else getattr(rec, "org", "")) or "").strip(),
                    "org": str((rec.get("org", "") if isinstance(rec, dict) else getattr(rec, "org", "")) or "").strip(),
                    "country": str((rec.get("country", "") if isinstance(rec, dict) else getattr(rec, "country", "")) or "").strip(),
                    "provider": str((rec.get("provider", "") if isinstance(rec, dict) else getattr(rec, "provider", "")) or "").strip(),
                    "providers": [],
                    "ips": [],
                })
                if ip and str(ip) not in bucket["ips"]:
                    bucket["ips"].append(str(ip))
                provider_name = str((rec.get("provider", "") if isinstance(rec, dict) else getattr(rec, "provider", "")) or "").strip()
                if provider_name and provider_name not in bucket["providers"]:
                    bucket["providers"].append(provider_name)
            elif ip:
                seen_ips.append(str(ip))

        # Fallback: resolve IPs to ASNs when ip_records have no asn field
        if not seen_asns and seen_ips:
            ip_asn_tasks = [self._ipinfo_asn(ip) for ip in seen_ips[:6]]
            ip_asn_results = await asyncio.gather(*ip_asn_tasks, return_exceptions=True)
            ipinfo_hints: Dict[str, dict] = {}
            for item in ip_asn_results:
                if isinstance(item, tuple) and len(item) == 2:
                    asn_str, hint = item
                    if isinstance(asn_str, str) and asn_str.startswith("AS"):
                        seen_asns.add(asn_str)
                        if isinstance(hint, dict) and hint:
                            ipinfo_hints[asn_str] = hint
        else:
            ipinfo_hints = {}

        if not seen_asns:
            return {}

        tasks = {}
        for asn in list(seen_asns)[:5]:
            tasks[asn] = asyncio.create_task(self._bgpview_asn(asn))
        results = await asyncio.gather(*tasks.values(), return_exceptions=True)
        asn_data = {}
        prefix_tasks = {}
        for asn, result in zip(tasks.keys(), results):
            if isinstance(result, dict) and result:
                merged = dict(observed_by_asn.get(asn, {}))
                merged.update(ipinfo_hints.get(asn, {}))
                merged.update(result)
                asn_data[asn] = merged
                prefix_tasks[asn] = asyncio.create_task(self._bgpview_prefixes(asn))
            elif asn in ipinfo_hints or asn in observed_by_asn:
                merged = dict(observed_by_asn.get(asn, {}))
                merged.update(ipinfo_hints.get(asn, {}))
                asn_data[asn] = merged
        if prefix_tasks:
            prefix_results = await asyncio.gather(*prefix_tasks.values(), return_exceptions=True)
            for asn, pr in zip(prefix_tasks.keys(), prefix_results):
                if isinstance(pr, list) and asn in asn_data:
                    ipv4_prefixes = [p.get("prefix", "") for p in pr if p.get("prefix")]
                    asn_data[asn]["ipv4_prefixes"] = ipv4_prefixes
                    asn_data[asn]["total_ipv4_ranges"] = len(ipv4_prefixes)
        # Also store as list for UI consumption
        asn_list = list(asn_data.values())
        provider_rows = []
        for asn, meta in asn_data.items():
            providers = [p for p in (meta.get("providers", []) or []) if p]
            if providers:
                provider_rows.append({
                    "asn": asn,
                    "org": meta.get("org") or meta.get("name", ""),
                    "providers": providers,
                })
        # Return dict with both formats for backward compat
        return {"by_asn": asn_data, "list": asn_list, "providers": provider_rows[:20], **asn_data}


# Ã¢â€â‚¬Ã¢â€â‚¬ TAKEOVER DETECTOR Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
class TakeoverDetector:
    def __init__(self, domain, mode, session, subdomains, dns_records, policy: Optional[ScanPolicy] = None):
        self.domain = domain
        self.mode = mode
        self.session = session
        self.subdomains = subdomains
        self.dns_records = dns_records
        self.timeout = TIMEOUTS[mode]
        self.policy = policy or ScanPolicy()

    def _get_cnames(self):
        cname_map = {}
        # From apex DNS records
        for rec in self.dns_records:
            rtype = rec.get("type") if isinstance(rec, dict) else rec.type
            rname = rec.get("name") if isinstance(rec, dict) else rec.name
            rval = rec.get("value") if isinstance(rec, dict) else rec.value
            if rtype == "CNAME":
                cname_map.setdefault(rname, []).append(rval.rstrip("."))
        # Also check CNAME data from per-subdomain records
        for sub in (self.subdomains or []):
            if not isinstance(sub, dict):
                continue
            sub_name = str(sub.get("name", "") or "")
            cnames = sub.get("cname", []) or []
            if isinstance(cnames, str):
                cnames = [cnames]
            for cv in cnames:
                cv = str(cv or "").rstrip(".")
                if cv and sub_name:
                    if cv not in cname_map.get(sub_name, []):
                        cname_map.setdefault(sub_name, []).append(cv)
        return cname_map

    def _match_provider(self, cname_val):
        for provider, fp in TAKEOVER_FINGERPRINTS.items():
            for marker in fp["cname"]:
                if marker.lstrip(".") in cname_val:
                    return provider, fp["severity"]
        return None, None

    async def _check_takeover(self, subdomain, cname_val):
        provider, severity = self._match_provider(cname_val)
        if not provider:
            return None
        try:
            urls = [f"https://{subdomain}"]
            if self.policy.allow_insecure_http_fallback:
                urls.append(f"http://{subdomain}")
            resp = None
            for u in urls:
                resp = await _safe_get(self.session, u, timeout=self.timeout)
                if resp:
                    break
            if resp:
                body = await resp.text()
                body_lower = body.lower()
                for fingerprint_str in TAKEOVER_FINGERPRINTS[provider]["content"]:
                    if fingerprint_str.lower() in body_lower:
                        return TakeoverRecord(
                            subdomain=subdomain,
                            cname_chain=[cname_val],
                            provider=provider,
                            status="VULNERABLE",
                            evidence=f"CNAME {cname_val!r} + fingerprint {fingerprint_str!r}",
                            severity=severity
                        )
                return TakeoverRecord(
                    subdomain=subdomain,
                    cname_chain=[cname_val],
                    provider=provider,
                    status="INVESTIGATE",
                    evidence=f"CNAME points to {provider} - fingerprint not confirmed",
                    severity="LOW"
                )
        except Exception:
            return TakeoverRecord(
                subdomain=subdomain,
                cname_chain=[cname_val],
                provider=provider,
                status="INVESTIGATE",
                evidence=f"CNAME points to {provider} - host unreachable",
                severity="LOW"
            )
        return None

    def _passive_scan(self):
        """Passive-only CNAME fingerprint scan — no HTTP requests."""
        records = []
        cname_map = self._get_cnames()
        for sub, cnames in cname_map.items():
            for cname_val in cnames:
                provider, severity = self._match_provider(cname_val)
                if provider:
                    records.append(TakeoverRecord(
                        subdomain=sub,
                        cname_chain=[cname_val],
                        provider=provider,
                        status="INVESTIGATE",
                        evidence=f"CNAME {cname_val!r} matches {provider} fingerprint (passive)",
                        severity=severity or "LOW",
                    ))
        return records

    async def scan(self):
        cname_map = self._get_cnames()
        # Always do passive fingerprint scan first
        passive_records = self._passive_scan()
        passive_subs = {r.subdomain for r in passive_records}
        # If policy allows active, do HTTP verification
        tasks = []
        for sub, cnames in cname_map.items():
            for cname_val in cnames:
                tasks.append(self._check_takeover(sub, cname_val))
        if tasks:
            results = await asyncio.gather(*tasks, return_exceptions=True)
            active_records = [r for r in results if isinstance(r, TakeoverRecord)]
            # Merge: prefer active results, fall back to passive for subs not covered
            active_subs = {r.subdomain for r in active_records}
            merged = list(active_records)
            for pr in passive_records:
                if pr.subdomain not in active_subs:
                    merged.append(pr)
            return merged
        return passive_records


# Ã¢â€â‚¬Ã¢â€â‚¬ SCORE ENGINE Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
class ScoreEngine:
    RISKY_CATEGORIES = {"web_server", "backend", "cms", "framework"}
    HIGH_RISK_TECHS = {"WordPress", "Drupal", "Joomla", "Magento", "ASP.NET",
                       "PHP", "Apache", "IIS", "Tomcat"}

    def __init__(self, result):
        self.result = result

    def attack_surface_score(self):
        import math
        score = 0
        # subdomain_coverage: log10(subdomain_count+1) * 10, max 20pts
        sub_count = len(self.result.subdomains)
        score += min(math.log10(sub_count + 1) * 10, 20)
        # ports_exposed: count * 0.1, max 10pts
        port_count = sum(len(r.get("open_ports", []) if isinstance(r, dict) else r.open_ports or [])
                         for r in self.result.ip_records)
        score += min(port_count * 0.1, 10)
        # cloud_assets: count * 0.5, max 10pts
        cloud_count = len(self.result.cloud_assets)
        score += min(cloud_count * 0.5, 10)
        # emails_found: log10(email_count+1) * 3, max 10pts
        email_count = len(self.result.emails)
        score += min(math.log10(email_count + 1) * 3, 10)
        # sensitive_archive_files: count * 2, max 10pts
        wayback = self.result.wayback_urls
        if isinstance(wayback, dict):
            sensitive_count = len(wayback.get("sensitive_files", []))
            score += min(sensitive_count * 2, 10)
        # takeover_risk: takeover_candidates * 15, max 15pts
        takeover_count = len([t for t in self.result.takeover_records
                               if (t.get("status") if isinstance(t, dict) else t.status) in ("VULNERABLE", "INVESTIGATE", "LIKELY_VULNERABLE")])
        score += min(takeover_count * 15, 15)
        return min(int(score), 100)

    def technology_risk_score(self):
        score = 0
        for tech in self.result.technologies:
            name = tech.get("name") if isinstance(tech, dict) else tech.name
            cat = tech.get("category") if isinstance(tech, dict) else tech.category
            if name in self.HIGH_RISK_TECHS:
                score += 12
            elif cat in self.RISKY_CATEGORIES:
                score += 6
            else:
                score += 2
        return min(score, 100)

    def exposure_score(self):
        score = 0
        breach_count = len(self.result.breach_records)
        score += min(breach_count * 20, 40)
        rep = self.result.reputation_data
        vt = rep.get("virustotal", {})
        if isinstance(vt, dict):
            malicious = vt.get("malicious", 0)
            score += min(malicious * 5, 30)
        otx = rep.get("otx", {})
        if isinstance(otx, dict):
            pulse_count = otx.get("pulse_count", 0)
            score += min(pulse_count * 2, 20)
        wayback = self.result.wayback_urls
        if isinstance(wayback, dict):
            interesting = wayback.get("interesting", [])
            score += min(len(interesting) * 1, 10)
        return min(score, 100)

    def vulnerability_score(self):
        score = 0
        for v in self.result.vulnerabilities:
            if not isinstance(v, dict):
                continue
            sev = str(v.get("severity", "INFO") or "INFO").upper()
            # Try to get CVSS score
            cvss = float(v.get("cvss", 0) or v.get("cvss_score", 0) or 0)
            if sev == "CRITICAL" or cvss >= 9:
                score += 5  # 5pts each, max 25pts
            elif sev == "HIGH" or cvss >= 7:
                score += 2  # 2pts each, max 15pts
            elif sev == "MEDIUM" or cvss >= 4:
                score += 0.5  # 0.5pts each, max 10pts
        return min(int(score), 100)

    def _risk_level(self, overall: float) -> str:
        if overall >= 81:
            return "SEVERE"
        if overall >= 66:
            return "CRITICAL"
        if overall >= 41:
            return "HIGH"
        if overall >= 21:
            return "MEDIUM"
        return "LOW"

    def explain_scores(self):
        atk  = self.attack_surface_score()
        tech = self.technology_risk_score()
        exp  = self.exposure_score()
        vuln = self.vulnerability_score()
        overall = round(atk * 0.30 + exp * 0.30 + vuln * 0.25 + tech * 0.15, 1)
        return {
            "attack_surface": atk,
            "technology_risk": tech,
            "exposure": exp,
            "vulnerability": vuln,
            "overall": overall,
            "risk_level": self._risk_level(overall).lower(),
        }


# Ã¢â€â‚¬Ã¢â€â‚¬ VULNERABILITY INTELLIGENCE Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
class VulnerabilityIntelligence:
    """Multi-source passive vulnerability detection Ã¢â‚¬â€ no direct target contact."""

    PORT_VULNS = {
        21:    {"title": "FTP Exposed",                  "severity": "MEDIUM",   "remediation": "Disable FTP or restrict access. Use SFTP instead.",
                "desc": "FTP service exposed - potential anonymous access or credential brute-force."},
        22:    {"title": "SSH Exposed",                   "severity": "LOW",      "remediation": "Restrict SSH to known IP ranges. Use key-based authentication only.",
                "desc": "SSH exposed to internet - verify strong key-based authentication is enforced."},
        23:    {"title": "Telnet Exposed",                "severity": "HIGH",     "remediation": "Disable Telnet and replace it with SSH.",
                "desc": "Telnet exposed - unencrypted protocol transmitting credentials in cleartext."},
        25:    {"title": "SMTP Exposed",                  "severity": "MEDIUM",   "remediation": "Configure SMTP to require authentication and restrict relaying.",
                "desc": "SMTP service exposed - check for open relay and credential exposure."},
        80:    {"title": "HTTP Without HTTPS",            "severity": "LOW",      "remediation": "Configure HTTPS and redirect all HTTP traffic to HTTPS.",
                "desc": "Web server running on HTTP only - data transmitted in cleartext."},
        445:   {"title": "SMB Exposed",                   "severity": "MEDIUM",   "remediation": "Restrict SMB ports 445/139 at the perimeter and review exposure necessity.",
                "desc": "SMB exposed - risk of EternalBlue (MS17-010) and lateral movement attacks."},
        3306:  {"title": "MySQL Database Exposed",        "severity": "HIGH",     "remediation": "Block port 3306 via firewall. Database should not be publicly accessible.",
                "desc": "MySQL database exposed to internet - risk of data exfiltration and remote exploitation."},
        3389:  {"title": "RDP Exposed",                   "severity": "MEDIUM",   "remediation": "Restrict RDP access via VPN. Enable Network Level Authentication.",
                "desc": "Remote Desktop Protocol exposed - brute force and BlueKeep exploit risk."},
        4443:  {"title": "Alternative HTTPS Port",        "severity": "LOW",      "remediation": "Review necessity of alternative HTTPS port exposure.",
                "desc": "Alternative HTTPS port 4443 exposed to internet."},
        5432:  {"title": "PostgreSQL Database Exposed",   "severity": "HIGH",     "remediation": "Block port 5432 via firewall. Database should not be publicly accessible.",
                "desc": "PostgreSQL database exposed to internet - risk of data exfiltration."},
        6379:  {"title": "Redis Exposed",                 "severity": "HIGH",     "remediation": "Block port 6379 via firewall. Configure Redis authentication (requirepass).",
                "desc": "Redis exposed - often unauthenticated by default, allowing full data access."},
        8080:  {"title": "Alternative HTTP Port",         "severity": "LOW",      "remediation": "Review necessity of alternative HTTP port. Ensure it enforces same security controls.",
                "desc": "Alternative web port 8080 exposed - may bypass WAF or security controls."},
        8443:  {"title": "Alternative HTTPS Port",        "severity": "LOW",      "remediation": "Review necessity of alternative HTTPS port exposure.",
                "desc": "Alternative HTTPS port 8443 exposed to internet."},
        8888:  {"title": "Dev/Jupyter Port Exposed",      "severity": "MEDIUM",   "remediation": "Restrict development ports from public internet. Use VPN or SSH tunneling.",
                "desc": "Port 8888 exposed - possible Jupyter notebook or development server with no authentication."},
        9200:  {"title": "Elasticsearch Exposed",         "severity": "HIGH",     "remediation": "Block port 9200 via firewall. Enable Elasticsearch security (X-Pack).",
                "desc": "Elasticsearch exposed to internet - risk of data exfiltration or index manipulation."},
        11211: {"title": "Memcached Exposed",             "severity": "MEDIUM",   "remediation": "Block port 11211 via firewall. Memcached has no authentication by default.",
                "desc": "Memcached exposed - DDoS amplification vector and unauthenticated data access."},
        27017: {"title": "MongoDB Exposed",               "severity": "HIGH",     "remediation": "Block port 27017 via firewall. Enable MongoDB authentication and TLS.",
                "desc": "MongoDB exposed to internet - risk of data exfiltration or ransomware."},
        2375:  {"title": "Docker API Exposed",            "severity": "HIGH",     "remediation": "Immediately block port 2375. Use TLS-authenticated Docker socket (2376).",
                "desc": "Docker daemon API exposed unauthenticated - allows full host takeover via container escape."},
    }

    # Maps technology name Ã¢â€ â€™ (vendor, product) for cve.circl.lu CVE search
    TECH_CVE_MAP: Dict[str, tuple] = {
        "WordPress":   ("wordpress",    "wordpress"),
        "Drupal":      ("drupal",       "drupal"),
        "Joomla":      ("joomla",       "joomla"),
        "Magento":     ("magento",      "magento"),
        "Apache":      ("apache",       "http_server"),
        "Nginx":       ("nginx",        "nginx"),
        "Tomcat":      ("apache",       "tomcat"),
        "IIS":         ("microsoft",    "internet_information_server"),
        "PHP":         ("php",          "php"),
        "Django":      ("djangoproject","django"),
        "Laravel":     ("laravel",      "laravel"),
        "Spring":      ("vmware",       "spring_framework"),
        "OpenResty":   ("openresty",    "openresty"),
        "jQuery":      ("jquery",       "jquery"),
        "ASP.NET":     ("microsoft",    "asp.net"),
        "Ruby-Rails":  ("rubyonrails",  "ruby_on_rails"),
        "Flask":       ("palletsprojects","flask"),
        "Struts":      ("apache",       "struts"),
    }
    TECH_OSV_PACKAGE_MAP: Dict[str, tuple[str, str]] = {
        "Django": ("PyPI", "django"),
        "Flask": ("PyPI", "flask"),
        "Laravel": ("Packagist", "laravel/framework"),
        "jQuery": ("npm", "jquery"),
        "Spring": ("Maven", "org.springframework:spring-core"),
    }

    def __init__(self, domain, mode, session, ip_records, dns_records, ssl_info,
                 security_headers, takeover_records, technologies: list = None):
        self.domain = domain
        self.mode = mode
        self.session = session
        self.ip_records = ip_records
        self.dns_records = dns_records
        self.ssl_info = ssl_info
        self.security_headers = security_headers
        self.takeover_records = takeover_records
        self.technologies = technologies or []
        self.timeout = TIMEOUTS[mode]

    def _vuln(self, **kw) -> dict:
        return {
            "cve_id":        kw.get("cve_id", ""),
            "title":         kw.get("title", ""),
            "description":   kw.get("description", ""),
            "severity":      kw.get("severity", "INFO"),
            "cvss_score":    kw.get("cvss_score"),
            "affected_asset":kw.get("affected_asset", self.domain),
            "source":        kw.get("source", "analysis"),
            "remediation":   kw.get("remediation", ""),
            "references":    kw.get("references", []),
            "classification": kw.get("classification", "evidenced"),
            "confidence":    kw.get("confidence"),
            "evidence_strength": kw.get("evidence_strength", "strong"),
        }

    async def _fetch_cve_details(self, cve_id: str) -> dict:
        details: dict = {}
        try:
            resp = await _safe_get(self.session, f"https://cve.circl.lu/api/cve/{cve_id}", timeout=10)
            if resp and resp.status == 200:
                data = await resp.json(content_type=None)
                details["summary"]    = (data.get("summary") or "")[:300]
                details["cvss"]       = data.get("cvss")
                details["cvss3"]      = data.get("cvss3")
                details["references"] = data.get("references", [])[:5]
        except Exception:
            pass
        return details

    async def _fetch_epss(self, cve_id: str) -> dict:
        """Fetch EPSS (Exploit Prediction Scoring System) score for a CVE."""
        try:
            resp = await _safe_get(
                self.session,
                f"https://api.first.org/data/v1/epss?cve={cve_id}",
                timeout=8
            )
            if resp and resp.status == 200:
                data = await resp.json(content_type=None)
                items = data.get("data", [])
                if items:
                    return {
                        "epss": float(items[0].get("epss", 0)),
                        "percentile": float(items[0].get("percentile", 0)),
                    }
        except Exception:
            pass
        return {}

    async def _check_nuclei_template(self, cve_id: str) -> bool:
        """Check if a public Nuclei template exists for this CVE."""
        try:
            year = cve_id.split("-")[1] if "-" in cve_id else ""
            if not year:
                return False
            url = (f"https://raw.githubusercontent.com/projectdiscovery/"
                   f"nuclei-templates/main/cves/{year}/{cve_id.lower()}.yaml")
            resp = await _safe_get(self.session, url, timeout=6)
            return resp is not None and resp.status == 200
        except Exception:
            return False

    async def _fetch_tech_cves(self) -> list:
        """Fetch CVEs for detected technologies from cve.circl.lu Ã¢â‚¬â€ no API key required."""
        vulns: list = []
        seen_cves: set = set()
        for tech in (self.technologies or [])[:10]:
            name = tech.get("name", "") if isinstance(tech, dict) else getattr(tech, "name", "")
            if name not in self.TECH_CVE_MAP:
                continue
            vendor, product = self.TECH_CVE_MAP[name]
            try:
                url = f"https://cve.circl.lu/api/search/{vendor}/{product}"
                resp = await _safe_get(self.session, url, timeout=15)
                if resp and resp.status == 200:
                    data = await resp.json(content_type=None)
                    results = data.get("results", [])
                    added = 0
                    for cve in results[:15]:
                        cve_id = cve.get("id", "")
                        if not cve_id or cve_id in seen_cves:
                            continue
                        try:
                            score = float(cve.get("cvss3") or cve.get("cvss") or 0)
                        except (ValueError, TypeError):
                            score = 0.0
                        if score < 7.0:
                            continue
                        seen_cves.add(cve_id)
                        sev = "HIGH" if score >= 9.0 else "MEDIUM"
                        summary = (cve.get("summary") or "")[:300]
                        vulns.append(self._vuln(
                            cve_id=cve_id,
                            title=f"{cve_id} - {name}: {summary[:80]}",
                            description=summary,
                            severity=sev,
                            cvss_score=score,
                            affected_asset=self.domain,
                            source="tech_cve_mapping",
                            remediation=f"Update {name} to the latest patched version immediately.",
                            references=(cve.get("references") or [])[:3],
                            classification="probable",
                            confidence=0.66,
                            evidence_strength="medium",
                        ))
                        added += 1
                        if added >= 5:
                            break
            except Exception:
                pass
            await asyncio.sleep(0.3)
        return vulns

    async def _osv_vuln_lookup(self, tech_name: str, version: str = "") -> list:
        tech_key = str(tech_name or "").strip()
        package_meta = self.TECH_OSV_PACKAGE_MAP.get(tech_key)
        if not package_meta:
            return []
        ecosystem, package_name = package_meta
        vulns = []
        body = {"package": {"name": package_name, "ecosystem": ecosystem}}
        if version:
            body["version"] = str(version)
        for attempt in range(3):
            try:
                resp = await _safe_post(self.session, "https://api.osv.dev/v1/query", timeout=30, json=body)
                if not resp or resp.status in {429, 500, 502, 503, 504}:
                    if attempt < 2:
                        await asyncio.sleep(float(2 ** attempt))
                    continue
                if resp.status != 200:
                    break
                data = await resp.json(content_type=None)
                for item in (data.get("vulns") or [])[:5]:
                    aliases = [str(a or "").upper() for a in (item.get("aliases") or [])]
                    cve_id = next((a for a in aliases if a.startswith("CVE-")), "")
                    summary = str(item.get("summary") or item.get("details") or "").strip()[:300]
                    refs = [r.get("url", "") for r in (item.get("references") or []) if isinstance(r, dict) and r.get("url")][:3]
                    record = self._vuln(
                        cve_id=cve_id,
                        title=f"{cve_id or 'OSV'} - {package_name}",
                        description=summary,
                        severity="MEDIUM",
                        affected_asset=self.domain,
                        source="osv_dev",
                        remediation=f"Review {package_name} exposure and update to a patched release.",
                        references=refs,
                        classification="probable",
                        confidence=0.55,
                        evidence_strength="medium",
                    )
                    if version:
                        record["observed_version"] = str(version)
                    if tech_key:
                        record["observed_technology"] = tech_key
                    if tech_key and version:
                        record["evidence"] = f"Passive technology detection observed {tech_key} {version}"
                    vulns.append(record)
                break
            except Exception:
                if attempt < 2:
                    await asyncio.sleep(float(2 ** attempt))
        return vulns

    async def _fetch_cvesearch_products(self) -> list:
        vulns: list = []
        seen_cves: set = set()
        for tech in (self.technologies or [])[:10]:
            name = tech.get("name", "") if isinstance(tech, dict) else getattr(tech, "name", "")
            product = str(name or "").strip().lower().replace(" ", "_")
            if not product:
                continue
            urls = [f"https://cve.circl.lu/api/search/{product}"]
            vendor_map = self.TECH_CVE_MAP.get(str(name or "").strip())
            if vendor_map:
                vendor, mapped_product = vendor_map
                urls.append(f"https://cve.circl.lu/api/search/{vendor}/{mapped_product}")
            data = None
            for url in urls:
                for attempt in range(3):
                    try:
                        resp = await _safe_get(self.session, url, timeout=30)
                        if not resp or resp.status in {429, 500, 502, 503, 504}:
                            if attempt < 2:
                                await asyncio.sleep(float(2 ** attempt))
                            continue
                        if resp.status != 200:
                            break
                        data = await resp.json(content_type=None)
                        break
                    except Exception:
                        if attempt < 2:
                            await asyncio.sleep(float(2 ** attempt))
                if data:
                    break
            rows = []
            if isinstance(data, dict):
                if isinstance(data.get("results"), list):
                    rows = data.get("results", [])
                elif isinstance(data.get("data"), list):
                    rows = data.get("data", [])
            elif isinstance(data, list):
                rows = data
            added = 0
            for cve in rows[:20]:
                if not isinstance(cve, dict):
                    continue
                cve_id = str(cve.get("id") or cve.get("cve") or "").strip()
                if not cve_id or cve_id in seen_cves:
                    continue
                try:
                    score = float(cve.get("cvss3") or cve.get("cvss") or 0)
                except (TypeError, ValueError):
                    score = 0.0
                if score < 7.0:
                    continue
                seen_cves.add(cve_id)
                vulns.append(self._vuln(
                    cve_id=cve_id,
                    title=f"{cve_id} - {name}",
                    description=str(cve.get("summary") or cve.get("description") or "").strip()[:300],
                    severity="HIGH" if score >= 9.0 else "MEDIUM",
                    cvss_score=score,
                    affected_asset=self.domain,
                    source="cvesearch",
                    remediation=f"Review {name} version exposure and update to a patched release.",
                    references=(cve.get("references") or [])[:3] if isinstance(cve.get("references"), list) else [],
                    classification="probable",
                    confidence=0.6,
                    evidence_strength="medium",
                ))
                added += 1
                if added >= 5:
                    break
            await asyncio.sleep(0.2)
        return vulns

    def _analyze_ports(self) -> list:
        vulns = []
        for ip_rec in self.ip_records:
            ip    = ip_rec.get("ip", "")    if isinstance(ip_rec, dict) else getattr(ip_rec, "ip",    "")
            ports = ip_rec.get("open_ports", []) if isinstance(ip_rec, dict) else getattr(ip_rec, "open_ports", [])
            for port in (ports or []):
                if port in self.PORT_VULNS:
                    pv = self.PORT_VULNS[port]
                    vulns.append(self._vuln(
                        cve_id=f"GHOST-PORT-{port}",
                        title=pv["title"],
                        description=pv["desc"],
                        severity=pv["severity"],
                        affected_asset=f"{ip}:{port}",
                        source="port_analysis",
                        remediation=pv["remediation"],
                        classification="probable",
                        confidence=0.72,
                        evidence_strength="medium",
                    ))
        return vulns

    def _analyze_dns(self) -> list:
        """Legacy heuristic DNS findings are intentionally disabled.

        Production vulnerability output is restricted to CVE-backed passive evidence in
        `analyze()` to avoid absence-based or policy-opinion findings.
        """
        return []

    def _analyze_ssl(self) -> list:
        """Legacy heuristic SSL/header findings are intentionally disabled."""
        return []

    def _analyze_headers(self) -> list:
        """Legacy heuristic header findings are intentionally disabled."""
        return []

    def _analyze_takeovers(self) -> list:
        vulns = []
        sev_map = {"VULNERABLE": "HIGH", "LIKELY_VULNERABLE": "MEDIUM", "INVESTIGATE": "LOW"}
        for t in self.takeover_records:
            status    = t.get("status",    "") if isinstance(t, dict) else getattr(t, "status",    "")
            subdomain = t.get("subdomain", "") if isinstance(t, dict) else getattr(t, "subdomain", "")
            provider  = t.get("provider",  "") if isinstance(t, dict) else getattr(t, "provider",  "")
            if status in ("VULNERABLE", "LIKELY_VULNERABLE", "INVESTIGATE"):
                slug = subdomain.replace(".", "-").upper()[:20]
                vulns.append(self._vuln(
                    cve_id=f"GHOST-TAKEOVER-{slug}",
                    title=f"Subdomain takeover exposure: {subdomain}",
                    description=f"Passive DNS/provider fingerprints indicate {'a strong' if status == 'VULNERABLE' else 'a possible'} takeover condition via {provider}.",
                    severity=sev_map.get(status, "LOW"),
                    affected_asset=subdomain, source="takeover",
                    remediation=f"Remove dangling CNAME for {subdomain} or claim the {provider} resource immediately.",
                    classification="evidenced" if status == "VULNERABLE" else "probable",
                    confidence=0.88 if status == "VULNERABLE" else 0.7,
                    evidence_strength="strong" if status == "VULNERABLE" else "medium",
                ))
        return vulns

    async def _fetch_shodan_cves(self) -> list:
        vulns = []
        seen_cves: set = set()
        for ip_rec in self.ip_records:
            ip        = ip_rec.get("ip",    "") if isinstance(ip_rec, dict) else getattr(ip_rec, "ip",    "")
            cve_list  = ip_rec.get("vulns", []) if isinstance(ip_rec, dict) else getattr(ip_rec, "vulns", [])
            parsed_cves = parse_shodan_cve_ids({"vulns": cve_list})
            for cve_id in (parsed_cves or []):
                if cve_id in seen_cves:
                    continue
                seen_cves.add(cve_id)
                try:
                    details, epss_data, has_nuclei = await asyncio.gather(
                        self._fetch_cve_details(cve_id),
                        self._fetch_epss(cve_id),
                        self._check_nuclei_template(cve_id),
                        return_exceptions=True
                    )
                    if isinstance(details, Exception): details = {}
                    if isinstance(epss_data, Exception): epss_data = {}
                    if isinstance(has_nuclei, Exception): has_nuclei = False
                    severity = "MEDIUM"
                    cvss = (details.get("cvss3") or details.get("cvss")) if isinstance(details, dict) else None
                    if cvss:
                        try:
                            score = float(cvss)
                            if score >= 9.0:   severity = "HIGH"
                            elif score >= 7.0: severity = "MEDIUM"
                            elif score >= 4.0: severity = "LOW"
                            else:              severity = "LOW"
                        except (ValueError, TypeError):
                            pass
                    # EPSS can raise urgency, but passive-only evidence does not justify CRITICAL on its own.
                    epss_score = epss_data.get("epss", 0) if isinstance(epss_data, dict) else 0
                    if epss_score > 0.5 and severity == "LOW":
                        severity = "MEDIUM"
                    elif epss_score > 0.8 and severity == "MEDIUM":
                        severity = "HIGH"
                    v = self._vuln(
                        cve_id=cve_id,
                        title=f"{cve_id} - {((details.get('summary','') if isinstance(details,dict) else '') or '')[:80]}",
                        description=details.get("summary", "") if isinstance(details, dict) else "",
                        severity=severity,
                        cvss_score=cvss,
                        affected_asset=ip,
                        source="shodan_internetdb",
                        references=(details.get("references", [])[:3] if isinstance(details, dict) else []),
                        remediation="Apply the relevant vendor security patches for this CVE.",
                        classification="probable",
                        confidence=0.68,
                        evidence_strength="medium",
                    )
                    if epss_score:
                        v["epss_score"] = round(epss_score, 4)
                        v["epss_percentile"] = round(epss_data.get("percentile", 0), 4) if isinstance(epss_data, dict) else 0
                    if has_nuclei:
                        v["has_nuclei_template"] = True
                    vulns.append(v)
                    await asyncio.sleep(0.25)
                except Exception:
                    pass
        return vulns

    async def analyze(self) -> list:
        """Return only evidence-backed passive vulnerability records."""
        all_vulns: list = []
        if self.mode in ("balanced", "deep"):
            shodan_vulns = await self._fetch_shodan_cves()
            all_vulns.extend(shodan_vulns)
            osv_vulns = []
            for tech in (self.technologies or [])[:10]:
                if not isinstance(tech, dict):
                    continue
                version = str(tech.get("version", "") or "").strip()
                if not version:
                    continue
                try:
                    osv_vulns.extend(await self._osv_vuln_lookup(tech.get("name", ""), version))
                except Exception:
                    pass
                await asyncio.sleep(0.2)
            all_vulns.extend(osv_vulns)
        # Deduplicate
        seen: set = set()
        deduped = []
        for v in all_vulns:
            if not isinstance(v, dict):
                continue
            cve_id = str(v.get("cve_id", "") or "").strip().upper()
            if not cve_id.startswith("CVE-"):
                continue
            v["cve_id"] = cve_id
            key = cve_id + "|" + str(v.get("affected_asset", "") or "")
            if key not in seen:
                seen.add(key)
                deduped.append(v)
        sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        deduped.sort(key=lambda x: sev_order.get(x.get("severity", "INFO"), 99))
        return deduped


# Ã¢â€â‚¬Ã¢â€â‚¬ CORRELATION ENGINE Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
class CorrelationEngine:
    """Connects findings across modules to surface high-value intelligence chains."""

    async def analyze(self, result) -> dict:
        correlations = []
        domain = result.domain if hasattr(result, "domain") else result.get("domain", "")
        subdomains    = result.subdomains    if hasattr(result, "subdomains")    else result.get("subdomains", [])
        emails        = result.emails        if hasattr(result, "emails")        else result.get("emails", [])
        breach_records= result.breach_records if hasattr(result, "breach_records") else result.get("breach_records", [])
        technologies  = result.technologies  if hasattr(result, "technologies")  else result.get("technologies", [])
        dns_records   = result.dns_records   if hasattr(result, "dns_records")   else result.get("dns_records", [])
        ip_records    = result.ip_records    if hasattr(result, "ip_records")    else result.get("ip_records", [])
        cloud_assets  = result.cloud_assets  if hasattr(result, "cloud_assets")  else result.get("cloud_assets", [])
        wayback_urls  = result.wayback_urls  if hasattr(result, "wayback_urls")  else result.get("wayback_urls", {})
        takeover_records = result.takeover_records if hasattr(result, "takeover_records") else result.get("takeover_records", [])
        vulnerabilities  = result.vulnerabilities  if hasattr(result, "vulnerabilities")  else result.get("vulnerabilities", [])

        def get_field(obj, *keys):
            for k in keys:
                if isinstance(obj, dict):
                    v = obj.get(k)
                else:
                    v = getattr(obj, k, None)
                if v is not None:
                    return v
            return None
        seen_marker = _utcnow_iso()

        def add_corr(
            corr_type: str,
            severity: str,
            title: str,
            detail: str,
            assets: List[str],
            action: str,
            *,
            classification: str = "probable",
            confidence: float = 0.7,
            evidence_strength: str = "multi_signal",
        ) -> None:
            if not title or not detail:
                return
            correlations.append({
                "type": corr_type,
                "severity": severity,
                "title": title,
                "detail": detail,
                "assets": assets[:5],
                "action": action,
                "classification": classification,
                "confidence": round(max(0.2, min(float(confidence or 0.7), 0.99)), 3),
                "evidence_strength": evidence_strength,
                "source": "correlation_engine",
                "first_seen": seen_marker,
                "last_seen": seen_marker,
            })

        # Build IP -> vulnerability index (evidence only from explicit vulnerability records).
        ip_to_vulns: Dict[str, List[Dict[str, str]]] = {}
        for v in vulnerabilities:
            asset = str(get_field(v, "affected_asset") or "")
            ip = asset.split(":")[0] if ":" in asset else asset
            sev = str(get_field(v, "severity") or "LOW").upper()
            cve = str(get_field(v, "cve_id") or get_field(v, "title") or "")
            if ip and cve:
                ip_to_vulns.setdefault(ip, []).append({"id": cve, "severity": sev})

        for sub in subdomains:
            sname = get_field(sub, "name") or ""
            sips = get_field(sub, "ips") or []
            for ip in sips:
                rows = ip_to_vulns.get(ip, [])
                if not rows:
                    continue
                hi = [r["id"] for r in rows if r.get("severity") in {"CRITICAL", "HIGH"}]
                sev = "MEDIUM" if hi else "LOW"
                add_corr(
                    "subdomain_has_cves",
                    sev,
                    f"{sname} linked to known vulnerabilities",
                    f"IP {ip} has {len(rows)} vulnerability records ({', '.join((hi or [rows[0]['id']])[:3])}).",
                    [sname, ip],
                    "Prioritize patch validation and service hardening for this asset.",
                    classification="evidenced",
                    confidence=0.86 if hi else 0.72,
                    evidence_strength="strong",
                )

        breach_with_passwords = [b for b in breach_records if "Passwords" in (get_field(b, "data_types") or [])]

        tech_names_lower = " ".join((get_field(t, "name") or "").lower() for t in technologies)
        has_mfa = any(x in tech_names_lower for x in ["okta", "auth0", "duo", "azure-ad", "google-sso"])
        has_waf = any(x in tech_names_lower for x in ["cloudflare", "waf", "akamai", "imperva", "f5", "incapsula"])

        if emails and breach_with_passwords:
            breach_names = [get_field(b, "name") or "" for b in breach_with_passwords[:3]]
            sev = "HIGH" if len(breach_with_passwords) >= 2 and len(emails) >= 3 else "MEDIUM"
            add_corr(
                "email_in_breach_with_passwords",
                sev,
                "Employee emails appear in password-related breaches",
                (f"{len(emails)} email(s) discovered and {len(breach_with_passwords)} breach record(s) include passwords: "
                 f"{', '.join(breach_names)}."),
                [(get_field(e, "email") or str(e)) for e in emails[:3]],
                "Force password reset and enforce MFA for exposed accounts.",
                classification="evidenced",
                confidence=0.86 if sev == "HIGH" else 0.76,
                evidence_strength="strong",
            )

        if emails and not has_mfa:
            add_corr(
                "emails_no_mfa_detected",
                "MEDIUM",
                "Emails discovered without observed MFA provider signals",
                (f"{len(emails)} email(s) found while no clear MFA/SSO provider fingerprint was detected. "
                 "This is an inference from passive signals."),
                [(get_field(e, "email") or str(e)) for e in emails[:3]],
                "Validate identity controls and ensure MFA is enforced organization-wide.",
                classification="heuristic",
                confidence=0.48,
                evidence_strength="weak",
            )

        dev_subs = [
            s for s in subdomains
            if any(k in (get_field(s, "name") or "").lower() for k in ["dev", "staging", "test", "uat", "qa", "sandbox"])
        ]
        if dev_subs and not has_waf:
            resolved = [s for s in dev_subs if get_field(s, "ips")]
            sev = "MEDIUM" if len(resolved) >= 2 else "LOW"
            add_corr(
                "dev_environments_no_waf",
                sev,
                f"{len(dev_subs)} non-production hostnames without WAF signal",
                (f"Non-production hosts detected ({', '.join((get_field(s, 'name') or '' for s in dev_subs[:3]))}) "
                 "without obvious WAF technology evidence."),
                [(get_field(s, "name") or "") for s in dev_subs[:4]],
                "Review exposure policy for non-production assets and apply access controls.",
                classification="probable",
                confidence=0.74 if sev == "HIGH" else 0.65,
                evidence_strength="medium",
            )

        evidenced_buckets = [
            a for a in cloud_assets
            if (get_field(a, "asset_type") or "") in ("s3", "gcs", "azure", "bucket")
            and (get_field(a, "classification") or "heuristic") in ("evidenced", "probable")
        ]
        interesting_urls = wayback_urls.get("interesting_urls", wayback_urls.get("interesting", [])) if isinstance(wayback_urls, dict) else []
        sensitive_paths = [u for u in (interesting_urls if isinstance(interesting_urls, list) else []) if any(k in str(u).lower() for k in [".env", "backup", "config", "admin", "db"])]
        if evidenced_buckets and sensitive_paths:
            add_corr(
                "cloud_and_sensitive_paths",
                "MEDIUM",
                "Cloud assets and sensitive historical paths co-occur",
                f"Found {len(evidenced_buckets)} cloud asset(s) with evidence and {len(sensitive_paths)} sensitive archive path hint(s).",
                [(get_field(a, "name") or "") for a in evidenced_buckets[:2]],
                "Validate cloud access policy and review historical exposure of sensitive paths.",
                classification="probable",
                confidence=0.66,
                evidence_strength="medium",
            )

        dmarc_records = [r for r in dns_records if (get_field(r, "type") or "") == "TXT" and "v=DMARC1" in (get_field(r, "value") or "")]
        has_enforced_dmarc = any(("p=reject" in (get_field(r, "value") or "") or "p=quarantine" in (get_field(r, "value") or "")) for r in dmarc_records)
        if emails and not has_enforced_dmarc:
            sev = "MEDIUM" if len(emails) >= 2 else "LOW"
            add_corr(
                "email_spoofing_risk",
                sev,
                "No enforced DMARC policy with discovered email identities",
                (f"DMARC policy is missing or not enforced while {len(emails)} email identity/ies were discovered for {domain}."),
                [domain],
                "Publish DMARC with enforcement policy and monitor spoofing attempts.",
                classification="evidenced",
                confidence=0.84 if sev == "MEDIUM" else 0.7,
                evidence_strength="strong",
            )

        vulnerable_takeovers = [t for t in takeover_records if (get_field(t, "status") or "") in ("VULNERABLE", "LIKELY_VULNERABLE")]
        for vt in vulnerable_takeovers:
            vsub = get_field(vt, "subdomain") or ""
            vprov = get_field(vt, "provider") or ""
            vstatus = str(get_field(vt, "status") or "")
            add_corr(
                "takeover_confirmed",
                "HIGH" if vstatus == "VULNERABLE" else "MEDIUM",
                f"Subdomain {vsub} shows takeover exposure",
                f"CNAME and provider fingerprint suggest unclaimed {vprov} resource on {vsub}.",
                [vsub],
                f"Remove dangling DNS or claim {vprov} resource immediately.",
                classification="evidenced",
                confidence=0.9 if vstatus == "VULNERABLE" else 0.78,
                evidence_strength="strong",
            )

        db_ports = {3306, 5432, 6379, 27017, 9200, 5984, 8091}
        exposed_db_ips = []
        for ip_rec in ip_records:
            ip = get_field(ip_rec, "ip") or ""
            ports = get_field(ip_rec, "open_ports") or []
            if any(p in db_ports for p in ports):
                exposed_db_ips.append(ip)
        if exposed_db_ips:
            sev = "HIGH" if len(exposed_db_ips) >= 2 else "MEDIUM"
            add_corr(
                "database_exposed",
                sev,
                f"Passive data suggests database exposure on {len(exposed_db_ips)} IP(s)",
                f"Passive InternetDB data indicates exposed database-related ports on: {', '.join(exposed_db_ips[:3])}.",
                exposed_db_ips[:3],
                "Verify perimeter controls and restrict database services from public access.",
                classification="evidenced",
                confidence=0.86 if sev == "HIGH" else 0.76,
                evidence_strength="strong",
            )

        devops_tags = ["jenkins", "gitlab", "jira", "confluence", "sonar", "nexus", "artifactory", "rancher", "k8s", "docker", "bamboo", "teamcity", "circleci"]
        exposed_devops = []
        for sub in subdomains:
            sname = get_field(sub, "name") or ""
            stags = get_field(sub, "tags") or []
            sips = get_field(sub, "ips") or []
            if (any(k in sname.lower() for k in devops_tags) or "devops" in (stags if isinstance(stags, list) else [])) and sips:
                exposed_devops.append(sname)
        if exposed_devops:
            sev = "MEDIUM" if len(exposed_devops) >= 2 else "LOW"
            add_corr(
                "devops_tools_exposed",
                sev,
                f"DevOps-related hosts appear internet-facing ({len(exposed_devops)})",
                f"DevOps-like hostnames with resolved IPs found: {', '.join(exposed_devops[:4])}.",
                exposed_devops[:4],
                "Confirm required exposure and enforce stronger access controls (SSO/MFA/VPN).",
                classification="probable",
                confidence=0.78 if sev == "HIGH" else 0.64,
                evidence_strength="medium",
            )

        if len(breach_with_passwords) >= 2 and emails and not has_mfa:
            breach_names = [get_field(b, "name") or "" for b in breach_with_passwords[:4]]
            add_corr(
                "account_takeover_chain",
                "MEDIUM",
                "Credential abuse chain risk (breaches + emails + weak identity signal)",
                (f"Multiple password-related breaches ({', '.join(breach_names)}) + discovered employee emails + "
                 "no clear MFA signal indicate elevated account takeover risk."),
                [(get_field(e, "email") or str(e)) for e in emails[:3]],
                "Enforce MFA and monitor suspicious authentication patterns.",
                classification="probable",
                confidence=0.72,
                evidence_strength="medium",
            )

        sensitive_js = []
        if isinstance(wayback_urls, dict):
            for entry in (wayback_urls.get("js_secrets", wayback_urls.get("interesting_urls", []))):
                if isinstance(entry, dict) and entry.get("secrets"):
                    sensitive_js.append({"url": entry.get("url", ""), "strong": True})
                elif isinstance(entry, str) and ".js" in entry:
                    sensitive_js.append({"url": entry, "strong": False})
        if sensitive_js:
            strong_hits = [x for x in sensitive_js if x["strong"]]
            sev = "MEDIUM" if strong_hits else "LOW"
            add_corr(
                "js_secrets_exposed",
                sev,
                f"Archived JavaScript may expose secrets ({len(sensitive_js)} files)",
                f"Archive analysis found JS files with possible secret indicators: {', '.join((x['url'] for x in sensitive_js[:3]))}.",
                [x["url"] for x in sensitive_js[:3]],
                "Review archived JS artifacts and rotate exposed credentials if confirmed.",
                classification="probable" if strong_hits else "heuristic",
                confidence=0.72 if strong_hits else 0.44,
                evidence_strength="medium" if strong_hits else "weak",
            )

        wayback_subs = set()
        if isinstance(wayback_urls, dict):
            for u in (wayback_urls.get("all", wayback_urls.get("interesting", []))):
                url_str = str(u.get("url", u) if isinstance(u, dict) else u)
                try:
                    host = urlparse(url_str).hostname or ""
                    if host.endswith("." + domain) and host != domain:
                        wayback_subs.add(host.lower())
                except Exception:
                    pass
        current_sub_names = set(get_field(s, "name") or "" for s in subdomains)
        ghost_subs = [s for s in wayback_subs if s not in current_sub_names]
        if ghost_subs:
            add_corr(
                "ghost_subdomains",
                "LOW",
                f"{len(ghost_subs)} archived subdomains not seen in current DNS",
                f"Archived hosts absent from current subdomain inventory: {', '.join(list(ghost_subs)[:4])}.",
                list(ghost_subs)[:4],
                "Validate whether these are retired assets with dangling DNS references.",
                classification="heuristic",
                confidence=0.38,
                evidence_strength="weak",
            )

        sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        correlations.sort(key=lambda x: sev_order.get(x.get("severity", "INFO"), 5))
        # Deduplicate by type+assets combination
        seen_corr: set = set()
        deduped = []
        for c in correlations:
            key = c["type"] + "|" + "|".join(sorted(c.get("assets", [])))
            if key not in seen_corr:
                seen_corr.add(key)
                deduped.append(c)
        return {
            "total": len(deduped),
            "critical": sum(1 for c in deduped if c["severity"] == "CRITICAL"),
            "high":     sum(1 for c in deduped if c["severity"] == "HIGH"),
            "medium":   sum(1 for c in deduped if c["severity"] == "MEDIUM"),
            "findings": deduped,
        }


# Ã¢â€â‚¬Ã¢â€â‚¬ RECON ENGINE ORCHESTRATOR Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
def _analyze_email_security(txt_records: list, dmarc_records: list, dkim_selectors: list) -> dict:
    """Compute a structured email security grade from SPF/DMARC/DKIM findings."""
    spf_present = False
    spf_policy = None
    spf_record = ""
    dmarc_present = False
    dmarc_policy = None
    dmarc_record = ""
    for r in txt_records:
        val = str(r.get("value", "") if isinstance(r, dict) else r).lower()
        if "v=spf1" in val:
            spf_present = True
            spf_record = val
            if "-all" in val:
                spf_policy = "strict"
            elif "~all" in val:
                spf_policy = "softfail"
            elif "+all" in val:
                spf_policy = "permissive"
            elif "?all" in val:
                spf_policy = "neutral"
    for r in dmarc_records:
        val = str(r.get("value", "") if isinstance(r, dict) else r).lower()
        if "v=dmarc1" in val:
            dmarc_present = True
            dmarc_record = val
            if "p=reject" in val:
                dmarc_policy = "reject"
            elif "p=quarantine" in val:
                dmarc_policy = "quarantine"
            elif "p=none" in val:
                dmarc_policy = "none"
    spf_strict = spf_present and spf_policy == "strict"
    dmarc_enforced = dmarc_present and dmarc_policy in ("reject", "quarantine")
    has_dkim = bool(dkim_selectors)
    if spf_strict and dmarc_enforced and has_dkim:
        grade, risk = "A", "LOW"
    elif spf_strict and dmarc_enforced:
        grade, risk = "B", "LOW"
    elif (spf_present and dmarc_enforced) or (spf_strict and dmarc_present):
        grade, risk = "C", "MEDIUM"
    elif spf_present and dmarc_present:
        grade, risk = "D", "HIGH"
    elif spf_present or dmarc_present:
        grade, risk = "D", "HIGH"
    else:
        grade, risk = "F", "CRITICAL"
    return {
        "grade": grade,
        "spoofing_risk": risk,
        "spf": {"present": spf_present, "policy": spf_policy, "record": spf_record},
        "dmarc": {"present": dmarc_present, "policy": dmarc_policy, "record": dmarc_record},
        "dkim_selectors_found": dkim_selectors,
        "email_spoofing_possible": grade in ("D", "F"),
    }


class ReconEngine:
    def __init__(
        self,
        domain,
        mode,
        api_keys,
        output_dir,
        progress_cb=None,
        policy: Optional[ScanPolicy] = None,
        debug_coverage: bool = False,
        source_registry: Optional[SourceRegistry] = None,
    ):
        self.domain = domain.strip().rstrip('.').lower()
        self.mode = mode
        self.api_keys = api_keys
        self.output_dir = Path(output_dir)
        self.timeout = TIMEOUTS[mode]
        self.sem = asyncio.Semaphore(SEMAPHORES[mode])
        self.progress_cb = progress_cb  # async callable(event_type: str, data: dict)
        self.policy = policy or ScanPolicy()
        self.debug_coverage = debug_coverage
        self.source_registry = source_registry or SourceRegistry(
            api_keys=self.api_keys,
            allow_target_requests=self.policy.allow_target_requests,
        )
        if self.mode == "deep":
            for source_name in DEEP_MODE_OPTIONAL_SOURCES:
                self.source_registry.enable_source(source_name)

    async def _emit(self, event_type: str, data: dict):
        if self.progress_cb:
            try:
                await self.progress_cb(event_type, data)
            except Exception:
                pass
        await asyncio.sleep(0)  # yield to event loop so SSE events flush in real-time

    def _make_session(self):
        connector = aiohttp.TCPConnector(
            limit=100,
            limit_per_host=10,
            ssl=True,
            ttl_dns_cache=300,
            force_close=False,
        )
        return aiohttp.ClientSession(connector=connector)

    def _mod_timeout(self, module: str) -> int:
        """Return the hard timeout (seconds) for a given module and current scan mode."""
        base_timeout = MODULE_TIMEOUTS.get(module, {}).get(self.mode, 60)
        active_scans = 1
        try:
            active_scans = max(1, get_http_guard().active_scan_count())
        except Exception:
            active_scans = 1
        concurrency_sensitive = {
            "Subdomain Enumeration",
            "Email Discovery",
            "IP Intelligence",
            "Web Archive",
            "Dork Intelligence",
            "Passive Artifact Intelligence",
            "Cloud Assets",
        }
        if active_scans <= 1 or module not in concurrency_sensitive:
            return base_timeout
        multiplier = min(1.8, 1.0 + (active_scans - 1) * 0.2)
        return int(round(base_timeout * multiplier))

    async def _enrich_cve(self, session: aiohttp.ClientSession, cve_id: str) -> dict:
        """Enrich a CVE with EPSS score, NVD CVSS, Exploit-DB PoC, and Nuclei templates."""
        result = {
            'cve_id': cve_id, 'epss_score': None, 'epss_percentile': None,
            'cvss_score': None, 'description': '', 'has_exploit': False,
            'poc_urls': [], 'exploit_db': [], 'nuclei_templates': [],
        }
        # EPSS — no API key required
        try:
            async with session.get(
                f'https://api.first.org/data/v1/epss?cve={cve_id}',
                timeout=aiohttp.ClientTimeout(total=8)
            ) as r:
                if r.status == 200:
                    data = await r.json(content_type=None)
                    if data.get('data'):
                        result['epss_score'] = float(data['data'][0].get('epss', 0))
                        result['epss_percentile'] = float(data['data'][0].get('percentile', 0))
        except Exception:
            pass
        # NVD — no key, 5 req/30s limit
        try:
            await asyncio.sleep(0.5)
            async with session.get(
                f'https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}',
                timeout=aiohttp.ClientTimeout(total=10)
            ) as r:
                if r.status == 200:
                    data = await r.json(content_type=None)
                    vulns_nvd = data.get('vulnerabilities', [])
                    if vulns_nvd:
                        cve_obj = vulns_nvd[0].get('cve', {})
                        desc = cve_obj.get('descriptions', [{}])[0].get('value', '')
                        result['description'] = desc
                        metrics = cve_obj.get('metrics', {})
                        for key in ['cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2']:
                            if metrics.get(key):
                                result['cvss_score'] = metrics[key][0].get('cvssData', {}).get('baseScore')
                                break
        except Exception:
            pass
        # Exploit-DB — no key required
        try:
            headers = {'Accept': 'application/json', 'X-Requested-With': 'XMLHttpRequest'}
            cve_num = cve_id.replace('CVE-', '')
            async with session.get(
                f'https://www.exploit-db.com/search?cve={cve_num}&type=&platform=&json=true',
                headers=headers, timeout=aiohttp.ClientTimeout(total=10)
            ) as r:
                if r.status == 200:
                    data = await r.json(content_type=None)
                    for item in (data.get('data') or [])[:3]:
                        edb_id = item.get('id') or item.get('edb_id', '')
                        if edb_id:
                            result['exploit_db'].append({
                                'id': str(edb_id),
                                'url': f'https://www.exploit-db.com/exploits/{edb_id}',
                                'title': str(item.get('description', ''))[:100],
                            })
                            result['has_exploit'] = True
        except Exception:
            pass
        # Nuclei templates — GitHub search
        try:
            import urllib.parse as _up
            gh_headers = _github_auth_headers(self.api_keys.get("github_token", ""), accept="application/vnd.github.v3+json")
            q = _up.quote(f'{cve_id} in:file repo:projectdiscovery/nuclei-templates')
            async with session.get(
                f'https://api.github.com/search/code?q={q}&per_page=3',
                headers=gh_headers, timeout=aiohttp.ClientTimeout(total=10)
            ) as r:
                if r.status == 200:
                    data = await r.json(content_type=None)
                    for item in data.get('items', [])[:3]:
                        result['nuclei_templates'].append({
                            'file': item.get('name', ''),
                            'url': item.get('html_url', ''),
                            'path': item.get('path', ''),
                        })
                        result['has_exploit'] = True
            await asyncio.sleep(2)
        except Exception:
            pass
        return result

    async def _run_module(self, module: str, coro):
        """Wrap a module coroutine with a per-module hard timeout."""
        try:
            return await asyncio.wait_for(coro, timeout=self._mod_timeout(module))
        except asyncio.TimeoutError:
            print(f"[SCAN] {module} TIMEOUT after {self._mod_timeout(module)}s")
            raise
        except Exception:
            raise

    @staticmethod
    def _subdomain_ip_literals(subdomains: List[Dict[str, Any]]) -> List[str]:
        ips: List[str] = []
        for sub in subdomains:
            if not isinstance(sub, dict):
                continue
            ips.extend(_extract_ip_literals(sub.get("ips") or sub.get("ip_addresses") or sub.get("resolved_ips") or []))
        return sorted(set(ips))

    @staticmethod
    def _subdomain_ip_port_hints(subdomains: List[Dict[str, Any]]) -> Dict[str, List[int]]:
        hints: Dict[str, set[int]] = {}
        for sub in (subdomains or []):
            if not isinstance(sub, dict):
                continue
            raw_ports = sub.get("ports") or sub.get("open_ports") or []
            ports = {
                int(port)
                for port in raw_ports
                if isinstance(port, int) or str(port).isdigit()
            }
            if not ports:
                continue
            for ip in _extract_ip_literals(sub.get("ips") or sub.get("ip_addresses") or sub.get("resolved_ips") or []):
                hints.setdefault(ip, set()).update(ports)
        return {ip: sorted(values) for ip, values in hints.items() if values}

    def _reconcile_dns_records(self, result: ReconResult) -> int:
        existing: Dict[Tuple[str, str, str], Dict[str, Any]] = {}
        for rec in (result.dns_records or []):
            if not isinstance(rec, dict):
                continue
            rtype = str(rec.get("type", "")).strip().upper()
            rname = normalize_hostname(rec.get("name", ""))
            rval = str(rec.get("value", "")).strip().rstrip(".")
            if not (rtype and rname and rval):
                continue
            rec["type"] = rtype
            rec["name"] = rname
            rec["value"] = rval
            existing[(rtype, rname, rval)] = rec

        added = 0
        for sub in (result.subdomains or []):
            if not isinstance(sub, dict):
                continue
            sname = normalize_hostname(sub.get("name", ""))
            if not sname:
                continue
            for ip in _extract_ip_literals(sub.get("ips") or []):
                rtype = "AAAA" if ":" in ip else "A"
                key = (rtype, sname, ip)
                if key in existing:
                    continue
                existing[key] = {"type": rtype, "name": sname, "value": ip, "source": "derived_subdomain"}
                added += 1
            for cname in (sub.get("cname") or []):
                cname_n = normalize_hostname(cname)
                if not cname_n:
                    continue
                key = ("CNAME", sname, cname_n)
                if key in existing:
                    continue
                existing[key] = {"type": "CNAME", "name": sname, "value": cname_n, "source": "derived_subdomain"}
                added += 1

        nameservers = result.whois_data.get("nameservers", []) if isinstance(result.whois_data, dict) else []
        for ns in (nameservers or []):
            ns_n = normalize_hostname(ns)
            if not ns_n:
                continue
            key = ("NS", normalize_hostname(self.domain), ns_n)
            if key in existing:
                continue
            existing[key] = {"type": "NS", "name": normalize_hostname(self.domain), "value": ns_n, "source": "whois_derived"}
            added += 1

        if existing:
            result.dns_records = list(existing.values())
        return added

    async def _late_resolve_subdomain_ips(self, session: aiohttp.ClientSession, result: ReconResult) -> int:
        active_scans = max(1, get_http_guard().active_scan_count())
        sem = asyncio.Semaphore(40 if active_scans == 1 else 16)
        budget = {"fast": 20, "balanced": 45, "deep": 180 if active_scans == 1 else 120, "turbo": 10}.get(self.mode, 45)
        limit = {"fast": 120, "balanced": 300, "deep": 1800 if active_scans == 1 else 900, "turbo": 80}.get(self.mode, 300)
        candidates = []
        for row in (result.subdomains or []):
            if not isinstance(row, dict):
                continue
            host = normalize_hostname(row.get("name", ""))
            if not host:
                continue
            existing_ips = _extract_ip_literals((row.get("ips") or []) + (row.get("resolved_ips") or []))
            if existing_ips:
                continue
            candidates.append(row)
        if not candidates:
            return 0
        candidates = sorted(
            candidates,
            key=lambda item: (-int(item.get("relevance_score", 0) or 0), -len(item.get("sources", []) or []), str(item.get("name", ""))),
        )[:limit]

        async def _resolve_row(row: Dict[str, Any]) -> tuple[Dict[str, Any], List[str]]:
            host = normalize_hostname(row.get("name", ""))
            async with sem:
                answers = await _doh_query(session, host, "A", timeout=12)
                ips = []
                for answer in answers:
                    ip = _normalize_ip_literal(str(answer.get("data", "")).strip().rstrip("."))
                    if ip:
                        ips.append(ip)
                if not ips:
                    answers6 = await _doh_query(session, host, "AAAA", timeout=12)
                    for answer in answers6:
                        ip = _normalize_ip_literal(str(answer.get("data", "")).strip().rstrip("."))
                        if ip:
                            ips.append(ip)
                return row, sorted(set(ips))

        recovered = 0
        tasks = [asyncio.create_task(_resolve_row(row)) for row in candidates]
        try:
            for task in asyncio.as_completed(tasks, timeout=budget):
                row, ips = await task
                if not ips:
                    row["resolution_status"] = row.get("resolution_status") or "failed"
                    continue
                row["ips"] = ips
                row["resolved_ips"] = ips
                row["resolution_status"] = "resolved"
                recovered += len(ips)
        except asyncio.TimeoutError:
            result.errors.append({
                "time": _utcnow_iso(),
                "module": "IP Intelligence",
                "source": "late_subdomain_resolver",
                "kind": "TimeoutError",
                "message_short": f"Late subdomain resolution budget exceeded ({budget}s); preserving partial IP enrichment",
            })
        finally:
            for task in tasks:
                if not task.done():
                    task.cancel()
        return recovered

    async def _reconcile_infrastructure(self, session: aiohttp.ClientSession, result: ReconResult) -> None:
        late_resolved = await self._late_resolve_subdomain_ips(session, result)
        if late_resolved:
            result.errors.append({
                "time": _utcnow_iso(),
                "module": "IP Intelligence",
                "source": "late_subdomain_resolver",
                "kind": "resolved_from_preserved_subdomains",
                "message_short": f"Recovered {late_resolved} IP observations from preserved subdomains during infrastructure reconciliation",
            })
        existing_ip_map: Dict[str, Dict[str, Any]] = {}
        subdomain_port_hints = self._subdomain_ip_port_hints(result.subdomains)
        for rec in result.ip_records:
            if not isinstance(rec, dict):
                continue
            ip = _normalize_ip_literal(rec.get("ip", ""))
            if ip:
                existing_ip_map[ip] = rec

        sub_ips = self._subdomain_ip_literals(result.subdomains)
        missing_ips = [ip for ip in sub_ips if ip not in existing_ip_map]

        if missing_ips:
            enrich_budget = {"fast": 30, "balanced": 60, "deep": 90, "turbo": 20}.get(self.mode, 45)
            ip_intel = IPIntelligence(
                self.domain,
                self.mode,
                session,
                result.dns_records,
                self.api_keys,
                self.policy,
                subdomains=result.subdomains,
            )
            try:
                enriched = await asyncio.wait_for(ip_intel.enrich_specific(missing_ips), timeout=enrich_budget)
                recovered = 0
                for item in enriched:
                    d = asdict(item)
                    ip = _normalize_ip_literal(d.get("ip", ""))
                    if ip and ip not in existing_ip_map:
                        existing_ip_map[ip] = d
                        recovered += 1
                if recovered:
                    result.errors.append({
                        "time": _utcnow_iso(),
                        "module": "IP Intelligence",
                        "source": "ip_backfill",
                        "kind": "recovered_from_subdomains",
                        "message_short": f"Recovered {recovered} IP records from subdomain-resolved IPs",
                    })
            except Exception as exc:
                result.errors.append({
                    "time": _utcnow_iso(),
                    "module": "IP Intelligence",
                    "source": "ip_backfill",
                    "kind": type(exc).__name__,
                    "message_short": str(exc)[:160],
                })

        # Never drop passively resolved IP evidence just because enrichment was partial or unavailable.
        for ip in sub_ips:
            if ip not in existing_ip_map:
                existing_ip_map[ip] = {
                    "ip": ip,
                    "asn": "",
                    "org": "",
                    "country": "",
                    "city": "",
                    "rdns": "",
                    "cloud_provider": "",
                    "cdn": False,
                    "open_ports": [],
                    "ports": [],
                    "vulns": [],
                    "cpes": [],
                    "tags": [],
                    "source": "subdomain_resolution_backfill",
                    "classification": "derived",
                }

        # Preserve passive port evidence learned at the subdomain layer.
        for ip, hinted_ports in subdomain_port_hints.items():
            rec = existing_ip_map.get(ip)
            if not isinstance(rec, dict):
                continue
            merged_ports = sorted({
                int(port)
                for port in (rec.get("open_ports") or rec.get("ports") or []) + hinted_ports
                if isinstance(port, int) or str(port).isdigit()
            })
            if merged_ports:
                rec["open_ports"] = merged_ports
                rec["ports"] = merged_ports
                rec["tags"] = list(dict.fromkeys((rec.get("tags") or []) + ["subdomain_port_hint"]))

        if existing_ip_map:
            result.ip_records = list(existing_ip_map.values())

        if result.ip_records and not result.asn_intelligence:
            try:
                asn_budget = {"fast": 20, "balanced": 35, "deep": 90, "turbo": 15}.get(self.mode, 35)
                result.asn_intelligence = await asyncio.wait_for(
                    ASNIntelligence(self.domain, self.mode, session, result.ip_records).enrich(),
                    timeout=asn_budget,
                )
            except (asyncio.TimeoutError, Exception) as exc:
                result.errors.append({
                    "time": _utcnow_iso(),
                    "module": "ASN Intelligence",
                    "source": "asn_backfill",
                    "kind": type(exc).__name__,
                    "message_short": str(exc)[:160],
                })
                # If ip_records have no asn field, backfill via ipinfo.io for top IPs
                if not any(
                    (r.get("asn") if isinstance(r, dict) else getattr(r, "asn", ""))
                    for r in result.ip_records[:5]
                ):
                    try:
                        for _ip_rec in result.ip_records[:6]:
                            _ip_addr = (_ip_rec.get("ip") if isinstance(_ip_rec, dict) else getattr(_ip_rec, "ip", "")) or ""
                            if not _ip_addr:
                                continue
                            _resp = await _safe_get(session, f"https://ipinfo.io/{_ip_addr}/json", timeout=5)
                            if _resp and _resp.status == 200:
                                _d = await _resp.json(content_type=None)
                                _org = str(_d.get("org", "") or "")
                                _parts = _org.split(" ", 1)
                                if _parts and _parts[0].startswith("AS"):
                                    if isinstance(_ip_rec, dict):
                                        _ip_rec["asn"] = _parts[0]
                                        _ip_rec["org"] = _parts[1] if len(_parts) > 1 else ""
                                        _ip_rec["country"] = _d.get("country", "") or _ip_rec.get("country", "")
                    except Exception:
                        pass

        # ASN fallback: build directly from ip_records if ASNIntelligence returned empty
        if not result.asn_intelligence and result.ip_records:
            asn_map = {}
            for ip_rec in result.ip_records:
                if not isinstance(ip_rec, dict):
                    continue
                asn = str(ip_rec.get("asn", "") or "").strip()
                if not asn:
                    continue
                if not asn.upper().startswith("AS"):
                    asn = f"AS{asn}"
                asn_upper = asn.upper()
                if asn_upper not in asn_map:
                    asn_map[asn_upper] = {
                        "asn": asn_upper,
                        "org": str(ip_rec.get("org", "") or "").strip(),
                        "name": str(ip_rec.get("org", "") or "").strip(),
                        "country": str(ip_rec.get("country", "") or "").strip(),
                        "ips": [],
                        "providers": [],
                    }
                ip_val = str(ip_rec.get("ip", "") or "").strip()
                if ip_val and ip_val not in asn_map[asn_upper]["ips"]:
                    asn_map[asn_upper]["ips"].append(ip_val)
            if asn_map:
                asn_list = list(asn_map.values())
                result.asn_intelligence = {
                    "by_asn": asn_map,
                    "list": asn_list,
                    "providers": asn_list,
                }

    def _merge_passive_host_evidence(self, result: ReconResult, source_name: str, hosts: List[str], *, confidence: float = 0.66, tags: Optional[List[str]] = None) -> int:
        existing: Dict[str, Dict[str, Any]] = {}
        for row in result.subdomains:
            if isinstance(row, dict):
                name = normalize_hostname(row.get("name", ""))
                if name:
                    existing[name] = row
        added = 0
        seen_ts = result.scan_date or _utcnow_iso()
        for raw in hosts:
            host = normalize_hostname(raw)
            if not host or host == self.domain or not host.endswith("." + self.domain) or not looks_like_hostname(host):
                continue
            row = existing.get(host)
            if row is None:
                row = {
                    "name": host,
                    "ips": [],
                    "ports": [],
                    "cname": [],
                    "sources": [],
                    "tags": [],
                    "confidence": round(max(0.35, min(confidence, 0.95)), 3),
                    "wildcard_candidate": False,
                    "relevance_score": 0,
                    "source_attribution": [],
                }
                result.subdomains.append(row)
                existing[host] = row
                added += 1
            if source_name not in (row.get("sources", []) or []):
                row.setdefault("sources", []).append(source_name)
                row.setdefault("source_attribution", []).append({
                    "entity_id": canonical_entity_id("subdomain", host),
                    "source": source_name,
                    "confidence": round(max(0.35, min(confidence, 0.95)), 3),
                    "first_seen": seen_ts,
                    "last_seen": seen_ts,
                })
            merged_tags = list(dict.fromkeys((row.get("tags", []) or []) + (tags or [])))
            row["tags"] = merged_tags
            row["confidence"] = round(max(float(row.get("confidence", 0.0) or 0.0), confidence), 3)
            family_tags, family_score = _host_family_enrichment(host, self.domain)
            row["tags"] = list(dict.fromkeys((row.get("tags", []) or []) + family_tags))
            base_score = 5 + min(len(row.get("sources", []) or []), 4) + (2 if row.get("ips") else 0)
            base_score += family_score
            if "remote_access" in row["tags"] or "identity_auth" in row["tags"]:
                base_score += 4
            if "admin_panel" in row["tags"]:
                base_score += 3
            if "api_endpoint" in row["tags"]:
                base_score += 2
            if "non_production" in row["tags"]:
                base_score += 2
            if "internal_hint" in row["tags"]:
                base_score += 1
            if source_name in {"archive_host_hint", "artifact_host_hint", "dork_host_hint", "wayback_host_hints"}:
                base_score += 1
            row["relevance_score"] = min(10, max(int(row.get("relevance_score", 0) or 0), base_score))
        if added:
            result.subdomains = sorted(
                [row for row in result.subdomains if isinstance(row, dict)],
                key=lambda item: (-int(item.get("relevance_score", 0) or 0), str(item.get("name", ""))),
            )
        return added

    def _hosts_from_passive_evidence(self, result: ReconResult) -> List[str]:
        hosts: set[str] = set()
        wayback = result.wayback_urls if isinstance(result.wayback_urls, dict) else {}
        for key in ("all", "interesting", "api_endpoints", "admin_paths", "js_endpoints", "documents"):
            for item in (wayback.get(key, []) or []):
                raw_url = item.get("url", "") if isinstance(item, dict) else str(item or "")
                try:
                    host = normalize_hostname(urlparse(raw_url).hostname or "")
                except Exception:
                    host = ""
                if host and host.endswith("." + self.domain):
                    hosts.add(host)
        for row in (result.dorks or []):
            if not isinstance(row, dict):
                continue
            raw_url = str(row.get("url", "") or "")
            try:
                host = normalize_hostname(urlparse(raw_url).hostname or "")
            except Exception:
                host = ""
            if host and host.endswith("." + self.domain):
                hosts.add(host)
        for cert in (result.ssl_info or []):
            if not isinstance(cert, dict):
                continue
            for field in ("subject", "common_name"):
                cert_host = normalize_hostname(str(cert.get(field, "") or "").lstrip("*."))
                if cert_host and cert_host.endswith("." + self.domain):
                    hosts.add(cert_host)
            for san in (cert.get("san_entries", []) or []):
                san_n = normalize_hostname(str(san or "").lstrip("*."))
                if san_n and san_n.endswith("." + self.domain):
                    hosts.add(san_n)
        for row in (result.interesting_endpoints or []):
            if not isinstance(row, dict):
                continue
            raw_url = str(row.get("url", "") or "")
            try:
                host = normalize_hostname(urlparse(raw_url).hostname or "")
            except Exception:
                host = ""
            if host and host.endswith("." + self.domain):
                hosts.add(host)
        for row in (result.potential_secrets or []):
            if not isinstance(row, dict):
                continue
            raw_url = str(row.get("location", "") or "")
            try:
                host = normalize_hostname(urlparse(raw_url).hostname or "")
            except Exception:
                host = ""
            if host and host.endswith("." + self.domain):
                hosts.add(host)
        for row in (result.developer_references or []):
            if not isinstance(row, dict):
                continue
            raw_url = str(row.get("location", "") or "")
            try:
                host = normalize_hostname(urlparse(raw_url).hostname or "")
            except Exception:
                host = ""
            if host and host.endswith("." + self.domain):
                hosts.add(host)
        for row in (result.high_value_targets or []):
            if not isinstance(row, dict):
                continue
            host = normalize_hostname(str(row.get("host", "") or ""))
            if host and host.endswith("." + self.domain):
                hosts.add(host)
        return sorted(hosts)

    async def run(self):
        scan_id = uuid.uuid4().hex[:12]
        scan_date = _utcnow_iso()
        t_start = time.time()
        ctx_tokens = set_scan_context(self.policy, self.domain)
        scan_http_guard = get_http_guard()
        scan_http_guard.register_scan(scan_id)
        guard_token = set_current_http_guard(scan_http_guard)
        scan_id_token = set_current_scan_id(scan_id)
        # Pre-load cloud IP ranges once
        try:
            _init_session = aiohttp.ClientSession(
                connector=aiohttp.TCPConnector(ssl=True, limit=20)
            )
            async with _init_session:
                await _load_cloud_ranges(_init_session)
        except Exception:
            pass

        result = ReconResult(
            domain=self.domain,
            scan_id=scan_id,
            scan_date=scan_date,
            mode=self.mode,
        )

        if not self.progress_cb:
            console.print(Panel(
                f"[bold green]Ghost Recon Tool[/bold green]\n"
                f"Target: [cyan]{self.domain}[/cyan]  |  Mode: [yellow]{self.mode}[/yellow]  |  ID: [dim]{scan_id}[/dim]",
                border_style="green"
            ))

        ordered_modules = [
            "DNS Intelligence",
            "Subdomain Enumeration", "Email Discovery", "Technology Detection",
            "WHOIS Intelligence", "IP Intelligence", "SSL Intelligence",
            "Web Archive", "Breach Intelligence", "Reputation Intel", "Cloud Assets",
            "Takeover Detection",
            "Typosquat Detection", "Security Headers", "Social Footprint", "ASN Intelligence", "Dork Intelligence",
            "Passive Artifact Intelligence",
            "Vulnerability Intelligence",
            "Risk Scoring",
            "Correlations",
        ]
        enabled_modules = [m for m in ordered_modules if self.policy.allows_module(MODULE_CLASSIFICATION.get(m, ModuleMode.PASSIVE))]
        disabled_modules = [m for m in ordered_modules if m not in enabled_modules]
        api_key_summary = summarize_services(self.api_keys)
        result.scan_context = {
            "policy": {
                "passive_only": self.policy.passive_only,
                "allow_active": self.policy.allow_active,
                "allow_target_requests": self.policy.allow_target_requests,
                "allow_insecure_http_fallback": self.policy.allow_insecure_http_fallback,
            },
            "enabled_modules": enabled_modules,
            "disabled_modules": disabled_modules,
            "sources_profile": self.source_registry.profile,
            "source_registry_status": self.source_registry.status_by_source,
            "api_keys": {
                "set_count": int(api_key_summary["configured_credentials_count"]),
                "missing_count": int(api_key_summary["credentials_total"] - api_key_summary["configured_credentials_count"]),
            },
            "api_key_summary": {
                "ready_services_count": int(api_key_summary["ready_services_count"]),
                "partial_services_count": int(api_key_summary["partial_services_count"]),
                "missing_services_count": int(api_key_summary["missing_services_count"]),
                "ready_services": [row["label"] for row in api_key_summary.get("ready_services", [])],
                "partial_services": [row["label"] for row in api_key_summary.get("partial_services", [])],
            },
            "provider_summary": {
                "ready": int(api_key_summary["ready_services_count"]),
                "success": 0,
                "partial": 0,
                "failed": 0,
                "missing_credentials": int(api_key_summary["missing_services_count"]),
                "skipped": 0,
                "api_enabled_count": int(api_key_summary["ready_services_count"]),
                "passive_open_count": 0,
                "premium_success_count": 0,
                "total_considered": int(api_key_summary["ready_services_count"] + api_key_summary["missing_services_count"]),
            },
        }
        await self._emit("start", {
            "scan_id": scan_id,
            "domain": self.domain,
            "mode": self.mode,
            "total_modules": len(enabled_modules),
            "enabled_modules": enabled_modules,
        })

        try:
            async with self._make_session() as session:
                _cli_prog = None
                if not self.progress_cb:
                    _cli_prog = Progress(
                        SpinnerColumn(style="green"),
                        TextColumn("[progress.description]{task.description}"),
                        BarColumn(bar_width=30),
                        TimeElapsedColumn(),
                        console=console,
                        transient=True,
                    )
                    _cli_prog.start()
                    _task_id = _cli_prog.add_task("[green]Running intelligence modules...", total=max(1, len(enabled_modules)))

                # Phase 1: DNS
                await self._emit("phase", {"name": "DNS Intelligence", "status": "running", "icon": "ok"})
                if _cli_prog:
                    _cli_prog.update(_task_id, description="[cyan]DNS Intelligence")
                dns_engine = DNSIntelligence(self.domain, self.mode, session)
                t0 = time.time()
                dns_status = "ok"
                try:
                    dns_records = await asyncio.wait_for(dns_engine.query(), timeout=self._mod_timeout("DNS Intelligence"))
                    result.dns_records = [asdict(r) for r in dns_records]
                except asyncio.TimeoutError as _e:
                    partial_dns = dns_engine.get_partial_records()
                    if partial_dns:
                        result.dns_records = [asdict(r) for r in partial_dns]
                        dns_status = "timeout_partial"
                        result.errors.append({
                            "time": _utcnow_iso(),
                            "module": "DNS Intelligence",
                            "source": "dns_intelligence",
                            "kind": "partial_results_recovered",
                            "message_short": f"Recovered {len(partial_dns)} DNS records from partial snapshot after timeout",
                        })
                    else:
                        result.dns_records = []
                        dns_status = "timeout"
                    result.errors.append({"time": _utcnow_iso(), "module": "DNS Intelligence",
                                          "kind": type(_e).__name__, "message_short": str(_e)[:160]})
                    print(f"[SCAN] DNS Intelligence error: {type(_e).__name__}: {_e}")
                except Exception as _e:
                    partial_dns = dns_engine.get_partial_records()
                    if partial_dns:
                        result.dns_records = [asdict(r) for r in partial_dns]
                        dns_status = "fail_partial"
                    else:
                        result.dns_records = []
                        dns_status = "fail"
                    result.errors.append({"time": _utcnow_iso(), "module": "DNS Intelligence",
                                          "kind": type(_e).__name__, "message_short": str(_e)[:160]})
                    print(f"[SCAN] DNS Intelligence error: {type(_e).__name__}: {_e}")
                result.source_metrics["dns"] = {
                    "doh_aggregate": {
                        "items_obtenidos": int(dns_engine.stats.get("queries_done", 0)),
                        "items_parseados": len(result.dns_records),
                        "items_aceptados": len(result.dns_records),
                        "items_descartados_por_dedupe": 0,
                        "items_descartados_por_filtro": 0,
                        "errores": 1 if dns_status.startswith("timeout") or dns_status.startswith("fail") else 0,
                        "latencia_ms": int((time.time() - t0) * 1000),
                        "status": dns_status,
                    }
                }
                await self._emit("source_metrics", {"module": "DNS Intelligence", "sources": result.source_metrics.get("dns", {})})
                print(f"[SCAN] DNS Intelligence done in {time.time()-t0:.1f}s")
                await self._emit("phase", {"name": "DNS Intelligence", "status": "done",
                                           "count": len(result.dns_records), "icon": "done"})
                if _cli_prog:
                    _cli_prog.advance(_task_id)

                # Email security analysis from DNS records
                try:
                    _dns_recs = result.dns_records or []
                    _txt_recs = [r for r in _dns_recs if isinstance(r, dict) and r.get("type", "").upper() == "TXT"]
                    _dmarc_recs = [r for r in _dns_recs if isinstance(r, dict)
                                   and r.get("type", "").upper() == "TXT"
                                   and str(r.get("name", "")).lower().startswith("_dmarc")]
                    _dkim_sels = list({
                        r.get("name", "") for r in _dns_recs
                        if isinstance(r, dict) and r.get("type", "").upper() in ("TXT", "DKIM")
                        and "v=dkim1" in str(r.get("value", "")).lower()
                    })
                    result.email_security = _analyze_email_security(_txt_recs, _dmarc_recs, _dkim_sels)
                except Exception:
                    pass

                # Phase 2: Parallel modules
                sub_enum = None
                if self.policy.allows_module(MODULE_CLASSIFICATION["Subdomain Enumeration"]):
                    # FIXED: run Subdomain Enumeration before the heavy parallel modules so high-yield passive APIs are not starved by archive/SSL/WHOIS concurrency.
                    await self._emit("phase", {"name": "Subdomain Enumeration", "status": "running", "icon": "Ã¢Å¡Â¡"})
                    if _cli_prog:
                        _cli_prog.update(_task_id, description="[cyan]Subdomain Enumeration")
                    sub_enum = SubdomainEnumerator(
                        self.domain,
                        self.mode,
                        session,
                        self.api_keys,
                        debug_coverage=self.debug_coverage,
                        source_registry=self.source_registry,
                    )
                    sub_mod_res: Any = {}
                    try:
                        sub_mod_res = await asyncio.wait_for(
                            sub_enum.enumerate(),
                            timeout=self._mod_timeout("Subdomain Enumeration"),
                        )
                    except Exception as exc:
                        sub_mod_res = exc
                    subdomain_map = sub_mod_res if isinstance(sub_mod_res, dict) else {}
                    if not subdomain_map and sub_enum:
                        subdomain_map = sub_enum.get_partial_results()
                        if subdomain_map:
                            result.errors.append({
                                "time": _utcnow_iso(),
                                "module": "Subdomain Enumeration",
                                "source": "subdomain_enumeration",
                                "kind": "partial_results_recovered",
                                "message_short": (
                                    f"Recovered {len(subdomain_map)} subdomains from partial snapshot "
                                    "after module timeout/error"
                                ),
                            })
                    if isinstance(sub_mod_res, Exception):
                        result.errors.append({
                            "time": _utcnow_iso(),
                            "module": "Subdomain Enumeration",
                            "source": "subdomain_enumeration",
                            "kind": type(sub_mod_res).__name__,
                            "message_short": str(sub_mod_res)[:160],
                        })
                    result.subdomains = [asdict(v) for v in subdomain_map.values()] if subdomain_map else []
                    result.source_metrics["subdomains"] = (sub_enum.source_metrics if sub_enum else {})
                    result.scan_context.setdefault("dropped_items", [])
                    dropped_cap = {"fast": 2000, "balanced": 5000, "deep": 10000, "turbo": 1500}.get(self.mode, 3000)
                    if sub_enum:
                        result.scan_context["dropped_items"].extend(sub_enum.dropped_items[:dropped_cap])
                        result.scan_context["subdomain_inventory"] = dict(sub_enum.inventory_stats or {})
                        result.errors.extend(sub_enum.source_errors[:500])
                    await self._emit("source_metrics", {"module": "Subdomain Enumeration", "sources": result.source_metrics.get("subdomains", {})})
                    await self._emit("phase", {
                        "name": "Subdomain Enumeration",
                        "status": "done",
                        "count": len(result.subdomains),
                        "icon": "done",
                    })
                    if _cli_prog:
                        _cli_prog.advance(_task_id)

                parallel_runners = {}
                email_discovery = None
                archive_intel = None
                archive_runner = None
                if self.policy.allows_module(MODULE_CLASSIFICATION["Email Discovery"]):
                    email_discovery = EmailDiscovery(
                        self.domain,
                        self.mode,
                        session,
                        self.api_keys,
                        policy=self.policy,
                        debug_coverage=self.debug_coverage,
                        source_registry=self.source_registry,
                    )
                    parallel_runners["Email Discovery"] = asyncio.wait_for(
                        email_discovery.discover(), timeout=self._mod_timeout("Email Discovery"))
                if self.policy.allows_module(MODULE_CLASSIFICATION["Technology Detection"]):
                    parallel_runners["Technology Detection"] = asyncio.wait_for(
                        TechnologyDetector(
                            self.domain,
                            self.mode,
                            session,
                            result.dns_records,
                            policy=self.policy,
                            subdomains=result.subdomains,
                            ssl_info=result.ssl_info,
                        ).detect(), timeout=self._mod_timeout("Technology Detection"))
                if self.policy.allows_module(MODULE_CLASSIFICATION["WHOIS Intelligence"]):
                    parallel_runners["WHOIS Intelligence"] = asyncio.wait_for(
                        WhoisIntelligence(self.domain, self.mode, session).lookup(),
                        timeout=self._mod_timeout("WHOIS Intelligence"))
                if self.policy.allows_module(MODULE_CLASSIFICATION["SSL Intelligence"]):
                    parallel_runners["SSL Intelligence"] = asyncio.wait_for(
                        SSLIntelligence(self.domain, self.mode, session).query(),
                        timeout=self._mod_timeout("SSL Intelligence"))
                if self.policy.allows_module(MODULE_CLASSIFICATION["Web Archive"]):
                    archive_intel = WebArchiveIntelligence(self.domain, self.mode, session)
                    archive_runner = asyncio.wait_for(
                        archive_intel.mine(),
                        timeout=self._mod_timeout("Web Archive"))
                if self.policy.allows_module(MODULE_CLASSIFICATION["Breach Intelligence"]):
                    parallel_runners["Breach Intelligence"] = asyncio.wait_for(
                        BreachIntelligence(self.domain, self.mode, session, self.api_keys).check(),
                        timeout=self._mod_timeout("Breach Intelligence"))
                if self.policy.allows_module(MODULE_CLASSIFICATION["Reputation Intel"]):
                    parallel_runners["Reputation Intel"] = asyncio.wait_for(
                        ReputationIntelligence(self.domain, self.mode, session, self.api_keys).check(),
                        timeout=self._mod_timeout("Reputation Intel"))
                for mod in parallel_runners.keys():
                    await self._emit("phase", {"name": mod, "status": "running", "icon": "Ã¢Å¡Â¡"})
                if archive_runner:
                    await self._emit("phase", {"name": "Web Archive", "status": "running", "icon": "Ã¢Å¡Â¡"})
                if _cli_prog and parallel_runners:
                    _cli_prog.update(_task_id, description="[cyan]Running parallel modules")

                if parallel_runners:
                    done = await asyncio.gather(*parallel_runners.values(), return_exceptions=True)
                    dropped_cap = {"fast": 2000, "balanced": 5000, "deep": 10000, "turbo": 1500}.get(self.mode, 3000)
                    for mod, mod_res in zip(parallel_runners.keys(), done):
                        if mod == "Email Discovery":
                            email_map = mod_res if isinstance(mod_res, dict) else {}
                            if not email_map and email_discovery:
                                email_map = email_discovery.get_partial_results()
                                if email_map:
                                    result.errors.append({
                                        "time": _utcnow_iso(),
                                        "module": "Email Discovery",
                                        "source": "email_discovery",
                                        "kind": "partial_results_recovered",
                                        "message_short": (
                                            f"Recovered {len(email_map)} emails from partial snapshot "
                                            "after module timeout/error"
                                        ),
                                    })
                            result.emails = [asdict(v) for v in email_map.values()] if email_map else []
                            # Safety net: ensure all emails have a populated 'role' field
                            for _em in result.emails:
                                if not _em.get('role') or _em.get('role') in ('?', ''):
                                    _em['role'] = categorize_email(_em.get('email', ''))
                            result.source_metrics["emails"] = (email_discovery.source_metrics if email_discovery else {})
                            result.scan_context.setdefault("dropped_items", [])
                            if email_discovery:
                                result.scan_context["dropped_items"].extend(email_discovery.dropped_items[:dropped_cap])
                                result.errors.extend(email_discovery.source_errors[:500])
                            await self._emit("source_metrics", {"module": mod, "sources": result.source_metrics.get("emails", {})})
                            cnt = len(result.emails)
                        elif mod == "Technology Detection":
                            result.technologies = [asdict(t) for t in mod_res] if isinstance(mod_res, list) else []
                            cnt = len(result.technologies)
                        elif mod == "WHOIS Intelligence":
                            result.whois_data = mod_res if isinstance(mod_res, dict) else {}
                            cnt = len(result.whois_data)
                            # Compute domain_age_days from registration date if not already set
                            if result.whois_data and isinstance(result.whois_data, dict):
                                reg_date = (result.whois_data.get("registration_date")
                                            or result.whois_data.get("created")
                                            or result.whois_data.get("creation_date"))
                                if reg_date and not result.whois_data.get("domain_age_days"):
                                    try:
                                        import re as _re
                                        date_match = _re.search(r'\d{4}-\d{2}-\d{2}', str(reg_date))
                                        if date_match:
                                            from datetime import datetime as _dt
                                            reg_dt = _dt.strptime(date_match.group(), "%Y-%m-%d")
                                            result.whois_data["domain_age_days"] = (datetime.now(timezone.utc).replace(tzinfo=None) - reg_dt).days
                                    except Exception:
                                        pass
                        elif mod == "SSL Intelligence":
                            result.ssl_info = [asdict(s) for s in mod_res] if isinstance(mod_res, list) else []
                            cnt = len(result.ssl_info)
                            # Extract SANs and inject into subdomains (dedup)
                            if result.ssl_info:
                                existing_names = {s.get("name", "") for s in result.subdomains}
                                for cert in result.ssl_info:
                                    for san in cert.get("san_entries", []):
                                        san = san.lstrip("*.").strip().lower()
                                        if san and san.endswith(f".{self.domain}") and san not in existing_names:
                                            existing_names.add(san)
                                            result.subdomains.append({
                                                "name": san, "ips": [], "ports": [], "cname": [],
                                                "sources": ["ssl_san"], "tags": ["ssl"],
                                                "confidence": 0.85, "wildcard_candidate": False,
                                                "relevance_score": 0, "source_attribution": [],
                                            })
                        elif mod == "Breach Intelligence":
                            result.breach_records = [asdict(b) for b in mod_res] if isinstance(mod_res, list) else []
                            cnt = len(result.breach_records)
                        elif mod == "Reputation Intel":
                            if isinstance(mod_res, dict) and mod_res:
                                merged_rep = dict(result.reputation_data or {})
                                merged_rep.update(mod_res)
                                result.reputation_data = merged_rep
                            cnt = len(result.reputation_data)
                        await self._emit("phase", {"name": mod, "status": "done", "count": cnt, "icon": "done"})
                        if isinstance(mod_res, Exception):
                            result.errors.append({
                                "time": _utcnow_iso(),
                                "module": mod,
                                "source": mod.lower().replace(" ", "_"),
                                "kind": type(mod_res).__name__,
                                "message_short": str(mod_res)[:160],
                            })
                if archive_runner:
                    archive_res = None
                    try:
                        archive_res = await archive_runner
                    except Exception as exc:
                        archive_res = exc
                    recovered_wayback = archive_res if isinstance(archive_res, dict) else {}
                    if not recovered_wayback and archive_intel:
                        recovered_wayback = archive_intel.get_partial_results()
                        if recovered_wayback and int(recovered_wayback.get("total_urls", 0) or 0) > 0:
                            result.errors.append({
                                "time": _utcnow_iso(),
                                "module": "Web Archive",
                                "source": "web_archive",
                                "kind": "partial_results_recovered",
                                "message_short": (
                                    f"Recovered {int(recovered_wayback.get('total_urls', 0) or 0)} archive URLs "
                                    "from partial snapshot after module timeout/error"
                                ),
                            })
                    result.wayback_urls = recovered_wayback if isinstance(recovered_wayback, dict) else {}
                    result.archive_urls = list((result.wayback_urls or {}).get("all", []) or [])
                    result.archive_summary = {
                        "total": int((result.wayback_urls or {}).get("total_urls", len(result.archive_urls)) or 0),
                        "interesting": len((result.wayback_urls or {}).get("interesting", []) or []),
                        "api_endpoints": len((result.wayback_urls or {}).get("api_endpoints", []) or []),
                        "js_files": len((result.wayback_urls or {}).get("js_files", []) or []),
                        "documents": len((result.wayback_urls or {}).get("documents", []) or []),
                    }
                    if result.wayback_urls:
                        favicon_url = None
                        all_wb_urls = []
                        for wbkey in ("interesting", "documents", "js_files", "api_endpoints"):
                            for entry in (result.wayback_urls.get(wbkey) or []):
                                url_str = entry if isinstance(entry, str) else (entry.get("url", "") if isinstance(entry, dict) else "")
                                if url_str:
                                    all_wb_urls.append(url_str)
                        for url_str in all_wb_urls:
                            if "/favicon.ico" in url_str.lower():
                                favicon_url = url_str
                                break
                        if not favicon_url:
                            favicon_url = f"https://web.archive.org/web/*/{self.domain}/favicon.ico"
                        if isinstance(result.scan_context, dict):
                            result.scan_context["favicon_wayback_url"] = favicon_url
                    await self._emit("phase", {"name": "Web Archive", "status": "done", "count": len(result.archive_urls), "icon": "done"})
                    if isinstance(archive_res, Exception):
                        result.errors.append({
                            "time": _utcnow_iso(),
                            "module": "Web Archive",
                            "source": "web_archive",
                            "kind": type(archive_res).__name__,
                            "message_short": str(archive_res)[:160],
                        })
                    if result.wayback_urls:
                        merged_archive_hosts = self._merge_passive_host_evidence(
                            result,
                            "archive_host_hint",
                            self._hosts_from_passive_evidence(result),
                            confidence=0.68,
                            tags=["archive"],
                        )
                        if merged_archive_hosts:
                            result.source_metrics.setdefault("subdomains", {})
                            result.source_metrics["subdomains"]["archive_host_hint"] = {
                                "items_obtenidos": merged_archive_hosts,
                                "items_parseados": merged_archive_hosts,
                                "items_aceptados": merged_archive_hosts,
                                "items_descartados_por_dedupe": 0,
                                "items_descartados_por_filtro": 0,
                                "errores": 0,
                                "latencia_ms": 0,
                                "status": "derived_ok",
                            }
                            result.errors.append({
                                "time": _utcnow_iso(),
                                "module": "Subdomain Enumeration",
                                "source": "archive_host_hint",
                                "kind": "passive_hosts_merged",
                                "message_short": f"Merged {merged_archive_hosts} archive-derived host(s) into subdomain inventory",
                            })
                        archival_tech = TechnologyDetector(
                            self.domain,
                            self.mode,
                            session,
                            result.dns_records,
                            wayback_urls=result.wayback_urls,
                            policy=self.policy,
                        )._archive_based_tech_detection()
                        if archival_tech:
                            merged: Dict[str, Dict[str, Any]] = {}
                            for row in result.technologies or []:
                                if isinstance(row, dict) and row.get("name"):
                                    merged[str(row.get("name", "")).lower()] = row
                            for finding in archival_tech:
                                key = str(finding.name or "").lower()
                                if not key:
                                    continue
                                if key in merged:
                                    existing = merged[key]
                                    existing["sources"] = sorted(set((existing.get("sources", []) or []) + (finding.sources or [])))
                                    existing["historical_only"] = bool(existing.get("historical_only", False) and finding.historical_only)
                                    existing["current_passive"] = bool(existing.get("current_passive", True))
                                else:
                                    merged[key] = asdict(finding)
                            result.technologies = list(merged.values())
                        ssl_tech = TechnologyDetector(
                            self.domain,
                            self.mode,
                            session,
                            result.dns_records,
                            wayback_urls=result.wayback_urls,
                            policy=self.policy,
                        )._ssl_based_tech_detection(result.ssl_info)
                        if ssl_tech:
                            merged_ssl: Dict[str, Dict[str, Any]] = {}
                            for row in result.technologies or []:
                                if isinstance(row, dict) and row.get("name"):
                                    merged_ssl[str(row.get("name", "")).lower()] = row
                            for finding in ssl_tech:
                                key = str(finding.name or "").lower()
                                if key and key not in merged_ssl:
                                    merged_ssl[key] = asdict(finding)
                            result.technologies = list(merged_ssl.values())
                        # Extract subdomains from JS file URLs in Wayback
                        try:
                            _wa = result.wayback_urls if isinstance(result.wayback_urls, dict) else {}
                            _all_urls = (_wa.get("urls") or _wa.get("all_urls") or _wa.get("all") or [])
                            if isinstance(_all_urls, list):
                                _js_subs = set()
                                _dom_esc = re.escape(self.domain)
                                for _wu in _all_urls[:2000]:
                                    _u = str(_wu.get("url", "") if isinstance(_wu, dict) else _wu)
                                    for _m in re.findall(r'https?://([a-z0-9][a-z0-9\-\.]+\.' + _dom_esc + r')', _u, re.I):
                                        _h = normalize_hostname(_m)
                                        if _h and looks_like_hostname(_h):
                                            _js_subs.add(_h)
                                if _js_subs:
                                    self._merge_passive_host_evidence(result, "wayback_js_extract", list(_js_subs), confidence=0.72, tags=["js_extracted", "passive"])
                        except Exception:
                            pass
                        if _cli_prog:
                            _cli_prog.advance(_task_id)
                    # CNAME-based technology detection from subdomain CNAME records
                    if result.subdomains:
                        try:
                            cname_tech = TechnologyDetector(
                                self.domain,
                                self.mode,
                                session,
                                result.dns_records,
                                policy=self.policy,
                                subdomains=result.subdomains,
                            )._cname_based_tech_detection(result.subdomains)
                            if cname_tech:
                                merged_c: Dict[str, Dict[str, Any]] = {}
                                for row in result.technologies or []:
                                    if isinstance(row, dict) and row.get("name"):
                                        merged_c[str(row.get("name", "")).lower()] = row
                                for finding in cname_tech:
                                    key = str(finding.name or "").lower()
                                    if key and key not in merged_c:
                                        merged_c[key] = asdict(finding)
                                result.technologies = list(merged_c.values())
                        except Exception:
                            pass
                    if result.ssl_info:
                        try:
                            ssl_tech = TechnologyDetector(
                                self.domain,
                                self.mode,
                                session,
                                result.dns_records,
                                policy=self.policy,
                                ssl_info=result.ssl_info,
                            )._ssl_based_tech_detection(result.ssl_info)
                            if ssl_tech:
                                merged_ssl: Dict[str, Dict[str, Any]] = {}
                                for row in result.technologies or []:
                                    if isinstance(row, dict) and row.get("name"):
                                        merged_ssl[str(row.get("name", "")).lower()] = row
                                for finding in ssl_tech:
                                    key = str(finding.name or "").lower()
                                    if key and key not in merged_ssl:
                                        merged_ssl[key] = asdict(finding)
                                result.technologies = list(merged_ssl.values())
                        except Exception:
                            pass

                dns_added = self._reconcile_dns_records(result)
                if dns_added:
                    result.errors.append({
                        "time": _utcnow_iso(),
                        "module": "DNS Intelligence",
                        "source": "dns_reconcile",
                        "kind": "derived_records_added",
                        "message_short": f"Added {dns_added} derived DNS record(s) from subdomain/WHOIS evidence",
                    })
                # Refresh email security with full dns_records (may have more data after parallel phase)
                try:
                    _dns_recs2 = result.dns_records or []
                    _txt_recs2 = [r for r in _dns_recs2 if isinstance(r, dict) and r.get("type", "").upper() == "TXT"]
                    _dmarc_recs2 = [r for r in _dns_recs2 if isinstance(r, dict)
                                    and r.get("type", "").upper() == "TXT"
                                    and str(r.get("name", "")).lower().startswith("_dmarc")]
                    _dkim_sels2 = list({
                        r.get("name", "") for r in _dns_recs2
                        if isinstance(r, dict) and r.get("type", "").upper() in ("TXT", "DKIM")
                        and "v=dkim1" in str(r.get("value", "")).lower()
                    })
                    _email_sec2 = _analyze_email_security(_txt_recs2, _dmarc_recs2, _dkim_sels2)
                    # Only upgrade if new result has better data
                    if _email_sec2 and (_email_sec2.get("spf", {}).get("present") or _email_sec2.get("dmarc", {}).get("present")):
                        result.email_security = _email_sec2
                    elif not result.email_security:
                        result.email_security = _email_sec2
                except Exception:
                    pass

                if self.policy.allows_module(MODULE_CLASSIFICATION["IP Intelligence"]):
                    await self._emit("phase", {"name": "IP Intelligence", "status": "running", "icon": "Ã¢Å¡Â¡"})
                    if _cli_prog:
                        _cli_prog.update(_task_id, description="[cyan]IP Intelligence")
                    try:
                        existing_ip_records = list(result.ip_records or [])
                        ip_results = await asyncio.wait_for(
                            IPIntelligence(
                                self.domain,
                                self.mode,
                                session,
                                result.dns_records,
                                self.api_keys,
                                self.policy,
                                result.subdomains,
                            ).enrich(),
                            timeout=self._mod_timeout("IP Intelligence"),
                        )
                        new_ip_records = [asdict(r) for r in ip_results] if isinstance(ip_results, list) else []
                        if new_ip_records or not existing_ip_records:
                            result.ip_records = new_ip_records
                        else:
                            result.ip_records = existing_ip_records
                        # Feed Shodan InternetDB hostnames back into subdomain pool
                        if result.ip_records and result.subdomains is not None:
                            _existing_sub_names = {
                                (s.get("name", "") if isinstance(s, dict) else getattr(s, "name", ""))
                                for s in result.subdomains
                            }
                            _idb_new_subs = []
                            for _iprec in result.ip_records:
                                _iprec_d = _iprec if isinstance(_iprec, dict) else asdict(_iprec)
                                for _hn in (_iprec_d.get("hostnames") or []):
                                    _hn = str(_hn or "").strip().lower()
                                    if (_hn and _hn.endswith("." + self.domain) or _hn == self.domain) and _hn not in _existing_sub_names:
                                        _existing_sub_names.add(_hn)
                                        _idb_new_subs.append(asdict(SubdomainRecord(
                                            name=_hn,
                                            sources=["shodan_internetdb"],
                                            first_seen=_utcnow_iso(),
                                            last_seen=_utcnow_iso(),
                                            confidence=0.6,
                                        )))
                            if _idb_new_subs:
                                result.subdomains = list(result.subdomains) + _idb_new_subs
                                log.debug("internetdb_hostnames_added count=%d", len(_idb_new_subs))
                        if result.ip_records:
                            merged_techs: Dict[str, Dict[str, Any]] = {}
                            for row in result.technologies or []:
                                if isinstance(row, dict) and row.get("name"):
                                    merged_techs[str(row.get("name", "")).lower()] = row
                            internetdb_map = {
                                "wordpress": ("WordPress", "cms"),
                                "jenkins": ("Jenkins", "devops"),
                                "apache": ("Apache", "web_server"),
                                "nginx": ("Nginx", "web_server"),
                                "iis": ("IIS", "web_server"),
                                "docker": ("Docker", "containers"),
                            }
                            for _iprec in result.ip_records:
                                _iprec_d = _iprec if isinstance(_iprec, dict) else asdict(_iprec)
                                for _tag in (_iprec_d.get("tags") or []):
                                    tech_hint = internetdb_map.get(str(_tag or "").strip().lower())
                                    if not tech_hint:
                                        continue
                                    name, category = tech_hint
                                    key = name.lower()
                                    if key in merged_techs:
                                        existing = merged_techs[key]
                                        existing["sources"] = sorted(set((existing.get("sources") or []) + ["shodan_internetdb"]))
                                        continue
                                    merged_techs[key] = asdict(TechnologyFinding(
                                        name=name,
                                        category=category,
                                        evidence=f"InternetDB tag: {_tag}",
                                        confidence="medium",
                                        sources=["shodan_internetdb"],
                                    ))
                            result.technologies = list(merged_techs.values())
                    except Exception as exc:
                        result.ip_records = existing_ip_records
                        result.errors.append({
                            "time": _utcnow_iso(),
                            "module": "IP Intelligence",
                            "source": "ip_intelligence",
                            "kind": type(exc).__name__,
                            "message_short": str(exc)[:160],
                        })
                    if _cli_prog:
                        _cli_prog.advance(_task_id)

                await self._reconcile_infrastructure(session, result)
                await self._emit("phase", {
                    "name": "IP Intelligence",
                    "status": "done",
                    "count": len(result.ip_records),
                    "ports": sum(
                        len((row.get("open_ports") or row.get("ports") or []))
                        for row in (result.ip_records or [])
                        if isinstance(row, dict)
                    ),
                    "icon": "done",
                })

                # CIRCL passive DNS: historical IPs
                try:
                    _ip_re = re.compile(r'^\d+\.\d+\.\d+\.\d+$')
                    _hist_ip_set = set()
                    _hist_ips = []
                    _circl_url = f"https://www.circl.lu/pdns/query/{self.domain}"
                    _circl_resp = await _safe_get(session, _circl_url, timeout=60,
                                                   headers={"Accept": "application/json"})
                    if _circl_resp and _circl_resp.status == 200:
                        _circl_text = await _circl_resp.text()
                        for _line in _circl_text.strip().splitlines():
                            try:
                                _item = json.loads(_line)
                                _rdata = str(_item.get("rdata", "") or "").strip()
                                if _ip_re.match(_rdata) and _rdata not in _hist_ip_set:
                                    _hist_ip_set.add(_rdata)
                                    _hist_ips.append(_rdata)
                            except Exception:
                                pass
                    # HackerTarget IP History fallback
                    try:
                        _ht_url = f"https://api.hackertarget.com/hostsearch/?q={self.domain}"
                        _ht_resp = await _safe_get(session, _ht_url, timeout=15)
                        if _ht_resp and _ht_resp.status == 200:
                            _ht_text = await _ht_resp.text()
                            if "API count exceeded" not in _ht_text and "error" not in _ht_text.lower()[:50]:
                                for _ht_line in _ht_text.strip().splitlines():
                                    _parts = _ht_line.split(",")
                                    if len(_parts) >= 2:
                                        _ht_ip = _parts[1].strip()
                                        if _ip_re.match(_ht_ip) and _ht_ip not in _hist_ip_set:
                                            _hist_ip_set.add(_ht_ip)
                                            _hist_ips.append(_ht_ip)
                    except Exception:
                        pass
                    if _hist_ips:
                        result.historical_ips = _hist_ips
                        if not isinstance(result.scan_context, dict):
                            result.scan_context = {}
                        result.scan_context["historical_ips"] = _hist_ips
                except Exception:
                    pass

                if self.policy.allows_module(MODULE_CLASSIFICATION["Cloud Assets"]):
                    await self._emit("phase", {"name": "Cloud Assets", "status": "running", "icon": "Ã¢Å¡Â¡"})
                    if _cli_prog:
                        _cli_prog.update(_task_id, description="[cyan]Cloud Assets")
                    try:
                        cloud_results = await asyncio.wait_for(
                            CloudIntelligence(
                                self.domain, self.mode, session, self.api_keys, self.policy,
                                subdomains=result.subdomains
                            ).discover(),
                            timeout=self._mod_timeout("Cloud Assets"),
                        )
                        result.cloud_assets = [asdict(c) for c in cloud_results] if isinstance(cloud_results, list) else []
                    except Exception as exc:
                        result.cloud_assets = []
                        result.errors.append({
                            "time": _utcnow_iso(),
                            "module": "Cloud Assets",
                            "source": "cloud_assets",
                            "kind": type(exc).__name__,
                            "message_short": str(exc)[:160],
                        })
                    await self._emit("phase", {"name": "Cloud Assets", "status": "done", "count": len(result.cloud_assets), "icon": "done"})
                    if _cli_prog:
                        _cli_prog.advance(_task_id)

                # Phase 3: Takeover detection (active)
                if self.policy.allows_module(MODULE_CLASSIFICATION["Takeover Detection"]):
                    await self._emit("phase", {"name": "Takeover Detection", "status": "running", "icon": "Ã°Å¸Å½Â¯"})
                    if _cli_prog:
                        _cli_prog.update(_task_id, description="[cyan]Takeover Detection")
                    takeover_det = TakeoverDetector(
                        self.domain,
                        self.mode,
                        session,
                        result.subdomains,
                        result.dns_records,
                        policy=self.policy,
                    )
                    takeover_results = await takeover_det.scan()
                    result.takeover_records = [asdict(t) for t in takeover_results] if isinstance(takeover_results, list) else []
                    await self._emit("phase", {"name": "Takeover Detection", "status": "done",
                                               "count": len(result.takeover_records), "icon": "done"})
                    if _cli_prog:
                        _cli_prog.advance(_task_id)

                # Phase 4: Extended modules
                extended = {}
                if self.policy.allows_module(MODULE_CLASSIFICATION["Typosquat Detection"]):
                    extended["Typosquat Detection"] = asyncio.wait_for(
                        TyposquatDetector(self.domain, self.mode, session).detect(),
                        timeout=self._mod_timeout("Typosquat Detection"))
                if self.policy.allows_module(MODULE_CLASSIFICATION["Security Headers"]):
                    extended["Security Headers"] = asyncio.wait_for(
                        SecurityHeadersAnalyzer(self.domain, self.mode, session, self.policy).analyze(),
                        timeout=self._mod_timeout("Security Headers"))
                if self.policy.allows_module(MODULE_CLASSIFICATION["Social Footprint"]):
                    extended["Social Footprint"] = asyncio.wait_for(
                        SocialFootprintDetector(self.domain, self.mode, session, self.api_keys).detect(),
                        timeout=self._mod_timeout("Social Footprint"))
                if self.policy.allows_module(MODULE_CLASSIFICATION["ASN Intelligence"]):
                    extended["ASN Intelligence"] = asyncio.wait_for(
                        ASNIntelligence(self.domain, self.mode, session, result.ip_records).enrich(),
                        timeout=self._mod_timeout("ASN Intelligence"))
                if self.policy.allows_module(MODULE_CLASSIFICATION["Dork Intelligence"]):
                    extended["Dork Intelligence"] = asyncio.wait_for(
                        DorkIntelligence(self.domain, self.mode, session, self.api_keys).search(),
                        timeout=self._mod_timeout("Dork Intelligence"))
                for mod in extended.keys():
                    await self._emit("phase", {"name": mod, "status": "running", "icon": "Ã¢Å¡Â¡"})
                if _cli_prog and extended:
                    _cli_prog.update(_task_id, description="[cyan]Extended Intelligence")
                if extended:
                    ext_done = await asyncio.gather(*extended.values(), return_exceptions=True)
                    for mod, mod_res in zip(extended.keys(), ext_done):
                        if mod == "Typosquat Detection":
                            result.typosquats = mod_res if isinstance(mod_res, list) else []
                            cnt = len(result.typosquats)
                        elif mod == "Security Headers":
                            result.security_headers = mod_res if isinstance(mod_res, dict) else {}
                            cnt = result.security_headers.get("score", 0)
                        elif mod == "Social Footprint":
                            if isinstance(mod_res, dict) and mod_res:
                                merged_social = dict(result.social_footprint or {})
                                if isinstance(merged_social.get("profiles"), dict) and isinstance(mod_res.get("profiles"), dict):
                                    profiles = dict(merged_social.get("profiles", {}))
                                    profiles.update(mod_res.get("profiles", {}))
                                    merged_social.update(mod_res)
                                    merged_social["profiles"] = profiles
                                else:
                                    merged_social.update(mod_res)
                                result.social_footprint = merged_social
                            cnt = len(result.social_footprint.get("profiles", {}))
                        elif mod == "Dork Intelligence":
                            if not isinstance(mod_res, list):
                                mod_res = []
                            if isinstance(mod_res, list) and mod_res:
                                existing_keys = {
                                    f"{row.get('source','')}:{row.get('category','')}:{row.get('file','')}:{row.get('url','')}"
                                    for row in (result.dorks or []) if isinstance(row, dict)
                                }
                                merged_dorks = list(result.dorks or [])
                                for row in mod_res:
                                    if not isinstance(row, dict):
                                        continue
                                    key = f"{row.get('source','')}:{row.get('category','')}:{row.get('file','')}:{row.get('url','')}"
                                    if key in existing_keys:
                                        continue
                                    existing_keys.add(key)
                                    merged_dorks.append(row)
                                result.dorks = merged_dorks
                            merged_dork_hosts = self._merge_passive_host_evidence(
                                result,
                                "dork_host_hint",
                                self._hosts_from_passive_evidence(result),
                                confidence=0.71,
                                tags=["dork"],
                            )
                            if merged_dork_hosts:
                                result.source_metrics.setdefault("subdomains", {})
                                result.source_metrics["subdomains"]["dork_host_hint"] = {
                                    "items_obtenidos": merged_dork_hosts,
                                    "items_parseados": merged_dork_hosts,
                                    "items_aceptados": merged_dork_hosts,
                                    "items_descartados_por_dedupe": 0,
                                    "items_descartados_por_filtro": 0,
                                    "errores": 0,
                                    "latencia_ms": 0,
                                    "status": "derived_ok",
                                }
                                result.errors.append({
                                    "time": _utcnow_iso(),
                                    "module": "Subdomain Enumeration",
                                    "source": "dork_host_hint",
                                    "kind": "passive_hosts_merged",
                                    "message_short": f"Merged {merged_dork_hosts} dork-derived host(s) into subdomain inventory",
                                })
                            cnt = len(result.dorks)
                        else:
                            if isinstance(mod_res, dict) and mod_res:
                                merged_asn = dict(result.asn_intelligence or {})
                                merged_asn.update(mod_res)
                                if isinstance(merged_asn.get("by_asn"), dict) and isinstance(mod_res.get("by_asn"), dict):
                                    by_asn = dict(merged_asn.get("by_asn", {}))
                                    by_asn.update(mod_res.get("by_asn", {}))
                                    merged_asn["by_asn"] = by_asn
                                if isinstance(mod_res.get("list"), list):
                                    seen_asn = {str(row.get("asn", "")) for row in (merged_asn.get("list", []) or []) if isinstance(row, dict)}
                                    merged_list = list(merged_asn.get("list", []) or [])
                                    for row in mod_res.get("list", []) or []:
                                        asn_key = str(row.get("asn", "")) if isinstance(row, dict) else ""
                                        if asn_key and asn_key not in seen_asn:
                                            seen_asn.add(asn_key)
                                            merged_list.append(row)
                                    merged_asn["list"] = merged_list
                                result.asn_intelligence = merged_asn
                            cnt = len(result.asn_intelligence)
                        await self._emit("phase", {"name": mod, "status": "done", "count": cnt, "icon": "done"})
                        if _cli_prog:
                            _cli_prog.advance(_task_id)

                if self.policy.allows_module(MODULE_CLASSIFICATION["Passive Artifact Intelligence"]):
                    await self._emit("phase", {"name": "Passive Artifact Intelligence", "status": "running", "icon": "ok"})
                    if _cli_prog:
                        _cli_prog.update(_task_id, description="[cyan]Passive Artifact Intelligence")
                    try:
                        artifact_results = await asyncio.wait_for(
                            PassiveArtifactIntelligence(
                                self.domain,
                                self.mode,
                                result.wayback_urls,
                                result.dorks,
                                result.subdomains,
                                result.ip_records,
                                result.cloud_assets,
                                result.asn_intelligence,
                                result.dns_records,
                            ).analyze(),
                            timeout=self._mod_timeout("Passive Artifact Intelligence"),
                        )
                    except Exception as exc:
                        artifact_results = {}
                        result.errors.append({
                            "time": _utcnow_iso(),
                            "module": "Passive Artifact Intelligence",
                            "source": "passive_artifact_intelligence",
                            "kind": type(exc).__name__,
                            "message_short": str(exc)[:160],
                        })
                    if isinstance(artifact_results, dict):
                        result.interesting_endpoints = artifact_results.get("interesting_endpoints", []) or []
                        result.potential_secrets = artifact_results.get("potential_secrets", []) or []
                        result.developer_references = artifact_results.get("developer_references", []) or []
                        result.high_value_targets = artifact_results.get("high_value_targets", []) or []
                        result.asset_clusters = artifact_results.get("asset_clusters", {}) or {}
                        merged_artifact_hosts = self._merge_passive_host_evidence(
                            result,
                            "artifact_host_hint",
                            self._hosts_from_passive_evidence(result),
                            confidence=0.72,
                            tags=["archive_artifact_hint"],
                        )
                        if merged_artifact_hosts:
                            result.source_metrics.setdefault("subdomains", {})
                            result.source_metrics["subdomains"]["artifact_host_hint"] = {
                                "items_obtenidos": merged_artifact_hosts,
                                "items_parseados": merged_artifact_hosts,
                                "items_aceptados": merged_artifact_hosts,
                                "items_descartados_por_dedupe": 0,
                                "items_descartados_por_filtro": 0,
                                "errores": 0,
                                "latencia_ms": 0,
                                "status": "derived",
                            }
                            result.errors.append({
                                "time": _utcnow_iso(),
                                "module": "Passive Artifact Intelligence",
                                "source": "artifact_host_hint",
                                "kind": "derived_recovery",
                                "message_short": f"Recovered {merged_artifact_hosts} subdomain(s) from passive artifact evidence.",
                            })
                    await self._emit("phase", {
                        "name": "Passive Artifact Intelligence",
                        "status": "done",
                        "count": len(result.interesting_endpoints) + len(result.potential_secrets) + len(result.high_value_targets),
                        "icon": "done",
                    })
                    if _cli_prog:
                        _cli_prog.advance(_task_id)

                # Phase 5: Vulnerability Intelligence
                await self._emit("phase", {"name": "Vulnerability Intelligence", "status": "running", "icon": "ok"})
                if _cli_prog:
                    _cli_prog.update(_task_id, description="[cyan]Vulnerability Intelligence")
                vuln_intel = VulnerabilityIntelligence(
                    domain=self.domain,
                    mode=self.mode,
                    session=session,
                    ip_records=result.ip_records,
                    dns_records=result.dns_records,
                    ssl_info=result.ssl_info,
                    security_headers=result.security_headers,
                    takeover_records=result.takeover_records,
                    technologies=result.technologies,
                )
                result.vulnerabilities = await vuln_intel.analyze()
                await self._emit("phase", {
                    "name": "Vulnerability Intelligence", "status": "done",
                    "count": len(result.vulnerabilities), "icon": "done"
                })
                if _cli_prog:
                    _cli_prog.advance(_task_id)

            # Phase 5b: Email pattern analysis
            if result.emails:
                try:
                    result.email_pattern = EmailDiscovery.detect_email_pattern(result.emails, self.domain)
                except Exception:
                    result.email_pattern = {}
            if isinstance(result.whois_data, dict):
                try:
                    whois_blob = json.dumps(result.whois_data, default=str)
                    whois_emails = {
                        e.strip().lower()
                        for e in re.findall(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}", whois_blob, re.I)
                    }
                except Exception:
                    whois_emails = set()
                existing_emails = {
                    (row.get("email", "") if isinstance(row, dict) else getattr(row, "email", ""))
                    for row in (result.emails or [])
                }
                for email in sorted(whois_emails):
                    if email in existing_emails or "@" not in email:
                        continue
                    result.emails.append(asdict(EmailRecord(
                        email=email,
                        sources=["whois"],
                        role="admin" if email.endswith("@" + self.domain) else "whois_contact",
                        confidence=0.62 if email.endswith("@" + self.domain) else 0.48,
                        first_seen=_utcnow_iso(),
                        last_seen=_utcnow_iso(),
                    )))

            # Phase 5c: CVE PoC Enrichment (skip in fast mode, cap at 20 CVEs)
            if self.mode != 'fast':
                try:
                    cve_ids = set()
                    for v in result.vulnerabilities:
                        cve = (v.get('cve_id') or v.get('cve') or v.get('id', '')).upper()
                        if cve.startswith('CVE-'):
                            cve_ids.add(cve)
                    for ip in result.ip_records:
                        ip_d = ip if isinstance(ip, dict) else asdict(ip)
                        for cve in (ip_d.get('vulns') or []):
                            if isinstance(cve, str) and cve.upper().startswith('CVE-'):
                                cve_ids.add(cve.upper())
                    if cve_ids:
                        enrichments = await asyncio.gather(
                            *[self._enrich_cve(session, cve) for cve in list(cve_ids)[:20]],
                            return_exceptions=True
                        )
                        cve_map = {e['cve_id']: e for e in enrichments if isinstance(e, dict)}
                        result.cve_intelligence = cve_map
                        # Backfill vulnerability records
                        for v in result.vulnerabilities:
                            cve = (v.get('cve_id') or v.get('cve') or v.get('id', '')).upper()
                            if cve in cve_map:
                                e = cve_map[cve]
                                v.update({
                                    'has_exploit': e.get('has_exploit', False),
                                    'epss_score': e.get('epss_score'),
                                    'epss_percentile': e.get('epss_percentile'),
                                    'cvss_score': e.get('cvss_score') or v.get('cvss_score'),
                                    'exploit_db': e.get('exploit_db', []),
                                    'nuclei_templates': e.get('nuclei_templates', []),
                                    'poc_count': len(e.get('exploit_db', [])) + len(e.get('nuclei_templates', [])),
                                })
                except Exception:
                    pass

            # Phase 5d: Tech-based NVD CVE lookup (deep mode, high-confidence techs only)
            if self.mode == "deep" and result.technologies:
                try:
                    high_conf_techs = [t.get("name", "") for t in result.technologies
                                       if isinstance(t, dict) and t.get("confidence") == "high" and t.get("name")]
                    for tech_name in high_conf_techs[:8]:
                        try:
                            r = await _safe_get(
                                session,
                                f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={tech_name}&resultsPerPage=5&cvssV3Severity=HIGH",
                                timeout=10
                            )
                            if r and r.status == 200:
                                data = await r.json(content_type=None)
                                for vuln_item in data.get("vulnerabilities", []):
                                    cve_obj = vuln_item.get("cve", {})
                                    cve_id = cve_obj.get("id", "")
                                    if cve_id and cve_id not in result.cve_intelligence:
                                        desc = ""
                                        descs = cve_obj.get("descriptions", [])
                                        if descs:
                                            desc = descs[0].get("value", "")
                                        metrics = cve_obj.get("metrics", {})
                                        cvss = None
                                        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                                            if metrics.get(key):
                                                cvss = metrics[key][0].get("cvssData", {}).get("baseScore")
                                                break
                                        result.cve_intelligence[cve_id] = {
                                            "cve_id": cve_id,
                                            "description": desc,
                                            "cvss_score": cvss,
                                            "tech_source": tech_name,
                                            "epss_score": None,
                                            "has_exploit": False,
                                        }
                            await asyncio.sleep(0.6)
                        except Exception:
                            pass
                except Exception:
                    pass

            # Phase 6: Scoring
            await self._emit("phase", {"name": "Risk Scoring", "status": "running", "icon": "ok"})
            if _cli_prog:
                _cli_prog.update(_task_id, description="[cyan]Scoring")
            scorer = ScoreEngine(result)
            result.scores = scorer.explain_scores()
            await self._emit("phase", {"name": "Risk Scoring", "status": "done", "count": 0, "icon": "done"})
            if _cli_prog:
                _cli_prog.advance(_task_id)

            # Phase 7: Correlation Engine
            await self._emit("phase", {"name": "Correlations", "status": "running", "icon": "ok"})
            if _cli_prog:
                _cli_prog.update(_task_id, description="[cyan]Correlation Engine")
            try:
                correlation_engine = CorrelationEngine()
                corr_data = await correlation_engine.analyze(result)
                result.correlations = corr_data.get("findings", [])
                await self._emit("phase", {
                    "name": "Correlations", "status": "done",
                    "count": corr_data.get("total", 0), "icon": "done"
                })
                for finding in result.correlations:
                    if finding.get("severity") in ("CRITICAL", "HIGH"):
                        await self._emit("log", {
                            "level": "!!!!" if finding["severity"] == "CRITICAL" else "!",
                            "message": f"{finding['severity']}: {finding['title']}"
                        })
            except Exception:
                result.correlations = []
                await self._emit("phase", {"name": "Correlations", "status": "done", "count": 0, "icon": "done"})
            if _cli_prog:
                _cli_prog.advance(_task_id)

            if _cli_prog:
                try:
                    _cli_prog.stop()
                except Exception:
                    pass
        finally:
            reset_current_scan_id(scan_id_token)
            reset_current_http_guard(guard_token)
            scan_http_guard.unregister_scan(scan_id)
            reset_scan_context(ctx_tokens)

        result.duration_seconds = round(time.time() - t_start, 2)
        _done_subs = len(result.subdomains)
        _done_emails = len(result.emails)
        _done_ips = len(result.ip_records)
        _done_ports = sum(len(ip.get("open_ports", [])) for ip in result.ip_records if isinstance(ip, dict))
        _done_dorks = len(result.dorks)
        log.info(
            "[DONE] %s | %d subs | %d emails | %d IPs | %d ports | %d dorks | %.0fs",
            self.domain, _done_subs, _done_emails, _done_ips, _done_ports, _done_dorks, result.duration_seconds,
        )
        final_report = build_canonical_report(result)
        completeness_watch = {
            "social_footprint": final_report.get("data", {}).get("social_footprint", {}),
            "asn_intelligence": final_report.get("data", {}).get("asn_intelligence", {}),
            "reputation_data": final_report.get("data", {}).get("reputation_data", {}),
            "web_archive": final_report.get("web_archive", {}),
            "summary": final_report.get("summary", {}),
        }
        missing_or_empty = []
        for field_name, value in completeness_watch.items():
            if value in (None, "", [], {}):
                missing_or_empty.append(field_name)
        if missing_or_empty:
            log.info("[DATA_COMPLETENESS] %s missing_or_empty=%s", self.domain, ",".join(missing_or_empty))
        runtime_providers = final_report.get("runtime", {}).get("providers", {}) if isinstance(final_report.get("runtime", {}), dict) else {}
        provider_summary = {
            "ready": int(result.scan_context.get("api_key_summary", {}).get("ready_services_count", 0) or 0),
            "success": int(runtime_providers.get("success", 0) or 0),
            "partial": int(runtime_providers.get("partial", 0) or 0),
            "failed": int(runtime_providers.get("failed", 0) or 0),
            "missing_credentials": int(result.scan_context.get("api_key_summary", {}).get("missing_services_count", 0) or 0),
            "skipped": int(runtime_providers.get("skipped", 0) or 0),
            "api_enabled_count": int(result.scan_context.get("api_key_summary", {}).get("ready_services_count", 0) or 0),
            "passive_open_count": int(runtime_providers.get("passive_open_count", 0) or 0),
            "premium_success_count": int(runtime_providers.get("premium_success_count", 0) or 0),
        }
        provider_summary["total_considered"] = (
            provider_summary["success"]
            + provider_summary["partial"]
            + provider_summary["failed"]
            + provider_summary["missing_credentials"]
        )
        result.scan_context["provider_summary"] = provider_summary
        await self._emit("complete", {
            "scan_id": scan_id,
            "domain": self.domain,
            "duration": result.duration_seconds,
            "scores": result.scores,
            "source_metrics": result.source_metrics,
            "summary": _sse_summary(result),
            "providers": provider_summary,
        })
        return result


# Ã¢â€â‚¬Ã¢â€â‚¬ OUTPUT WRITERS Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
def _component_scores_view(scores: Any) -> Dict[str, Any]:
    raw = scores if isinstance(scores, dict) else {}
    allowed = ("attack_surface", "technology_risk", "exposure", "vulnerability")
    normalized: Dict[str, Any] = {}
    for key in allowed:
        value = raw.get(key, 0)
        try:
            normalized[key] = round(max(0.0, min(float(value or 0), 100.0)), 1)
        except (TypeError, ValueError):
            normalized[key] = 0.0
    return normalized


def _sanitize_export_scores_payload(payload: Any) -> Any:
    if not isinstance(payload, dict):
        return payload
    safe = copy.deepcopy(payload)
    if isinstance(safe.get("scores"), dict):
        safe["scores"] = _component_scores_view(safe.get("scores", {}))
    return safe


WEB_RESULT_SUMMARY_FILE = "web_summary.json"
WEB_RESULT_SECTION_DIR = "web_sections"
RESULT_META_CACHE_FILE = ".result_meta.json"
RESULT_META_CACHE_VERSION = 1
_RESULT_DATA_CACHE_KEY = "__grt_result_cache_key__"
_CANONICAL_REPORT_CACHE: "OrderedDict[str, Dict[str, Any]]" = OrderedDict()
WEB_RESULT_SECTION_FIELDS: Dict[str, Tuple[str, str]] = {
    "subdomains": ("subdomains", "data"),
    "emails": ("emails", "data"),
    "ips": ("ip_records", "data"),
    "certs": ("ssl_info", "data"),
    "dorks": ("dorks", "data"),
    "archive": ("web_archive", "report"),
    "techs": ("technologies", "data"),
    "vulns": ("vulnerabilities", "data"),
    "social": ("social_footprint", "report"),
    "reputation": ("reputation_data", "report"),
    "asn": ("asn_intelligence", "report"),
    "cloud": ("cloud_assets", "data"),
    "breach": ("breach_records", "data"),
    "takeover": ("takeover_records", "data"),
    "dns": ("dns_records", "data"),
}
STANDALONE_OFFLINE_SECTION_LIMITS: Dict[str, int] = {
    "subdomains": 1500,
    "emails": 1000,
    "ips": 800,
    "certs": 500,
    "techs": 500,
    "vulns": 800,
    "dorks": 500,
    "cloud": 500,
    "breach": 400,
    "takeover": 400,
    "dns": 800,
}
STANDALONE_OFFLINE_SECTION_LABELS: Dict[str, str] = {
    "subdomains": "subdomains",
    "emails": "emails",
    "ips": "infrastructure records",
    "certs": "SSL certificate records",
    "techs": "technology records",
    "vulns": "vulnerability findings",
    "dorks": "dorks",
    "cloud": "cloud asset records",
    "breach": "breach records",
    "takeover": "takeover records",
    "dns": "DNS records",
    "archive": "archive URLs",
}


def _result_meta_cache_path(out_dir: Path) -> Path:
    return out_dir / RESULT_META_CACHE_FILE


def _path_signature(path: Path) -> Dict[str, int]:
    if not isinstance(path, Path) or not path.exists():
        return {"mtime_ns": 0, "size": 0}
    try:
        stat = path.stat()
    except OSError:
        return {"mtime_ns": 0, "size": 0}
    return {
        "mtime_ns": int(getattr(stat, "st_mtime_ns", int(stat.st_mtime * 1_000_000_000))),
        "size": int(stat.st_size),
    }


def _signatures_match(left: Any, right: Any) -> bool:
    if not isinstance(left, dict) or not isinstance(right, dict):
        return False
    return (
        int(left.get("mtime_ns", 0) or 0) == int(right.get("mtime_ns", 0) or 0)
        and int(left.get("size", 0) or 0) == int(right.get("size", 0) or 0)
    )


def _safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _normalize_saved_scan_payload(raw: Any) -> Dict[str, Any]:
    """Normalize saved scan payloads to a flat data dict for old/new report formats."""
    if not isinstance(raw, dict):
        return {}
    if isinstance(raw.get("data"), dict):
        flat = dict(raw["data"])
        for key in (
            "scan_id",
            "domain",
            "scan_date",
            "mode",
            "report_version",
            "schema_version",
            "policy",
            "sources_enabled",
            "sources_disabled",
            "runtime",
            "sources_status",
            "summary",
            "coverage_score",
            "risk_score",
            "risk_level",
            "risk_details",
            "top_findings",
            "completeness",
            "coverage_by_source",
            "source_scoring",
            "source_intelligence",
            "source_overlaps",
            "subdomain_inventory",
            "policy_blocked_sources",
            "bug_bounty",
            "findings",
            "dorks",
            "web_archive",
            "archive_urls",
            "archive_summary",
            "entities",
            "entity_graph",
            "scores",
            "social_footprint",
            "asn_intelligence",
            "reputation",
            "email_security",
            "whois_data",
            "dns_records",
            "ip_records",
            "historical_ips",
            "takeover_candidates",
            "errors",
            "errors_summary",
            "raw_preservation",
            "analyst_summary",
            "executive_overview",
        ):
            if key not in flat and key in raw:
                flat[key] = raw[key]
        if "reputation_data" not in flat and isinstance(raw.get("reputation"), dict):
            flat["reputation_data"] = raw["reputation"]
        return flat
    return dict(raw)


def _history_total(summary: Dict[str, Any], render_totals: Dict[str, Any], data: Dict[str, Any], field: str, summary_key: Optional[str] = None) -> int:
    key = summary_key or field
    if isinstance(summary, dict):
        raw = summary.get(key)
        if raw not in (None, ""):
            return _safe_int(raw, 0)
    if isinstance(render_totals, dict):
        raw = render_totals.get(field)
        if raw not in (None, ""):
            return _safe_int(raw, 0)
    rows = data.get(field)
    if isinstance(rows, list):
        return len(rows)
    return 0


def _build_result_meta_entry(scan_dir: Path, *, scan_id: str, domain: str, scan_date: str, mode: str, duration: Any, risk_level: Any, overall_score: Any, summary: Dict[str, Any], render_totals: Dict[str, Any], data: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "scan_id": str(scan_id or scan_dir.name),
        "domain": str(domain or ""),
        "scan_date": str(scan_date or ""),
        "mode": str(mode or ""),
        "duration": round(float(duration or 0)),
        "risk_level": str(risk_level or "LOW"),
        "overall_score": overall_score if overall_score is not None else 0,
        "subdomains": _history_total(summary, render_totals, data, "subdomains"),
        "emails": _history_total(summary, render_totals, data, "emails"),
        "vulns": _history_total(summary, render_totals, data, "vulnerabilities", "vulns"),
        "ip_records": _history_total(summary, render_totals, data, "ip_records", "ips"),
        "typosquats": _history_total(summary, render_totals, data, "typosquats"),
        "dir": str(scan_dir),
    }


def _build_result_meta_from_report_payload(scan_dir: Path, raw_payload: Dict[str, Any]) -> Dict[str, Any]:
    data = _normalize_saved_scan_payload(raw_payload)
    summary = raw_payload.get("summary", data.get("summary", {}))
    summary = summary if isinstance(summary, dict) else {}
    scores = data.get("scores", {}) if isinstance(data.get("scores", {}), dict) else {}
    runtime = raw_payload.get("runtime", data.get("runtime", {}))
    runtime = runtime if isinstance(runtime, dict) else {}
    meta = raw_payload.get("meta", {}) if isinstance(raw_payload.get("meta", {}), dict) else {}
    risk_level = raw_payload.get("risk_level")
    if risk_level is None:
        risk_level = data.get("risk_level")
    if risk_level is None:
        risk_level = scores.get("risk_level", "LOW")
    overall_score = raw_payload.get("risk_score")
    if overall_score is None:
        overall_score = data.get("risk_score")
    if overall_score is None:
        overall_score = scores.get("overall", 0)
    return _build_result_meta_entry(
        scan_dir,
        scan_id=str(data.get("scan_id") or meta.get("scan_id") or scan_dir.name),
        domain=str(data.get("domain") or meta.get("domain") or ""),
        scan_date=str(data.get("scan_date") or meta.get("scan_date") or ""),
        mode=str(data.get("mode") or meta.get("mode") or ""),
        duration=data.get("duration_seconds", runtime.get("duration_seconds", meta.get("duration_seconds", 0))),
        risk_level=risk_level,
        overall_score=overall_score,
        summary=summary,
        render_totals={},
        data=data,
    )


def _build_result_meta_from_summary_bundle(scan_dir: Path, summary_bundle: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    if not isinstance(summary_bundle, dict):
        return None
    result_view = summary_bundle.get("result", {})
    report_view = summary_bundle.get("report", {})
    if not isinstance(result_view, dict) or not isinstance(report_view, dict):
        return None
    summary = report_view.get("summary", {}) if isinstance(report_view.get("summary", {}), dict) else {}
    render_totals = ((result_view.get("_render_meta", {}) if isinstance(result_view.get("_render_meta", {}), dict) else {}).get("totals", {}))
    render_totals = render_totals if isinstance(render_totals, dict) else {}
    return _build_result_meta_entry(
        scan_dir,
        scan_id=str(result_view.get("scan_id") or report_view.get("scan_id") or scan_dir.name),
        domain=str(result_view.get("domain") or report_view.get("domain") or ""),
        scan_date=str(result_view.get("scan_date") or report_view.get("scan_date") or ""),
        mode=str(result_view.get("mode") or report_view.get("mode") or ""),
        duration=result_view.get("duration_seconds", ((report_view.get("runtime", {}) if isinstance(report_view.get("runtime", {}), dict) else {}).get("duration_seconds", 0))),
        risk_level=report_view.get("risk_level", "LOW"),
        overall_score=report_view.get("risk_score", ((report_view.get("scores", {}) if isinstance(report_view.get("scores", {}), dict) else {}).get("overall", 0))),
        summary=summary,
        render_totals=render_totals,
        data=result_view,
    )


class StorageWriteError(OSError):
    """Raised when a report or settings write cannot be completed."""


def _ensure_directory(path: Path, *, label: str) -> None:
    try:
        path.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise StorageWriteError(f"Unable to create {label}: {exc}") from exc


def _write_json_file(
    path: Path,
    payload: Any,
    *,
    label: str,
    indent: Optional[int] = None,
    separators: Optional[Tuple[str, str]] = None,
) -> None:
    try:
        with open(path, "w", encoding="utf-8", newline="\n") as f:
            json.dump(payload, f, indent=indent, default=str, ensure_ascii=False, separators=separators)
    except OSError as exc:
        raise StorageWriteError(f"Unable to write {label} at {path}: {exc}") from exc


def _write_text_file(path: Path, text: str, *, label: str) -> None:
    try:
        with open(path, "w", encoding="utf-8", newline="\n") as f:
            f.write(normalize_text(text))
    except OSError as exc:
        raise StorageWriteError(f"Unable to write {label} at {path}: {exc}") from exc


def _write_jsonl_items(path: Path, items: Iterable[Any], *, label: str) -> None:
    try:
        with open(path, "w", encoding="utf-8", newline="\n") as f:
            for item in items:
                f.write(normalize_text(json.dumps(_normalize_text_tree(item), ensure_ascii=False)) + "\n")
    except OSError as exc:
        raise StorageWriteError(f"Unable to write {label} at {path}: {exc}") from exc


def _log_optional_write_failure(label: str, path: Path, exc: Exception) -> None:
    log.warning("%s optional write failed path=%s error=%s", label, path, exc)


def _write_result_meta_cache(out_dir: Path, entry: Dict[str, Any], report_signature: Dict[str, int]) -> None:
    if not isinstance(entry, dict):
        return
    payload = _normalize_text_tree({
        "version": RESULT_META_CACHE_VERSION,
        "report_signature": report_signature if isinstance(report_signature, dict) else {"mtime_ns": 0, "size": 0},
        "entry": entry,
    })
    _write_json_file(
        _result_meta_cache_path(out_dir),
        payload,
        label="result metadata cache",
        separators=(",", ":"),
    )


def build_canonical_report(result: Any) -> Dict[str, Any]:
    if isinstance(result, dict):
        cache_key = str(result.get(_RESULT_DATA_CACHE_KEY, "") or "")
        payload = _normalize_saved_scan_payload(result)
        payload.pop(_RESULT_DATA_CACHE_KEY, None)
        if cache_key:
            cached = _CANONICAL_REPORT_CACHE.get(cache_key)
            if isinstance(cached, dict):
                _CANONICAL_REPORT_CACHE.move_to_end(cache_key)
                return cached
            report = _build_canonical_report_raw(copy.deepcopy(payload))
            _CANONICAL_REPORT_CACHE[cache_key] = report
            _CANONICAL_REPORT_CACHE.move_to_end(cache_key)
            while len(_CANONICAL_REPORT_CACHE) > 16:
                _CANONICAL_REPORT_CACHE.popitem(last=False)
            return report
        return _build_canonical_report_raw(copy.deepcopy(payload))
    return _build_canonical_report_raw(result)


def _web_summary_path(out_dir: Path) -> Path:
    return out_dir / WEB_RESULT_SUMMARY_FILE


def _web_section_path(out_dir: Path, section: str) -> Path:
    return out_dir / WEB_RESULT_SECTION_DIR / f"{section}.json"


def _should_persist_web_section_sidecars(report_payload: Dict[str, Any]) -> bool:
    summary = report_payload.get("summary", {}) if isinstance(report_payload.get("summary", {}), dict) else {}
    archive = report_payload.get("web_archive", {}) if isinstance(report_payload.get("web_archive", {}), dict) else {}
    findings = report_payload.get("findings", {}) if isinstance(report_payload.get("findings", {}), dict) else {}
    archive_total = int(archive.get("total_retrieved", archive.get("total", summary.get("archive_urls", 0))) or 0)
    exposures = findings.get("exposures", []) if isinstance(findings.get("exposures", []), list) else []
    infra_findings = findings.get("infrastructure_observations", []) if isinstance(findings.get("infrastructure_observations", []), list) else []
    return any((
        archive_total > 5000,
        int(summary.get("subdomains", 0) or 0) > 250,
        int(summary.get("emails", 0) or 0) > 250,
        int(summary.get("ips", 0) or 0) > 250,
        int(summary.get("vulns", 0) or 0) > 100,
        len(exposures) > 200,
        len(infra_findings) > 120,
    ))


def _write_web_render_summary(out_dir: Path, result_payload: Dict[str, Any], report_payload: Dict[str, Any]) -> None:
    render_result, render_report = WebServer._build_render_payload(
        result_payload if isinstance(result_payload, dict) else {},
        report_payload if isinstance(report_payload, dict) else {},
    )
    payload = _normalize_text_tree({
        "result": render_result,
        "report": render_report,
    })
    _write_json_file(
        _web_summary_path(out_dir),
        payload,
        label="web render summary",
        separators=(",", ":"),
    )


def _write_web_section_sidecars(out_dir: Path, report_payload: Dict[str, Any]) -> None:
    if not _should_persist_web_section_sidecars(report_payload):
        return
    data_payload = report_payload.get("data", {}) if isinstance(report_payload.get("data", {}), dict) else {}
    section_dir = out_dir / WEB_RESULT_SECTION_DIR
    _ensure_directory(section_dir, label="web section sidecar directory")
    for section, (field, scope) in WEB_RESULT_SECTION_FIELDS.items():
        source = report_payload if scope == "report" else data_payload
        value = source.get(field)
        if value in (None, "", [], {}):
            continue
        payload = _normalize_text_tree({
            "section": section,
            "field": field,
            "data": value,
        })
        _write_json_file(
            _web_section_path(out_dir, section),
            payload,
            label=f"web section sidecar {section}",
            separators=(",", ":"),
        )


def _export_error_record(label: str, path: Path, exc: Exception) -> Dict[str, Any]:
    return {
        "time": _utcnow_iso(),
        "module": "Export",
        "source": str(label or "export"),
        "kind": type(exc).__name__,
        "message_short": normalize_text(f"{label} write failed: {exc}")[:160],
        "path": str(path),
    }


def _build_scan_output_dir(base_dir: Path | str, domain: str, suffix: str) -> Path:
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    return Path(base_dir) / f"{domain}_{timestamp}_{suffix}"


def _build_recon_engine(
    *,
    domain: str,
    mode: str,
    api_keys: Dict[str, str],
    output_dir: Path,
    policy: ScanPolicy,
    debug_coverage: bool,
    source_registry: SourceRegistry,
    progress_cb: Optional[Callable[[str, dict], Awaitable[None]]] = None,
) -> "ReconEngine":
    return ReconEngine(
        domain=domain,
        mode=mode,
        api_keys=api_keys,
        output_dir=str(output_dir),
        progress_cb=progress_cb,
        policy=policy,
        debug_coverage=debug_coverage,
        source_registry=source_registry,
    )


def write_json(result: ReconResult, out_dir: Path):
    path = out_dir / "report.json"
    canonical = build_canonical_report(result)
    data = canonical.get("data", asdict(result))
    data_payload = data if isinstance(data, dict) else {}
    data_payload = _sanitize_export_scores_payload(data_payload)
    scan_ctx = data_payload.get("scan_context", {}) if isinstance(data_payload.get("scan_context", {}), dict) else {}
    if "api_keys" in scan_ctx:
        scan_ctx["api_keys"] = {
            "set_count": int((scan_ctx.get("api_keys", {}) or {}).get("set_count", 0)),
            "missing_count": int((scan_ctx.get("api_keys", {}) or {}).get("missing_count", 0)),
        }
        data_payload["scan_context"] = scan_ctx

    component_scores = _component_scores_view(canonical.get("scores", result.scores))

    output = {
        "report_version": canonical.get("report_version", "0.1"),
        "schema_version": canonical.get("schema_version", "3.1"),
        "policy": canonical.get("policy", {}),
        "sources_enabled": canonical.get("sources_enabled", []),
        "sources_disabled": canonical.get("sources_disabled", []),
        "sources_status": canonical.get("sources_status", {}),
        "runtime": canonical.get("runtime", {}),
        "completeness": canonical.get("completeness", {}),
        "coverage_by_source": canonical.get("coverage_by_source", {}),
        "source_scoring": canonical.get("source_scoring", {}),
        "source_intelligence": canonical.get("source_intelligence", {}),
        "source_overlaps": canonical.get("source_overlaps", []),
        "subdomain_inventory": canonical.get("subdomain_inventory", {}),
        "top_findings": canonical.get("top_findings", []),
        "coverage_score": canonical.get("coverage_score", 0),
        "risk_score": canonical.get("risk_score", 0),
        "risk_level": canonical.get("risk_level", "LOW"),
        "risk_details": canonical.get("risk_details", {}),
        "bug_bounty": canonical.get("bug_bounty", {}),
        "findings": canonical.get("findings", {}),
        "entities": canonical.get("entities", {}),
        "entity_graph": canonical.get("entity_graph", {}),
        "errors": canonical.get("errors", []),
        "errors_summary": canonical.get("errors_summary", {}),
        "meta": {
            "tool": "Ghost Recon Tool",
            "version": canonical.get("report_version", "0.1"),
            "domain": result.domain,
            "scan_id": result.scan_id,
            "scan_date": result.scan_date,
            "mode": result.mode,
            "duration_seconds": result.duration_seconds,
        },
        "scores": component_scores,
        "score_components": component_scores,
        "summary": canonical.get("summary", {}),
        "ip_records": canonical.get("ip_records", data_payload.get("ip_records", [])),
        "web_archive": canonical.get("web_archive", {}),
        "archive_urls": canonical.get("archive_urls", data_payload.get("archive_urls", [])),
        "archive_summary": canonical.get("archive_summary", data_payload.get("archive_summary", {})),
        "social_footprint": canonical.get("social_footprint", data_payload.get("social_footprint", {})),
        "asn_intelligence": canonical.get("asn_intelligence", data_payload.get("asn_intelligence", {})),
        "reputation_data": canonical.get("reputation", data_payload.get("reputation_data", {})),
        "raw_preservation": canonical.get("raw_preservation", data_payload.get("raw_preservation", {})),
        "data": data_payload,
    }
    secrets = [v for v in load_api_keys().values() if isinstance(v, str) and v]
    safe_output = _redact_sensitive_tree(_normalize_text_tree(output), secrets)
    _write_json_file(path, safe_output, label="JSON export", indent=2)
    try:
        _write_result_meta_cache(out_dir, _build_result_meta_from_report_payload(out_dir, safe_output), _path_signature(path))
    except Exception as exc:
        _log_optional_write_failure("result_meta_cache", _result_meta_cache_path(out_dir), exc)
    try:
        _write_web_render_summary(out_dir, safe_output.get("data", {}), safe_output)
    except Exception as exc:
        _log_optional_write_failure("web_summary", _web_summary_path(out_dir), exc)
    try:
        _write_web_section_sidecars(out_dir, safe_output)
    except Exception as exc:
        _log_optional_write_failure("web_sections", out_dir / WEB_RESULT_SECTION_DIR, exc)
    dropped = (output.get("data", {}) or {}).get("scan_context", {}).get("dropped_items", [])
    if isinstance(dropped, list) and dropped:
        drops_path = out_dir / "dropped_items.jsonl"
        try:
            _write_jsonl_items(drops_path, dropped, label="dropped-items export")
        except Exception as exc:
            _log_optional_write_failure("dropped_items", drops_path, exc)
    return path


def _rebuild_recon_result_view(payload: dict) -> ReconResult:
    base = ReconResult(domain="", scan_id="", scan_date="", mode="")
    values = asdict(base)
    for field_name, default_value in values.items():
        setattr(base, field_name, payload.get(field_name, default_value))
    return base


def _iter_text_bytes(text: str, chunk_size: int = 1 << 16) -> Iterator[bytes]:
    if not isinstance(text, str):
        text = str(text)
    total = len(text)
    for start in range(0, total, chunk_size):
        yield text[start:start + chunk_size].encode("utf-8")


async def _download_file_response(
    request: aio_web.Request,
    path: Path,
    filename: str,
    content_type: str,
) -> aio_web.StreamResponse:
    quoted_fn = quote(filename, safe="")
    stat = path.stat()
    response = aio_web.StreamResponse(
        status=200,
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"; filename*=UTF-8\'\'{quoted_fn}',
            "Content-Type": content_type,
            "Content-Length": str(stat.st_size),
            "X-Content-Type-Options": "nosniff",
        },
    )
    await response.prepare(request)
    with open(path, "rb") as f:
        while True:
            chunk = f.read(1 << 16)
            if not chunk:
                break
            await response.write(chunk)
    await response.write_eof()
    return response


async def _stream_text_download(
    request: aio_web.Request,
    content_type: str,
    filename: str,
    text: str,
) -> aio_web.StreamResponse:
    quoted_fn = quote(filename, safe="")
    payload = normalize_text(text).encode("utf-8")
    response = aio_web.StreamResponse(
        status=200,
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"; filename*=UTF-8\'\'{quoted_fn}',
            "X-Content-Type-Options": "nosniff",
            "Content-Length": str(len(payload)),
        },
    )
    response.content_type = content_type
    response.charset = "utf-8"
    await response.prepare(request)
    for chunk in _iter_text_bytes(payload.decode("utf-8")):
        await response.write(chunk)
    await response.write_eof()
    return response


async def _stream_bytes_download(
    request: aio_web.Request,
    content_type: str,
    filename: str,
    payload: bytes,
) -> aio_web.StreamResponse:
    quoted_fn = quote(filename, safe="")
    response = aio_web.StreamResponse(
        status=200,
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"; filename*=UTF-8\'\'{quoted_fn}',
            "Content-Type": content_type,
            "Content-Length": str(len(payload)),
            "X-Content-Type-Options": "nosniff",
        },
    )
    await response.prepare(request)
    for start in range(0, len(payload), 1 << 16):
        await response.write(payload[start:start + (1 << 16)])
    await response.write_eof()
    return response


def write_txt(result: ReconResult, out_dir: Path):
    path = out_dir / "report.txt"
    canonical = build_canonical_report(result)
    canonical_data = canonical.get("data", asdict(result))
    result = _rebuild_recon_result_view(canonical_data if isinstance(canonical_data, dict) else {})
    completeness = canonical.get("completeness", {})
    top_findings = canonical.get("top_findings", [])
    risk_details = canonical.get("risk_details", {})
    finding_groups = canonical.get("findings", {})
    source_intelligence = canonical.get("source_intelligence", {})
    source_summary = source_intelligence.get("summary", {}) if isinstance(source_intelligence, dict) else {}
    subdomain_inventory = canonical.get("subdomain_inventory", {}) if isinstance(canonical.get("subdomain_inventory", {}), dict) else {}
    provider_summary = canonical.get("runtime", {}).get("providers", {}) if isinstance(canonical.get("runtime", {}), dict) else {}
    source_ranking = source_intelligence.get("ranking", []) if isinstance(source_intelligence, dict) else []
    source_overlaps = canonical.get("source_overlaps", []) if isinstance(canonical.get("source_overlaps", []), list) else []
    bug_bounty = canonical.get("bug_bounty", {}) if isinstance(canonical.get("bug_bounty", {}), dict) else {}
    artifact_inventory = bug_bounty.get("artifact_inventory", {}) if isinstance(bug_bounty.get("artifact_inventory", {}), dict) else {}
    artifact_summary = artifact_inventory.get("summary", {}) if isinstance(artifact_inventory.get("summary", {}), dict) else {}
    high_value_files = artifact_inventory.get("high_value_files", []) if isinstance(artifact_inventory.get("high_value_files", []), list) else []
    archived_files = artifact_inventory.get("archived_files", []) if isinstance(artifact_inventory.get("archived_files", []), list) else []
    grouped_endpoints = artifact_inventory.get("interesting_endpoints", []) if isinstance(artifact_inventory.get("interesting_endpoints", []), list) else []
    artifact_hints = artifact_inventory.get("artifact_hints", []) if isinstance(artifact_inventory.get("artifact_hints", []), list) else []
    internal_references = artifact_inventory.get("internal_references", []) if isinstance(artifact_inventory.get("internal_references", []), list) else []
    lines = []
    sep    = "=" * 72
    thin   = "-" * 72
    scores = _component_scores_view(canonical.get("scores", result.scores or {}))
    risk = canonical.get("risk_level", "N/A")
    overall = canonical.get("risk_score", 0)

    def _artifact_count(key: str, rows: list) -> int:
        return int(artifact_summary.get(key, len(rows)) or 0)

    def _append_artifact_rows(title: str, rows: list, *, limit: int = 15, secondary: bool = False) -> None:
        if not rows:
            return
        lines.append(f"\n[{title}]  ({len(rows)} found)")
        for row in rows[:limit]:
            label = str(row.get("label", row.get("asset", row.get("url", ""))) or "")
            url = str(row.get("url", "") or "")
            type_label = str(row.get("type", "") or "")
            subtype = str(row.get("subtype", "") or "")
            source = str(row.get("source", "") or "")
            recency = str(row.get("observation_recency", "") or "")
            evidence = str(row.get("evidence", "") or "")
            confidence = float(row.get("confidence", 0.0) or 0.0)
            prefix = "  [secondary]" if secondary else f"  [{type_label or 'artifact':<17}]"
            descriptor = subtype or type_label or "artifact"
            lines.append(
                f"{prefix} {label[:42]:<42} {descriptor:<18} "
                f"conf={confidence:.2f} src={source or '-'} recency={recency or '-'}"
            )
            if url:
                lines.append(f"             url: {url[:104]}")
            if evidence:
                lines.append(f"             why: {evidence[:104]}")

    # Ã¢â€â‚¬Ã¢â€â‚¬ Executive Summary Box Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
    lines.append(sep)
    lines.append("  GHOST RECON TOOL - Passive Domain Reconnaissance Report")
    lines.append(sep)
    lines.append(f"  Target   : {result.domain}")
    lines.append(f"  Scan ID  : {result.scan_id}")
    lines.append(f"  Date     : {result.scan_date}")
    lines.append(f"  Mode     : {result.mode.upper()}")
    lines.append(f"  Duration : {result.duration_seconds}s")
    lines.append(thin)
    lines.append("  EXECUTIVE SUMMARY")
    lines.append(thin)

    crit_vulns  = [v for v in result.vulnerabilities if v.get("severity") == "CRITICAL"]
    high_vulns  = [v for v in result.vulnerabilities if v.get("severity") == "HIGH"]
    crit_corr   = [c for c in (result.correlations or []) if c.get("severity") == "CRITICAL"]
    vuln_takeo  = [t for t in result.takeover_records if t.get("status") == "VULNERABLE"]
    public_cloud = [c for c in result.cloud_assets if c.get("public")]

    lines.append(f"  Risk Level       : {risk} ({overall}/100)")
    if risk_details.get("explain_short"):
        lines.append(f"  Risk Rationale   : {risk_details.get('explain_short')}")
    if scores:
        lines.append(
            f"  Component Scores : attack_surface={scores.get('attack_surface',0)} "
            f"technology={scores.get('technology_risk',0)} exposure={scores.get('exposure',0)} "
            f"vulnerability={scores.get('vulnerability',0)}"
        )
    lines.append(f"  Data Completeness: {completeness.get('overall_percent', 0)}%")
    lines.append(f"  Multi-source Obs : {source_summary.get('multi_source_findings', 0)}")
    lines.append(f"  API-only Findings: {source_summary.get('api_only_findings', 0)}")
    lines.append(
        f"  Subdomain Flow   : raw={subdomain_inventory.get('raw_discovered_count', len(result.subdomains))} "
        f"unique={subdomain_inventory.get('unique_normalized_count', len(result.subdomains))} "
        f"final={subdomain_inventory.get('accepted_final_count', len(result.subdomains))} "
        f"rejected={subdomain_inventory.get('rejected_noise_count', 0)}"
    )
    lines.append(
        f"  Confidence Mix   : high={subdomain_inventory.get('high_confidence_count', 0)} "
        f"medium={subdomain_inventory.get('medium_confidence_count', 0)} noisy={subdomain_inventory.get('noisy_count', 0)} "
        f"wildcard={subdomain_inventory.get('wildcard_suspected_count', 0)}"
    )
    lines.append(
        f"  Providers        : ready={provider_summary.get('ready', 0)} ok={provider_summary.get('success', 0)} "
        f"partial={provider_summary.get('partial', 0)} failed={provider_summary.get('failed', 0)} "
        f"missing={provider_summary.get('missing_credentials', 0)}"
    )
    lines.append(f"  Subdomains       : {len(result.subdomains)}")
    lines.append(f"  Emails Exposed   : {len(result.emails)}")
    lines.append(f"  Technologies     : {len(result.technologies)}")
    lines.append(
        f"  Vulnerabilities  : {len((finding_groups.get('vulnerabilities', []) if isinstance(finding_groups, dict) else []))} confirmed/passive "
        f"({len((finding_groups.get('exposures', []) if isinstance(finding_groups, dict) else []))} exposures, "
        f"{len((finding_groups.get('intelligence_leads', []) if isinstance(finding_groups, dict) else []))} intelligence leads)"
    )
    lines.append(f"  Finding Records  : {len(result.vulnerabilities)} total "
                 f"({len(crit_vulns)} CRITICAL, {len(high_vulns)} HIGH)")
    lines.append(f"  Takeovers        : {len(vuln_takeo)} confirmed, "
                 f"{len(result.takeover_records) - len(vuln_takeo)} potential")
    lines.append(f"  Breaches         : {len(result.breach_records)}")
    lines.append(f"  High-Value Files : {_artifact_count('high_value_files', high_value_files)}")
    lines.append(f"  Archived Files   : {_artifact_count('archived_files', archived_files)}")
    lines.append(f"  Interesting EPs  : {_artifact_count('interesting_endpoints', grouped_endpoints)}")
    lines.append(f"  Artifact Hints   : {_artifact_count('artifact_hints', artifact_hints)}")
    lines.append(f"  Internal Refs    : {_artifact_count('internal_references', internal_references)}")
    lines.append(f"  Correlations     : {len(result.correlations or [])} "
                 f"({len(crit_corr)} CRITICAL)")
    lines.append(f"  Public Cloud     : {len(public_cloud)} exposed assets")

    if crit_vulns or crit_corr or vuln_takeo:
        lines.append("")
        lines.append("  !! IMMEDIATE ACTION REQUIRED !!")
        for v in crit_vulns[:5]:
            lines.append(f"    [CRITICAL VULN] {v.get('cve_id','')} - {v.get('title','')[:60]}")
        for c in crit_corr[:3]:
            lines.append(f"    [CRITICAL CORR] {c.get('title','')[:65]}")
        for t in vuln_takeo[:3]:
            lines.append(f"    [TAKEOVER] {t.get('subdomain','')} Ã¢â€ â€™ {t.get('provider','')}")
    lines.append(sep)

    lines.append("\n[TOP FINDINGS]")
    if top_findings:
        for f in top_findings[:8]:
            classification = str(f.get("classification", "") or "").upper()
            suffix = f" [{classification}]" if classification else ""
            scope = "1P" if f.get("first_party", True) else "3P"
            recency = str(f.get("observation_recency", "historical_only") or "historical_only")
            rationale = f.get("why_prioritized", "") or ""
            lines.append(
                f"  [{f.get('severity','INFO')}] {f.get('type','finding')}: "
                f"{(f.get('title','') or '')[:88]}{suffix} "
                f"(confidence={float(f.get('confidence', 0)):.2f}, {scope}, {recency})"
            )
            if rationale:
                lines.append(f"             why: {rationale[:110]}")
    else:
        lines.append("  No high-priority passive findings.")

    if result.high_value_targets:
        lines.append("\n[HIGH VALUE TARGETS]")
        for row in result.high_value_targets[:12]:
            lines.append(
                f"  {row.get('host',''):<45} score={row.get('score',0):>3} "
                f"class={row.get('classification','passive')} recency={row.get('observation_recency','current_passive')} "
                f"reasons={','.join(row.get('reasons', [])[:3])}"
            )

    _append_artifact_rows("HIGH-VALUE FILES", high_value_files, limit=18)
    _append_artifact_rows("ARCHIVED FILES", archived_files, limit=18)
    _append_artifact_rows("INTERESTING ENDPOINTS", grouped_endpoints, limit=20)
    _append_artifact_rows("ARTIFACT HINTS", artifact_hints, limit=16, secondary=True)
    _append_artifact_rows("INTERNAL REFERENCES", internal_references, limit=12, secondary=True)

    if source_ranking:
        lines.append("\n[TOP SOURCES]")
        for row in source_ranking[:8]:
            lines.append(
                f"  {row.get('source',''):<22} bucket={row.get('quality_bucket','medium_confidence'):<17} "
                f"total={row.get('findings_total',0):>4} unique={row.get('uniques_contributed',0):>4} "
                f"api_only={row.get('api_only_findings',0):>3} weight={float(row.get('effective_weight',0)):.2f}"
            )

    if source_overlaps:
        lines.append("\n[TOP SOURCE OVERLAPS]")
        for row in source_overlaps[:6]:
            lines.append(
                f"  {row.get('left','')} + {row.get('right','')} => {row.get('shared_findings',0)} shared findings"
            )

    lines.append("\n[DATA COMPLETENESS]")
    sections = completeness.get("sections", {})
    if isinstance(sections, dict) and sections:
        for sec_name, sec_meta in sections.items():
            reason = sec_meta.get("reason", "")
            reason_tail = f" ({reason})" if reason else ""
            lines.append(f"  {sec_name:<16} {sec_meta.get('percent',0):>5}%{reason_tail}")
    else:
        lines.append("  Completeness metrics unavailable.")

    overlaps = canonical.get("source_overlaps", [])
    if overlaps:
        lines.append("\n[SOURCE OVERLAPS]")
        for row in overlaps[:10]:
            lines.append(
                f"  {row.get('left',''):<20} + {row.get('right',''):<20}  shared={row.get('shared_findings',0)}"
            )

    # Ã¢â€â‚¬Ã¢â€â‚¬ Subdomains Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
    lines.append(f"\n[SUBDOMAINS]  ({len(result.subdomains)} total)")
    for s in result.subdomains:
        ips   = ", ".join(s.get("ips", [])) or "-"
        src   = ", ".join(s.get("sources", []))
        tags  = ",".join(s.get("tags", []))
        score = s.get("relevance_score", 0)
        tag_str = f"  [{tags}]" if tags else ""
        lines.append(f"  {s.get('name',''):<50}  IPs:{ips:<18}  score:{score}/10{tag_str}  src:[{src}]")

    # Ã¢â€â‚¬Ã¢â€â‚¬ DNS Records Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
    lines.append(f"\n[DNS RECORDS]  ({len(result.dns_records)} records)")
    for r in result.dns_records:
        lines.append(f"  {r.get('type',''):6}  {r.get('name',''):40}  {r.get('value','')}")

    # Ã¢â€â‚¬Ã¢â€â‚¬ Emails Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
    lines.append(f"\n[EMAILS]  ({len(result.emails)} found)")
    ep = result.email_pattern or {}
    if ep.get("pattern"):
        lines.append(f"  Pattern detected: {ep['pattern']} (confidence: {ep.get('confidence',0)}%)")
    for e in result.emails:
        lines.append(f"  {e.get('email',''):<45}  [{e.get('role', e.get('role_category',''))}]  via {', '.join(e.get('sources',[]))}")

    # Ã¢â€â‚¬Ã¢â€â‚¬ Technologies Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
    lines.append(f"\n[TECHNOLOGIES]  ({len(result.technologies)} detected)")
    for t in result.technologies:
        ver = f" v{t['version']}" if t.get("version") else ""
        lines.append(
            f"  {t.get('name',''):25}  {t.get('category',''):20}  {t.get('confidence','')}{ver}  "
            f"{t.get('observation_recency','current_passive')}"
        )

    # Ã¢â€â‚¬Ã¢â€â‚¬ IP Records Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
    lines.append(f"\n[IP INTELLIGENCE]  ({len(result.ip_records)} IPs)")
    for ip in result.ip_records:
        shared = ip.get("shared_hosting", [])
        shared_str = f"  shared:{len(shared)} domains" if shared else ""
        lines.append(f"  {ip.get('ip',''):18}  ASN:{ip.get('asn',''):<12}  "
                     f"{ip.get('org',''):<30}  {ip.get('country','')}  CDN:{ip.get('cdn',False)}{shared_str}")

    # Ã¢â€â‚¬Ã¢â€â‚¬ Vulnerabilities Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
    lines.append(f"\n[VULNERABILITIES]  ({len(result.vulnerabilities)} findings)")
    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    sorted_vulns = sorted(result.vulnerabilities,
                          key=lambda x: sev_order.get(x.get("severity", "INFO"), 99))
    for v in sorted_vulns:
        sev    = v.get("severity", "")
        cve    = v.get("cve_id", "")
        title  = v.get("title", "")[:65]
        asset  = v.get("affected_asset", "")
        cvss   = v.get("cvss_score", "")
        epss   = v.get("epss_score", "")
        nuclei = " [PoC]" if v.get("has_nuclei_template") else ""
        epss_s = f" EPSS:{epss:.0%}" if epss else ""
        cvss_s = f" CVSS:{cvss}" if cvss else ""
        classification = str(v.get("classification", "") or "")
        class_s = f" class:{classification}" if classification else ""
        confidence = v.get("confidence")
        conf_s = ""
        if confidence not in (None, ""):
            try:
                conf_s = f" conf:{float(confidence):.2f}"
            except (TypeError, ValueError):
                conf_s = ""
        fam_s = f" family:{v.get('finding_family','vulnerability')}"
        tier_s = f" tier:{v.get('evidence_tier','supported_passive_inference')}"
        lines.append(f"  [{sev:<8}] {cve:<20}  {title:<65}  asset:{asset}{cvss_s}{epss_s}{nuclei}{class_s}{conf_s}{fam_s}{tier_s}")
        if v.get("remediation"):
            lines.append(f"             Remediation: {v['remediation'][:80]}")

    # Ã¢â€â‚¬Ã¢â€â‚¬ Correlations Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
    correlations = result.correlations or []
    if correlations:
        lines.append(f"\n[INTELLIGENCE CORRELATIONS]  ({len(correlations)} findings)")
        for c in correlations:
            sev    = c.get("severity", "")
            title  = c.get("title", "")
            detail = c.get("detail", "")
            action = c.get("action", "")
            lines.append(f"  [{sev:<8}] {title}")
            if detail:
                lines.append(f"             {detail[:100]}")
            if action:
                lines.append(f"             ACTION: {action[:80]}")

    # Ã¢â€â‚¬Ã¢â€â‚¬ Takeover Candidates Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
    lines.append(f"\n[SUBDOMAIN TAKEOVERS]  ({len(result.takeover_records)} candidates)")
    for t in result.takeover_records:
        lines.append(f"  [{t.get('severity',''):<8}] {t.get('subdomain',''):<40} "
                     f"-> {t.get('provider',''):<20}  ({t.get('status','')})")
        if t.get("evidence"):
            lines.append(f"             Evidence: {t['evidence'][:80]}")

    # Ã¢â€â‚¬Ã¢â€â‚¬ Cloud Assets Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
    lines.append(f"\n[CLOUD ASSETS]  ({len(result.cloud_assets)} found)")
    for c in result.cloud_assets:
        pub = "PUBLIC" if c.get("public") else "private"
        lines.append(f"  [{pub}]  {c.get('asset_type',''):10}  {c.get('name','')}")

    # Ã¢â€â‚¬Ã¢â€â‚¬ Breach Records Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
    lines.append(f"\n[BREACH RECORDS]  ({len(result.breach_records)} breaches)")
    for b in result.breach_records:
        dtypes = ", ".join(b.get("data_types", []))
        lines.append(f"  {b.get('name',''):<30}  {b.get('date',''):<12}  "
                     f"records:{b.get('breach_count','?')}  data:[{dtypes}]")

    # Ã¢â€â‚¬Ã¢â€â‚¬ WHOIS Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
    lines.append("\n[WHOIS]")
    for k, v in result.whois_data.items():
        if k != "source":
            lines.append(f"  {k}: {v}")

    # Ã¢â€â‚¬Ã¢â€â‚¬ Scores Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
    lines.append("\n[SCORE COMPONENTS]")
    for k, v in scores.items():
        lines.append(f"  {k}: {v}")
    lines.append(sep)

    appendix_sections = [
        ("TOP FINDINGS", top_findings),
        ("FINDING GROUPS", finding_groups),
        ("WEB ARCHIVE", canonical.get("web_archive", {})),
        ("BUG BOUNTY", canonical.get("bug_bounty", {})),
        ("SOURCE SCORING", canonical.get("source_scoring", {})),
        ("SOURCE INTELLIGENCE", canonical.get("source_intelligence", {})),
        ("SOURCE OVERLAPS", source_overlaps),
        ("ENTITY GRAPH", canonical.get("entity_graph", {})),
        ("RAW PRESERVATION", canonical.get("raw_preservation", {})),
        ("ARCHIVE SUMMARY", canonical.get("archive_summary", {})),
        ("SOCIAL FOOTPRINT", getattr(result, "social_footprint", {}) or {}),
        ("ASN INTELLIGENCE", getattr(result, "asn_intelligence", {}) or {}),
        ("REPUTATION", getattr(result, "reputation_data", {}) or {}),
        ("EMAIL SECURITY", canonical_data.get("email_security", {}) if isinstance(canonical_data, dict) else {}),
        ("SCAN CONTEXT", canonical_data.get("scan_context", {}) if isinstance(canonical_data, dict) else {}),
    ]
    for title, payload in appendix_sections:
        if payload in (None, {}, []):
            continue
        lines.append(f"\n[{title}]")
        payload_text = normalize_text(json.dumps(_normalize_text_tree(payload), indent=2, default=str, ensure_ascii=False))
        for row in payload_text.splitlines():
            lines.append(f"  {row}" if row else "")

    _write_text_file(path, "\n".join(lines), label="TXT export")
    return path


def write_html(result: ReconResult, out_dir: Path):
    path = out_dir / "report.html"
    canonical = build_canonical_report(result)
    html = _render_standalone_report_html(canonical.get("data", asdict(result)), canonical)
    _write_text_file(path, html, label="HTML export")
    return path


def _inline_standalone_assets(html: str) -> str:
    css_path = Path(__file__).parent / "static" / "app.css"
    js_path = Path(__file__).parent / "static" / "app.js"
    logo_path = Path(__file__).parent / "static" / "logo.png"
    css = css_path.read_text(encoding="utf-8") if css_path.exists() else ""
    js = js_path.read_text(encoding="utf-8") if js_path.exists() else ""
    logo_uri = ""
    if logo_path.exists():
        logo_uri = f"data:image/png;base64,{base64.b64encode(logo_path.read_bytes()).decode('ascii')}"
    if css:
        html = html.replace('<link rel="stylesheet" href="/static/app.css">', f"<style>\n{css}\n</style>")
    if js:
        html = html.replace('<script src="/static/app.js"></script>', f"<script>\n{js}\n</script>")
    html = html.replace('<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>', "")
    if logo_uri:
        html = html.replace('href="/static/logo.png"', f'href="{logo_uri}"')
        html = html.replace('src="/static/logo.png"', f'src="{logo_uri}"')
    return html


def _standalone_archive_subset(canonical_data: dict, canonical_report: dict, sample_limit: int = 500) -> tuple[dict, dict]:
    standalone_data = copy.deepcopy(canonical_data if isinstance(canonical_data, dict) else {})
    archive = copy.deepcopy(canonical_report.get("web_archive", {}) if isinstance(canonical_report, dict) else {})
    if not isinstance(archive, dict):
        return standalone_data, {}
    total_urls = int(archive.get("total_retrieved", archive.get("total", 0)) or 0)
    if total_urls <= 10000:
        return standalone_data, archive

    sample_rows: List[Dict[str, Any]] = []
    sample_seen: set[str] = set()
    sample_keys = (
        "interesting_paths",
        "api_endpoints",
        "sensitive_files",
        "admin_paths",
        "documents",
        "js_files",
        "uncategorized_urls",
        "all_urls",
    )

    def add_rows(items: Any) -> None:
        for row in (items if isinstance(items, list) else []):
            if len(sample_rows) >= sample_limit:
                return
            if isinstance(row, dict):
                url = str(row.get("url", "") or "")
                if url and url in sample_seen:
                    continue
                if url:
                    sample_seen.add(url)
                sample_rows.append(copy.deepcopy(row))
            elif row:
                url = str(row)
                if url in sample_seen:
                    continue
                sample_seen.add(url)
                sample_rows.append({"url": url})

    for key in sample_keys:
        add_rows(archive.get(key, []))
        if len(sample_rows) >= sample_limit:
            break

    archive["all_urls"] = sample_rows[:sample_limit]
    archive["uncategorized_urls"] = []
    archive["standalone_limited"] = True
    archive["standalone_limit_reason"] = "Large archive inventory omitted from standalone bundle; use JSON download for full history."

    wayback = standalone_data.get("wayback_urls", {}) if isinstance(standalone_data.get("wayback_urls", {}), dict) else {}
    wayback_copy = copy.deepcopy(wayback)
    wayback_copy["all"] = archive["all_urls"]
    wayback_copy["all_urls"] = archive["all_urls"]
    wayback_copy["standalone_limited"] = True
    standalone_data["wayback_urls"] = wayback_copy
    standalone_data["archive_urls"] = archive["all_urls"]
    standalone_data["archive_summary"] = {
        **(standalone_data.get("archive_summary", {}) if isinstance(standalone_data.get("archive_summary", {}), dict) else {}),
        "standalone_limited": True,
        "standalone_limit": sample_limit,
    }
    return standalone_data, archive


def _build_standalone_offline_list_section(section: str, field: str, rows: Any, limit: int) -> Dict[str, Any]:
    items = rows if isinstance(rows, list) else []
    safe_limit = max(1, int(limit or len(items) or 1))
    embedded_rows = [copy.deepcopy(row) for row in items[:safe_limit]]
    total = len(items)
    limited = total > len(embedded_rows)
    label = STANDALONE_OFFLINE_SECTION_LABELS.get(section, field.replace("_", " "))
    return {
        "section": section,
        "field": field,
        "data": embedded_rows,
        "total": total,
        "embedded_total": len(embedded_rows),
        "standalone_limited": limited,
        "standalone_limit": safe_limit,
        "standalone_limit_reason": (
            f"Standalone export embeds the first {len(embedded_rows):,} of {total:,} {label} for offline browsing. Full inventory remains in the JSON export."
            if limited else ""
        ),
    }


def _build_standalone_archive_section_payload(archive_payload: dict) -> Dict[str, Any]:
    archive_payload = archive_payload if isinstance(archive_payload, dict) else {}
    rows = archive_payload.get("all_urls", [])
    rows = rows if isinstance(rows, list) else []
    total = int(archive_payload.get("total_retrieved", archive_payload.get("total", len(rows))) or 0)
    if total <= 0:
        total = len(rows)
    embedded_total = len(rows)
    limited = bool(archive_payload.get("standalone_limited")) or total > embedded_total
    return {
        "section": "archive",
        "field": "web_archive",
        "data": copy.deepcopy(archive_payload),
        "total": total,
        "embedded_total": embedded_total,
        "standalone_limited": limited,
        "standalone_limit": int(archive_payload.get("standalone_limit", embedded_total) or embedded_total),
        "standalone_limit_reason": str(archive_payload.get("standalone_limit_reason", "") or ""),
    }


def _build_standalone_offline_sections(standalone_data: dict, standalone_archive: dict) -> Dict[str, Any]:
    source_data = standalone_data if isinstance(standalone_data, dict) else {}
    sections: Dict[str, Any] = {
        "archive": _build_standalone_archive_section_payload(standalone_archive if isinstance(standalone_archive, dict) else {}),
    }
    for section, (field, _scope) in WEB_RESULT_SECTION_FIELDS.items():
        if section == "archive":
            continue
        value = source_data.get(field)
        if isinstance(value, list):
            limit = STANDALONE_OFFLINE_SECTION_LIMITS.get(section, len(value) or 1)
            sections[section] = _build_standalone_offline_list_section(section, field, value, limit)
        elif value not in (None, "", {}, []):
            sections[section] = {
                "section": section,
                "field": field,
                "data": copy.deepcopy(value),
                "standalone_limited": False,
                "standalone_limit_reason": "",
            }
    return sections


def _build_standalone_section_payloads(scan_id: str, canonical_data: dict, canonical_report: dict) -> Dict[str, Any]:
    standalone_data, standalone_archive = _standalone_archive_subset(canonical_data, canonical_report)
    return {
        "scan_id": str(scan_id or ""),
        "standalone": True,
        "sections": _build_standalone_offline_sections(
            standalone_data if isinstance(standalone_data, dict) else {},
            standalone_archive if isinstance(standalone_archive, dict) else {},
        ),
    }


def _build_lightweight_web_export_payloads(
    scan_id: str,
    canonical_data: dict,
    canonical_report: dict,
    archive_limit: int = 500,
) -> tuple[dict, dict, dict, str]:
    export_data = dict(canonical_data if isinstance(canonical_data, dict) else {})
    export_report = dict(canonical_report if isinstance(canonical_report, dict) else {})
    archive_limit = max(1, int(archive_limit or 500))

    source_archive = canonical_report.get("web_archive", {}) if isinstance(canonical_report, dict) else {}
    source_archive = source_archive if isinstance(source_archive, dict) else {}
    full_archive_rows = source_archive.get("all_urls", [])
    full_archive_rows = full_archive_rows if isinstance(full_archive_rows, list) else []
    limited_archive_rows = [copy.deepcopy(row) for row in full_archive_rows[:archive_limit]]
    total_archive_urls = int(source_archive.get("total_retrieved", source_archive.get("total", len(full_archive_rows))) or 0)
    if total_archive_urls <= 0:
        total_archive_urls = len(full_archive_rows)
    archive_note = f"{total_archive_urls:,} total archive URLs - full list available in JSON export"
    archive_was_limited = total_archive_urls > len(limited_archive_rows)

    export_archive = dict(source_archive)
    export_archive["all_urls"] = limited_archive_rows
    export_archive["standalone_limited"] = archive_was_limited
    export_archive["standalone_limit"] = archive_limit
    export_archive["standalone_limit_reason"] = archive_note
    export_report["web_archive"] = export_archive
    export_report["archive_urls"] = limited_archive_rows

    source_wayback = canonical_data.get("wayback_urls", {}) if isinstance(canonical_data, dict) else {}
    source_wayback = source_wayback if isinstance(source_wayback, dict) else {}
    wayback_rows = source_wayback.get("all")
    if not isinstance(wayback_rows, list):
        wayback_rows = source_wayback.get("all_urls")
    if not isinstance(wayback_rows, list):
        wayback_rows = full_archive_rows
    limited_wayback_rows = [copy.deepcopy(row) for row in wayback_rows[:archive_limit]]

    export_wayback = dict(source_wayback)
    export_wayback["all"] = limited_wayback_rows
    export_wayback["all_urls"] = limited_wayback_rows
    export_wayback["standalone_limited"] = archive_was_limited
    export_wayback["standalone_limit"] = archive_limit
    export_wayback["standalone_limit_reason"] = archive_note
    if total_archive_urls and not export_wayback.get("total_urls"):
        export_wayback["total_urls"] = total_archive_urls
    export_data["wayback_urls"] = export_wayback
    export_data["archive_urls"] = limited_archive_rows
    export_data["archive_summary"] = {
        **(export_data.get("archive_summary", {}) if isinstance(export_data.get("archive_summary", {}), dict) else {}),
        "standalone_limited": archive_was_limited,
        "standalone_limit": archive_limit,
        "standalone_limit_reason": archive_note,
    }
    export_report["archive_summary"] = export_data["archive_summary"]
    export_report["data"] = export_data

    standalone_bundle = {
        "scan_id": str(scan_id or ""),
        "standalone": True,
        "sections": _build_standalone_offline_sections(
            export_data if isinstance(export_data, dict) else {},
            export_archive if isinstance(export_archive, dict) else {},
        ),
    }
    return export_data, export_report, standalone_bundle, archive_note


def _inject_archive_export_note(html: str, note: str) -> str:
    message = str(note or "").strip()
    if not message:
        return html
    generic_note = "Archive view is compacted for performance. Full archive data remains in the JSON export."
    if generic_note in html:
        return html.replace(generic_note, message, 1)
    marker = '<div id="archive-browser"'
    note_html = f'<div class="section-alert alert-blue" style="margin-bottom:12px">{message}</div>\n          '
    if marker in html:
        return html.replace(marker, f"{note_html}{marker}", 1)
    return html


def _render_standalone_report_html(
    result_data: dict,
    canonical_report: dict,
    admin_token: str = "",
    standalone_bundle: Optional[Dict[str, Any]] = None,
) -> str:
    env = Environment(
        loader=FileSystemLoader(str(Path(__file__).parent / "templates")),
        autoescape=select_autoescape(["html", "xml"]),
    )
    tmpl = env.get_template("web.html")
    render_result, render_report = WebServer._build_render_payload(result_data or {}, canonical_report or {})
    standalone_bundle = standalone_bundle if isinstance(standalone_bundle, dict) else _build_standalone_section_payloads(
        str((result_data or {}).get("scan_id", "") or (canonical_report or {}).get("scan_id", "")),
        result_data if isinstance(result_data, dict) else {},
        canonical_report if isinstance(canonical_report, dict) else {},
    )
    html = tmpl.render(
        page="results",
        result=_normalize_text_tree(render_result or {}),
        report=_normalize_text_tree(render_report or {}),
        scan_id=str((result_data or {}).get("scan_id", "") or (canonical_report or {}).get("scan_id", "")),
        recent_scans=[],
        admin_token=admin_token,
        standalone_bundle=_normalize_text_tree(standalone_bundle),
    )
    return normalize_text(_inline_standalone_assets(html))


def _render_lightweight_web_export_html(canonical_data: dict, canonical_report: dict, admin_token: str = "") -> str:
    scan_id = str((canonical_data or {}).get("scan_id", "") or (canonical_report or {}).get("scan_id", ""))
    export_data, export_report, standalone_bundle, archive_note = _build_lightweight_web_export_payloads(
        scan_id,
        canonical_data if isinstance(canonical_data, dict) else {},
        canonical_report if isinstance(canonical_report, dict) else {},
        archive_limit=500,
    )
    html = _render_standalone_report_html(
        export_data,
        export_report,
        admin_token=admin_token,
        standalone_bundle=standalone_bundle,
    )
    return _inject_archive_export_note(html, archive_note)


def _render_full_static_web_export_html(canonical_report: dict) -> str:
    env = Environment(
        loader=FileSystemLoader(str(Path(__file__).parent / "templates")),
        autoescape=select_autoescape(["html", "xml"]),
    )
    tmpl = env.get_template("full_static_report.html")
    context = build_full_static_report_context(canonical_report if isinstance(canonical_report, dict) else {})
    return normalize_text(tmpl.render(**_normalize_text_tree(context)))


# Ã¢â€â‚¬Ã¢â€â‚¬ RESULTS PRINTER Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
def print_results(result: ReconResult):
    canonical = build_canonical_report(result)
    scores = canonical.get("scores", result.scores or {})
    risk = canonical.get("risk_level", "LOW")
    color_map = {"CRITICAL": "red", "HIGH": "orange3", "MEDIUM": "yellow", "LOW": "green"}
    col = color_map.get(risk, "green")

    # Score cards
    score_table = Table(show_header=False, box=None, padding=(0, 2))
    score_table.add_column(style="dim")
    score_table.add_column(style="bold")
    score_table.add_row("Attack Surface", f"[cyan]{scores.get('attack_surface',0)}/100[/cyan]")
    score_table.add_row("Technology Risk", f"[yellow]{scores.get('technology_risk',0)}/100[/yellow]")
    score_table.add_row("Exposure", f"[magenta]{scores.get('exposure',0)}/100[/magenta]")
    score_table.add_row("Overall", f"[{col}]{canonical.get('risk_score',0)}/100 - {risk}[/{col}]")
    console.print(Panel(score_table, title="[bold]Risk Components[/bold]", border_style=col))

    # Summary table
    summary = Table(title="Module Summary", show_header=True, header_style="bold cyan")
    summary.add_column("Module", style="dim")
    summary.add_column("Count", justify="right")
    summary.add_row("Subdomains", str(len(result.subdomains)))
    summary.add_row("Emails", str(len(result.emails)))
    summary.add_row("Technologies", str(len(result.technologies)))
    summary.add_row("DNS Records", str(len(result.dns_records)))
    summary.add_row("IP Records", str(len(result.ip_records)))
    summary.add_row("SSL Certs", str(len(result.ssl_info)))
    summary.add_row("Takeover Candidates", str(len(result.takeover_records)))
    summary.add_row("Cloud Assets", str(len(result.cloud_assets)))
    summary.add_row("Breach Records", str(len(result.breach_records)))
    wbu = result.wayback_urls
    interesting = len(wbu.get("interesting", [])) if isinstance(wbu, dict) else 0
    summary.add_row("Wayback Interesting", str(interesting))
    console.print(summary)

    exec_table = Table(title="Executive Summary", show_header=True, header_style="bold green")
    exec_table.add_column("Metric", style="dim")
    exec_table.add_column("Value")
    exec_table.add_row("Report Schema", str(canonical.get("report_version", "0.1")))
    exec_table.add_row("Data Completeness", f"{canonical.get('completeness', {}).get('overall_percent', 0)}%")
    exec_table.add_row("Top Findings", str(len(canonical.get("top_findings", []))))
    exec_table.add_row("Coverage Score", str(canonical.get("coverage_score", 0)))
    exec_table.add_row("Enabled Modules", str(len(canonical.get("sources_enabled", []))))
    exec_table.add_row("Disabled Modules", str(len(canonical.get("sources_disabled", []))))
    status_counts: Dict[str, int] = {}
    for mod in (result.source_metrics or {}).values():
        if isinstance(mod, dict):
            for src_m in mod.values():
                if isinstance(src_m, dict):
                    st = str(src_m.get("status", "ok"))
                    status_counts[st] = status_counts.get(st, 0) + 1
    exec_table.add_row("Sources Status", ", ".join(f"{k}:{v}" for k, v in sorted(status_counts.items())) or "n/a")
    exec_table.add_row("Errors", str(canonical.get("errors_summary", {}).get("total", 0)))
    console.print(exec_table)

    top_findings = canonical.get("top_findings", [])
    if top_findings:
        tf = Table(title="Top Findings", show_header=True, header_style="bold red")
        tf.add_column("Severity")
        tf.add_column("Type")
        tf.add_column("Title")
        tf.add_column("Confidence", justify="right")
        for finding in top_findings[:10]:
            tf.add_row(
                str(finding.get("severity", "INFO")),
                str(finding.get("type", "")),
                str(finding.get("title", ""))[:88],
                f"{float(finding.get('confidence', 0)):.2f}",
            )
        console.print(tf)

    if result.source_metrics:
        src_table = Table(title="Coverage by Source", show_header=True, header_style="bold magenta")
        src_table.add_column("Module", style="dim")
        src_table.add_column("Source")
        src_table.add_column("Accepted", justify="right")
        src_table.add_column("Dedupe", justify="right")
        src_table.add_column("Filtered", justify="right")
        src_table.add_column("Errors", justify="right")
        src_table.add_column("Latency", justify="right")
        for module_name, module_metrics in result.source_metrics.items():
            if not isinstance(module_metrics, dict):
                continue
            for source, metric in sorted(
                module_metrics.items(),
                key=lambda kv: int((kv[1] or {}).get("items_aceptados", 0)),
                reverse=True,
            ):
                m = metric if isinstance(metric, dict) else {}
                src_table.add_row(
                    module_name,
                    source,
                    str(m.get("items_aceptados", 0)),
                    str(m.get("items_descartados_por_dedupe", 0)),
                    str(m.get("items_descartados_por_filtro", 0)),
                    str(m.get("errores", 0)),
                    f"{m.get('latencia_ms', 0)} ms",
                )
        console.print(src_table)

    err_sum = canonical.get("errors_summary", {})
    if err_sum.get("total", 0):
        err_table = Table(title="Errors Summary", show_header=True, header_style="bold red")
        err_table.add_column("Module")
        err_table.add_column("Count", justify="right")
        for mod, count in sorted((err_sum.get("by_module", {}) or {}).items(), key=lambda kv: kv[1], reverse=True):
            err_table.add_row(mod, str(count))
        console.print(err_table)

    # Takeover alerts
    critical_takeovers = [t for t in result.takeover_records
                          if (t.get("status") if isinstance(t, dict) else t.get("status", "")) == "VULNERABLE"]
    if critical_takeovers:
        console.print("\n[bold red]TAKEOVER VULNERABILITIES:[/bold red]")
        for t in critical_takeovers:
            sub = t.get("subdomain", "")
            prov = t.get("provider", "")
            sev = t.get("severity", "")
            console.print(f"  [red]CRITICAL[/red] {sub} -> {prov} [{sev}]")

    # Scan completion summary
    _sub_count = len(result.subdomains)
    _email_count = len(result.emails)
    _ip_count = len(result.ip_records)
    _vuln_count = len(result.vulnerabilities)
    _cloud_count = len(result.cloud_assets)
    _cert_count = len(result.ssl_info)
    _arch_count = len(result.archive_urls) if hasattr(result, "archive_urls") else 0
    _takeover_count = len(critical_takeovers)
    _err_count = err_sum.get("total", 0)
    _dur = result.duration_seconds or 0
    log.info(
        "SCAN COMPLETE domain=%s mode=%s duration=%ss "
        "subdomains=%d emails=%d ips=%d vulns=%d cloud=%d certs=%d archive=%d takeovers=%d errors=%d",
        getattr(result, "domain", "?"), getattr(result, "mode", "?"), _dur,
        _sub_count, _email_count, _ip_count, _vuln_count, _cloud_count, _cert_count, _arch_count, _takeover_count, _err_count,
    )
    console.print(f"\n[bold green]Scan complete[/bold green] domain=[cyan]{getattr(result,'domain','?')}[/cyan] "
                  f"| [bold]{_dur}s[/bold] "
                  f"| subs=[cyan]{_sub_count}[/cyan] emails=[cyan]{_email_count}[/cyan] "
                  f"ips=[cyan]{_ip_count}[/cyan] vulns=[yellow]{_vuln_count}[/yellow] "
                  f"cloud=[cyan]{_cloud_count}[/cyan] archive=[cyan]{_arch_count}[/cyan] "
                  f"errors=[{'red' if _err_count else 'dim'}]{_err_count}[/{'red' if _err_count else 'dim'}]")


# Ã¢â€â‚¬Ã¢â€â‚¬ LOAD API KEYS Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
def _load_dotenv():
    """Load .env file from script directory if it exists."""
    env_path = Path(__file__).parent / ".env"
    if not env_path.exists():
        return
    try:
        with open(env_path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, _, val = line.partition("=")
                key = key.strip()
                val = val.strip().strip('"').strip("'")
                if key and key not in os.environ:
                    os.environ[key] = val
    except Exception:
        pass


def load_api_keys():
    _load_dotenv()
    return load_store_keys()


def run_doctor(out_dir: str, source_registry: SourceRegistry) -> int:
    checks = []

    def add_check(name: str, ok: bool, detail: str, warn: bool = False):
        status = "PASS" if ok and not warn else ("WARN" if warn else "FAIL")
        checks.append((name, status, detail))

    py_ok = sys.version_info >= (3, 11)
    add_check(
        "Python",
        py_ok,
        f"{platform.python_version()} ({platform.system()})",
        warn=not py_ok,
    )

    deps = [
        "aiohttp",
        "rich",
        "jinja2",
        "bs4",
        "tldextract",
    ]
    for dep in deps:
        add_check(f"Dependency:{dep}", importlib.util.find_spec(dep) is not None, "import check")

    tpl = Path(__file__).parent / "templates" / "web.html"
    add_check("Template:web.html", tpl.exists(), str(tpl))

    try:
        out_path = Path(out_dir)
        out_path.mkdir(parents=True, exist_ok=True)
        probe = out_path / ".doctor_write_test"
        probe.write_text("ok", encoding="utf-8")
        probe.unlink(missing_ok=True)
        add_check("ResultsDir", True, str(out_path))
    except OSError as exc:
        add_check("ResultsDir", False, f"write failed: {exc}")

    guard_ok = DEFAULT_HTTP_GUARD is not None and hasattr(DEFAULT_HTTP_GUARD, "request")
    add_check("HTTPGuard", guard_ok, "central guard present")

    doctor_keys, doctor_key_sources = load_key_layers()
    provider_rows = keystore_provider_status(doctor_keys, doctor_key_sources)
    for provider in ("chaos", "virustotal", "github_token", "bevigil", "otx"):
        meta = provider_rows.get(provider, {})
        label = str(meta.get("label", provider.replace("_", " ").title()))
        credential_source = str(meta.get("source", "") or "not_configured")
        if source_registry.force_no_keys:
            state = "disabled_other"
            detail = f"state={state}; env={meta.get('env_var', '')}; credential_source={credential_source}; reason=--no-keys"
            add_check(f"Provider:{label}", True, detail, warn=True)
            continue
        if meta.get("present", "false") == "true":
            state = "active"
            detail = f"state={state}; env={meta.get('env_var', '')}; credential_source={credential_source}"
            add_check(f"Provider:{label}", True, detail)
        else:
            state = "missing_key"
            detail = f"state={state}; env={meta.get('env_var', '')}; credential_source={credential_source}"
            add_check(f"Provider:{label}", True, detail, warn=True)

    missing_keys = [s["name"] for s in source_registry.list_sources() if s.get("status") in {"skipped_missing_key", "disabled_no_keys_mode"}]
    add_check(
        "Keyed Sources",
        True,
        f"{len(missing_keys)} skipped (expected without keys)",
        warn=len(missing_keys) > 0,
    )

    t = Table(title="Ghost Recon Doctor", show_header=True, header_style="bold cyan")
    t.add_column("Check", style="bold")
    t.add_column("Status")
    t.add_column("Detail")
    for name, status, detail in checks:
        color = {"PASS": "green", "WARN": "yellow", "FAIL": "red"}.get(status, "white")
        t.add_row(name, f"[{color}]{status}[/{color}]", detail)
    console.print(t)

    fails = sum(1 for _, s, _ in checks if s == "FAIL")
    return 0 if fails == 0 else 2


def run_smoke(out_dir: str, policy: ScanPolicy, source_registry: SourceRegistry) -> int:
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    scan_dir = Path(out_dir) / f"smoke_test_{ts}"
    try:
        _ensure_directory(scan_dir, label="smoke output directory")
    except OSError as exc:
        console.print(Panel(f"[red]Smoke failed:[/red]\nUnable to create output directory:\n{exc}", border_style="red"))
        return 2
    r = ReconResult(
        domain="smoke.example",
        scan_id=f"smk{hashlib.md5(ts.encode()).hexdigest()[:5]}",
        scan_date=_utcnow_iso(),
        mode="fast",
    )
    r.subdomains = [{
        "name": "api.smoke.example",
        "sources": ["crt.sh", "wayback"],
        "confidence": 0.88,
        "first_seen": r.scan_date,
        "last_seen": r.scan_date,
        "source_attribution": [{"source": "crt.sh", "confidence": 0.95, "first_seen": r.scan_date, "last_seen": r.scan_date}],
    }]
    r.emails = [{
        "email": "security@smoke.example",
        "sources": ["ct_logs"],
        "role": "security",
        "confidence": 0.81,
        "first_seen": r.scan_date,
        "last_seen": r.scan_date,
        "source_attribution": [{"source": "ct_logs", "confidence": 0.88, "first_seen": r.scan_date, "last_seen": r.scan_date}],
    }]
    r.source_metrics = {
        "subdomains": {"crt.sh": {"items_obtenidos": 2, "items_parseados": 2, "items_aceptados": 1, "items_descartados_por_dedupe": 1, "items_descartados_por_filtro": 0, "errores": 0, "latencia_ms": 12, "status": "ok"}},
        "emails": {"ct_logs": {"items_obtenidos": 1, "items_parseados": 1, "items_aceptados": 1, "items_descartados_por_dedupe": 0, "items_descartados_por_filtro": 0, "errores": 0, "latencia_ms": 9, "status": "ok"}},
    }
    r.scan_context = {
        "policy": {
            "passive_only": policy.passive_only,
            "allow_active": policy.allow_active,
            "allow_target_requests": policy.allow_target_requests,
            "allow_insecure_http_fallback": policy.allow_insecure_http_fallback,
        },
        "enabled_modules": ["Subdomain Enumeration", "Email Discovery"],
        "disabled_modules": ["Technology Detection"],
        "sources_profile": source_registry.profile,
        "source_registry_status": source_registry.status_by_source,
        "dropped_items": [{"section": "subdomains", "source": "crt.sh", "item": "www.smoke.example", "reason": "dedupe"}],
    }
    r.scores = {"attack_surface": 42, "technology_risk": 18, "exposure": 12, "vulnerability": 8}
    r.duration_seconds = 0.42
    r.errors = [{"time": r.scan_date, "module": "Subdomain Enumeration", "source": "wayback", "kind": "timeout", "message_short": "mock timeout"}]

    try:
        write_json(r, scan_dir)
        write_txt(r, scan_dir)
        write_html(r, scan_dir)
    except OSError as exc:
        console.print(Panel(f"[red]Smoke failed:[/red]\nUnable to write smoke artifacts:\n{exc}", border_style="red"))
        return 2

    expected = [scan_dir / "report.json", scan_dir / "report.txt", scan_dir / "report.html", scan_dir / "dropped_items.jsonl"]
    missing = [str(p) for p in expected if not p.exists()]
    if missing:
        console.print(Panel(f"[red]Smoke failed:[/red]\nMissing files:\n- " + "\n- ".join(missing), border_style="red"))
        return 2
    console.print(Panel(f"[green]Smoke OK[/green]\nGenerated in [cyan]{scan_dir}[/cyan]", border_style="green"))
    return 0


# Ã¢â€â‚¬Ã¢â€â‚¬ CLI Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
def build_parser():
    p = argparse.ArgumentParser(
        prog="recon.py",
        description="Ghost Recon Tool - Passive Domain Reconnaissance",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python recon.py                          -> Web UI on http://localhost:5000\n"
            "  python recon.py --port 8080              -> Web UI on custom port\n"
            "  python recon.py -d example.com           -> CLI scan\n"
            "  python recon.py -d example.com --mode deep --output all\n"
        )
    )
    p.add_argument("-d", "--domain", default=None, help="Target domain - omit to start web UI")
    p.add_argument(
        "--mode", choices=["fast", "balanced", "deep"],
        default="balanced",
        help="Scan mode [default: balanced]"
    )
    p.add_argument("--turbo", action="store_true", help="Turbo mode (max concurrency)")
    p.add_argument(
        "--output", choices=["json", "txt", "html", "all"],
        default="all", help="Output format [default: all]"
    )
    p.add_argument("--out-dir", default="./results", help="Output base directory")
    p.add_argument("--port", type=int, default=5000, help="Web UI port [default: 5000]")
    p.add_argument("--no-browser", action="store_true", help="Don't open browser automatically")
    p.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    p.add_argument("--passive-only", action="store_true", default=True,
                   help="Passive-only mode (default): blocks direct requests to target domain.")
    p.add_argument("--allow-active", action="store_true",
                   help="Allow active modules (e.g., takeover checks).")
    p.add_argument("--allow-target-requests", action="store_true",
                   help="Allow direct HTTP requests to target domain/subdomains (opt-in).")
    p.add_argument("--allow-insecure-http-fallback", action="store_true",
                   help="Allow HTTP (non-TLS) fallback providers when HTTPS fails.")
    p.add_argument("--debug-coverage", action="store_true",
                   help="Debug coverage mode: more generous limits and per-source metrics/logging.")
    p.add_argument("--list-sources", action="store_true",
                   help="List registered OSINT sources and exit.")
    p.add_argument("--doctor", action="store_true",
                   help="Run environment/config diagnostics and exit.")
    p.add_argument("--smoke", action="store_true",
                   help="Run offline smoke report generation and exit.")
    p.add_argument("--no-keys", action="store_true",
                   help="Disable all key-required sources even if keys are configured.")
    p.add_argument("--enable-source", action="append", default=[],
                   help="Enable a source by name (repeatable).")
    p.add_argument("--disable-source", action="append", default=[],
                   help="Disable a source by name (repeatable).")
    p.add_argument("--sources-profile", choices=["conservative", "balanced", "aggressive"],
                   default="balanced", help="Source execution profile.")
    p.add_argument("--admin-token", default="",
                   help="Admin token for /settings in web mode. If omitted, auto-generated.")
    return p


# Ã¢â€â‚¬Ã¢â€â‚¬ WEB SERVER Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
class WebServer:
    """aiohttp web server providing the Ghost Recon Tool web interface."""

    def __init__(
        self,
        port: int,
        results_dir: str,
        policy: Optional[ScanPolicy] = None,
        admin_token: str = "",
        debug_coverage: bool = False,
        source_registry: Optional[SourceRegistry] = None,
    ):
        self.port = port
        self.results_dir = Path(results_dir)
        _ensure_directory(self.results_dir, label="web results directory")
        self.active_scans: "OrderedDict[str, dict]" = OrderedDict()
        self._memory_api_keys: Dict[str, str] = {}
        self.api_keys, self.api_key_sources = load_key_layers(in_memory=self._memory_api_keys)
        self.policy = policy or ScanPolicy()
        self.debug_coverage = debug_coverage
        self.source_registry = source_registry or SourceRegistry(
            api_keys=self.api_keys,
            allow_target_requests=self.policy.allow_target_requests,
        )
        self.scan_manager = ScanManager(
            max_concurrent_scans=_env_int("GRT_MAX_SCANS", 3),
            keep_last_n_scans=_env_int("GRT_KEEP_LAST_SCANS", 20),
        )
        self.admin_token = admin_token or load_or_create_admin_token()
        self._history_cache: list = []
        self._history_cache_expiry = 0.0
        self._result_index: Dict[str, Path] = {}
        self._scan_dir_index: Dict[str, Path] = {}
        self._result_index_expiry = 0.0
        self._fragment_cache: Dict[str, Dict[str, Any]] = {}
        self._result_meta_memory: Dict[str, Dict[str, Any]] = {}
        self._result_data_cache: "OrderedDict[str, Dict[str, Any]]" = OrderedDict()
        self._saved_markup_cache: "OrderedDict[str, Dict[str, Any]]" = OrderedDict()
        self._web_summary_cache: "OrderedDict[str, Dict[str, Any]]" = OrderedDict()
        self._web_section_cache: "OrderedDict[str, Dict[str, Any]]" = OrderedDict()
        self._jinja_env = Environment(
            loader=FileSystemLoader(str(Path(__file__).parent / "templates")),
            autoescape=select_autoescape(["html", "xml"]),
        )
        self.static_dir = Path(__file__).parent / "static"
        _ensure_directory(self.static_dir, label="web static directory")
        self._admin_cookie_name = "grt_admin_token"

    @staticmethod
    @aio_web.middleware
    async def security_headers_middleware(request: aio_web.Request, handler):
        response = await handler(request)
        if isinstance(response, aio_web.StreamResponse):
            response.headers.setdefault("X-Content-Type-Options", "nosniff")
            response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
            response.headers.setdefault("X-Frame-Options", "DENY")
            response.headers.setdefault("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
            response.headers.setdefault(
                "Content-Security-Policy",
                "default-src 'self'; "
                "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
                "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
                "font-src 'self' https://fonts.gstatic.com data:; "
                "img-src 'self' data:; "
                "connect-src 'self'; "
                "frame-ancestors 'none'; base-uri 'self'; form-action 'self'",
            )
            response.headers.setdefault("Cache-Control", "no-store")
        return response

    # Ã¢â€â‚¬Ã¢â€â‚¬ route setup Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
    def make_app(self) -> aio_web.Application:
        app = aio_web.Application(middlewares=[self.security_headers_middleware])
        app.router.add_get("/",                                    self.handle_home)
        app.router.add_get("/scans",                               self.handle_scans)
        app.router.add_get("/history",                             self.handle_history)
        app.router.add_get("/scan/{scan_id}",                      self.handle_scan_view)
        app.router.add_get("/scan/stream",                         self.handle_sse)
        app.router.add_get("/scan/stream/{scan_id}",               self.handle_sse_attach)
        app.router.add_get("/api/scans",                           self.handle_api_scans)
        app.router.add_post("/api/scan",                           self.handle_api_scan_create)
        app.router.add_get("/api/scan/{scan_id}/status",           self.handle_api_scan_status)
        app.router.add_post("/api/scan/{scan_id}/cancel",          self.handle_api_scan_cancel)
        app.router.add_get("/results/{scan_id}",                   self.handle_results)
        app.router.add_get("/api/result/{scan_id}",                self.handle_api_result)
        app.router.add_get("/api/result-data/{scan_id}/{section}", self.handle_api_result_section)
        app.router.add_get("/api/result-fragment/{scan_id}",       self.handle_result_fragment)
        app.router.add_get("/api/diff/{scan_a}/{scan_b}",          self.handle_diff)
        app.router.add_get("/api/download/{scan_id}/{fmt}",        self.handle_download)
        app.router.add_get("/api/debug/{scan_id}",                 self.handle_debug)
        app.router.add_get("/logo.png",                            self.handle_logo)
        app.router.add_static("/static/", path=str(self.static_dir), name="static")
        app.router.add_get("/settings",                            self.handle_settings)
        app.router.add_post("/api/settings/auth",                  self.handle_api_settings_auth)
        app.router.add_post("/api/settings/logout",                self.handle_api_settings_logout)
        app.router.add_get("/api/settings",                        self.handle_api_settings_status)
        app.router.add_post("/api/settings",                       self.handle_api_settings)
        return app

    # Ã¢â€â‚¬Ã¢â€â‚¬ helpers Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
    def _load_web_template(self) -> str:
        tpl = Path(__file__).parent / "templates" / "web.html"
        if tpl.exists():
            return tpl.read_text(encoding="utf-8")
        return "<html><body><h1>Template missing</h1></body></html>"

    @staticmethod
    def _normalize_scan_data(raw: dict) -> dict:
        """Normalize JSON to flat dict regardless of old/new format."""
        return _normalize_saved_scan_payload(raw)

    @staticmethod
    def _cache_get(cache: "OrderedDict[str, Dict[str, Any]]", key: str) -> Optional[Dict[str, Any]]:
        item = cache.get(key)
        if item is not None:
            cache.move_to_end(key)
        return item

    @staticmethod
    def _cache_put(cache: "OrderedDict[str, Dict[str, Any]]", key: str, value: Dict[str, Any], max_items: int = 64) -> None:
        cache[key] = value
        cache.move_to_end(key)
        while len(cache) > max_items:
            cache.popitem(last=False)

    @staticmethod
    def _read_json_file(path: Path) -> Optional[dict]:
        if not path.exists():
            return None
        try:
            with open(path, encoding="utf-8") as f:
                payload = json.load(f)
            return payload if isinstance(payload, dict) else None
        except (OSError, json.JSONDecodeError, ValueError):
            return None

    @staticmethod
    def _read_web_summary_file(summary_path: Path, report_json: Path) -> Optional[dict]:
        if not summary_path.exists():
            return None
        try:
            if report_json.exists():
                with contextlib.suppress(OSError):
                    if summary_path.stat().st_mtime_ns < report_json.stat().st_mtime_ns:
                        return None
            payload = WebServer._read_json_file(summary_path)
            if not isinstance(payload, dict):
                return None
            result_view = payload.get("result", {})
            report_view = payload.get("report", {})
            if not isinstance(result_view, dict) or not isinstance(report_view, dict):
                return None
            return {"result": result_view, "report": report_view}
        except OSError:
            return None

    def _load_cached_result_meta(self, scan_dir: Path, report_json: Path) -> Optional[dict]:
        cache_payload = self._read_json_file(_result_meta_cache_path(scan_dir))
        if not isinstance(cache_payload, dict):
            return None
        if int(cache_payload.get("version", 0) or 0) != RESULT_META_CACHE_VERSION:
            return None
        if not _signatures_match(cache_payload.get("report_signature", {}), _path_signature(report_json)):
            return None
        entry = cache_payload.get("entry", {})
        if not isinstance(entry, dict):
            return None
        return dict(entry)

    def _load_result_meta_entry(self, scan_dir: Path) -> Optional[dict]:
        if not scan_dir.exists() or not scan_dir.is_dir():
            return None
        report_json = scan_dir / "report.json"
        if not report_json.exists():
            return None
        summary_path = _web_summary_path(scan_dir)
        report_sig = _path_signature(report_json)
        summary_sig = _path_signature(summary_path)
        cache_key = f"{report_sig.get('mtime_ns',0)}:{report_sig.get('size',0)}:{summary_sig.get('mtime_ns',0)}:{summary_sig.get('size',0)}"
        memory_key = str(scan_dir)
        cached = self._result_meta_memory.get(memory_key)
        if cached and str(cached.get("cache_key", "")) == cache_key and isinstance(cached.get("entry"), dict):
            entry = copy.deepcopy(cached.get("entry", {}))
            scan_id = str(entry.get("scan_id", "") or "")
            if scan_id:
                self._scan_dir_index[scan_id] = scan_dir
            return entry

        entry = self._load_cached_result_meta(scan_dir, report_json)
        if entry is None:
            summary_bundle = self._read_web_summary_file(summary_path, report_json)
            if summary_bundle:
                entry = _build_result_meta_from_summary_bundle(scan_dir, summary_bundle)
            if entry is None:
                raw = self._read_json_file(report_json)
                if not raw:
                    return None
                entry = _build_result_meta_from_report_payload(scan_dir, raw)
            with contextlib.suppress(Exception):
                _write_result_meta_cache(scan_dir, entry, report_sig)

        if not isinstance(entry, dict):
            return None
        entry = dict(entry)
        self._result_meta_memory[memory_key] = {"cache_key": cache_key, "entry": copy.deepcopy(entry)}
        scan_id = str(entry.get("scan_id", "") or "")
        if scan_id:
            self._scan_dir_index[scan_id] = scan_dir
        return copy.deepcopy(entry)

    def _saved_result_paths(self, scan_id: str) -> Tuple[Path, Path, Path, Path]:
        scan_dir, report_json = self._scan_artifact_paths(scan_id)
        return scan_dir, report_json, (scan_dir / "report.html"), (scan_dir / "report.txt")

    def _saved_result_stamp(self, scan_id: str) -> int:
        scan_dir, report_json, report_html, report_txt = self._saved_result_paths(scan_id)
        stamp = 0
        for path in (report_json, report_html, report_txt, _web_summary_path(scan_dir)):
            if not path.exists():
                continue
            with contextlib.suppress(OSError):
                stamp = max(stamp, int(path.stat().st_mtime_ns))
        return stamp

    @staticmethod
    def _saved_text_report_markup(scan_id: str, report_text: str, *, fragment: bool) -> str:
        escaped_scan_id = html_escape(str(scan_id or "scan"))
        escaped_report = html_escape(normalize_text(str(report_text or "")))
        fragment_html = normalize_text(
            f"""
<div id="results-page" data-scan-id="{escaped_scan_id}">
  <div class="results-layout">
    <main class="results-main" style="width:100%;max-width:none">
      <div class="summary-bar">
        <div class="summary-top">
          <div class="summary-domain">{escaped_scan_id}</div>
          <span class="badge badge-yellow">Saved text artifact fallback</span>
        </div>
        <div class="summary-meta">
          <div class="meta-item"><strong>Compatibility mode</strong> Opened from a canonical saved artifact because structured web sidecars were not available for this scan.</div>
        </div>
      </div>
      <div class="section-card">
        <div class="section-header open">
          <div class="section-title">Saved Text Report</div>
        </div>
        <div class="section-body" style="max-height:none">
          <div class="section-inner">
            <pre style="white-space:pre-wrap;word-break:break-word;font-family:var(--font-mono,monospace);font-size:12px;line-height:1.7">{escaped_report}</pre>
          </div>
        </div>
      </div>
    </main>
  </div>
</div>
"""
        )
        if fragment:
            return fragment_html
        return normalize_text(
            f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>Ghost Recon Tool - {escaped_scan_id}</title>
<style>
body{{margin:0;background:#0a0a12;color:#f1f5f9;font-family:system-ui,sans-serif}}
.results-main{{padding:24px}}
.summary-bar,.section-card{{background:#111827;border:1px solid #1e293b;border-radius:16px;margin-bottom:16px}}
.summary-bar{{padding:20px 24px}}
.summary-domain{{font-size:24px;font-weight:800;font-family:ui-monospace,monospace}}
.summary-meta{{margin-top:14px;color:#cbd5e1;font-size:14px}}
.badge{{display:inline-block;padding:4px 10px;border-radius:999px;background:rgba(245,158,11,.18);color:#f59e0b;border:1px solid rgba(245,158,11,.3);font-size:12px;font-weight:700}}
.section-header{{padding:16px 20px;border-bottom:1px solid #1e293b}}
.section-title{{font-size:15px;font-weight:700}}
.section-inner{{padding:18px 20px}}
pre{{margin:0;white-space:pre-wrap;word-break:break-word;font-family:ui-monospace,monospace;font-size:12px;line-height:1.7}}
</style>
</head>
<body>{fragment_html}</body>
</html>"""
        )

    @staticmethod
    def _extract_saved_results_fragment(report_html: str) -> str:
        html_text = normalize_text(str(report_html or ""))
        if not html_text.strip():
            return ""
        try:
            soup = BeautifulSoup(html_text, "html.parser")
        except Exception:
            return html_text
        fragment = soup.find(id="results-page")
        if fragment is not None:
            return normalize_text(str(fragment))
        body = soup.body
        if body is not None:
            for tag in body.find_all("script"):
                tag.decompose()
            return normalize_text("".join(str(child) for child in body.contents))
        return html_text

    def _load_saved_result_markup(self, scan_id: str, *, fragment: bool) -> Optional[str]:
        _scan_dir, _report_json, report_html, report_txt = self._saved_result_paths(scan_id)
        report_html_sig = _path_signature(report_html)
        report_txt_sig = _path_signature(report_txt)
        variant = "fragment" if fragment else "full"
        cache_slot = f"{scan_id}:{variant}"
        cache_key = (
            f"{report_html_sig.get('mtime_ns',0)}:{report_html_sig.get('size',0)}:"
            f"{report_txt_sig.get('mtime_ns',0)}:{report_txt_sig.get('size',0)}"
        )
        cached = self._cache_get(self._saved_markup_cache, cache_slot)
        if cached and str(cached.get("cache_key", "")) == cache_key and isinstance(cached.get("html"), str):
            return str(cached.get("html", ""))
        if report_html.exists():
            try:
                html = report_html.read_text(encoding="utf-8")
            except OSError:
                html = ""
            if html:
                rendered = self._extract_saved_results_fragment(html) if fragment else normalize_text(html)
                self._cache_put(
                    self._saved_markup_cache,
                    cache_slot,
                    {"cache_key": cache_key, "html": rendered},
                    max_items=16,
                )
                return rendered
        if report_txt.exists():
            try:
                report_text = report_txt.read_text(encoding="utf-8")
            except OSError:
                report_text = ""
            if report_text:
                rendered = self._saved_text_report_markup(scan_id, report_text, fragment=fragment)
                self._cache_put(
                    self._saved_markup_cache,
                    cache_slot,
                    {"cache_key": cache_key, "html": rendered},
                    max_items=16,
                )
                return rendered
        return None

    @staticmethod
    def _compact_wayback_view(wayback: dict) -> dict:
        if not isinstance(wayback, dict):
            return {}
        out = copy.deepcopy(wayback)
        caps = {
            "all": 0,
            "interesting": 100,
            "interesting_urls": 100,
            "api_endpoints": 100,
            "admin_paths": 100,
            "sensitive_files": 100,
            "sensitive_path_hits": 100,
            "top_paths": 100,
            "robots_disallow": 100,
            "sitemap_urls": 100,
            "js_files": 100,
            "documents": 100,
        }
        hidden = {}
        totals = {}
        for key, cap in caps.items():
            val = out.get(key)
            if not isinstance(val, list):
                continue
            total = len(val)
            totals[key] = total
            hidden[key] = max(0, total - cap)
            out[key] = list(val[:cap]) if cap > 0 else []
        out["_render_hidden"] = hidden
        out["_render_totals"] = totals
        return out

    @staticmethod
    def _compact_archive_report_view(archive: dict) -> dict:
        if not isinstance(archive, dict):
            return {}
        caps = {
            "all_urls": 0,
            "interesting_paths": 0,
            "api_endpoints": 0,
            "admin_paths": 0,
            "sensitive_files": 0,
            "documents": 0,
            "js_files": 0,
            "uncategorized_urls": 0,
            "query_params": 0,
            "api_endpoint_profiles": 0,
            "historical_robots": 0,
            "historical_sitemaps": 0,
        }
        out = {
            "total": int(archive.get("total", 0) or 0),
            "total_retrieved": int(archive.get("total_retrieved", archive.get("total", 0)) or 0),
            "total_categorized": int(archive.get("total_categorized", 0) or 0),
            "scope_filtered_out": int(archive.get("scope_filtered_out", 0) or 0),
        }
        hidden = {}
        totals = {}
        for key, cap in caps.items():
            val = archive.get(key)
            if not isinstance(val, list):
                continue
            total = len(val)
            totals[key] = total
            hidden[key] = max(0, total - cap)
            out[key] = [copy.deepcopy(row) for row in val[:cap]] if cap > 0 else []
        out["_render_hidden"] = hidden
        out["_render_totals"] = totals
        return out

    @staticmethod
    def _compact_artifact_inventory_view(inventory: dict) -> dict:
        if not isinstance(inventory, dict):
            return {}
        caps = {
            "high_value_files": 12,
            "archived_files": 12,
            "interesting_endpoints": 16,
            "artifact_hints": 10,
            "internal_references": 8,
        }
        out = {
            "summary": copy.deepcopy(inventory.get("summary", {})) if isinstance(inventory.get("summary", {}), dict) else {},
            "suppressed_noise": copy.deepcopy(inventory.get("suppressed_noise", {})) if isinstance(inventory.get("suppressed_noise", {}), dict) else {},
        }
        hidden = {}
        totals = {}
        for key, cap in caps.items():
            rows = inventory.get(key)
            if not isinstance(rows, list):
                out[key] = []
                continue
            total = len(rows)
            totals[key] = total
            hidden[key] = max(0, total - cap)
            out[key] = [copy.deepcopy(row) for row in rows[:cap]]
        out["_render_hidden"] = hidden
        out["_render_totals"] = totals
        return out

    @staticmethod
    def _archive_row_url(row: Any) -> str:
        if isinstance(row, dict):
            return str(row.get("url", "") or "")
        return str(getattr(row, "url", row) or "")

    @staticmethod
    def _archive_row_view(row: Any) -> Dict[str, Any]:
        if isinstance(row, dict):
            return {
                "url": WebServer._archive_row_url(row),
                "timestamp": row.get("timestamp", ""),
                "status_code": row.get("status_code", ""),
                "mime_type": row.get("mime_type", ""),
            }
        return {
            "url": WebServer._archive_row_url(row),
            "timestamp": getattr(row, "timestamp", ""),
            "status_code": getattr(row, "status_code", ""),
            "mime_type": getattr(row, "mime_type", ""),
        }

    @staticmethod
    def _archive_page_payload(archive: dict, *, offset: int = 0, limit: int = 200, q: str = "") -> Dict[str, Any]:
        rows = archive.get("all_urls") if isinstance(archive.get("all_urls"), list) else archive.get("all")
        rows = rows if isinstance(rows, list) else []
        offset = max(0, int(offset or 0))
        limit = max(1, min(int(limit or 200), 1000))
        query = str(q or "").strip().lower()
        total = len(rows)

        if not query:
            page_rows = rows[offset:offset + limit]
            items = [WebServer._archive_row_view(row) for row in page_rows]
            filtered_total = total
        else:
            items: List[Dict[str, Any]] = []
            filtered_total = 0
            end = offset + limit
            for row in rows:
                row_url = WebServer._archive_row_url(row).lower()
                if query not in row_url:
                    continue
                if filtered_total >= offset and filtered_total < end:
                    items.append(WebServer._archive_row_view(row))
                filtered_total += 1

        return {
            "items": items,
            "total": total,
            "filtered_total": filtered_total,
            "offset": offset,
            "limit": limit,
            "has_more": (offset + len(items)) < filtered_total,
        }

    @staticmethod
    def _preview_list(rows: Any, limit: int) -> List[Any]:
        if not isinstance(rows, list) or limit <= 0:
            return []
        return [copy.deepcopy(row) for row in rows[:limit]]

    @staticmethod
    def _scan_context_view(scan_context: dict) -> dict:
        if not isinstance(scan_context, dict):
            return {}
        out: Dict[str, Any] = {}
        for key in ("policy", "provider_summary", "subdomain_inventory"):
            if isinstance(scan_context.get(key), dict):
                out[key] = copy.deepcopy(scan_context.get(key, {}))
        if isinstance(scan_context.get("api_key_summary", {}), dict):
            api_summary = scan_context.get("api_key_summary", {})
            out["api_key_summary"] = {
                "ready_services_count": int(api_summary.get("ready_services_count", 0) or 0),
                "missing_services_count": int(api_summary.get("missing_services_count", 0) or 0),
                "ready_services": list(api_summary.get("ready_services", [])[:8]) if isinstance(api_summary.get("ready_services", []), list) else [],
            }
        return out

    @staticmethod
    def _finding_groups_view(groups: dict, preview_limit: int = 4) -> dict:
        if not isinstance(groups, dict):
            return {}
        out: Dict[str, Any] = {}
        for key in ("vulnerabilities", "exposures", "intelligence_leads", "infrastructure_observations"):
            rows = groups.get(key, [])
            out[key] = WebServer._preview_list(rows, preview_limit)
        return out

    @staticmethod
    def _finding_group_totals(groups: dict) -> dict:
        if not isinstance(groups, dict):
            return {}
        totals: Dict[str, int] = {}
        for key in ("vulnerabilities", "exposures", "intelligence_leads", "infrastructure_observations"):
            rows = groups.get(key, [])
            if isinstance(rows, list):
                totals[key] = len(rows)
        return totals

    @staticmethod
    def _compact_entity_graph_view(graph: dict) -> dict:
        if not isinstance(graph, dict):
            return {}
        nodes = graph.get("nodes", []) if isinstance(graph.get("nodes", []), list) else []
        edges = graph.get("edges", []) if isinstance(graph.get("edges", []), list) else []
        return {
            "nodes": [],
            "edges": [],
            "_render_hidden": {
                "nodes": len(nodes),
                "edges": len(edges),
            },
            "_render_totals": {
                "nodes": len(nodes),
                "edges": len(edges),
            },
        }

    @staticmethod
    def _append_search_tokens(parts: List[str], value: Any) -> None:
        if value in (None, ""):
            return
        if isinstance(value, dict):
            for child in value.values():
                WebServer._append_search_tokens(parts, child)
            return
        if isinstance(value, (list, tuple, set)):
            for child in value:
                WebServer._append_search_tokens(parts, child)
            return
        parts.append(str(value))

    @staticmethod
    def _row_search_text(section: str, row: Any) -> str:
        if not isinstance(row, dict):
            return str(row or "").lower()
        field_map = {
            "subdomains": ("name", "subdomain", "host", "ips", "resolved_ips", "open_ports", "ports", "sources", "tags", "cloud_provider", "takeover_status", "status"),
            "emails": ("email", "role", "role_category", "sources", "source_attribution", "confidence"),
            "ips": ("ip", "asn", "org", "country", "city", "rdns", "ports", "open_ports", "tags"),
            "certs": ("subject", "common_name", "issuer", "not_after", "san_entries"),
            "techs": ("name", "category", "version", "sources", "evidence"),
            "vulns": ("severity", "cve_id", "title", "description", "affected_asset", "affected_host", "source", "references"),
            "dorks": ("source", "category", "severity", "url", "snippet"),
            "cloud": ("asset_type", "name", "url", "classification", "public"),
            "breach": ("name", "title", "domain", "description", "data_types"),
            "takeover": ("subdomain", "provider", "status", "fingerprint"),
            "dns": ("type", "name", "value"),
        }
        parts: List[str] = []
        for field in field_map.get(section, tuple(row.keys())):
            if field in row:
                WebServer._append_search_tokens(parts, row.get(field))
        return " ".join(parts).lower()

    @staticmethod
    def _list_page_payload(rows: Any, *, section: str, field: str, offset: int = 0, limit: int = 200, q: str = "") -> Dict[str, Any]:
        items = rows if isinstance(rows, list) else []
        offset = max(0, int(offset or 0))
        limit = max(1, min(int(limit or 200), 1000))
        query = str(q or "").strip().lower()
        total = len(items)
        if not query:
            page_rows = items[offset:offset + limit]
            filtered_total = total
        else:
            page_rows = []
            filtered_total = 0
            end = offset + limit
            for row in items:
                if query not in WebServer._row_search_text(section, row):
                    continue
                if offset <= filtered_total < end:
                    page_rows.append(row)
                filtered_total += 1
        return {
            "section": section,
            "field": field,
            "total": total,
            "filtered_total": filtered_total,
            "offset": offset,
            "limit": limit,
            "has_more": (offset + len(page_rows)) < filtered_total,
            "data": page_rows,
        }

    @staticmethod
    def _build_render_payload(data: dict, report: dict) -> tuple[dict, dict]:
        data = data if isinstance(data, dict) else {}
        report = report if isinstance(report, dict) else {}
        inline_threshold = 0
        lazy_keys = (
            "subdomains",
            "emails",
            "dns_records",
            "ip_records",
            "vulnerabilities",
            "correlations",
            "takeover_records",
            "cloud_assets",
            "breach_records",
            "technologies",
            "dorks",
            "typosquats",
            "ssl_info",
            "interesting_endpoints",
            "potential_secrets",
            "developer_references",
            "high_value_targets",
        )
        hidden_counts: Dict[str, int] = {}
        totals: Dict[str, int] = {}
        for key in lazy_keys:
            val = data.get(key)
            if not isinstance(val, list):
                continue
            totals[key] = len(val)
            hidden_counts[key] = len(val)

        finding_totals = WebServer._finding_group_totals(report.get("findings", {}) or {})
        result_view = {
            "domain": data.get("domain", ""),
            "scan_id": data.get("scan_id", ""),
            "scan_date": data.get("scan_date", ""),
            "mode": data.get("mode", ""),
            "duration_seconds": data.get("duration_seconds", 0),
            "scores": copy.deepcopy(data.get("scores", {})) if isinstance(data.get("scores", {}), dict) else {},
            "email_pattern": copy.deepcopy(data.get("email_pattern", {})) if isinstance(data.get("email_pattern", {}), dict) else {},
            "scan_context": WebServer._scan_context_view(data.get("scan_context", {}) or {}),
            "source_metrics": copy.deepcopy(data.get("source_metrics", {})) if isinstance(data.get("source_metrics", {}), dict) else {},
        }
        for key in lazy_keys:
            result_view[key] = []

        report_view = {
            "report_version": report.get("report_version", ""),
            "schema_version": report.get("schema_version", ""),
            "summary": copy.deepcopy(report.get("summary", {})) if isinstance(report.get("summary", {}), dict) else {},
            "scores": copy.deepcopy(report.get("scores", {})) if isinstance(report.get("scores", {}), dict) else {},
            "risk_score": report.get("risk_score", 0),
            "risk_level": report.get("risk_level", "LOW"),
            "risk_details": copy.deepcopy(report.get("risk_details", {})) if isinstance(report.get("risk_details", {}), dict) else {},
            "completeness": copy.deepcopy(report.get("completeness", {})) if isinstance(report.get("completeness", {}), dict) else {},
            "coverage_score": report.get("coverage_score", 0),
            "coverage_by_source": copy.deepcopy(report.get("coverage_by_source", data.get("source_metrics", {}))) if isinstance(report.get("coverage_by_source", data.get("source_metrics", {})), dict) else {},
            "source_intelligence": {
                "summary": copy.deepcopy(((report.get("source_intelligence", {}) if isinstance(report.get("source_intelligence", {}), dict) else {}).get("summary", {}))),
            },
            "source_overlaps": WebServer._preview_list(report.get("source_overlaps", []), 5),
            "scan_context": WebServer._scan_context_view(report.get("scan_context", data.get("scan_context", {})) or {}),
            "runtime": copy.deepcopy(report.get("runtime", {})) if isinstance(report.get("runtime", {}), dict) else {},
            "subdomain_inventory": copy.deepcopy(report.get("subdomain_inventory", {})) if isinstance(report.get("subdomain_inventory", {}), dict) else {},
            "sources_enabled": list(report.get("sources_enabled", [])[:40]) if isinstance(report.get("sources_enabled", []), list) else [],
            "errors": WebServer._preview_list(report.get("errors", []), 8),
            "errors_summary": copy.deepcopy(report.get("errors_summary", {})) if isinstance(report.get("errors_summary", {}), dict) else {},
            "top_findings": WebServer._preview_list(report.get("top_findings", []), 8),
            "findings": WebServer._finding_groups_view(report.get("findings", {}) or {}, preview_limit=4),
            "analyst_summary": copy.deepcopy(report.get("analyst_summary", {})) if isinstance(report.get("analyst_summary", {}), dict) else {},
            "executive_overview": {},
            "bug_bounty": {
                "artifact_inventory": WebServer._compact_artifact_inventory_view(
                    ((report.get("bug_bounty", {}) if isinstance(report.get("bug_bounty", {}), dict) else {}).get("artifact_inventory", {}))
                ),
            },
            "web_archive": WebServer._compact_archive_report_view(report.get("web_archive", {}) or {}),
            "entity_graph": WebServer._compact_entity_graph_view(report.get("entity_graph", {}) or {}),
        }
        executive = report.get("executive_overview", {}) if isinstance(report.get("executive_overview", {}), dict) else {}
        report_view["executive_overview"] = {
            "story": executive.get("story", ""),
            "priority_targets": WebServer._preview_list(executive.get("priority_targets", []), 5),
            "priority_findings": WebServer._preview_list(executive.get("priority_findings", []), 6),
            "quick_wins": WebServer._preview_list(executive.get("quick_wins", []), 6),
        }
        render_meta = {
            "inline_threshold": inline_threshold,
            "totals": totals,
            "hidden_counts": hidden_counts,
            "finding_totals": finding_totals,
            "archive_hidden": report_view.get("web_archive", {}).get("_render_hidden", {}),
            "archive_totals": report_view.get("web_archive", {}).get("_render_totals", {}),
            "artifact_hidden": ((report_view.get("bug_bounty", {}) if isinstance(report_view.get("bug_bounty", {}), dict) else {}).get("artifact_inventory", {}) or {}).get("_render_hidden", {}),
            "artifact_totals": ((report_view.get("bug_bounty", {}) if isinstance(report_view.get("bug_bounty", {}), dict) else {}).get("artifact_inventory", {}) or {}).get("_render_totals", {}),
            "entity_graph_hidden": report_view.get("entity_graph", {}).get("_render_hidden", {}),
            "entity_graph_totals": report_view.get("entity_graph", {}).get("_render_totals", {}),
            "top_findings_total": len(report.get("top_findings", []) or []) if isinstance(report.get("top_findings", []), list) else 0,
            "errors_total": len(report.get("errors", []) or []) if isinstance(report.get("errors", []), list) else int((report.get("errors_summary", {}) if isinstance(report.get("errors_summary", {}), dict) else {}).get("total", 0) or 0),
        }
        report_view["render_meta"] = render_meta
        result_view["_render_meta"] = render_meta
        return result_view, report_view

    def _require_admin(self, request: aio_web.Request) -> None:
        if self._admin_request_authorized(request):
            return
        raise aio_web.HTTPUnauthorized(text="Missing or invalid admin token.")

    def _admin_request_token(self, request: aio_web.Request) -> str:
        supplied = request.headers.get("X-GRT-Admin-Token", "")
        if not supplied and request.method == "POST":
            supplied = request.headers.get("X-Admin-Token", "")
        if not supplied:
            supplied = request.cookies.get(self._admin_cookie_name, "")
        return str(supplied or "")

    def _admin_request_authorized(self, request: aio_web.Request) -> bool:
        return constant_time_equals(self._admin_request_token(request), self.admin_token)

    def _admin_cookie_redirect(self, location: str) -> aio_web.HTTPFound:
        response = aio_web.HTTPFound(location)
        response.set_cookie(
            self._admin_cookie_name,
            self.admin_token,
            httponly=True,
            samesite="Strict",
            secure=False,
            max_age=86400,
            path="/",
        )
        return response

    def _clear_admin_cookie_redirect(self, location: str) -> aio_web.HTTPFound:
        response = aio_web.HTTPFound(location)
        response.del_cookie(self._admin_cookie_name, path="/")
        return response

    def _reload_api_keys(self) -> None:
        self.api_keys, self.api_key_sources = load_key_layers(in_memory=self._memory_api_keys)
        self.source_registry = SourceRegistry(
            profile=self.source_registry.profile,
            enable=list(self.source_registry._enabled_overrides),
            disable=list(self.source_registry._disabled_overrides),
            api_keys=self.api_keys,
            force_no_keys=self.source_registry.force_no_keys,
            allow_target_requests=self.policy.allow_target_requests,
        )

    def _api_key_summary(self) -> Dict[str, Any]:
        return summarize_services(self.api_keys)

    def _settings_rows(self) -> List[Dict[str, Any]]:
        rows = []
        statuses = keystore_provider_status(self.api_keys, self.api_key_sources)
        for provider, meta in sorted(statuses.items()):
            rows.append(
                {
                    "key": provider,
                    "label": meta.get("label", provider.replace("_", " ").title()),
                    "env_var": meta.get("env_var", ""),
                    "set": meta.get("present", "false") == "true",
                    "masked": meta.get("masked_hint", ""),
                    "source": meta.get("source", ""),
                }
            )
        return rows

    def _refresh_results_index(self) -> None:
        now = time.time()
        if now < self._result_index_expiry:
            return
        idx: Dict[str, Path] = {}
        dir_idx: Dict[str, Path] = {}
        if self.results_dir.exists():
            for scan_dir in self.results_dir.iterdir():
                if not scan_dir.is_dir():
                    continue
                entry = self._load_result_meta_entry(scan_dir)
                scan_id = str((entry or {}).get("scan_id", "") or "")
                if not scan_id:
                    continue
                report_json = scan_dir / "report.json"
                idx[scan_id] = report_json
                dir_idx[scan_id] = scan_dir
        self._result_index = idx
        self._scan_dir_index = dir_idx
        self._result_index_expiry = now + RESULT_INDEX_TTL_SECONDS

    def _prune_active_scans(self) -> None:
        now = time.time()
        stale = []
        for scan_id, meta in self.active_scans.items():
            ts = float(meta.get("ts", now))
            if now - ts > ACTIVE_SCANS_TTL_SECONDS:
                stale.append(scan_id)
        for scan_id in stale:
            self.active_scans.pop(scan_id, None)
        while len(self.active_scans) > ACTIVE_SCANS_MAX:
            self.active_scans.popitem(last=False)

    def _invalidate_result_catalog(self, scan_id: str = "", scan_dir: Optional[Path] = None) -> None:
        self._history_cache_expiry = 0.0
        self._result_index_expiry = 0.0
        if scan_id:
            self._result_index.pop(scan_id, None)
            self._scan_dir_index.pop(scan_id, None)
            self._fragment_cache.pop(scan_id, None)
            self._result_data_cache.pop(scan_id, None)
            stale_markup_keys = [key for key in self._saved_markup_cache.keys() if key.startswith(f"{scan_id}:")]
            for key in stale_markup_keys:
                self._saved_markup_cache.pop(key, None)
            self._web_summary_cache.pop(scan_id, None)
            stale_report_keys = [key for key in _CANONICAL_REPORT_CACHE.keys() if key.startswith(f"{scan_id}:")]
            for key in stale_report_keys:
                _CANONICAL_REPORT_CACHE.pop(key, None)
            stale_section_keys = [key for key in self._web_section_cache.keys() if key.startswith(f"{scan_id}:")]
            for key in stale_section_keys:
                self._web_section_cache.pop(key, None)
        if scan_dir:
            self._result_meta_memory.pop(str(scan_dir), None)

    def _scan_history(self) -> List[dict]:
        now = time.time()
        if now < self._history_cache_expiry:
            return list(self._history_cache)
        history = []
        if not self.results_dir.exists():
            return history
        for scan_dir in sorted(self.results_dir.iterdir(), reverse=True):
            if not scan_dir.is_dir():
                continue
            entry = self._load_result_meta_entry(scan_dir)
            if entry:
                history.append(entry)
        self._history_cache = history
        self._history_cache_expiry = now + RESULT_INDEX_TTL_SECONDS
        return history

    def _load_scan_result(self, scan_id: str) -> Optional[dict]:
        scan_id = _normalize_scan_id_value(scan_id)
        if not scan_id:
            return None
        self._prune_active_scans()
        # Check in-memory first (completed scan)
        if scan_id in self.active_scans:
            info = self.active_scans[scan_id]
            if info.get("result"):
                return asdict(info["result"])
        self._refresh_results_index()
        report_json = self._result_index.get(scan_id)
        if report_json and report_json.exists():
            report_sig = _path_signature(report_json)
            cache_key = f"{scan_id}:{report_sig.get('mtime_ns',0)}:{report_sig.get('size',0)}"
            cached = self._cache_get(self._result_data_cache, scan_id)
            if cached and str(cached.get("cache_key", "")) == cache_key and isinstance(cached.get("data"), dict):
                payload = dict(cached.get("data", {}))
                payload[_RESULT_DATA_CACHE_KEY] = cache_key
                return payload
            try:
                with open(report_json, encoding="utf-8") as f:
                    raw = json.load(f)
                data = self._normalize_scan_data(raw)
                if str(data.get("scan_id", "")) != str(scan_id):
                    return None
                self._cache_put(
                    self._result_data_cache,
                    scan_id,
                    {"cache_key": cache_key, "data": data},
                    max_items=24,
                )
                payload = dict(data)
                payload[_RESULT_DATA_CACHE_KEY] = cache_key
                return payload
            except (OSError, json.JSONDecodeError, ValueError):
                return None
        return None

    def _scan_artifact_paths(self, scan_id: str) -> Tuple[Path, Path]:
        scan_id = _normalize_scan_id_value(scan_id)
        if not scan_id:
            invalid_dir = self.results_dir / "__invalid_scan__"
            return invalid_dir, (invalid_dir / "report.json")
        self._refresh_results_index()
        scan_dir = self._scan_dir_index.get(scan_id)
        if scan_dir and scan_dir.exists():
            return scan_dir, (scan_dir / "report.json")
        report_json = self._result_index.get(scan_id)
        if report_json and report_json.exists():
            return report_json.parent, report_json
        scan_dir = self.results_dir / scan_id
        return scan_dir, (scan_dir / "report.json")

    def _load_web_render_summary(self, scan_id: str) -> Optional[dict]:
        scan_dir, report_json = self._scan_artifact_paths(scan_id)
        summary_path = _web_summary_path(scan_dir)
        if not summary_path.exists():
            return None
        report_sig = _path_signature(report_json)
        summary_sig = _path_signature(summary_path)
        cache_key = f"{scan_id}:{summary_sig.get('mtime_ns',0)}:{summary_sig.get('size',0)}:{report_sig.get('mtime_ns',0)}:{report_sig.get('size',0)}"
        cached = self._cache_get(self._web_summary_cache, scan_id)
        if cached and str(cached.get("cache_key", "")) == cache_key and isinstance(cached.get("payload"), dict):
            return copy.deepcopy(cached.get("payload", {}))
        payload = self._read_web_summary_file(summary_path, report_json)
        if not payload:
            return None
        self._cache_put(
            self._web_summary_cache,
            scan_id,
            {"cache_key": cache_key, "payload": copy.deepcopy(payload)},
            max_items=48,
        )
        return copy.deepcopy(payload)

    def _load_web_section_payload(self, scan_id: str, section: str) -> Optional[dict]:
        scan_dir, report_json = self._scan_artifact_paths(scan_id)
        section_path = _web_section_path(scan_dir, section)
        if not section_path.exists():
            return None
        report_sig = _path_signature(report_json)
        section_sig = _path_signature(section_path)
        if report_sig.get("mtime_ns", 0) and section_sig.get("mtime_ns", 0) < report_sig.get("mtime_ns", 0):
            return None
        cache_id = f"{scan_id}:{section}"
        cache_key = f"{cache_id}:{section_sig.get('mtime_ns',0)}:{section_sig.get('size',0)}:{report_sig.get('mtime_ns',0)}:{report_sig.get('size',0)}"
        cached = self._cache_get(self._web_section_cache, cache_id)
        if cached and str(cached.get("cache_key", "")) == cache_key and isinstance(cached.get("payload"), dict):
            return copy.deepcopy(cached.get("payload", {}))
        payload = self._read_json_file(section_path)
        if not isinstance(payload, dict):
            return None
        self._cache_put(
            self._web_section_cache,
            cache_id,
            {"cache_key": cache_key, "payload": copy.deepcopy(payload)},
            max_items=96,
        )
        return copy.deepcopy(payload)

    # Ã¢â€â‚¬Ã¢â€â‚¬ render helper Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
    def _render(self, page: str, **ctx) -> str:
        """Render web template with full error context on failure."""
        try:
            tmpl = self._jinja_env.get_template("web.html")
            render_ctx = dict(ctx)
            render_ctx.setdefault("settings_authenticated", False)
            return normalize_text(tmpl.render(page=page, **render_ctx))
        except Exception as exc:
            tb = _traceback.format_exc()
            logging.error("Template render error [page=%s]: %s\n%s", page, exc, tb)
            return (
                "<!DOCTYPE html><html><head><meta charset='UTF-8'>"
                "<title>Ghost Recon - Render Error</title>"
                "<style>body{background:#070b14;color:#e2e8f0;font-family:monospace;"
                "padding:32px;max-width:900px}h2{color:#ef4444;margin-bottom:16px}"
                "a{color:#3b82f6}</style></head><body>"
                f"<h2>&#128683; Template Render Error - page=<code>{page}</code></h2>"
                f"<p>The results page crashed while rendering. "
                f"Use <a href='/api/debug/{ctx.get('scan_id','')}'>Debug JSON</a> to inspect raw data.</p>"
                "<p>Internal details were written to the local log.</p>"
                "</body></html>"
            )

    # Ã¢â€â‚¬Ã¢â€â‚¬ route handlers Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
    async def handle_home(self, request: aio_web.Request) -> aio_web.Response:
        try:
            self._reload_api_keys()
            history = self._scan_history()
            scans = self.scan_manager.list_scans()
            html = self._render(
                "home",
                history=history,
                history_json=json.dumps(history),
                scans=scans,
                scans_json=json.dumps(scans, ensure_ascii=False),
                api_key_summary=self._api_key_summary(),
            )
            return aio_web.Response(text=html, content_type="text/html", charset="utf-8")
        except Exception as exc:
            logging.error("handle_home error: %s\n%s", exc, _traceback.format_exc())
            raise aio_web.HTTPInternalServerError(text="Internal server error. Check local logs for details.")

    async def handle_scans(self, request: aio_web.Request) -> aio_web.Response:
        try:
            self._reload_api_keys()
            history = self._scan_history()
            scans = self.scan_manager.list_scans()
            html = self._render(
                "scans",
                history=history,
                history_json=json.dumps(history),
                scans=scans,
                scans_json=json.dumps(scans, ensure_ascii=False),
                api_key_summary=self._api_key_summary(),
            )
            return aio_web.Response(text=html, content_type="text/html", charset="utf-8")
        except Exception as exc:
            logging.error("handle_scans error: %s\n%s", exc, _traceback.format_exc())
            raise aio_web.HTTPInternalServerError(text="Internal server error. Check local logs for details.")

    async def handle_scan_view(self, request: aio_web.Request) -> aio_web.Response:
        try:
            self._reload_api_keys()
            history = self._scan_history()
            scans = self.scan_manager.list_scans()
            html = self._render(
                "scans",
                history=history,
                history_json=json.dumps(history),
                scans=scans,
                scans_json=json.dumps(scans, ensure_ascii=False),
                initial_scan_id=_normalize_scan_id_value(request.match_info.get("scan_id", "")),
                api_key_summary=self._api_key_summary(),
            )
            return aio_web.Response(text=html, content_type="text/html", charset="utf-8")
        except Exception as exc:
            logging.error("handle_scan_view error: %s\n%s", exc, _traceback.format_exc())
            raise aio_web.HTTPInternalServerError(text="Internal server error. Check local logs for details.")

    async def handle_history(self, request: aio_web.Request) -> aio_web.Response:
        try:
            self._reload_api_keys()
            history = self._scan_history()
            html = self._render(
                "history",
                history=history,
                history_json=json.dumps(history),
                scans=self.scan_manager.list_scans(),
                api_key_summary=self._api_key_summary(),
            )
            return aio_web.Response(text=html, content_type="text/html", charset="utf-8")
        except Exception as exc:
            logging.error("handle_history error: %s\n%s", exc, _traceback.format_exc())
            raise aio_web.HTTPInternalServerError(text="Internal server error. Check local logs for details.")

    async def handle_settings(self, request: aio_web.Request) -> aio_web.Response:
        """Render the API key settings page."""
        try:
            settings_authenticated = self._admin_request_authorized(request)
            render_ctx: Dict[str, Any] = {
                "saved": request.rel_url.query.get("saved", ""),
                "deleted": request.rel_url.query.get("deleted", ""),
                "error": request.rel_url.query.get("error", ""),
                "storage_error": request.rel_url.query.get("storage_error", ""),
                "changed": request.rel_url.query.get("changed", ""),
                "login_error": request.rel_url.query.get("login_error", ""),
                "settings_authenticated": settings_authenticated,
            }
            if settings_authenticated:
                self._reload_api_keys()
                render_ctx.update(
                    api_key_list=self._settings_rows(),
                    api_key_summary=self._api_key_summary(),
                )
            html = self._render("settings", **render_ctx)
            return aio_web.Response(text=html, content_type="text/html", charset="utf-8")
        except aio_web.HTTPException:
            raise
        except Exception as exc:
            logging.error("handle_settings error: %s\n%s", exc, _traceback.format_exc())
            raise aio_web.HTTPInternalServerError(text="Internal server error. Check local logs for details.")

    async def handle_api_settings_auth(self, request: aio_web.Request) -> aio_web.Response:
        form_data = await request.post()
        supplied = str(form_data.get("admin_token", "")).strip()
        if constant_time_equals(supplied, self.admin_token):
            raise self._admin_cookie_redirect("/settings")
        raise aio_web.HTTPFound("/settings?login_error=1")

    async def handle_api_settings_logout(self, request: aio_web.Request) -> aio_web.Response:
        raise self._clear_admin_cookie_redirect("/settings")

    async def handle_api_settings_status(self, request: aio_web.Request) -> aio_web.Response:
        self._require_admin(request)
        self._reload_api_keys()
        rows = self._settings_rows()
        payload = [
            {
                "provider": row["key"],
                "label": row["label"],
                "env_var": row["env_var"],
                "present": bool(row["set"]),
                "masked_hint": row["masked"],
                "source": row["source"],
            }
            for row in rows
        ]
        return aio_web.Response(
            text=normalize_text(json.dumps({
                "providers": payload,
                "summary": self._api_key_summary(),
            }, ensure_ascii=False)),
            content_type="application/json",
            charset="utf-8",
        )

    async def handle_api_settings(self, request: aio_web.Request) -> aio_web.Response:
        """Save/delete API keys using keystore."""
        try:
            self._require_admin(request)
            form_data = await request.post()
            requested_action = str(form_data.get("action", "save")).strip().lower()
            provider_to_delete = str(form_data.get("provider", "")).strip().lower()
            delete_list: List[str] = []
            updates: Dict[str, str] = {}
            if requested_action == "delete":
                canonical_provider = KEY_ALIASES.get(provider_to_delete, provider_to_delete)
                if canonical_provider:
                    delete_list.append(canonical_provider)
            else:
                for raw_provider, value in form_data.items():
                    if raw_provider in {"action", "provider", "admin_token"}:
                        continue
                    canonical_provider = KEY_ALIASES.get(str(raw_provider).lower(), str(raw_provider).lower())
                    raw_val = str(value or "").strip()
                    if not raw_val:
                        continue
                    is_valid, reason = validate_provider_value(canonical_provider, raw_val)
                    if not is_valid:
                        raise aio_web.HTTPFound(f"/settings?error={canonical_provider}:{reason}")
                    updates[canonical_provider] = raw_val
            save_store_keys(updates, delete_providers=delete_list)
            for provider in delete_list:
                self._memory_api_keys.pop(provider, None)
            self._memory_api_keys.update(updates)
            self._reload_api_keys()
            change_count = len(updates) + len(delete_list)
            status_key = "deleted" if delete_list and not updates else "saved"
            raise aio_web.HTTPFound(f"/settings?{status_key}=1&changed={change_count}")
        except KeystoreWriteError as exc:
            logging.warning("handle_api_settings storage error: %s", exc)
            raise aio_web.HTTPFound(f"/settings?{urlencode({'storage_error': str(exc)})}")
        except aio_web.HTTPException:
            raise
        except Exception as exc:
            logging.error("handle_api_settings error: %s", exc)
            raise aio_web.HTTPInternalServerError(text="Internal server error. Check local logs for details.")

    async def handle_results(self, request: aio_web.Request) -> aio_web.Response:
        scan_id = _normalize_scan_id_value(request.match_info["scan_id"])
        if not scan_id:
            raise aio_web.HTTPBadRequest(text="Invalid scan id")
        try:
            summary_bundle = self._load_web_render_summary(scan_id)
            if summary_bundle:
                render_result = summary_bundle.get("result", {})
                render_report = summary_bundle.get("report", {})
            else:
                scan_dir, report_json, report_html, _report_txt = self._saved_result_paths(scan_id)
                prefer_saved_html = report_html.exists()
                if prefer_saved_html and report_json.exists():
                    with contextlib.suppress(OSError):
                        prefer_saved_html = report_html.stat().st_mtime_ns >= report_json.stat().st_mtime_ns
                if prefer_saved_html:
                    saved_html = self._load_saved_result_markup(scan_id, fragment=False)
                    if saved_html is not None:
                        return aio_web.Response(text=saved_html, content_type="text/html", charset="utf-8")
                data = self._load_scan_result(scan_id)
                if data:
                    report = build_canonical_report(data)
                    render_result, render_report = self._build_render_payload(report.get("data", data), report)
                else:
                    saved_html = self._load_saved_result_markup(scan_id, fragment=False)
                    if saved_html is None:
                        raise aio_web.HTTPNotFound(text=f"Scan {scan_id!r} not found")
                    return aio_web.Response(text=saved_html, content_type="text/html", charset="utf-8")
            html = self._render(
                "results",
                result=render_result,
                report=render_report,
                scan_id=scan_id,
            )
            return aio_web.Response(text=html, content_type="text/html", charset="utf-8")
        except aio_web.HTTPException:
            raise
        except Exception as exc:
            logging.error("handle_results error [%s]: %s\n%s", scan_id, exc, _traceback.format_exc())
            html = (
                "<!DOCTYPE html><html><head><meta charset='UTF-8'>"
                "<title>Ghost Recon - Error</title>"
                "<style>body{background:#070b14;color:#e2e8f0;font-family:monospace;"
                "padding:32px;max-width:900px}h2{color:#ef4444;margin-bottom:16px}"
                "a{color:#3b82f6}</style></head><body>"
                f"<h2>&#128683; Error loading results for scan <code>{scan_id}</code></h2>"
                f"<p><a href='/api/debug/{scan_id}'>View raw JSON debug</a> &nbsp;|&nbsp; "
                f"<a href='/history'>Back to History</a> &nbsp;|&nbsp; <a href='/'>Home</a></p>"
                "<p>Internal details were written to the local log.</p>"
                "</body></html>"
            )
            return aio_web.Response(text=html, content_type="text/html", charset="utf-8", status=500)

    async def handle_api_result(self, request: aio_web.Request) -> aio_web.Response:
        scan_id = _normalize_scan_id_value(request.match_info["scan_id"])
        if not scan_id:
            raise aio_web.HTTPBadRequest(text="Invalid scan id")
        data = self._load_scan_result(scan_id)
        if not data:
            raise aio_web.HTTPNotFound()
        schema = request.rel_url.query.get("schema", "").lower()
        if schema in {"raw", "debug"}:
            payload = data
        else:
            payload = build_canonical_report(data)
        return aio_web.Response(
            text=normalize_text(json.dumps(_normalize_text_tree(payload), default=str, ensure_ascii=False)),
            content_type="application/json",
            charset="utf-8",
        )

    async def handle_api_result_section(self, request: aio_web.Request) -> aio_web.Response:
        """Return a specific data section for lazy tab loading.
        GET /api/result-data/{scan_id}/{section}
        section = subdomains | emails | ips | certs | dorks | archive | techs | vulns | social | reputation | asn
        """
        scan_id = _normalize_scan_id_value(request.match_info["scan_id"])
        if not scan_id:
            raise aio_web.HTTPBadRequest(text="Invalid scan id")
        section = request.match_info["section"].lower().strip()

        def _query_int(name: str, default: int) -> int:
            raw = request.rel_url.query.get(name, "")
            if raw in {"", None}:
                return default
            try:
                return int(str(raw).strip())
            except (TypeError, ValueError):
                raise aio_web.HTTPBadRequest(text=f"Invalid integer for {name}: {raw!r}")

        offset = max(0, _query_int("offset", 0))
        limit = _query_int("limit", 200 if section == "archive" else 500)
        limit = max(1, min(limit, 1000))
        _SECTION_MAP = {
            "subdomains": "subdomains",
            "emails": "emails",
            "ips": "ip_records",
            "certs": "ssl_info",
            "dorks": "dorks",
            "archive": "wayback_urls",
            "techs": "technologies",
            "vulns": "vulnerabilities",
            "social": "social_footprint",
            "reputation": "reputation_data",
            "asn": "asn_intelligence",
            "cloud": "cloud_assets",
            "breach": "breach_records",
            "takeover": "takeover_records",
            "dns": "dns_records",
        }
        field = _SECTION_MAP.get(section)
        if not field:
            raise aio_web.HTTPNotFound(text=f"Unknown section: {section!r}. Valid: {', '.join(_SECTION_MAP)}")
        q = request.rel_url.query.get("q", "")
        section_payload = self._load_web_section_payload(scan_id, section)
        if section_payload:
            value = section_payload.get("data")
        else:
            data = self._load_scan_result(scan_id)
            if not data:
                raise aio_web.HTTPNotFound()
            value = None
            if section == "archive":
                archive = data.get("web_archive", {}) if isinstance(data.get("web_archive", {}), dict) else {}
                if not archive and isinstance(data.get("wayback_urls", {}), dict):
                    archive = data.get("wayback_urls", {})
                value = archive if isinstance(archive, dict) else {}
            elif section == "asn":
                value = data.get(field, {})
            else:
                value = data.get(field)
        if section == "archive":
            payload = self._archive_page_payload(
                value if isinstance(value, dict) else {},
                offset=offset,
                limit=limit,
                q=q,
            )
        elif section == "asn":
            payload = {
                "section": section,
                "field": field,
                "data": value if isinstance(value, dict) else {},
            }
        else:
            if isinstance(value, list):
                payload = self._list_page_payload(
                    value,
                    section=section,
                    field=field,
                    offset=offset,
                    limit=limit,
                    q=q,
                )
            elif isinstance(value, dict):
                payload = {"section": section, "field": field, "data": value}
            else:
                payload = {"section": section, "field": field, "data": value}
        return aio_web.Response(
            text=normalize_text(json.dumps(_normalize_text_tree(payload), default=str, ensure_ascii=False)),
            content_type="application/json",
            charset="utf-8",
        )

    async def handle_logo(self, request: aio_web.Request) -> aio_web.Response:
        static_logo = self.static_dir / "logo.png"
        root_logo = Path(__file__).parent / "logo.png"
        logo_path = static_logo if static_logo.exists() else root_logo
        if not logo_path.exists():
            raise aio_web.HTTPNotFound()
        data = logo_path.read_bytes()
        return aio_web.Response(
            body=data,
            content_type="image/png",
            headers={"Cache-Control": "public, max-age=86400"},
        )

    async def handle_result_fragment(self, request: aio_web.Request) -> aio_web.Response:
        """Return just the rendered results section as an HTML fragment for inline injection."""
        scan_id = _normalize_scan_id_value(request.match_info["scan_id"])
        if not scan_id:
            raise aio_web.HTTPBadRequest(text="Invalid scan id")
        try:
            stamp = self._saved_result_stamp(scan_id)
            now = time.time()
            cached = self._fragment_cache.get(scan_id)
            if cached and int(cached.get("stamp", 0)) == stamp and (now - float(cached.get("ts", 0.0))) <= 20.0:
                return aio_web.Response(text=str(cached.get("html", "")), content_type="text/html", charset="utf-8")
            summary_bundle = self._load_web_render_summary(scan_id)
            if summary_bundle:
                render_result = summary_bundle.get("result", {})
                render_report = summary_bundle.get("report", {})
                html = self._render(
                    "results_fragment",
                    result=render_result,
                    report=render_report,
                    scan_id=scan_id,
                )
            else:
                data = self._load_scan_result(scan_id)
                if data:
                    report = build_canonical_report(data)
                    render_result, render_report = self._build_render_payload(report.get("data", data), report)
                    html = self._render(
                        "results_fragment",
                        result=render_result,
                        report=render_report,
                        scan_id=scan_id,
                    )
                else:
                    html = self._load_saved_result_markup(scan_id, fragment=True)
                    if html is None:
                        raise aio_web.HTTPNotFound(text=f"Scan {scan_id!r} not found")
            self._fragment_cache[scan_id] = {"stamp": stamp, "ts": now, "html": html}
            if len(self._fragment_cache) > 64:
                oldest = sorted(self._fragment_cache.items(), key=lambda kv: float(kv[1].get("ts", 0.0)))[:16]
                for sid, _ in oldest:
                    self._fragment_cache.pop(sid, None)
            return aio_web.Response(text=html, content_type="text/html", charset="utf-8")
        except aio_web.HTTPException:
            raise
        except Exception as exc:
            logging.error("handle_result_fragment error [%s]: %s\n%s",
                          scan_id, exc, _traceback.format_exc())
            raise aio_web.HTTPInternalServerError(text="Internal server error. Check local logs for details.")

    async def handle_debug(self, request: aio_web.Request) -> aio_web.Response:
        """Dump raw scan data as JSON for debugging template crashes."""
        scan_id = _normalize_scan_id_value(request.match_info["scan_id"])
        if not scan_id:
            raise aio_web.HTTPBadRequest(text="Invalid scan id")
        data = self._load_scan_result(scan_id)
        if not data:
            raise aio_web.HTTPNotFound(text=f"Scan {scan_id!r} not found")
        # Build a diagnostic report
        diag = {
            "scan_id": scan_id,
            "keys_present": list(data.keys()),
            "field_types": {k: type(v).__name__ for k, v in data.items()},
            "list_lengths": {k: len(v) for k, v in data.items() if isinstance(v, list)},
            "null_fields": [k for k, v in data.items() if v is None],
            "data": data,
        }
        return aio_web.Response(
            text=normalize_text(json.dumps(_normalize_text_tree(diag), indent=2, default=str, ensure_ascii=False)),
            content_type="application/json",
            charset="utf-8",
        )

    async def handle_download(self, request: aio_web.Request) -> aio_web.Response:
        scan_id = _normalize_scan_id_value(request.match_info["scan_id"])
        if not scan_id:
            raise aio_web.HTTPBadRequest(text="Invalid scan id")
        fmt = request.match_info["fmt"]
        data = self._load_scan_result(scan_id)
        if not data:
            raise aio_web.HTTPNotFound()

        self._refresh_results_index()
        report_json_path = self._result_index.get(scan_id)
        scan_dir = report_json_path.parent if report_json_path and report_json_path.exists() else (self.results_dir / scan_id)
        report_json_path = report_json_path if report_json_path and report_json_path.exists() else (scan_dir / "report.json")
        report_txt_path = scan_dir / "report.txt"
        report_html_path = scan_dir / "report.html"
        canonical_report = build_canonical_report(data)
        canonical_data = canonical_report.get("data", data) if isinstance(canonical_report, dict) else data
        stream_text_response: Optional[Tuple[str, str, str]] = None
        if fmt == "json":
            fn = _safe_download_filename(scan_id, "json")
            if report_json_path.exists():
                return await _download_file_response(request, report_json_path, fn, "application/json")
            secrets = [v for v in load_api_keys().values() if isinstance(v, str) and v]
            safe_report = _redact_sensitive_tree(_normalize_text_tree(canonical_report), secrets)
            body = normalize_text(json.dumps(safe_report, indent=2, default=str, ensure_ascii=False))
            return await _stream_text_download(request, "application/json", fn, body)
        elif fmt == "json-raw":
            body = normalize_text(json.dumps(_normalize_text_tree(data), indent=2, default=str, ensure_ascii=False))
            ct = "application/json"
            fn = _safe_download_filename(scan_id, "json", "raw")
        elif fmt == "txt":
            fn = _safe_download_filename(scan_id, "txt")
            if report_txt_path.exists():
                return await _download_file_response(request, report_txt_path, fn, "text/plain")
            result_obj = ReconResult(**{k: data.get(k, v)
                                        for k, v in asdict(ReconResult(
                                            domain="", scan_id="", scan_date="", mode="")).items()})
            for field_name in asdict(result_obj).keys():
                setattr(result_obj, field_name, data.get(field_name,
                        getattr(result_obj, field_name)))
            try:
                scan_dir.mkdir(parents=True, exist_ok=True)
                p = write_txt(result_obj, scan_dir)
            except OSError as exc:
                raise aio_web.HTTPInsufficientStorage(text=f"Unable to generate TXT export: {exc}") from exc
            return await _download_file_response(request, p, fn, "text/plain")
        elif fmt == "html":
            render_result, render_report = self._build_render_payload(canonical_data, canonical_report)
            fn = _safe_download_filename(scan_id, "html")
            stream_text_response = ("text/html", fn, self._render(
                "results",
                result=render_result,
                report=render_report,
                result_json=json.dumps(render_report, default=str, ensure_ascii=False),
                scan_id=scan_id,
            ))
        elif fmt == "html-standalone":
            fn = _safe_download_filename(scan_id, "html")
            html = _render_lightweight_web_export_html(canonical_data, canonical_report)
            return await _stream_text_download(request, "text/html", fn, html)
        elif fmt == "html-full":
            fn = _safe_download_filename(scan_id, "html", "full_static_report")
            html = _render_full_static_web_export_html(canonical_report)
            return await _stream_text_download(request, "text/html", fn, html)
        elif fmt == "zip":
            fn = _safe_download_filename(scan_id, "zip")
            result_obj = ReconResult(**{k: data.get(k, v)
                                        for k, v in asdict(ReconResult(
                                            domain="", scan_id="", scan_date="", mode="")).items()})
            for field_name in asdict(result_obj).keys():
                setattr(result_obj, field_name, data.get(field_name,
                        getattr(result_obj, field_name)))
            if not report_txt_path.exists():
                try:
                    scan_dir.mkdir(parents=True, exist_ok=True)
                    write_txt(result_obj, scan_dir)
                except OSError as exc:
                    raise aio_web.HTTPInsufficientStorage(text=f"Unable to generate ZIP contents: {exc}") from exc
            export_html = _render_lightweight_web_export_html(canonical_data, canonical_report)
            full_static_html = _render_full_static_web_export_html(canonical_report)
            mem = io.BytesIO()
            with zipfile.ZipFile(mem, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
                if report_json_path.exists():
                    zf.write(report_json_path, arcname=_safe_download_filename(scan_id, "json"))
                else:
                    payload = normalize_text(
                        json.dumps(_normalize_text_tree(canonical_report), indent=2, default=str, ensure_ascii=False)
                    ).encode("utf-8")
                    zf.writestr(_safe_download_filename(scan_id, "json"), payload)
                if report_txt_path.exists():
                    zf.write(report_txt_path, arcname=_safe_download_filename(scan_id, "txt"))
                zf.writestr(_safe_download_filename(scan_id, "html"), export_html.encode("utf-8"))
                zf.writestr(_safe_download_filename(scan_id, "html", "full_static_report"), full_static_html.encode("utf-8"))
            return await _stream_bytes_download(request, "application/zip", fn, mem.getvalue())
        elif fmt == "csv_subdomains":
            buf = io.StringIO()
            w = csv.writer(buf)
            w.writerow(["subdomain", "ips", "ports", "sources", "tags", "relevance_score", "status", "cloud"])
            for s in canonical_data.get("subdomains", []):
                if isinstance(s, dict):
                    ips   = ";".join(s.get("ips") or s.get("ip_addresses") or [])
                    ports = ";".join(str(p) for p in (s.get("ports") or s.get("open_ports") or []))
                    srcs  = ";".join(s.get("sources") or [])
                    tags  = ";".join(s.get("tags") or [])
                    name  = s.get("name") or s.get("subdomain") or s.get("host") or ""
                    score = s.get("relevance_score", s.get("score", ""))
                    status= s.get("status", "")
                    cloud = s.get("cloud_provider", "")
                    w.writerow([name, ips, ports, srcs, tags, score, status, cloud])
            body = normalize_text(buf.getvalue())
            ct = "text/csv"
            fn = _safe_download_filename(scan_id, "csv", "subdomains")
        elif fmt == "csv_emails":
            buf = io.StringIO()
            w = csv.writer(buf)
            email_pattern = canonical_data.get("email_pattern", {}) if isinstance(canonical_data.get("email_pattern", {}), dict) else {}
            w.writerow(["email", "sources", "role", "pattern", "confidence"])
            for e in canonical_data.get("emails", []):
                if isinstance(e, dict):
                    srcs = ";".join(e.get("sources") or [])
                    w.writerow([
                        e.get("email", ""), srcs,
                        e.get("role", e.get("role_category", "")),
                        email_pattern.get("pattern", ""),
                        e.get("confidence", ""),
                    ])
                elif isinstance(e, str):
                    w.writerow([e, "", "", email_pattern.get("pattern", ""), ""])
            body = normalize_text(buf.getvalue())
            ct = "text/csv"
            fn = _safe_download_filename(scan_id, "csv", "emails")
        elif fmt == "csv_vulns":
            buf = io.StringIO()
            w = csv.writer(buf)
            w.writerow(["cve", "severity", "finding_family", "evidence_tier", "cvss", "epss", "description", "affected_host", "reference"])
            for v in canonical_data.get("vulnerabilities", []):
                if isinstance(v, dict):
                    w.writerow([
                        v.get("cve_id") or v.get("id", ""),
                        v.get("severity", ""),
                        v.get("finding_family", ""),
                        v.get("evidence_tier", ""),
                        v.get("cvss_score", v.get("cvss", "")),
                        v.get("epss_score", v.get("epss", "")),
                        (v.get("description", "") or "")[:200],
                        v.get("affected_asset") or v.get("affected_host") or v.get("host", ""),
                        (v.get("references", []) or [""])[0] if isinstance(v.get("references"), list) else v.get("reference") or v.get("url", ""),
                    ])
            body = normalize_text(buf.getvalue())
            ct = "text/csv"
            fn = _safe_download_filename(scan_id, "csv", "vulnerabilities")
        elif fmt in {"entity-graph", "entity-graph.json"}:
            graph = canonical_report.get("entity_graph", {})
            body = normalize_text(json.dumps(_normalize_text_tree(graph), indent=2, ensure_ascii=False))
            ct = "application/json"
            fn = _safe_download_filename(scan_id, "json", "entity_graph")
        else:
            raise aio_web.HTTPBadRequest()

        if stream_text_response is not None:
            return await _stream_text_download(
                request,
                stream_text_response[0],
                stream_text_response[1],
                stream_text_response[2],
            )

        quoted_fn = quote(fn, safe="")

        return aio_web.Response(
            text=body,
            content_type=ct,
            charset="utf-8",
            headers={
                "Content-Disposition": f'attachment; filename="{fn}"; filename*=UTF-8\'\'{quoted_fn}',
                "Content-Length": str(len(body.encode("utf-8"))),
                "X-Content-Type-Options": "nosniff",
            },
        )

    async def handle_diff(self, request: aio_web.Request) -> aio_web.Response:
        scan_a = request.match_info["scan_a"]
        scan_b = request.match_info["scan_b"]
        a = self._load_scan_result(scan_a)
        b = self._load_scan_result(scan_b)
        if not a or not b:
            raise aio_web.HTTPNotFound(text="One or both scans not found")
        a_subs = {s.get("name", "") for s in (a.get("subdomains", []) or []) if isinstance(s, dict)}
        b_subs = {s.get("name", "") for s in (b.get("subdomains", []) or []) if isinstance(s, dict)}
        a_emails = {e.get("email", "") for e in (a.get("emails", []) or []) if isinstance(e, dict)}
        b_emails = {e.get("email", "") for e in (b.get("emails", []) or []) if isinstance(e, dict)}
        a_vulns = {v.get("cve_id") or v.get("title", "") for v in (a.get("vulnerabilities", []) or []) if isinstance(v, dict)}
        b_vulns = {v.get("cve_id") or v.get("title", "") for v in (b.get("vulnerabilities", []) or []) if isinstance(v, dict)}
        diff = {
            "scan_a": scan_a,
            "scan_b": scan_b,
            "added": {
                "subdomains": sorted(x for x in (b_subs - a_subs) if x),
                "emails": sorted(x for x in (b_emails - a_emails) if x),
                "vulnerabilities": sorted(x for x in (b_vulns - a_vulns) if x),
            },
            "removed": {
                "subdomains": sorted(x for x in (a_subs - b_subs) if x),
                "emails": sorted(x for x in (a_emails - b_emails) if x),
                "vulnerabilities": sorted(x for x in (a_vulns - b_vulns) if x),
            },
        }
        return aio_web.Response(text=json.dumps(diff, indent=2), content_type="application/json")

    async def _create_and_submit_scan(self, domain: str, mode: str, debug_coverage: bool) -> str:
        scan_id = ""
        for _ in range(8):
            candidate = uuid.uuid4().hex[:12]
            if candidate not in self.active_scans and not self.scan_manager.get_state(candidate):
                scan_id = candidate
                break
        if not scan_id:
            scan_id = uuid.uuid4().hex[:12]
        out_dir = _build_scan_output_dir(self.results_dir, domain, scan_id)
        try:
            out_dir.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            raise aio_web.HTTPInsufficientStorage(text=f"Unable to create scan output directory: {exc}") from exc

        async def runner(scan_id_local: str, publish: Callable[[str, Dict[str, Any]], Awaitable[None]]) -> Dict[str, Any]:
            def _progress(event_type: str, data: dict) -> Awaitable[None]:
                payload = dict(data or {})
                payload["scan_id"] = scan_id_local
                return publish(event_type, payload)

            scan_source_registry = self.source_registry.clone()
            scan_http_guard = HttpGuard(config=DEFAULT_HTTP_GUARD.config)
            engine = _build_recon_engine(
                domain=domain,
                mode=mode,
                api_keys=self.api_keys,
                output_dir=out_dir,
                progress_cb=_progress,
                policy=self.policy,
                debug_coverage=debug_coverage,
                source_registry=scan_source_registry,
            )
            guard_token = set_current_http_guard(scan_http_guard)
            try:
                result = await engine.run()
            finally:
                reset_current_http_guard(guard_token)
            result.scan_id = scan_id_local
            self.active_scans[scan_id_local] = {"result": result, "domain": domain, "ts": time.time()}
            self._prune_active_scans()
            report_json = out_dir / "report.json"
            report_txt = out_dir / "report.txt"
            report_html = out_dir / "report.html"
            for label, writer, default_path in (
                ("json_export", write_json, report_json),
                ("txt_export", write_txt, report_txt),
                ("html_export", write_html, report_html),
            ):
                try:
                    written = writer(result, out_dir)
                    if isinstance(written, Path):
                        if label == "json_export":
                            report_json = written
                        elif label == "txt_export":
                            report_txt = written
                        else:
                            report_html = written
                except Exception as exc:
                    result.errors.append(_export_error_record(label, default_path, exc))
            self._invalidate_result_catalog(scan_id_local, out_dir)
            return {
                "report_json": str(report_json),
                "report_txt": str(report_txt),
                "report_html": str(report_html),
                "report_html_standalone": str(out_dir / "report.html"),
            }

        await self.scan_manager.submit(scan_id, domain, mode, runner)
        return scan_id

    async def _stream_scan_events(
        self, request: aio_web.Request, scan_id: str, domain_hint: str = ""
    ) -> aio_web.StreamResponse:
        state = self.scan_manager.get_state(scan_id)
        if not state:
            raise aio_web.HTTPNotFound(text=f"Scan {scan_id!r} not found")

        origin = request.headers.get("Origin", "")
        allowed_origin = ""
        if origin in {f"http://localhost:{self.port}", f"http://127.0.0.1:{self.port}"}:
            allowed_origin = origin
        response = aio_web.StreamResponse()
        response.headers.update(
            {
                "Content-Type": "text/event-stream; charset=utf-8",
                "Cache-Control": "no-cache",
                "Connection": "keep-alive",
                "X-Accel-Buffering": "no",
            }
        )
        if allowed_origin:
            response.headers["Access-Control-Allow-Origin"] = allowed_origin
        try:
            await response.prepare(request)
        except Exception as exc:
            if _is_expected_client_disconnect(exc):
                raise ExpectedClientDisconnect() from exc
            raise
        stop_heartbeat = asyncio.Event()
        phase_state: Dict[str, str] = {"running": ""}
        client_state: Dict[str, bool] = {"connected": True}
        queue = await self.scan_manager.subscribe(scan_id, replay=True)

        async def write_sse_event(event_type: str, data: Dict[str, Any]) -> None:
            payload = _normalize_text_tree(data)
            msg = f"event: {event_type}\ndata: {json.dumps(payload, default=str, ensure_ascii=False)}\n\n"
            try:
                await response.write(msg.encode("utf-8"))
            except Exception as exc:
                if not _is_expected_client_disconnect(exc):
                    raise
                client_state["connected"] = False
                stop_heartbeat.set()
                raise ExpectedClientDisconnect() from exc

        async def write_sse_comment(raw: str) -> None:
            try:
                await response.write(raw.encode("utf-8"))
            except Exception as exc:
                if not _is_expected_client_disconnect(exc):
                    raise
                client_state["connected"] = False
                stop_heartbeat.set()
                raise ExpectedClientDisconnect() from exc

        async def hb_event(event_type: str, data: Dict[str, Any]) -> None:
            await write_sse_event(event_type, data)

        async def hb_comment(raw: str) -> None:
            await write_sse_comment(raw)

        heartbeat_task = asyncio.create_task(
            _sse_heartbeat_loop(
                emit_event=hb_event,
                emit_comment=hb_comment,
                stop_event=stop_heartbeat,
                get_scan_meta=lambda: {
                    "scan_id": scan_id,
                    "domain": domain_hint or str(state.get("domain", "")),
                },
                get_running_phase=lambda: phase_state.get("running", ""),
                ping_interval_seconds=8.0,
                phase_tick_interval_seconds=12.0,
            )
        )

        try:
            while True:
                if not client_state.get("connected", True):
                    break
                try:
                    item = await asyncio.wait_for(queue.get(), timeout=15)
                    event_type = str(item.get("event", ""))
                    data = item.get("data", {}) if isinstance(item, dict) else {}
                    if event_type == "phase":
                        name = str((data or {}).get("name", "")).strip()
                        status = str((data or {}).get("status", "")).strip().lower()
                        if status == "running":
                            phase_state["running"] = name
                        elif status in {"done", "failed", "error"} and phase_state.get("running") == name:
                            phase_state["running"] = ""
                    await write_sse_event(event_type, data if isinstance(data, dict) else {})
                    if event_type in {"saved", "error", "cancelled"}:
                        break
                except ExpectedClientDisconnect:
                    break
                except asyncio.TimeoutError:
                    try:
                        await write_sse_comment(": keep-alive\n\n")
                    except ExpectedClientDisconnect:
                        break
        finally:
            stop_heartbeat.set()
            self.scan_manager.unsubscribe(scan_id, queue)
            if not heartbeat_task.done():
                heartbeat_task.cancel()
            with contextlib.suppress(asyncio.CancelledError, ExpectedClientDisconnect):
                await heartbeat_task
        return response

    async def handle_api_scan_create(self, request: aio_web.Request) -> aio_web.Response:
        payload = await request.json()
        domain_raw = str((payload or {}).get("domain", "")).strip().lower()
        mode = str((payload or {}).get("mode", "balanced")).strip().lower()
        debug_coverage = bool((payload or {}).get("debug_coverage", False))
        if mode not in ("fast", "balanced", "deep", "turbo"):
            mode = "balanced"
        domain = normalize_domain(domain_raw)
        if not is_valid_domain(domain):
            raise aio_web.HTTPBadRequest(text="invalid domain")
        scan_id = await self._create_and_submit_scan(domain, mode, debug_coverage)
        return aio_web.Response(
            text=normalize_text(json.dumps({"scan_id": scan_id}, ensure_ascii=False)),
            content_type="application/json",
            charset="utf-8",
        )

    async def handle_api_scans(self, request: aio_web.Request) -> aio_web.Response:
        rows = self.scan_manager.list_scans()
        return aio_web.Response(
            text=normalize_text(json.dumps({"scans": rows}, ensure_ascii=False)),
            content_type="application/json",
            charset="utf-8",
        )

    async def handle_api_scan_status(self, request: aio_web.Request) -> aio_web.Response:
        scan_id = _normalize_scan_id_value(request.match_info["scan_id"])
        if not scan_id:
            raise aio_web.HTTPBadRequest(text="Invalid scan id")
        row = self.scan_manager.get_state(scan_id)
        if not row:
            saved = self._load_scan_result(scan_id)
            if not saved:
                raise aio_web.HTTPNotFound(text="scan not found")
            row = {
                "scan_id": scan_id,
                "domain": saved.get("domain", ""),
                "status": "saved",
                "phase": "results",
                "progress": 100,
            }
        return aio_web.Response(
            text=normalize_text(json.dumps(row, ensure_ascii=False)),
            content_type="application/json",
            charset="utf-8",
        )

    async def handle_api_scan_cancel(self, request: aio_web.Request) -> aio_web.Response:
        scan_id = _normalize_scan_id_value(request.match_info["scan_id"])
        if not scan_id:
            raise aio_web.HTTPBadRequest(text="Invalid scan id")
        cancelled = await self.scan_manager.cancel(scan_id)
        return aio_web.Response(
            text=normalize_text(json.dumps({"scan_id": scan_id, "cancelled": cancelled}, ensure_ascii=False)),
            content_type="application/json",
            charset="utf-8",
        )

    async def handle_sse_attach(self, request: aio_web.Request) -> aio_web.StreamResponse:
        scan_id = _normalize_scan_id_value(request.match_info["scan_id"])
        if not scan_id:
            raise aio_web.HTTPBadRequest(text="Invalid scan id")
        try:
            return await self._stream_scan_events(request, scan_id)
        except ExpectedClientDisconnect:
            raise aio_web.HTTPOk(text="")

    async def handle_sse(self, request: aio_web.Request) -> aio_web.StreamResponse:
        existing_scan_id = request.rel_url.query.get("scan_id", "").strip()
        if existing_scan_id:
            try:
                return await self._stream_scan_events(request, existing_scan_id)
            except ExpectedClientDisconnect:
                raise aio_web.HTTPOk(text="")

        domain_raw = request.rel_url.query.get("domain", "").strip().lower()
        mode = request.rel_url.query.get("mode", "balanced")
        debug_coverage = self.debug_coverage or (
            request.rel_url.query.get("debug_coverage", "").strip().lower() in {"1", "true", "yes", "on"}
        )
        if mode not in ("fast", "balanced", "deep", "turbo"):
            mode = "balanced"

        # Sanitize domain
        domain = normalize_domain(domain_raw)
        if not is_valid_domain(domain):
            resp = aio_web.StreamResponse()
            resp.headers.update({
                "Content-Type": "text/event-stream; charset=utf-8",
                "Cache-Control": "no-cache",
                "Connection": "keep-alive",
                "X-Accel-Buffering": "no",
            })
            await resp.prepare(request)
            err = json.dumps({"message": normalize_text(f"Invalid domain: {domain_raw!r}")}, ensure_ascii=False)
            try:
                await resp.write(f"event: error\ndata: {err}\n\n".encode())
            except Exception as exc:
                if not _is_expected_client_disconnect(exc):
                    raise
            return resp
        scan_id = await self._create_and_submit_scan(domain, mode, debug_coverage)
        try:
            return await self._stream_scan_events(request, scan_id, domain_hint=domain)
        except ExpectedClientDisconnect:
            raise aio_web.HTTPOk(text="")

    async def start(self, open_browser: bool = True):
        app = self.make_app()
        runner = aio_web.AppRunner(app)
        await runner.setup()
        site = aio_web.TCPSite(runner, "localhost", self.port)
        await site.start()

        url = f"http://localhost:{self.port}"
        key_summary_data = self._api_key_summary()
        ready_labels = [row["label"] for row in key_summary_data["ready_services"]]
        missing_labels = [row["label"] for row in key_summary_data["missing_services"]]
        key_summary = (
            f"[green][OK] Credentials configured: {key_summary_data['configured_credentials_count']}/{key_summary_data['credentials_total']}[/green]\n"
            f"[green][READY] Providers ready: {key_summary_data['ready_services_count']}[/green] "
            f"{', '.join(ready_labels[:8]) if ready_labels else 'none'}"
            + (f" +{len(ready_labels)-8}" if len(ready_labels) > 8 else "")
            + (
                f"\n[dim][MISSING] Providers pending: {key_summary_data['missing_services_count']}[/dim] "
                f"{', '.join(missing_labels[:6])}"
                + (f" +{len(missing_labels)-6}" if len(missing_labels) > 6 else "")
                if missing_labels else ""
            )
        )
        panel_text = normalize_text(
            f"[bold green]Ghost Recon Tool - Web Interface[/bold green]\n"
            f"[cyan]{url}[/cyan]\n"
            f"[yellow]Settings URL:[/yellow] {url}/settings\n"
            f"[yellow]Admin token:[/yellow] {self.admin_token}\n"
            f"[dim]Admin token fp: {token_fingerprint(self.admin_token)} (accepted via login form or X-GRT-Admin-Token header)[/dim]\n"
            f"[dim]Policy: passive_only={self.policy.passive_only}, allow_active={self.policy.allow_active}, "
            f"allow_target_requests={self.policy.allow_target_requests}[/dim]\n"
            f"{key_summary}\n"
            f"[dim]Press Ctrl+C to stop | /settings to add API keys[/dim]"
        )
        console.print(Panel(panel_text, border_style="green"))

        should_auto_open = (
            open_browser
            and not os.environ.get("GRT_NO_BROWSER_AUTOOPEN")
            and not os.environ.get("CI")
            and (sys.stdin.isatty() or sys.stdout.isatty())
        )
        if should_auto_open:
            # Delay slightly so the browser lands on a ready server.
            await asyncio.sleep(0.8)
            try:
                opened = await asyncio.to_thread(webbrowser.open, url, new=2)
                if not opened:
                    logging.info("Browser auto-open was not handled by the host OS for %s", url)
            except Exception as exc:
                logging.warning("Browser auto-open skipped for %s: %s", url, exc)

        # Run forever
        try:
            while True:
                await asyncio.sleep(3600)
        except asyncio.CancelledError:
            pass
        finally:
            await runner.cleanup()


# Ã¢â€â‚¬Ã¢â€â‚¬ MAIN Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
async def main():
    _install_windows_asyncio_disconnect_guard()
    _load_dotenv()
    parser = build_parser()
    args = parser.parse_args()
    passive_only = True if args.passive_only else False
    if args.allow_active or args.allow_target_requests:
        passive_only = False
    policy = ScanPolicy(
        passive_only=passive_only,
        allow_active=args.allow_active,
        allow_target_requests=args.allow_target_requests,
        allow_insecure_http_fallback=args.allow_insecure_http_fallback,
    )
    api_keys = load_api_keys()
    source_registry = SourceRegistry(
        profile=args.sources_profile,
        enable=args.enable_source,
        disable=args.disable_source,
        api_keys=api_keys,
        force_no_keys=args.no_keys,
        allow_target_requests=policy.allow_target_requests,
    )
    if args.doctor:
        rc = run_doctor(args.out_dir, source_registry)
        if args.domain is None and not args.smoke:
            return
        if rc != 0 and not args.smoke:
            sys.exit(rc)
    if args.smoke:
        rc = run_smoke(args.out_dir, policy, source_registry)
        if rc != 0:
            sys.exit(rc)
        return
    if args.list_sources:
        table = Table(title="Registered OSINT Sources", show_header=True, header_style="bold cyan")
        table.add_column("Name", style="bold")
        table.add_column("Category")
        table.add_column("Mode")
        table.add_column("Needs Key")
        table.add_column("Status")
        table.add_column("Hosts")
        for row in source_registry.list_sources():
            table.add_row(
                row.get("name", ""),
                row.get("category", ""),
                row.get("mode", ""),
                "yes" if row.get("requires_keys") else "no",
                row.get("status", ""),
                ",".join(row.get("hosts", [])[:3]),
            )
        console.print(table)
        return
    http_cfg = HttpConfig(
        timeout=60 if args.debug_coverage else 45,
        retries=3,
        backoff_base=0.25 if args.debug_coverage else 0.35,
        per_host_limit=16 if args.debug_coverage else 10,
        rate_limit_per_sec=40 if args.debug_coverage else 24,
    )
    configure_http_guard(http_cfg)
    if args.debug_coverage:
        log.setLevel(logging.DEBUG)
        log.debug(
            "debug_coverage_enabled timeout=%s retries=%s per_host=%s rps=%s",
            http_cfg.timeout,
            http_cfg.retries,
            http_cfg.per_host_limit,
            http_cfg.rate_limit_per_sec,
        )

    # Ã¢â€â‚¬Ã¢â€â‚¬ Web UI mode (no -d argument) Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
    if args.domain is None:
        try:
            server = WebServer(
                port=args.port,
                results_dir=args.out_dir,
                policy=policy,
                admin_token=args.admin_token,
                debug_coverage=args.debug_coverage,
                source_registry=source_registry,
            )
            await server.start(open_browser=not args.no_browser)
        except OSError as exc:
            console.print(f"[red]Unable to start web UI:[/red] {exc}")
            sys.exit(1)
        return

    # Ã¢â€â‚¬Ã¢â€â‚¬ CLI mode Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
    domain = normalize_domain(args.domain)
    mode = "turbo" if args.turbo else args.mode
    api_keys = api_keys

    if not is_valid_domain(domain):
        console.print(f"[red]Invalid domain: {domain}[/red]")
        sys.exit(1)

    run_suffix = uuid.uuid4().hex[:8]
    out_dir = _build_scan_output_dir(args.out_dir, domain, run_suffix)
    try:
        out_dir.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        console.print(f"[red]Unable to create output directory:[/red] {exc}")
        sys.exit(1)

    engine = _build_recon_engine(
        domain=domain,
        mode=mode,
        api_keys=api_keys,
        output_dir=out_dir,
        policy=policy,
        debug_coverage=args.debug_coverage,
        source_registry=source_registry,
    )
    result = await engine.run()
    print_results(result)

    saved = []
    save_errors = []
    if args.output in ("json", "all"):
        try:
            saved.append(str(write_json(result, out_dir)))
        except Exception as exc:
            save_errors.append(f"JSON export: {exc}")
    if args.output in ("txt", "all"):
        try:
            saved.append(str(write_txt(result, out_dir)))
        except Exception as exc:
            save_errors.append(f"TXT export: {exc}")
    if args.output in ("html", "all"):
        try:
            saved.append(str(write_html(result, out_dir)))
        except Exception as exc:
            save_errors.append(f"HTML export: {exc}")

    if saved:
        console.print("\n[bold green]Results saved to:[/bold green]")
        for s in saved:
            console.print(f"  [cyan]{s}[/cyan]")
    if save_errors:
        console.print("\n[bold yellow]Export warnings:[/bold yellow]")
        for message in save_errors:
            console.print(f"  [yellow]{message}[/yellow]")


if __name__ == "__main__":
    asyncio.run(main())
