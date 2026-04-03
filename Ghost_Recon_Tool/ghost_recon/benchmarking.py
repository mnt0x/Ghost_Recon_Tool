from __future__ import annotations

import asyncio
import json
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Sequence

from ghost_recon.core.policy import ScanPolicy
from ghost_recon.sources.registry import SourceRegistry


BENCHMARK_BASELINES: Dict[str, Dict[str, int]] = {
    "ginandjuice.shop": {"subdomains": 1, "emails": 1, "ips": 2},
    "psoe.es": {"subdomains": 690, "emails": 1, "ips": 86, "dorks": 24},
    "github.com": {"subdomains": 776, "emails": 45, "ips": 59, "dorks": 33},
    "dgt.es": {"subdomains": 63, "emails": 28, "ips": 22, "dorks": 24, "archive_urls": 46404},
    "tesla.com": {"subdomains": 1309, "emails": 19, "ips": 104, "dorks": 30, "archive_urls": 45436},
    "microsoft.com": {"subdomains": 8357, "emails": 54, "ips": 188, "dorks": 26, "archive_urls": 39356},
}

BENCHMARK_DOMAINS: List[str] = list(BENCHMARK_BASELINES.keys())
METRIC_ORDER: List[str] = ["subdomains", "emails", "ips", "ports", "dorks", "certs", "vulns", "archive_urls"]


def _count_from_data(data: Mapping[str, Any], key: str) -> int:
    value = data.get(key)
    if isinstance(value, list):
        return len(value)
    if isinstance(value, dict):
        if key == "wayback_urls":
            all_urls = value.get("all")
            if isinstance(all_urls, list):
                return len(all_urls)
        return len(value)
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def extract_metrics(payload: Mapping[str, Any]) -> Dict[str, int]:
    summary = payload.get("summary", {}) if isinstance(payload.get("summary", {}), Mapping) else {}
    data = payload.get("data", payload) if isinstance(payload.get("data", payload), Mapping) else {}
    ip_records = data.get("ip_records", payload.get("ip_records", []))
    if not isinstance(ip_records, list):
        ip_records = []
    ports = 0
    for row in ip_records:
        if not isinstance(row, Mapping):
            continue
        port_values = row.get("open_ports") or row.get("ports") or []
        if isinstance(port_values, list):
            ports += len(port_values)
    metrics = {
        "subdomains": int(summary.get("subdomains", _count_from_data(data, "subdomains")) or 0),
        "emails": int(summary.get("emails", _count_from_data(data, "emails")) or 0),
        "ips": int(summary.get("ips", summary.get("ip_records", len(ip_records))) or 0),
        "ports": int(summary.get("ports", ports) or 0),
        "dorks": int(summary.get("dorks", _count_from_data(data, "dorks")) or 0),
        "certs": int(summary.get("certs", _count_from_data(data, "ssl_info")) or 0),
        "vulns": int(summary.get("vulns", _count_from_data(data, "vulnerabilities")) or 0),
        "archive_urls": int(summary.get("archive_urls", _count_from_data(data, "archive_urls") or _count_from_data(data, "wayback_urls")) or 0),
    }
    return metrics


def extract_preservation(payload: Mapping[str, Any]) -> Dict[str, int]:
    raw = payload.get("raw_preservation", {}) if isinstance(payload.get("raw_preservation", {}), Mapping) else {}
    data = payload.get("data", {}) if isinstance(payload.get("data", {}), Mapping) else {}
    if not raw and isinstance(data.get("raw_preservation", {}), Mapping):
        raw = data.get("raw_preservation", {})
    return {
        "raw_subdomains": int(raw.get("raw_subdomains", 0) or 0),
        "exported_subdomains": int(raw.get("exported_subdomains", 0) or 0),
        "raw_emails": int(raw.get("raw_emails", 0) or 0),
        "exported_emails": int(raw.get("exported_emails", 0) or 0),
        "raw_ips": int(raw.get("raw_ips", 0) or 0),
        "exported_ips": int(raw.get("exported_ips", 0) or 0),
        "raw_archive_urls": int(raw.get("raw_archive_urls", 0) or 0),
        "exported_archive_urls": int(raw.get("exported_archive_urls", 0) or 0),
        "raw_dorks": int(raw.get("raw_dorks", 0) or 0),
        "exported_dorks": int(raw.get("exported_dorks", 0) or 0),
    }


def preservation_shortfalls(preservation: Mapping[str, int]) -> List[str]:
    checks = [
        ("subdomains", "raw_subdomains", "exported_subdomains"),
        ("emails", "raw_emails", "exported_emails"),
        ("ips", "raw_ips", "exported_ips"),
        ("archive_urls", "raw_archive_urls", "exported_archive_urls"),
        ("dorks", "raw_dorks", "exported_dorks"),
    ]
    failures: List[str] = []
    for label, raw_key, exported_key in checks:
        raw_count = int(preservation.get(raw_key, 0) or 0)
        exported_count = int(preservation.get(exported_key, 0) or 0)
        if raw_count > exported_count:
            failures.append(f"{label}: raw={raw_count} exported={exported_count}")
    return failures


def classify_result_blocker(
    metrics: Mapping[str, int],
    preservation: Mapping[str, int],
    provider_summary: Mapping[str, Any] | None = None,
) -> str:
    shortfalls = preservation_shortfalls(preservation)
    provider_summary = provider_summary if isinstance(provider_summary, Mapping) else {}
    if shortfalls:
        return "PIPELINE"
    failed = int(provider_summary.get("failed", 0) or 0)
    partial = int(provider_summary.get("partial", 0) or 0)
    success = int(provider_summary.get("success", 0) or 0)
    meaningful_counts = sum(int(metrics.get(key, 0) or 0) for key in ("subdomains", "emails", "ips", "archive_urls"))
    if meaningful_counts == 0 and (failed or partial or success == 0):
        return "ENVIRONMENT"
    if meaningful_counts == 0:
        return "BOTH"
    return "UNKNOWN"


def compare_metrics(
    domain: str,
    observed: Mapping[str, int],
    *,
    baseline_map: Mapping[str, Mapping[str, int]] = BENCHMARK_BASELINES,
    single_scan_reference: Mapping[str, int] | None = None,
) -> Dict[str, Any]:
    baseline = dict(baseline_map.get(domain, {}))
    failures: List[str] = []
    delta_parts: List[str] = []
    for key, baseline_value in baseline.items():
        observed_value = int(observed.get(key, 0) or 0)
        delta_parts.append(f"{key}:{observed_value - baseline_value:+d}")
        if observed_value < baseline_value:
            failures.append(f"{key} {observed_value} < {baseline_value}")
    if single_scan_reference:
        for key, single_value in single_scan_reference.items():
            if key not in baseline and observed.get(key, 0) + 0 < single_value:
                delta_parts.append(f"{key}_vs_single:{int(observed.get(key, 0)) - int(single_value):+d}")
    return {
        "domain": domain,
        "baseline": baseline,
        "observed": dict(observed),
        "delta": ", ".join(delta_parts),
        "status": "PASS" if not failures else "FAIL",
        "failures": failures,
    }


def registry_truth_rows(rows: Iterable[Mapping[str, Any]]) -> List[Dict[str, Any]]:
    output: List[Dict[str, Any]] = []
    for row in rows:
        output.append(
            {
                "source_name": str(row.get("name", "")),
                "category": str(row.get("category", "")),
                "executable": bool(row.get("runnable", False)),
                "keyed": bool(row.get("requires_keys", False)),
                "default_enabled": bool(row.get("default_enabled", False)),
                "runtime_verified": str(row.get("runtime_support", "metadata_only")) in {"direct", "indirect"},
                "runtime_support": str(row.get("runtime_support", "")),
                "status": str(row.get("status", "")),
            }
        )
    return output


def render_benchmark_markdown(
    title: str,
    rows: Iterable[Mapping[str, Any]],
    *,
    include_delta: bool = True,
) -> str:
    lines = [f"# {title}", "", "| Domain | Baseline | Observed | Delta | PASS/FAIL |", "|---|---|---|---|---|"]
    for row in rows:
        baseline = ", ".join(f"{k}={v}" for k, v in row.get("baseline", {}).items())
        observed = ", ".join(f"{k}={v}" for k, v in row.get("observed", {}).items() if k in METRIC_ORDER and v)
        delta = row.get("delta", "") if include_delta else ""
        lines.append(
            f"| `{row.get('domain','')}` | `{baseline}` | `{observed}` | `{delta}` | `{row.get('status','')}` |"
        )
    return "\n".join(lines) + "\n"


async def run_benchmark_batch(
    domains: Iterable[str],
    *,
    mode: str,
    results_root: Path,
    concurrent: bool,
) -> Dict[str, Any]:
    from recon import ReconEngine, build_canonical_report, configure_http_guard, HttpConfig, write_json, write_txt

    configure_http_guard(
        HttpConfig(
            timeout=25,
            retries=2,
            backoff_base=0.35,
            per_host_limit=10,
            rate_limit_per_sec=24,
        )
    )
    policy = ScanPolicy(passive_only=True, allow_active=False, allow_target_requests=False)
    source_registry = SourceRegistry(profile="balanced", api_keys={}, force_no_keys=True, allow_target_requests=False)
    batch_root = results_root / ("concurrent" if concurrent else "single")
    batch_root.mkdir(parents=True, exist_ok=True)

    async def _run_one(domain: str) -> Dict[str, Any]:
        scan_dir = batch_root / domain
        scan_dir.mkdir(parents=True, exist_ok=True)
        engine = ReconEngine(
            domain,
            mode,
            {},
            scan_dir,
            policy=policy,
            progress_cb=None,
            debug_coverage=False,
            source_registry=source_registry.clone(),
        )
        result = await engine.run()
        report_path = write_json(result, scan_dir)
        write_txt(result, scan_dir)
        payload = json.loads(report_path.read_text(encoding="utf-8"))
        metrics = extract_metrics(payload)
        preservation = extract_preservation(payload)
        return {
            "domain": domain,
            "metrics": metrics,
            "preservation": preservation,
            "scan_id": result.scan_id,
            "duration_seconds": result.duration_seconds,
            "report_json": str(report_path),
            "module_states": (result.scan_context or {}).get("module_states", {}),
            "canonical_summary": payload.get("summary", {}),
            "provider_summary": ((payload.get("runtime") or {}).get("providers", {}) if isinstance(payload.get("runtime"), Mapping) else {}),
            "source_metrics": payload.get("source_metrics", {}),
            "entity_graph_nodes": len(((payload.get("entity_graph") or {}).get("nodes") or [])),
        }

    if concurrent:
        finished = await asyncio.gather(*[_run_one(domain) for domain in domains])
    else:
        finished = []
        for domain in domains:
            finished.append(await _run_one(domain))

    stamp = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    return {
        "generated_at": stamp,
        "mode": mode,
        "concurrent": concurrent,
        "domains": list(domains),
        "results": finished,
    }


def save_json(path: Path, payload: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")


def save_markdown(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def current_timestamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%SZ")


def result_map(batch_payload: Mapping[str, Any]) -> Dict[str, Dict[str, int]]:
    mapping: Dict[str, Dict[str, int]] = {}
    for row in batch_payload.get("results", []):
        if not isinstance(row, Mapping):
            continue
        mapping[str(row.get("domain", ""))] = dict(row.get("metrics", {}))
    return mapping


def scan_result_row(
    domain: str,
    single_metrics: Mapping[str, int],
    concurrent_metrics: Mapping[str, int],
) -> Dict[str, Any]:
    baseline = BENCHMARK_BASELINES.get(domain, {})
    failures: List[str] = []
    for key, baseline_value in baseline.items():
        if int(single_metrics.get(key, 0) or 0) < baseline_value:
            failures.append(f"single:{key}")
        if int(concurrent_metrics.get(key, 0) or 0) < baseline_value:
            failures.append(f"concurrent:{key}")
    return {
        "domain": domain,
        "baseline": baseline,
        "single": dict(single_metrics),
        "concurrent": dict(concurrent_metrics),
        "delta": ", ".join(
            f"{key}:{int(concurrent_metrics.get(key, 0) or 0) - int(single_metrics.get(key, 0) or 0):+d}"
            for key in METRIC_ORDER
            if key in baseline or single_metrics.get(key) or concurrent_metrics.get(key)
        ),
        "status": "PASS" if not failures else "FAIL",
        "failures": failures,
    }


def render_release_gate_markdown(rows: Iterable[Mapping[str, Any]], verdict: str, blockers: Iterable[str]) -> str:
    lines = [
        "# Ghost Recon Release Gate",
        "",
        f"Verdict: **{verdict}**",
        "",
        "| Domain | Baseline | Single Scan | Concurrent Scan | Delta | PASS/FAIL |",
        "|---|---|---|---|---|---|",
    ]
    for row in rows:
        baseline = ", ".join(f"{k}={v}" for k, v in row.get("baseline", {}).items())
        single_scan = ", ".join(f"{k}={v}" for k, v in row.get("single", {}).items() if k in METRIC_ORDER and v)
        concurrent_scan = ", ".join(f"{k}={v}" for k, v in row.get("concurrent", {}).items() if k in METRIC_ORDER and v)
        lines.append(
            f"| `{row.get('domain','')}` | `{baseline}` | `{single_scan}` | `{concurrent_scan}` | `{row.get('delta','')}` | `{row.get('status','')}` |"
        )
    lines.extend(["", "## Remaining Blockers", ""])
    blocker_list = list(blockers)
    if blocker_list:
        for blocker in blocker_list:
            lines.append(f"- {blocker}")
    else:
        lines.append("- None")
    return "\n".join(lines) + "\n"


def render_registry_truth_markdown(rows: Iterable[Mapping[str, Any]]) -> str:
    lines = [
        "# Ghost Recon Registry Truth",
        "",
        "| source_name | category | executable | keyed | default_enabled | runtime_verified | runtime_support | status |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for row in rows:
        lines.append(
            f"| `{row.get('source_name','')}` | `{row.get('category','')}` | `{row.get('executable', False)}` | "
            f"`{row.get('keyed', False)}` | `{row.get('default_enabled', False)}` | "
            f"`{row.get('runtime_verified', False)}` | `{row.get('runtime_support','')}` | `{row.get('status','')}` |"
        )
    return "\n".join(lines) + "\n"


def render_provider_diagnostics_markdown(rows: Sequence[Mapping[str, Any]]) -> str:
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


def render_preservation_audit_markdown(
    title: str,
    rows: Sequence[Mapping[str, Any]],
) -> str:
    lines = [
        f"# {title}",
        "",
        "| Domain | raw/exported subdomains | raw/exported emails | raw/exported ips | raw/exported archive | raw/exported dorks | blocker | preservation shortfalls |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for row in rows:
        preservation = row.get("preservation", {}) if isinstance(row.get("preservation", {}), Mapping) else {}
        blocker = classify_result_blocker(
            row.get("metrics", {}) if isinstance(row.get("metrics", {}), Mapping) else {},
            preservation,
            row.get("provider_summary", {}) if isinstance(row.get("provider_summary", {}), Mapping) else {},
        )
        shortfalls = preservation_shortfalls(preservation)
        lines.append(
            f"| `{row.get('domain','')}` | "
            f"`{int(preservation.get('raw_subdomains', 0) or 0)}/{int(preservation.get('exported_subdomains', 0) or 0)}` | "
            f"`{int(preservation.get('raw_emails', 0) or 0)}/{int(preservation.get('exported_emails', 0) or 0)}` | "
            f"`{int(preservation.get('raw_ips', 0) or 0)}/{int(preservation.get('exported_ips', 0) or 0)}` | "
            f"`{int(preservation.get('raw_archive_urls', 0) or 0)}/{int(preservation.get('exported_archive_urls', 0) or 0)}` | "
            f"`{int(preservation.get('raw_dorks', 0) or 0)}/{int(preservation.get('exported_dorks', 0) or 0)}` | "
            f"`{blocker}` | `{'; '.join(shortfalls) if shortfalls else 'none'}` |"
        )
    return "\n".join(lines) + "\n"
