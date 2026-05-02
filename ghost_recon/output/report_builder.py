"""Canonical report builder for Ghost Recon outputs."""

from __future__ import annotations

from dataclasses import asdict, is_dataclass
from datetime import datetime, timezone
import ipaddress
from pathlib import Path
from urllib.parse import urlparse
from typing import Any, Dict, List, Optional

from ghost_recon.core.keystore import source_to_required_credentials
from ghost_recon.utils.text import normalize_text
from ghost_recon.sources.analysis import build_source_intelligence, source_quality_bucket, source_weight


REPORT_VERSION = "0.1"
SCHEMA_VERSION = "3.1"
FULL_STATIC_ARCHIVE_THRESHOLD = 10000
FULL_STATIC_ARCHIVE_RENDER_LIMIT = 5000
CANONICAL_FRESHNESS = {"current_passive", "recent_passive", "historical_only"}
CANONICAL_OWNERSHIP_SCOPES = {"first_party", "third_party", "mixed"}
CANONICAL_EVIDENCE_TYPES = {"direct_passive", "derived_passive", "archival_passive", "intelligence_mapping"}
LOW_VALUE_ARTIFACT_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".css", ".woff", ".woff2",
}
LOW_VALUE_ARTIFACT_PREFIXES = ("/static/", "/assets/", "/images/", "/fonts/")
HIGH_VALUE_FILE_EXTENSIONS = {
    ".env", ".bak", ".old", ".backup", ".sql", ".db", ".dump", ".log",
    ".zip", ".tar", ".gz", ".tgz", ".json", ".yaml", ".yml", ".ini", ".cfg",
    ".conf", ".xml", ".txt", ".csv", ".doc", ".docx", ".xls", ".xlsx", ".pdf",
    ".map",
}
HIGH_VALUE_FILE_NAMES = {
    ".env", "config.json", "config.yaml", "config.yml", "settings.json",
    "docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml",
    "openapi.json", "swagger.json", "package.json", "package-lock.json",
    "composer.json", "pom.xml", "build.gradle", "requirements.txt",
    "webpack.config.js", "vite.config.js", "next.config.js", "nuxt.config.js",
    "angular.json", "asset-manifest.json", "manifest.json", "security.txt",
}
ARTIFACT_SIGNAL_TOKENS = (
    "/api", "/graphql", "/gql", "/admin", "/auth", "/oauth", "/login", "/sso",
    "/console", "/manager", "/portal", "/internal", "/debug", "/metrics",
    "/health", "/actuator", "/swagger", "/openapi", "/webhook", "/gateway",
    "config", "settings", "backup", "dump", "secret", "token", "password", "credential",
    "security.txt", "package.json", "composer.json", "requirements.txt",
    "pom.xml", "build.gradle", "docker-compose", "compose.yaml", "compose.yml",
    ".env", ".bak", ".old", ".sql", ".db", ".dump", ".log", ".zip", ".tar",
    ".gz", ".map",
)
INTERNAL_REFERENCE_TOKENS = ("internal", "intra", "corp", "private", "vpn", "partner", "legacy")
SUMMARY_KEYS = (
    "subdomains",
    "emails",
    "vulns",
    "ips",
    "ports",
    "cloud_assets",
    "exposures",
    "takeovers",
    "technologies",
    "breaches",
    "archive_urls",
    "certs",
    "dorks",
)


SECTION_FIELD_MAP = {
    "identity": ["domain", "scan_id", "scan_date", "mode", "whois_data", "dns_records"],
    "subdomains": ["subdomains"],
    "emails": ["emails", "email_pattern"],
    "infrastructure": ["ip_records", "asn_intelligence", "infrastructure_observations"],
    "certificates": ["ssl_info"],
    "history": ["wayback_urls"],
    "cloud": ["cloud_assets"],
    "reputation": ["reputation_data", "breach_records"],
    "vulnerabilities": ["vulnerabilities", "takeover_records", "security_headers"],
    "correlation": ["correlations", "scores"],
    "bug_bounty": ["interesting_endpoints", "potential_secrets", "developer_references", "high_value_targets", "asset_clusters"],
}


SECTION_MODULE_MAP = {
    "identity": "DNS Intelligence",
    "subdomains": "Subdomain Enumeration",
    "emails": "Email Discovery",
    "infrastructure": "IP Intelligence",
    "certificates": "SSL Intelligence",
    "history": "Web Archive",
    "cloud": "Cloud Assets",
    "reputation": "Reputation Intel",
    "vulnerabilities": "Vulnerability Intelligence",
    "correlation": "Correlations",
    "bug_bounty": "Passive Artifact Intelligence",
}

RENDERED_FIELDS = {
    "domain",
    "scan_id",
    "scan_date",
    "mode",
    "subdomains",
    "emails",
    "technologies",
    "dns_records",
    "ip_records",
    "ssl_info",
    "breach_records",
    "takeover_records",
    "cloud_assets",
    "wayback_urls",
    "whois_data",
    "reputation_data",
    "scores",
    "typosquats",
    "dorks",
    "security_headers",
    "social_footprint",
    "asn_intelligence",
    "vulnerabilities",
    "correlations",
    "interesting_endpoints",
    "potential_secrets",
    "developer_references",
    "high_value_targets",
    "asset_clusters",
    "infrastructure_observations",
    "email_pattern",
    "source_metrics",
    "duration_seconds",
    "scan_context",
}


def _to_dict(result: Any) -> Dict[str, Any]:
    if isinstance(result, dict):
        return dict(result)
    if is_dataclass(result):
        return asdict(result)
    return dict(result.__dict__) if hasattr(result, "__dict__") else {}


def _empty(v: Any) -> bool:
    return v is None or v == "" or v == [] or v == {}


def _safe_len(v: Any) -> int:
    if isinstance(v, (list, dict, set, tuple)):
        return len(v)
    return 0 if _empty(v) else 1


def _safe_int(v: Any, default: int = 0) -> int:
    try:
        return int(v)
    except (TypeError, ValueError):
        return default


def _component_scores(scores: Any) -> Dict[str, float]:
    raw = scores if isinstance(scores, dict) else {}
    allowed = ("attack_surface", "technology_risk", "exposure", "vulnerability")
    normalized: Dict[str, float] = {}
    for key in allowed:
        value = raw.get(key, 0)
        try:
            normalized[key] = round(max(0.0, min(float(value or 0), 100.0)), 1)
        except (TypeError, ValueError):
            normalized[key] = 0.0
    # Compute overall weighted score and risk_level
    overall = round(
        normalized.get("attack_surface", 0) * 0.30
        + normalized.get("exposure", 0) * 0.30
        + normalized.get("vulnerability", 0) * 0.25
        + normalized.get("technology_risk", 0) * 0.15,
        1,
    )
    normalized["overall"] = overall
    normalized["risk_level"] = (
        "critical" if overall >= 75
        else "high" if overall >= 50
        else "medium" if overall >= 25
        else "low"
    )
    return normalized


def _severity_rank(severity: Any) -> int:
    order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
    return order.get(str(severity or "INFO").upper(), 0)


def _severity_name(rank: int) -> str:
    mapping = {4: "CRITICAL", 3: "HIGH", 2: "MEDIUM", 1: "LOW", 0: "INFO"}
    return mapping.get(max(0, min(int(rank), 4)), "INFO")


def _reduce_severity(severity: Any, steps: int = 1) -> str:
    return _severity_name(_severity_rank(severity) - max(0, int(steps)))


def _finding_classification(record: Dict[str, Any], default: str = "probable") -> str:
    value = str(record.get("classification", default) or default).strip().lower()
    if value == "potential_secret":
        return "probable_secret_exposure"
    if value in {
        "confirmed", "evidenced", "probable", "heuristic", "hint", "passive",
        "weak_artifact", "suspicious_secret_reference", "probable_secret_exposure", "strong_passive_exposure",
    }:
        return "hint" if value == "heuristic" and default == "hint" else value
    return default


def _recency_bucket(record: Dict[str, Any]) -> str:
    explicit = str(record.get("observation_recency", "") or "").strip().lower()
    if explicit == "archival_passive":
        return "historical_only"
    if explicit in CANONICAL_FRESHNESS:
        return explicit
    if bool(record.get("historical_only", False)):
        return "historical_only"
    if bool(record.get("current_passive", False)):
        return "current_passive"
    return "recent_passive" if record.get("last_seen") else "historical_only"


def _is_first_party(record: Dict[str, Any]) -> bool:
    if "first_party" in record:
        return bool(record.get("first_party"))
    return not bool(record.get("third_party_context", False))


def _ownership_scope(record: Dict[str, Any]) -> str:
    explicit = str(record.get("ownership_scope", "") or "").strip().lower()
    if explicit in CANONICAL_OWNERSHIP_SCOPES:
        return explicit
    if bool(record.get("third_party_context", False)) and _is_first_party(record):
        return "mixed"
    return "first_party" if _is_first_party(record) else "third_party"


def _evidence_type(record: Dict[str, Any], kind: str) -> str:
    explicit = str(record.get("evidence_type", "") or "").strip().lower()
    if explicit in CANONICAL_EVIDENCE_TYPES:
        return explicit
    source = str(record.get("source", "") or "").lower()
    recency = _recency_bucket(record)
    if source in {"tech_cve_mapping"}:
        return "intelligence_mapping"
    if source in {"port_analysis", "shodan_internetdb"}:
        return "derived_passive"
    if recency == "historical_only":
        return "archival_passive"
    if kind == "correlation":
        return "derived_passive"
    return "direct_passive"


def _finding_family(record: Dict[str, Any], kind: str) -> str:
    source = str(record.get("source", "") or "").lower()
    if kind == "vulnerability":
        if source in {"tech_cve_mapping"}:
            return "intelligence_lead"
        if source in {"port_analysis", "shodan_internetdb"}:
            return "exposure"
        return "vulnerability"
    return kind


def _evidence_tier(record: Dict[str, Any], kind: str) -> str:
    classification = _finding_classification(record, "evidenced" if kind == "vulnerability" else "probable")
    evidence_type = _evidence_type(record, kind)
    scope = _ownership_scope(record)
    if classification in {"evidenced", "confirmed"} and evidence_type == "direct_passive" and scope == "first_party":
        return "confirmed_passive_evidence"
    if evidence_type == "intelligence_mapping":
        return "intelligence_lead"
    if evidence_type == "derived_passive":
        return "derived_exposure"
    if classification in {"probable", "probable_secret_exposure", "strong_passive_exposure"}:
        return "supported_passive_inference"
    return "historical_or_weak_signal"


def _apply_canonical_finding_semantics(record: Dict[str, Any], kind: str) -> Dict[str, Any]:
    recency = _recency_bucket(record)
    scope = _ownership_scope(record)
    family = _finding_family(record, kind)
    evidence_type = _evidence_type(record, kind)
    record["observation_recency"] = recency
    record["historical_only"] = recency == "historical_only"
    record["current_passive"] = recency == "current_passive"
    record["first_party"] = _is_first_party(record)
    record["third_party_context"] = bool(record.get("third_party_context", False))
    record["ownership_scope"] = scope
    record["finding_family"] = family
    record["evidence_type"] = evidence_type
    record["evidence_tier"] = _evidence_tier(record, kind)
    return record


def _priority_multiplier(record: Dict[str, Any]) -> float:
    mult = 1.0
    classification = _finding_classification(record, "probable")
    recency = _recency_bucket(record)
    evidence_type = _evidence_type(record, "finding")
    scope = _ownership_scope(record)
    if classification in {"weak_artifact", "hint"}:
        mult *= 0.3
    elif classification in {"heuristic", "passive", "suspicious_secret_reference"}:
        mult *= 0.48
    elif classification in {"probable", "probable_secret_exposure"}:
        mult *= 0.72
    elif classification == "strong_passive_exposure":
        mult *= 0.88
    if recency == "historical_only":
        mult *= 0.38
    elif recency == "recent_passive":
        mult *= 0.72
    if evidence_type == "intelligence_mapping":
        mult *= 0.42
    elif evidence_type == "derived_passive":
        mult *= 0.7
    elif evidence_type == "archival_passive":
        mult *= 0.52
    if bool(record.get("third_party_context", False)):
        mult *= 0.24
    if not _is_first_party(record):
        mult *= 0.55
    if scope == "mixed":
        mult *= 0.72
    return max(0.08, min(mult, 1.0))


def _asset_text(record: Dict[str, Any]) -> str:
    return normalize_text(
        str(
            record.get("asset")
            or record.get("affected_asset")
            or record.get("location")
            or record.get("url")
            or ""
        )
    ).lower()


def _strong_hvt(record: Dict[str, Any]) -> bool:
    reasons = {str(reason or "").strip().lower() for reason in (record.get("reasons", []) or [])}
    return bool(reasons.intersection({"interesting_endpoints", "potential_secret_reference", "developer_reference", "takeover_signal", "multi_signal_convergence"}))


def _weak_hvt(record: Dict[str, Any]) -> bool:
    reasons = {str(reason or "").strip().lower() for reason in (record.get("reasons", []) or [])}
    return bool(reasons) and reasons.issubset({"sensitive_subdomain_tag", "host_keyword_signal", "infra_signal", "resolves_publicly", "cloud_mapping"})


def _generic_metadata_asset(asset_text: str) -> bool:
    return any(
        marker in asset_text
        for marker in (
            "/.well-known/assetlinks.json",
            "/.well-known/apple-app-site-association",
            "/.well-known/ai-plugin.json",
            "/.well-known/gpc.json",
            "/.well-known/dnt-policy.txt",
            "/.well-known/trust.txt",
        )
    )


def _normalized_story_family(asset_text: str) -> str:
    raw = normalize_text(asset_text).lower().strip()
    if not raw:
        return ""
    host = ""
    if raw.startswith("http://") or raw.startswith("https://"):
        parsed = urlparse(raw)
        host = (parsed.hostname or "").lower()
    else:
        host = raw.split("/", 1)[0]
    labels = [label for label in host.split(".") if label]
    if len(labels) <= 3:
        return host
    noise = {
        "as", "eu", "na", "oc", "sw", "uk", "us", "emea", "apac", "latam",
        "prod", "prd", "dev", "test", "stage", "staging", "ppe", "int", "internal",
        "eastus", "eastus2", "westus", "westus2", "centralus", "westeurope", "northeurope",
    }
    trimmed = list(labels)
    while len(trimmed) > 3 and (
        trimmed[0] in noise
        or (len(trimmed[0]) <= 3 and trimmed[0].isalpha())
    ):
        trimmed = trimmed[1:]
    return ".".join(trimmed)


def _passive_effective_severity(record: Dict[str, Any], kind: str) -> str:
    severity = str(record.get("severity", "INFO") or "INFO").upper()
    source = str(record.get("source", "") or "")
    classification = _finding_classification(record, "evidenced" if kind == "vulnerability" else "probable")
    evidence_strength = str(record.get("evidence_strength", "") or "").lower()
    confidence = float(record.get("confidence", 0.0) or 0.0)

    if classification in {"heuristic", "hint"}:
        return _reduce_severity(severity, 2)
    if classification == "probable":
        severity = _reduce_severity(severity, 1)

    if kind == "vulnerability" and source in {"port_analysis", "shodan_internetdb", "tech_cve_mapping"}:
        severity = _reduce_severity(severity, 1)
    if kind == "vulnerability" and _finding_family(record, kind) in {"exposure", "intelligence_lead"}:
        severity = _reduce_severity(severity, 1)
    if source == "ssl_analysis" and (_recency_bucket(record) == "historical_only" or bool(record.get("third_party_context", False))):
        severity = _reduce_severity(severity, 2)
    if kind == "correlation":
        if classification != "evidenced":
            severity = _reduce_severity(severity, 1)
        if evidence_strength == "weak":
            severity = _reduce_severity(severity, 1)
    if confidence and confidence < 0.55:
        severity = _reduce_severity(severity, 1)
    priority_mult = _priority_multiplier(record)
    if priority_mult < 0.5:
        severity = _reduce_severity(severity, 1)
    if priority_mult < 0.3:
        severity = _reduce_severity(severity, 1)

    return severity


def _normalize_ip(value: Any) -> str:
    raw = str(value or "").strip().rstrip(".")
    if not raw:
        return ""
    try:
        return str(ipaddress.ip_address(raw))
    except Exception:
        return ""


def _backfill_ip_records_from_subdomains(data: Dict[str, Any]) -> int:
    existing = {}
    for rec in (data.get("ip_records", []) or []):
        if not isinstance(rec, dict):
            continue
        ip = _normalize_ip(rec.get("ip", ""))
        if ip:
            rec["ip"] = ip
            existing[ip] = rec
    added = 0
    for sub in (data.get("subdomains", []) or []):
        if not isinstance(sub, dict):
            continue
        sub_ports = sorted({
            int(port)
            for port in (sub.get("ports") or sub.get("open_ports") or [])
            if isinstance(port, int) or str(port).isdigit()
        })
        for raw in ((sub.get("ips", []) or []) + (sub.get("resolved_ips", []) or [])):
            ip = _normalize_ip(raw)
            if not ip:
                continue
            if ip not in existing:
                existing[ip] = {
                    "ip": ip,
                    "asn": "",
                    "org": "",
                    "country": "",
                    "city": "",
                    "rdns": "",
                    "cloud_provider": "",
                    "cdn": False,
                    "open_ports": list(sub_ports),
                    "ports": list(sub_ports),
                    "vulns": [],
                    "cpes": [],
                    "tags": ["subdomain_resolution_backfill"] if sub_ports else [],
                    "source": "subdomain_resolution_backfill",
                    "classification": "derived",
                }
                added += 1
                continue
            if sub_ports:
                merged_ports = sorted({
                    int(port)
                    for port in (existing[ip].get("open_ports") or existing[ip].get("ports") or []) + sub_ports
                    if isinstance(port, int) or str(port).isdigit()
                })
                existing[ip]["open_ports"] = merged_ports
                existing[ip]["ports"] = merged_ports
                existing[ip]["tags"] = list(dict.fromkeys((existing[ip].get("tags") or []) + ["subdomain_port_hint"]))
    data["ip_records"] = list(existing.values())
    return added


def _archive_urls_count(data: Dict[str, Any]) -> int:
    explicit_archive_urls = data.get("archive_urls", [])
    if isinstance(explicit_archive_urls, list) and explicit_archive_urls:
        return len(explicit_archive_urls)
    wayback = data.get("wayback_urls", {}) or {}
    if not isinstance(wayback, dict):
        return _safe_len(wayback)
    explicit_total = _safe_int(wayback.get("total_urls", 0), 0)
    if explicit_total > 0:
        return explicit_total
    total = 0
    for key in ("interesting", "urls", "all", "all_urls"):
        total += _safe_len(wayback.get(key, []))
    return total


def _raw_preservation_summary(data: Dict[str, Any], summary: Dict[str, int]) -> Dict[str, int]:
    source_metrics = data.get("source_metrics", {}) if isinstance(data.get("source_metrics", {}), dict) else {}
    sub_metrics = source_metrics.get("subdomains", {}) if isinstance(source_metrics.get("subdomains", {}), dict) else {}
    email_metrics = source_metrics.get("emails", {}) if isinstance(source_metrics.get("emails", {}), dict) else {}
    raw_subdomains = sum(_safe_int((row or {}).get("items_obtenidos", (row or {}).get("items_parseados", 0)), 0) for row in sub_metrics.values() if isinstance(row, dict))
    raw_emails = sum(_safe_int((row or {}).get("items_obtenidos", (row or {}).get("items_parseados", 0)), 0) for row in email_metrics.values() if isinstance(row, dict))
    raw_ips = max(
        _safe_len(data.get("ip_records", [])),
        len({
            str(ip).strip()
            for row in (data.get("subdomains", []) or [])
            if isinstance(row, dict)
            for ip in (row.get("ips") or row.get("resolved_ips") or [])
            if str(ip or "").strip()
        }),
    )
    wayback = data.get("wayback_urls", {}) if isinstance(data.get("wayback_urls", {}), dict) else {}
    raw_archive_urls = max(
        _archive_urls_count(data),
        _safe_int((wayback or {}).get("total_urls", 0), 0),
    )
    raw_dorks = max(_safe_len(data.get("dorks", [])), 0)
    raw_vulns = _safe_len(data.get("vulnerabilities", []))
    raw_certs = _safe_len(data.get("ssl_info", []))
    return {
        "raw_subdomains": max(raw_subdomains, summary.get("subdomains", 0)),
        "exported_subdomains": summary.get("subdomains", 0),
        "raw_emails": max(raw_emails, summary.get("emails", 0)),
        "exported_emails": summary.get("emails", 0),
        "raw_ips": max(raw_ips, summary.get("ips", 0)),
        "exported_ips": summary.get("ips", 0),
        "raw_archive_urls": max(raw_archive_urls, summary.get("archive_urls", 0)),
        "exported_archive_urls": summary.get("archive_urls", 0),
        "raw_dorks": max(raw_dorks, summary.get("dorks", 0)),
        "exported_dorks": summary.get("dorks", 0),
        "raw_certs": max(raw_certs, summary.get("certs", 0)),
        "exported_certs": summary.get("certs", 0),
        "raw_vulns": max(raw_vulns, summary.get("vulns", 0)),
        "exported_vulns": summary.get("vulns", 0),
    }


def _archive_url_value(item: Any) -> str:
    if isinstance(item, dict):
        return normalize_text(str(item.get("url", "") or "")).strip()
    if hasattr(item, "url"):
        return normalize_text(str(getattr(item, "url", "") or "")).strip()
    return normalize_text(str(item or "")).strip()


def _archive_url_record(item: Any) -> Dict[str, Any]:
    if isinstance(item, dict):
        return {
            "url": _archive_url_value(item),
            "timestamp": normalize_text(str(item.get("timestamp", "") or "")),
            "status_code": item.get("status_code", 0),
            "mime_type": normalize_text(str(item.get("mime_type", "") or "")),
        }
    if hasattr(item, "url"):
        return {
            "url": _archive_url_value(item),
            "timestamp": normalize_text(str(getattr(item, "timestamp", "") or "")),
            "status_code": getattr(item, "status_code", 0),
            "mime_type": normalize_text(str(getattr(item, "mime_type", "") or "")),
        }
    return {
        "url": _archive_url_value(item),
        "timestamp": "",
        "status_code": 0,
        "mime_type": "",
    }


def _archive_url_in_scope(url: str, domain: str) -> bool:
    if not url:
        return False
    if not domain:
        return True
    try:
        host = str(urlparse(url).hostname or "").strip().lower()
    except Exception:
        return False
    target = str(domain or "").strip().lower()
    return bool(host) and (host == target or host.endswith(f".{target}"))


def _normalize_archive_bucket(items: Any, domain: str) -> List[Dict[str, Any]]:
    normalized: List[Dict[str, Any]] = []
    seen: set[str] = set()
    for item in list(items or []):
        row = _archive_url_record(item)
        url = row.get("url", "")
        if not url or not _archive_url_in_scope(url, domain):
            continue
        if url in seen:
            continue
        seen.add(url)
        normalized.append(row)
    return normalized


def _normalize_archive_query_params(items: Any) -> List[Dict[str, Any]]:
    normalized: List[Dict[str, Any]] = []
    seen: set[str] = set()
    for item in list(items or []):
        if isinstance(item, dict):
            name = normalize_text(str(item.get("name", "") or "")).strip().lower()
            count = _safe_int(item.get("count", 0), 0)
            suspicious = bool(item.get("suspicious", False))
        else:
            name = normalize_text(str(item or "")).strip().lower()
            count = 1
            suspicious = False
        if not name or name in seen:
            continue
        seen.add(name)
        normalized.append({
            "name": name,
            "count": max(1, count),
            "suspicious": suspicious,
        })
    normalized.sort(key=lambda row: (0 if row.get("suspicious") else 1, -int(row.get("count", 0) or 0), str(row.get("name", ""))))
    return normalized[:40]


def _artifact_url_parts(raw_url: Any, *, host_hint: str = "", path_hint: str = "") -> Dict[str, str]:
    url = normalize_text(str(raw_url or "")).strip()
    host = normalize_text(str(host_hint or "")).strip().lower()
    path = normalize_text(str(path_hint or "")).strip()
    if url.startswith("http"):
        try:
            parsed = urlparse(url)
            host = normalize_text(str(parsed.hostname or host)).strip().lower()
            path = normalize_text(str(parsed.path or path or "/")).strip() or "/"
        except Exception:
            pass
    elif url and url.startswith("/"):
        path = url
    elif url and not path and "/" in url:
        path = url
    if not path:
        path = "/"
    normalized_host = normalize_text(host).strip().lower()
    lowered = f"{normalized_host}{path}".lower()
    clean_path = path.split("?", 1)[0] or "/"
    filename = Path(clean_path).name.lower()
    ext = Path(filename).suffix.lower()
    return {
        "url": url,
        "host": normalized_host,
        "path": clean_path,
        "filename": filename,
        "ext": ext,
        "lowered": lowered,
    }


def _artifact_has_strong_signal(parts: Dict[str, str]) -> bool:
    lowered = str(parts.get("lowered", "") or "")
    return any(token in lowered for token in ARTIFACT_SIGNAL_TOKENS)


def _artifact_is_low_value_noise(parts: Dict[str, str]) -> bool:
    ext = str(parts.get("ext", "") or "")
    path = str(parts.get("path", "") or "")
    lowered = str(parts.get("lowered", "") or "")
    if ext in LOW_VALUE_ARTIFACT_EXTENSIONS:
        return not _artifact_has_strong_signal(parts)
    if any(path.startswith(prefix) for prefix in LOW_VALUE_ARTIFACT_PREFIXES):
        return not _artifact_has_strong_signal(parts)
    if not path or path in {"/", "/index.html", "/favicon.ico"}:
        return True
    if any(token in lowered for token in ("javascript:void", "{", "}", "<", ">")):
        return True
    return False


def _artifact_is_internal_reference(parts: Dict[str, str]) -> bool:
    lowered = str(parts.get("lowered", "") or "")
    return any(token in lowered for token in INTERNAL_REFERENCE_TOKENS) or any(
        marker in lowered for marker in ("/internal", "/debug", "/metrics", "/health", "/actuator")
    )


def _artifact_file_weight(parts: Dict[str, str]) -> int:
    filename = str(parts.get("filename", "") or "")
    ext = str(parts.get("ext", "") or "")
    lowered = str(parts.get("lowered", "") or "")
    score = 0
    if ext in HIGH_VALUE_FILE_EXTENSIONS or filename in HIGH_VALUE_FILE_NAMES:
        score += 24
    if ext in {".env", ".bak", ".old", ".backup", ".sql", ".db", ".dump", ".log"}:
        score += 20
    elif ext in {".zip", ".tar", ".gz", ".tgz"}:
        score += 16
    elif ext in {".json", ".yaml", ".yml", ".ini", ".cfg", ".conf", ".xml"}:
        score += 12
    elif ext in {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".csv", ".txt"}:
        score += 8
    if any(token in lowered for token in ("config", "backup", "dump", "secret", "credential", "token", "password")):
        score += 10
    return score


def _artifact_endpoint_weight(parts: Dict[str, str], category: str = "", reasons: Any = None) -> int:
    lowered = str(parts.get("lowered", "") or "")
    score = 0
    category_l = normalize_text(str(category or "")).strip().lower()
    if category_l in {"admin", "auth", "graphql"}:
        score += 26
    elif category_l in {"api", "internal"}:
        score += 22
    elif category_l in {"metadata"}:
        score += 10
    else:
        score += 12
    if any(token in lowered for token in ("/admin", "/auth", "/oauth", "/login", "/graphql", "/api", "/swagger", "/openapi", "/webhook")):
        score += 12
    if any(token in lowered for token in ("/export", "/import", "/download", "/upload", "/console", "/manager", "/portal")):
        score += 8
    if isinstance(reasons, list):
        score += min(12, len([reason for reason in reasons if str(reason or "").strip()]) * 2)
    return score


def _artifact_label(parts: Dict[str, str], fallback: str = "") -> str:
    filename = str(parts.get("filename", "") or "")
    path = str(parts.get("path", "") or "")
    if filename:
        return normalize_text(filename)
    if path and path != "/":
        return normalize_text(path)
    return normalize_text(fallback or str(parts.get("host", "") or "artifact"))


def _artifact_record(
    artifact_type: str,
    *,
    url: str = "",
    host: str = "",
    path: str = "",
    subtype: str = "",
    label: str = "",
    source: str = "",
    evidence: str = "",
    classification: str = "",
    confidence: Any = 0.0,
    historical_only: bool = False,
    current_passive: bool = False,
    first_party: bool = True,
    observation_recency: str = "",
    reasons: Any = None,
    priority_score: int = 0,
    timestamp: str = "",
    status_code: Any = "",
    mime_type: str = "",
) -> Dict[str, Any]:
    parts = _artifact_url_parts(url, host_hint=host, path_hint=path)
    recency = normalize_text(str(observation_recency or "")).strip().lower()
    if not recency:
        recency = "current_passive" if current_passive and not historical_only else "historical_only" if historical_only else "recent_passive"
    return {
        "type": normalize_text(artifact_type),
        "subtype": normalize_text(subtype or artifact_type),
        "label": normalize_text(label or _artifact_label(parts, subtype or artifact_type)),
        "asset": normalize_text(url or parts.get("path") or parts.get("host") or ""),
        "url": normalize_text(url or ""),
        "host": normalize_text(parts.get("host", "")),
        "path": normalize_text(parts.get("path", "")),
        "source": normalize_text(source or ""),
        "classification": normalize_text(classification or ""),
        "confidence": round(max(0.0, min(float(confidence or 0.0), 0.99)), 3) if confidence not in ("", None) else 0.0,
        "historical_only": bool(historical_only),
        "current_passive": bool(current_passive),
        "first_party": bool(first_party),
        "third_party_context": not bool(first_party),
        "observation_recency": recency,
        "evidence": normalize_text(str(evidence or "")[:220]),
        "reasons": [normalize_text(str(reason)) for reason in (reasons or []) if str(reason or "").strip()][:6],
        "priority_score": int(priority_score or 0),
        "timestamp": normalize_text(str(timestamp or "")),
        "status_code": _safe_int(status_code, 0) if status_code not in ("", None) else 0,
        "mime_type": normalize_text(str(mime_type or "")),
    }


def _artifact_sort_key(row: Dict[str, Any]) -> tuple:
    recency = str(row.get("observation_recency", "") or "")
    recency_rank = {"current_passive": 0, "recent_passive": 1, "historical_only": 2}.get(recency, 3)
    return (
        -int(row.get("priority_score", 0) or 0),
        recency_rank,
        -float(row.get("confidence", 0.0) or 0.0),
        str(row.get("asset", "") or ""),
    )


def _artifact_inventory(data: Dict[str, Any], archive_export: Dict[str, Any]) -> Dict[str, Any]:
    groups: Dict[str, Dict[str, Dict[str, Any]]] = {
        "high_value_files": {},
        "archived_files": {},
        "internal_references": {},
        "interesting_endpoints": {},
        "artifact_hints": {},
    }
    suppressed = {
        "count": 0,
        "static_assets": 0,
        "generic_archive_urls": 0,
        "duplicates": 0,
    }
    priority_order = {
        "high_value_files": 0,
        "archived_files": 1,
        "internal_references": 2,
        "interesting_endpoints": 3,
        "artifact_hints": 4,
    }
    assigned: Dict[str, tuple[str, int]] = {}

    def suppress(reason: str) -> None:
        suppressed["count"] += 1
        suppressed[reason] = suppressed.get(reason, 0) + 1

    def push(group: str, row: Dict[str, Any], *, key: str = "") -> None:
        if not isinstance(row, dict):
            return
        asset_key = normalize_text(str(key or row.get("url") or row.get("asset") or row.get("host") or row.get("label") or "")).strip().lower()
        if not asset_key:
            return
        current = assigned.get(asset_key)
        if current is not None and priority_order[group] > priority_order[current[0]]:
            suppress("duplicates")
            return
        if current is not None and priority_order[group] == priority_order[current[0]]:
            existing = groups[group].get(asset_key)
            if existing and _artifact_sort_key(existing) <= _artifact_sort_key(row):
                groups[group][asset_key] = row
            else:
                suppress("duplicates")
            return
        if current is not None and current[0] in groups:
            groups[current[0]].pop(asset_key, None)
        assigned[asset_key] = (group, int(row.get("priority_score", 0) or 0))
        groups[group][asset_key] = row

    for endpoint in data.get("interesting_endpoints", []) or []:
        if not isinstance(endpoint, dict):
            continue
        raw_url = str(endpoint.get("url", "") or "")
        parts = _artifact_url_parts(raw_url, host_hint=str(endpoint.get("host", "") or ""), path_hint=str(endpoint.get("path", "") or ""))
        if _artifact_is_low_value_noise(parts):
            suppress("static_assets")
            continue
        reasons = endpoint.get("reasons", []) if isinstance(endpoint.get("reasons", []), list) else []
        weight = _artifact_endpoint_weight(parts, str(endpoint.get("category", "") or ""), reasons)
        file_weight = _artifact_file_weight(parts)
        if _artifact_is_internal_reference(parts):
            push("internal_references", _artifact_record(
                "internal_reference",
                url=raw_url,
                host=str(endpoint.get("host", "") or ""),
                path=str(endpoint.get("path", "") or ""),
                subtype=str(endpoint.get("category", "internal") or "internal"),
                label=_artifact_label(parts, "internal_reference"),
                source=str(endpoint.get("source", "passive_artifact_intelligence") or "passive_artifact_intelligence"),
                evidence=str(endpoint.get("evidence", "")),
                classification=str(endpoint.get("classification", "passive") or "passive"),
                confidence=endpoint.get("confidence", 0.0),
                historical_only=bool(endpoint.get("historical_only", False)),
                current_passive=bool(endpoint.get("current_passive", False)),
                first_party=bool(endpoint.get("first_party", True)),
                observation_recency=str(endpoint.get("observation_recency", "")),
                reasons=reasons,
                priority_score=weight + 8,
            ))
            continue
        if file_weight >= 18:
            target_group = "archived_files" if bool(endpoint.get("historical_only", False)) else "high_value_files"
            target_type = "archived_file" if target_group == "archived_files" else "confirmed_file"
            push(target_group, _artifact_record(
                target_type,
                url=raw_url,
                host=str(endpoint.get("host", "") or ""),
                path=str(endpoint.get("path", "") or ""),
                subtype=str(endpoint.get("category", "file") or "file"),
                label=_artifact_label(parts, "high_value_file"),
                source=str(endpoint.get("source", "passive_artifact_intelligence") or "passive_artifact_intelligence"),
                evidence=str(endpoint.get("evidence", "")),
                classification=str(endpoint.get("classification", "passive") or "passive"),
                confidence=endpoint.get("confidence", 0.0),
                historical_only=bool(endpoint.get("historical_only", False)),
                current_passive=bool(endpoint.get("current_passive", False)),
                first_party=bool(endpoint.get("first_party", True)),
                observation_recency=str(endpoint.get("observation_recency", "")),
                reasons=reasons,
                priority_score=file_weight + weight + 12,
            ))
            continue
        push("interesting_endpoints", _artifact_record(
            "endpoint",
            url=raw_url,
            host=str(endpoint.get("host", "") or ""),
            path=str(endpoint.get("path", "") or ""),
            subtype=str(endpoint.get("category", "endpoint") or "endpoint"),
            label=_artifact_label(parts, str(endpoint.get("category", "endpoint") or "endpoint")),
            source=str(endpoint.get("source", "passive_artifact_intelligence") or "passive_artifact_intelligence"),
            evidence=str(endpoint.get("evidence", "")),
            classification=str(endpoint.get("classification", "passive") or "passive"),
            confidence=endpoint.get("confidence", 0.0),
            historical_only=bool(endpoint.get("historical_only", False)),
            current_passive=bool(endpoint.get("current_passive", False)),
            first_party=bool(endpoint.get("first_party", True)),
            observation_recency=str(endpoint.get("observation_recency", "")),
            reasons=reasons,
            priority_score=weight + int(endpoint.get("priority_score", 0) or 0),
        ))

    for secret in data.get("potential_secrets", []) or []:
        if not isinstance(secret, dict):
            continue
        raw_url = str(secret.get("location", "") or "")
        parts = _artifact_url_parts(raw_url)
        if _artifact_is_low_value_noise(parts):
            suppress("static_assets")
            continue
        file_weight = _artifact_file_weight(parts)
        classification = str(secret.get("classification", "") or "")
        historical_only = bool(secret.get("historical_only", False))
        confidence = float(secret.get("confidence", 0.0) or 0.0)
        if file_weight >= 18 and classification in {"probable_secret_exposure", "strong_passive_exposure", "suspicious_secret_reference"}:
            target_group = "archived_files" if historical_only else "high_value_files"
            target_type = "archived_file" if historical_only else "confirmed_file"
            push(target_group, _artifact_record(
                target_type,
                url=raw_url,
                subtype=str(secret.get("secret_type", "secret") or "secret"),
                label=_artifact_label(parts, str(secret.get("secret_type", "secret") or "secret")),
                source=str(secret.get("source", "passive_artifact_intelligence") or "passive_artifact_intelligence"),
                evidence=str(secret.get("evidence", "")),
                classification=classification,
                confidence=confidence,
                historical_only=historical_only,
                current_passive=bool(secret.get("current_passive", False)),
                first_party=bool(secret.get("first_party", True)),
                observation_recency=str(secret.get("observation_recency", "")),
                reasons=[str(secret.get("match_preview", ""))] if str(secret.get("match_preview", "")).strip() else [],
                priority_score=file_weight + (22 if classification == "strong_passive_exposure" else 16),
            ))
            continue
        push("artifact_hints", _artifact_record(
            "artifact_hint",
            url=raw_url,
            subtype=str(secret.get("secret_type", "secret_hint") or "secret_hint"),
            label=_artifact_label(parts, str(secret.get("secret_type", "secret_hint") or "secret_hint")),
            source=str(secret.get("source", "passive_artifact_intelligence") or "passive_artifact_intelligence"),
            evidence=str(secret.get("evidence", "")),
            classification=classification or "hint",
            confidence=confidence,
            historical_only=historical_only,
            current_passive=bool(secret.get("current_passive", False)),
            first_party=bool(secret.get("first_party", True)),
            observation_recency=str(secret.get("observation_recency", "")),
            reasons=[str(secret.get("match_preview", ""))] if str(secret.get("match_preview", "")).strip() else [],
            priority_score=max(10, file_weight + 8),
        ))

    for ref in data.get("developer_references", []) or []:
        if not isinstance(ref, dict):
            continue
        raw_url = str(ref.get("location", "") or ref.get("repo", "") or "")
        parts = _artifact_url_parts(raw_url)
        if raw_url and _artifact_is_low_value_noise(parts):
            suppress("static_assets")
            continue
        category = str(ref.get("category", "reference") or "reference")
        classification = str(ref.get("classification", "passive") or "passive")
        confidence = float(ref.get("confidence", 0.0) or 0.0)
        historical_only = bool(ref.get("historical_only", False))
        file_weight = _artifact_file_weight(parts)
        if _artifact_is_internal_reference(parts):
            push("internal_references", _artifact_record(
                "internal_reference",
                url=raw_url,
                subtype=category,
                label=_artifact_label(parts, category),
                source=str(ref.get("source", "passive_artifact_intelligence") or "passive_artifact_intelligence"),
                evidence=str(ref.get("evidence", "")),
                classification=classification,
                confidence=confidence,
                historical_only=historical_only,
                current_passive=bool(ref.get("current_passive", False)),
                first_party=bool(ref.get("first_party", True)),
                observation_recency=str(ref.get("observation_recency", "")),
                reasons=[str(ref.get("file", ""))] if str(ref.get("file", "")).strip() else [],
                priority_score=max(18, file_weight + 6),
            ))
            continue
        if file_weight >= 16 and (not historical_only or category.lower() in {"config_exposure", "credentials", "source_map", "manifest", "build_metadata"}):
            target_group = "archived_files" if historical_only else "high_value_files"
            target_type = "archived_file" if historical_only else "confirmed_file"
            push(target_group, _artifact_record(
                target_type,
                url=raw_url,
                subtype=category,
                label=_artifact_label(parts, category),
                source=str(ref.get("source", "passive_artifact_intelligence") or "passive_artifact_intelligence"),
                evidence=str(ref.get("evidence", "")),
                classification=classification,
                confidence=confidence,
                historical_only=historical_only,
                current_passive=bool(ref.get("current_passive", False)),
                first_party=bool(ref.get("first_party", True)),
                observation_recency=str(ref.get("observation_recency", "")),
                reasons=[str(ref.get("file", ""))] if str(ref.get("file", "")).strip() else [],
                priority_score=file_weight + 12,
            ))
            continue
        push("artifact_hints", _artifact_record(
            "artifact_hint",
            url=raw_url,
            subtype=category,
            label=_artifact_label(parts, category),
            source=str(ref.get("source", "passive_artifact_intelligence") or "passive_artifact_intelligence"),
            evidence=str(ref.get("evidence", "")),
            classification=classification,
            confidence=confidence,
            historical_only=historical_only,
            current_passive=bool(ref.get("current_passive", False)),
            first_party=bool(ref.get("first_party", True)),
            observation_recency=str(ref.get("observation_recency", "")),
            reasons=[str(ref.get("file", ""))] if str(ref.get("file", "")).strip() else [],
            priority_score=max(8, file_weight + 4),
        ))

    for row in archive_export.get("sensitive_files", []) or []:
        if not isinstance(row, dict):
            continue
        parts = _artifact_url_parts(row.get("url", ""))
        if _artifact_is_low_value_noise(parts):
            suppress("static_assets")
            continue
        push("archived_files", _artifact_record(
            "archived_file",
            url=str(row.get("url", "") or ""),
            subtype="sensitive_file",
            label=_artifact_label(parts, "archived_file"),
            source="web_archive",
            evidence="archived_sensitive_file",
            classification="passive",
            confidence=0.74,
            historical_only=True,
            current_passive=False,
            first_party=True,
            observation_recency="historical_only",
            priority_score=_artifact_file_weight(parts) + 18,
            timestamp=str(row.get("timestamp", "") or ""),
            status_code=row.get("status_code", 0),
            mime_type=str(row.get("mime_type", "") or ""),
        ))

    for row in archive_export.get("documents", []) or []:
        if not isinstance(row, dict):
            continue
        parts = _artifact_url_parts(row.get("url", ""))
        if _artifact_is_low_value_noise(parts):
            suppress("static_assets")
            continue
        if _artifact_file_weight(parts) < 8:
            suppress("generic_archive_urls")
            continue
        push("archived_files", _artifact_record(
            "archived_file",
            url=str(row.get("url", "") or ""),
            subtype="document",
            label=_artifact_label(parts, "archived_document"),
            source="web_archive",
            evidence="archived_document",
            classification="passive",
            confidence=0.62,
            historical_only=True,
            current_passive=False,
            first_party=True,
            observation_recency="historical_only",
            priority_score=_artifact_file_weight(parts) + 8,
            timestamp=str(row.get("timestamp", "") or ""),
            status_code=row.get("status_code", 0),
            mime_type=str(row.get("mime_type", "") or ""),
        ))

    for bucket_name, subtype in (("api_endpoints", "api"), ("admin_paths", "admin")):
        for row in archive_export.get(bucket_name, []) or []:
            if not isinstance(row, dict):
                continue
            parts = _artifact_url_parts(row.get("url", ""))
            if _artifact_is_low_value_noise(parts):
                suppress("static_assets")
                continue
            if _artifact_is_internal_reference(parts):
                push("internal_references", _artifact_record(
                    "internal_reference",
                    url=str(row.get("url", "") or ""),
                    subtype=subtype,
                    label=_artifact_label(parts, subtype),
                    source="web_archive",
                    evidence="archived_internal_surface",
                    classification="passive",
                    confidence=0.58,
                    historical_only=True,
                    current_passive=False,
                    first_party=True,
                    observation_recency="historical_only",
                    priority_score=_artifact_endpoint_weight(parts, subtype) + 6,
                    timestamp=str(row.get("timestamp", "") or ""),
                    status_code=row.get("status_code", 0),
                    mime_type=str(row.get("mime_type", "") or ""),
                ))
                continue
            if _artifact_file_weight(parts) >= 18:
                push("archived_files", _artifact_record(
                    "archived_file",
                    url=str(row.get("url", "") or ""),
                    subtype=subtype,
                    label=_artifact_label(parts, subtype),
                    source="web_archive",
                    evidence="archived_operational_file",
                    classification="passive",
                    confidence=0.66,
                    historical_only=True,
                    current_passive=False,
                    first_party=True,
                    observation_recency="historical_only",
                    priority_score=_artifact_file_weight(parts) + 10,
                    timestamp=str(row.get("timestamp", "") or ""),
                    status_code=row.get("status_code", 0),
                    mime_type=str(row.get("mime_type", "") or ""),
                ))
                continue
            push("interesting_endpoints", _artifact_record(
                "endpoint",
                url=str(row.get("url", "") or ""),
                subtype=subtype,
                label=_artifact_label(parts, subtype),
                source="web_archive",
                evidence="archived_operational_surface",
                classification="passive",
                confidence=0.6,
                historical_only=True,
                current_passive=False,
                first_party=True,
                observation_recency="historical_only",
                priority_score=_artifact_endpoint_weight(parts, subtype) + 4,
                timestamp=str(row.get("timestamp", "") or ""),
                status_code=row.get("status_code", 0),
                mime_type=str(row.get("mime_type", "") or ""),
            ))

    for row in archive_export.get("interesting_paths", []) or []:
        if not isinstance(row, dict):
            continue
        parts = _artifact_url_parts(row.get("url", ""))
        if _artifact_is_low_value_noise(parts):
            suppress("generic_archive_urls")
            continue
        if not _artifact_has_strong_signal(parts):
            suppress("generic_archive_urls")
            continue
        push("artifact_hints", _artifact_record(
            "artifact_hint",
            url=str(row.get("url", "") or ""),
            subtype="archive_hint",
            label=_artifact_label(parts, "archive_hint"),
            source="web_archive",
            evidence="archived_interesting_path",
            classification="hint",
            confidence=0.46,
            historical_only=True,
            current_passive=False,
            first_party=True,
            observation_recency="historical_only",
            priority_score=max(10, _artifact_file_weight(parts) + 4),
            timestamp=str(row.get("timestamp", "") or ""),
            status_code=row.get("status_code", 0),
            mime_type=str(row.get("mime_type", "") or ""),
        ))

    wayback = data.get("wayback_urls", {}) if isinstance(data.get("wayback_urls", {}), dict) else {}
    for row in wayback.get("sensitive_path_hits", []) or []:
        if not isinstance(row, dict):
            continue
        parts = _artifact_url_parts(row.get("url", ""))
        if _artifact_is_low_value_noise(parts):
            suppress("generic_archive_urls")
            continue
        push("artifact_hints", _artifact_record(
            "artifact_hint",
            url=str(row.get("url", "") or ""),
            subtype=str(row.get("tag", "archive_hint") or "archive_hint"),
            label=_artifact_label(parts, str(row.get("tag", "archive_hint") or "archive_hint")),
            source=str(row.get("source", "wayback/commoncrawl_index") or "wayback/commoncrawl_index"),
            evidence=str(row.get("evidence", "path_pattern_from_archive_index")),
            classification=str(row.get("classification", "hint") or "hint"),
            confidence=0.42,
            historical_only=True,
            current_passive=False,
            first_party=True,
            observation_recency="historical_only",
            priority_score=max(8, _artifact_file_weight(parts) + 2),
        ))

    for sub in data.get("subdomains", []) or []:
        if not isinstance(sub, dict):
            continue
        host = normalize_text(str(sub.get("name", "") or "")).strip().lower()
        tags = [normalize_text(str(tag)).strip().lower() for tag in (sub.get("tags", []) or []) if str(tag or "").strip()]
        if not host:
            continue
        if "internal_hint" not in tags and not any(token in host for token in INTERNAL_REFERENCE_TOKENS):
            continue
        push("internal_references", _artifact_record(
            "internal_reference",
            url=f"https://{host}",
            host=host,
            path="/",
            subtype="host_hint",
            label=host,
            source="subdomain_inventory",
            evidence=", ".join(tags[:4]) if tags else "subdomain_internal_hint",
            classification="hint",
            confidence=max(0.42, float(sub.get("confidence", 0.42) or 0.42)),
            historical_only=False,
            current_passive=True,
            first_party=True,
            observation_recency=str(sub.get("observation_recency", "current_passive")),
            reasons=tags[:4],
            priority_score=18 + min(12, int(sub.get("relevance_score", 0) or 0)),
        ))

    rendered = {key: sorted(bucket.values(), key=_artifact_sort_key) for key, bucket in groups.items()}
    return {
        "summary": {
            "high_value_files": len(rendered["high_value_files"]),
            "archived_files": len(rendered["archived_files"]),
            "interesting_endpoints": len(rendered["interesting_endpoints"]),
            "artifact_hints": len(rendered["artifact_hints"]),
            "internal_references": len(rendered["internal_references"]),
            "suppressed_noise": int(suppressed.get("count", 0) or 0),
        },
        "high_value_files": rendered["high_value_files"],
        "archived_files": rendered["archived_files"],
        "interesting_endpoints": rendered["interesting_endpoints"],
        "artifact_hints": rendered["artifact_hints"],
        "internal_references": rendered["internal_references"],
        "suppressed_noise": suppressed,
    }


def _summary_contract(data: Dict[str, Any]) -> Dict[str, int]:
    vulns = _safe_len(data.get("vulnerabilities", []))
    takeovers = _safe_len(data.get("takeover_records", []))
    breaches = _safe_len(data.get("breach_records", []))
    cloud_assets = _safe_len(data.get("cloud_assets", []))
    ports = 0
    for row in (data.get("ip_records", []) or []):
        if not isinstance(row, dict):
            continue
        ports += len([
            port for port in (row.get("open_ports") or row.get("ports") or [])
            if isinstance(port, int) or str(port).isdigit()
        ])
    evidenced_cloud_assets = _safe_len([
        a for a in (data.get("cloud_assets", []) or [])
        if isinstance(a, dict) and str(a.get("classification", "heuristic")) in {"evidenced", "probable"}
    ])
    return {
        "subdomains": _safe_len(data.get("subdomains", [])),
        "emails": _safe_len(data.get("emails", [])),
        "vulns": vulns,
        "ips": _safe_len(data.get("ip_records", [])),
        "ports": ports,
        "cloud_assets": cloud_assets,
        "exposures": vulns + takeovers + breaches + evidenced_cloud_assets,
        "takeovers": takeovers,
        "technologies": _safe_len(data.get("technologies", [])),
        "breaches": breaches,
        "archive_urls": _archive_urls_count(data),
        "certs": _safe_len(data.get("ssl_info", [])),
        "dorks": _safe_len(data.get("dorks", [])),
    }


def _enforce_summary_contract(summary: Dict[str, Any], errors: List[Dict[str, Any]]) -> Dict[str, int]:
    out: Dict[str, int] = {}
    defaulted: List[str] = []
    for key in SUMMARY_KEYS:
        if key in summary:
            out[key] = _safe_int(summary.get(key, 0), 0)
        else:
            out[key] = 0
            defaulted.append(key)
    if defaulted:
        errors.append({
            "module": "ui",
            "source": "report_builder",
            "kind": "ui_schema_defaulted",
            "message_short": f"Summary defaults applied: {', '.join(defaulted)}",
            "missing_keys": defaulted,
        })
    return out


def _section_completeness(data: Dict[str, Any], section: str, policy_ctx: Dict[str, Any]) -> Dict[str, Any]:
    fields = SECTION_FIELD_MAP.get(section, [])
    if section == "bug_bounty":
        meaningful = {
            "interesting_endpoints": len([r for r in (data.get("interesting_endpoints", []) or []) if isinstance(r, dict) and int(r.get("priority_score", 0) or 0) >= 28]),
            "potential_secrets": len([r for r in (data.get("potential_secrets", []) or []) if isinstance(r, dict) and str(r.get("classification", "")) in {"probable_secret_exposure", "strong_passive_exposure", "suspicious_secret_reference"}]),
            "developer_references": len([r for r in (data.get("developer_references", []) or []) if isinstance(r, dict)]),
            "high_value_targets": len([r for r in (data.get("high_value_targets", []) or []) if isinstance(r, dict) and int(r.get("score", 0) or 0) >= 45]),
            "asset_clusters": sum(len((data.get("asset_clusters", {}) or {}).get(k, []) or []) for k in ("by_ip", "by_asn", "providers")),
        }
        technologies = len([r for r in (data.get("technologies", []) or []) if isinstance(r, dict) and str(r.get("name", "")).strip()])
        field_status = [{"field": field, "present": meaningful.get(field, 0) > 0} for field in fields]
        filled = sum(1 for row in field_status if row["present"])
        if technologies > 0 and filled < len(fields):
            filled += 1
        total = max(1, len(fields) + 1)
        pct = round((filled / total) * 100, 1)
        reason = ""
        if pct == 0:
            mod = SECTION_MODULE_MAP.get(section, "")
            disabled = set(policy_ctx.get("disabled_modules", []))
            reason = "disabled_by_policy" if mod and mod in disabled else "not_available_from_sources"
        return {
            "section": section,
            "percent": pct,
            "filled": filled,
            "total": total,
            "reason": reason,
            "fields": field_status + [{"field": "technologies", "present": technologies > 0}],
        }
    filled = 0
    field_status = []
    for f in fields:
        value = data.get(f)
        present = not _empty(value)
        if present:
            filled += 1
        field_status.append({"field": f, "present": present})
    total = max(1, len(fields))
    pct = round((filled / total) * 100, 1)
    mod = SECTION_MODULE_MAP.get(section, "")
    disabled = set(policy_ctx.get("disabled_modules", []))
    reason = ""
    if pct == 0:
        reason = "disabled_by_policy" if mod and mod in disabled else "not_available_from_sources"
    return {
        "section": section,
        "percent": pct,
        "filled": filled,
        "total": total,
        "reason": reason,
        "fields": field_status,
    }


def _coverage_summary(source_metrics: Dict[str, Any]) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    provider_summary = {"success": 0, "partial": 0, "failed": 0, "skipped": 0, "premium_success_count": 0}
    for module_name, module_metrics in (source_metrics or {}).items():
        if not isinstance(module_metrics, dict):
            continue
        module_total = {
            "items_obtenidos": 0,
            "items_parseados": 0,
            "items_aceptados": 0,
            "items_descartados_por_dedupe": 0,
            "items_descartados_por_filtro": 0,
            "errores": 0,
            "latencia_ms_promedio": 0,
            "sources": {},
            "source_status_counts": {},
        }
        lats: List[int] = []
        for src, m in module_metrics.items():
            if not isinstance(m, dict):
                continue
            module_total["sources"][src] = m
            st = str(m.get("status", "ok"))
            if st == "ok" and int(m.get("errores", 0)) > 0 and int(m.get("items_aceptados", 0)) > 0:
                st = "partial"
            module_total["source_status_counts"][st] = module_total["source_status_counts"].get(st, 0) + 1
            if st in {"ok", "derived_ok"}:
                provider_summary["success"] += 1
                if source_to_required_credentials(str(src)):
                    provider_summary["premium_success_count"] += 1
            elif st in {"partial", "timeout_partial", "fail_partial", "derived"}:
                provider_summary["partial"] += 1
            elif st in {"skipped_missing_key", "disabled_no_keys_mode", "blocked_missing_api_key", "blocked_target_requests_policy", "disabled", "disabled_by_profile", "disabled_default"}:
                provider_summary["skipped"] += 1
            elif st not in {"blocked_missing_api_key", "blocked_target_requests_policy"}:
                provider_summary["failed"] += 1
            module_total["items_obtenidos"] += int(m.get("items_obtenidos", 0))
            module_total["items_parseados"] += int(m.get("items_parseados", 0))
            module_total["items_aceptados"] += int(m.get("items_aceptados", 0))
            module_total["items_descartados_por_dedupe"] += int(m.get("items_descartados_por_dedupe", 0))
            module_total["items_descartados_por_filtro"] += int(m.get("items_descartados_por_filtro", 0))
            module_total["errores"] += int(m.get("errores", 0))
            lats.append(int(m.get("latencia_ms", 0)))
        module_total["latencia_ms_promedio"] = round(sum(lats) / len(lats), 1) if lats else 0
        out[module_name] = module_total
    out["_provider_summary"] = provider_summary
    return out


def _source_scoring(source_metrics: Dict[str, Any], data: Dict[str, Any]) -> Dict[str, Any]:
    flat: Dict[str, Dict[str, Any]] = {}
    for module_name, module_metrics in (source_metrics or {}).items():
        if not isinstance(module_metrics, dict):
            continue
        for source_name, metric in module_metrics.items():
            if not isinstance(metric, dict):
                continue
            bucket = flat.setdefault(
                str(source_name),
                {
                    "source": str(source_name),
                    "modules": set(),
                    "latencies": [],
                    "items_found": 0,
                    "errors": 0,
                },
            )
            bucket["modules"].add(str(module_name))
            bucket["latencies"].append(int(metric.get("latencia_ms", 0) or 0))
            bucket["items_found"] += int(
                metric.get("items_obtenidos", metric.get("items_parseados", metric.get("items_aceptados", 0))) or 0
            )
            bucket["errors"] += int(metric.get("errores", 0) or 0)

    finding_sources: Dict[str, set[str]] = {}
    for sub in data.get("subdomains", []) or []:
        if not isinstance(sub, dict):
            continue
        key = f"subdomain:{sub.get('name', '')}".strip()
        if key:
            finding_sources[key] = {str(s) for s in (sub.get("sources", []) or []) if str(s)}
    for email in data.get("emails", []) or []:
        if isinstance(email, dict):
            addr = str(email.get("email", "")).strip()
            if addr:
                finding_sources[f"email:{addr}"] = {str(s) for s in (email.get("sources", []) or []) if str(s)}
    for vuln in data.get("vulnerabilities", []) or []:
        if not isinstance(vuln, dict):
            continue
        key = str(vuln.get("cve_id") or vuln.get("title") or "").strip()
        src = str(vuln.get("source", "")).strip()
        if key and src:
            finding_sources[f"vuln:{key}"] = {src}

    seen_counts: Dict[str, int] = {name: 0 for name in flat}
    unique_counts: Dict[str, int] = {name: 0 for name in flat}
    for _, srcs in finding_sources.items():
        norm_sources = [s for s in srcs if s in flat]
        for source_name in norm_sources:
            seen_counts[source_name] = seen_counts.get(source_name, 0) + 1
        if len(norm_sources) == 1:
            unique_counts[norm_sources[0]] = unique_counts.get(norm_sources[0], 0) + 1

    by_source: Dict[str, Dict[str, Any]] = {}
    for source_name, bucket in flat.items():
        items_found = int(bucket.get("items_found", 0) or 0)
        errors = int(bucket.get("errors", 0) or 0)
        avg_latency = round(
            sum(bucket.get("latencies", []) or [0]) / max(1, len(bucket.get("latencies", []) or [])),
            1,
        )
        error_rate = round(errors / max(1, items_found + errors), 4)
        uniques = int(unique_counts.get(source_name, 0))
        latency_component = max(0.0, 100.0 - min(5000.0, float(avg_latency)) / 50.0)
        error_component = max(0.0, 100.0 - (error_rate * 100.0))
        unique_component = min(100.0, float(uniques) * 20.0)
        quality = round((error_component * 0.45) + (unique_component * 0.35) + (latency_component * 0.20), 1)
        by_source[source_name] = {
            "source": source_name,
            "modules": sorted(bucket.get("modules", set())),
            "source_latency_ms": avg_latency,
            "source_items_found": items_found,
            "source_unique_findings": uniques,
            "source_error_rate": error_rate,
            "source_quality_score": quality,
            "source_findings_seen": int(seen_counts.get(source_name, 0)),
            "source_error_count": errors,
            "source_quality_bucket": source_quality_bucket(source_name),
            "effective_weight": source_weight(source_name),
            "massive_source": source_name in {"jldc", "anubisdb"},
        }

    ranking = sorted(
        by_source.values(),
        key=lambda item: (
            -float(item.get("source_quality_score", 0)),
            -int(item.get("source_unique_findings", 0)),
            -int(item.get("source_items_found", 0)),
        ),
    )
    top_sources = [row["source"] for row in ranking[:5]]
    noisy_sources = [
        row["source"]
        for row in ranking
        if float(row.get("source_error_rate", 0)) >= 0.35 or float(row.get("source_quality_score", 0)) < 30.0
    ][:5]
    return {
        "schema_version": SCHEMA_VERSION,
        "by_source": by_source,
        "ranking": ranking,
        "recommendations": {
            "top_sources": top_sources,
            "noisy_sources": noisy_sources,
        },
    }


def _policy_blocked_sources(source_metrics: Dict[str, Any]) -> List[Dict[str, str]]:
    blocked: List[Dict[str, str]] = []
    for module_name, module_metrics in (source_metrics or {}).items():
        if not isinstance(module_metrics, dict):
            continue
        for src_name, src_metrics in module_metrics.items():
            if not isinstance(src_metrics, dict):
                continue
            status = str(src_metrics.get("status", ""))
            if status == "blocked_target_requests_policy":
                blocked.append({
                    "module": str(module_name),
                    "source": str(src_name),
                    "status": status,
                })
    return blocked


def _bug_bounty_summary(data: Dict[str, Any], artifact_inventory: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    return {
        "interesting_endpoints": data.get("interesting_endpoints", []) or [],
        "potential_secrets": data.get("potential_secrets", []) or [],
        "developer_references": data.get("developer_references", []) or [],
        "high_value_targets": data.get("high_value_targets", []) or [],
        "asset_clusters": data.get("asset_clusters", {}) or {},
        "artifact_inventory": artifact_inventory if isinstance(artifact_inventory, dict) else {},
    }


def _normalize_vulnerability_records(data: Dict[str, Any]) -> None:
    normalized: List[Dict[str, Any]] = []
    for row in data.get("vulnerabilities", []) or []:
        if not isinstance(row, dict):
            continue
        copy = dict(row)
        copy.setdefault("classification", "evidenced")
        copy.setdefault("confidence", 0.72)
        copy = _apply_canonical_finding_semantics(copy, "vulnerability")
        normalized.append(copy)
    data["vulnerabilities"] = normalized


def _normalize_takeover_records(data: Dict[str, Any]) -> None:
    normalized: List[Dict[str, Any]] = []
    for row in data.get("takeover_records", []) or []:
        if not isinstance(row, dict):
            continue
        copy = dict(row)
        status = str(copy.get("status", "") or "").upper()
        copy.setdefault("classification", "evidenced" if status == "VULNERABLE" else "probable")
        copy.setdefault("confidence", 0.85 if status == "VULNERABLE" else 0.68)
        copy.setdefault("evidence_type", "direct_passive")
        copy.setdefault("ownership_scope", "first_party")
        copy = _apply_canonical_finding_semantics(copy, "takeover")
        normalized.append(copy)
    data["takeover_records"] = normalized


def _normalize_correlation_records(data: Dict[str, Any]) -> None:
    normalized: List[Dict[str, Any]] = []
    for row in data.get("correlations", []) or []:
        if not isinstance(row, dict):
            continue
        copy = dict(row)
        copy.setdefault("classification", "probable")
        copy.setdefault("confidence", 0.7)
        copy.setdefault("source", "correlation_engine")
        copy = _apply_canonical_finding_semantics(copy, "correlation")
        normalized.append(copy)
    data["correlations"] = normalized


def _normalize_bug_bounty_rows(data: Dict[str, Any]) -> None:
    row_kinds = {
        "interesting_endpoints": "exposure",
        "potential_secrets": "potential_secret",
        "developer_references": "developer_reference",
        "high_value_targets": "high_value_target",
    }
    for field, kind in row_kinds.items():
        normalized: List[Dict[str, Any]] = []
        for row in data.get(field, []) or []:
            if not isinstance(row, dict):
                continue
            copy = dict(row)
            if kind == "interesting_endpoints":
                copy.setdefault("classification", "passive")
                copy.setdefault("confidence", 0.62)
            elif kind == "potential_secret":
                copy.setdefault("classification", "suspicious_secret_reference")
                copy.setdefault("confidence", 0.58)
            elif kind == "developer_reference":
                copy.setdefault("classification", "passive")
                copy.setdefault("confidence", 0.56)
            elif kind == "high_value_target":
                copy.setdefault("classification", "passive")
                copy.setdefault("confidence", 0.64)
                copy.setdefault("evidence_type", "derived_passive")
            copy = _apply_canonical_finding_semantics(copy, kind)
            normalized.append(copy)
        data[field] = normalized


def _normalize_infrastructure_observations(data: Dict[str, Any]) -> None:
    normalized: List[Dict[str, Any]] = []
    for row in data.get("infrastructure_observations", []) or []:
        if not isinstance(row, dict):
            continue
        copy = dict(row)
        copy.setdefault("classification", "passive")
        copy.setdefault("confidence", 0.62)
        copy.setdefault("evidence_type", "derived_passive")
        copy = _apply_canonical_finding_semantics(copy, "infrastructure_observation")
        normalized.append(copy)
    data["infrastructure_observations"] = normalized


def _derive_infrastructure_observations(data: Dict[str, Any]) -> None:
    existing = data.get("infrastructure_observations", []) or []
    observations: List[Dict[str, Any]] = [dict(row) for row in existing if isinstance(row, dict)]
    seen = {
        (
            str(row.get("type", "")),
            str(row.get("asset", "")),
            str(row.get("title", "")),
        )
        for row in observations
    }
    ip_to_hosts: Dict[str, List[str]] = {}
    for sub in data.get("subdomains", []) or []:
        if not isinstance(sub, dict):
            continue
        host = str(sub.get("name", "") or "")
        for raw_ip in sub.get("ips", []) or []:
            ip = _normalize_ip(raw_ip)
            if ip and host:
                ip_to_hosts.setdefault(ip, []).append(host)
    sensitive_ports = {
        21: ("observed_open_port", "FTP service observed via passive dataset", "MEDIUM", 0.78),
        22: ("observed_open_port", "SSH service observed via passive dataset", "LOW", 0.7),
        23: ("observed_open_port", "Telnet service observed via passive dataset", "HIGH", 0.86),
        25: ("observed_open_port", "SMTP service observed via passive dataset", "MEDIUM", 0.72),
        3306: ("exposed_service", "MySQL exposure observed via passive dataset", "HIGH", 0.88),
        3389: ("exposed_service", "RDP exposure observed via passive dataset", "MEDIUM", 0.8),
        5432: ("exposed_service", "PostgreSQL exposure observed via passive dataset", "HIGH", 0.88),
        6379: ("exposed_service", "Redis exposure observed via passive dataset", "HIGH", 0.9),
        8080: ("public_attack_surface_hint", "Alternative HTTP surface observed", "LOW", 0.64),
        8443: ("public_attack_surface_hint", "Alternative HTTPS surface observed", "LOW", 0.64),
        8888: ("exposed_service", "Development or notebook port observed", "MEDIUM", 0.78),
        9200: ("exposed_service", "Elasticsearch exposure observed", "HIGH", 0.9),
        11211: ("exposed_service", "Memcached exposure observed", "MEDIUM", 0.78),
        2375: ("exposed_service", "Docker API exposure observed", "HIGH", 0.92),
        27017: ("exposed_service", "MongoDB exposure observed", "HIGH", 0.9),
    }
    ip_annotations: Dict[str, List[Dict[str, Any]]] = {}
    for row in data.get("ip_records", []) or []:
        if not isinstance(row, dict):
            continue
        ip = _normalize_ip(row.get("ip", ""))
        if not ip:
            continue
        hosts = sorted(set(ip_to_hosts.get(ip, [])))[:5]
        shared = row.get("shared_hosting", []) or []
        ports = [int(p) for p in (row.get("open_ports") or row.get("ports") or []) if str(p).isdigit() or isinstance(p, int)]
        cpes = [str(v) for v in (row.get("cpes", []) or []) if str(v).strip()]
        tags = [str(v) for v in (row.get("tags", []) or []) if str(v).strip()]
        rdns = str(row.get("rdns", "") or "")
        org = str(row.get("org", "") or "")
        cloud = str(row.get("cloud_provider", "") or "")
        greynoise = row.get("greynoise", {}) if isinstance(row.get("greynoise", {}), dict) else {}
        abuse = row.get("abuseipdb", {}) if isinstance(row.get("abuseipdb", {}), dict) else {}
        cdn = bool(row.get("cdn", False))
        if ports:
            for port in sorted(set(ports))[:8]:
                if port not in sensitive_ports:
                    continue
                obs_type, title, severity, confidence = sensitive_ports[port]
                asset = f"{ip}:{port}"
                key = (obs_type, asset, title)
                if key in seen:
                    continue
                seen.add(key)
                observations.append({
                    "type": obs_type,
                    "title": title,
                    "asset": asset,
                    "severity": severity,
                    "description": normalize_text(f"Passive InternetDB/IP enrichment observed port {port} on {ip}."),
                    "source": "ip_intelligence",
                    "classification": "probable",
                    "confidence": confidence,
                    "evidence_strength": "medium",
                    "evidence_type": "derived_passive",
                    "ownership_scope": "first_party" if hosts and not cdn else "mixed" if hosts else "third_party",
                    "first_party": bool(hosts and not cdn),
                    "third_party_context": bool(cdn and not hosts),
                    "observation_recency": "recent_passive",
                    "related_hosts": hosts,
                    "related_ip": ip,
                })
                ip_annotations.setdefault(ip, []).append(observations[-1])
        if cpes or tags:
            title = "Passive service fingerprint observed"
            key = ("passive_service_fingerprint", ip, title)
            if key not in seen:
                seen.add(key)
                observations.append({
                    "type": "passive_service_fingerprint",
                    "title": title,
                    "asset": ip,
                    "severity": "LOW" if not any("database" in v.lower() for v in tags) else "MEDIUM",
                    "description": normalize_text(", ".join((cpes[:2] + tags[:3])[:5])),
                    "source": "ip_intelligence",
                    "classification": "passive",
                    "confidence": 0.7,
                    "evidence_strength": "medium",
                    "evidence_type": "derived_passive",
                    "ownership_scope": "first_party" if hosts and not cdn else "mixed" if hosts else "third_party",
                    "first_party": bool(hosts and not cdn),
                    "third_party_context": bool(cdn and not hosts),
                    "observation_recency": "recent_passive",
                    "related_hosts": hosts,
                    "related_ip": ip,
                })
                ip_annotations.setdefault(ip, []).append(observations[-1])
        if hosts and not cdn and len(shared) <= 5:
            title = "Origin candidate inferred from first-party IP association"
            key = ("origin_candidate", ip, title)
            if key not in seen:
                seen.add(key)
                observations.append({
                    "type": "origin_candidate",
                    "title": title,
                    "asset": ip,
                    "severity": "MEDIUM" if ports else "LOW",
                    "description": normalize_text(f"{ip} resolves for first-party hosts without strong edge-provider indicators."),
                    "source": "ip_intelligence",
                    "classification": "probable",
                    "confidence": 0.76 if ports else 0.66,
                    "evidence_strength": "medium",
                    "evidence_type": "derived_passive",
                    "ownership_scope": "first_party",
                    "first_party": True,
                    "third_party_context": False,
                    "observation_recency": "current_passive",
                    "related_hosts": hosts,
                    "related_ip": ip,
                })
                ip_annotations.setdefault(ip, []).append(observations[-1])
        if cdn or cloud:
            title = "Provider-edge or cloud-fronted infrastructure observation"
            key = ("provider_edge_observation", ip, title)
            if key not in seen:
                seen.add(key)
                observations.append({
                    "type": "provider_edge_observation",
                    "title": title,
                    "asset": ip,
                    "severity": "INFO",
                    "description": normalize_text(cloud or org or "Edge/network provider markers present on this IP."),
                    "source": "ip_intelligence",
                    "classification": "passive",
                    "confidence": 0.74,
                    "evidence_strength": "medium",
                    "evidence_type": "derived_passive",
                    "ownership_scope": "mixed" if hosts else "third_party",
                    "first_party": False,
                    "third_party_context": True,
                    "observation_recency": "current_passive",
                    "related_hosts": hosts,
                    "related_ip": ip,
                })
                ip_annotations.setdefault(ip, []).append(observations[-1])
        if rdns or org:
            title = "First-party infrastructure signal"
            key = ("first_party_infra_signal", ip, title)
            if key not in seen and hosts:
                seen.add(key)
                observations.append({
                    "type": "first_party_infra_signal",
                    "title": title,
                    "asset": ip,
                    "severity": "LOW",
                    "description": normalize_text(f"{org or rdns}"),
                    "source": "ip_intelligence",
                    "classification": "passive",
                    "confidence": 0.68,
                    "evidence_strength": "medium",
                    "evidence_type": "derived_passive",
                    "ownership_scope": "first_party",
                    "first_party": True,
                    "third_party_context": False,
                    "observation_recency": "current_passive",
                    "related_hosts": hosts,
                    "related_ip": ip,
                })
                ip_annotations.setdefault(ip, []).append(observations[-1])
        if int(abuse.get("abuse_score", 0) or 0) >= 35 or int(greynoise.get("pulse_count", 0) or 0) >= 5:
            title = "Public attack-surface hint from passive reputation telemetry"
            key = ("public_attack_surface_hint", ip, title)
            if key not in seen:
                seen.add(key)
                observations.append({
                    "type": "public_attack_surface_hint",
                    "title": title,
                    "asset": ip,
                    "severity": "MEDIUM" if ports else "LOW",
                    "description": normalize_text(f"Abuse/reputation telemetry is elevated for {ip}."),
                    "source": "ip_intelligence",
                    "classification": "probable",
                    "confidence": 0.64,
                    "evidence_strength": "medium",
                    "evidence_type": "derived_passive",
                    "ownership_scope": "mixed" if hosts else "third_party",
                    "first_party": bool(hosts and not cdn),
                    "third_party_context": bool(not hosts or cdn),
                    "observation_recency": "recent_passive",
                    "related_hosts": hosts,
                    "related_ip": ip,
                })
                ip_annotations.setdefault(ip, []).append(observations[-1])
    for row in data.get("ip_records", []) or []:
        if isinstance(row, dict):
            ip = _normalize_ip(row.get("ip", ""))
            row["observations"] = ip_annotations.get(ip, [])[:8]
    data["infrastructure_observations"] = observations[:160]
    _normalize_infrastructure_observations(data)


def _finding_sections(data: Dict[str, Any]) -> Dict[str, List[Dict[str, Any]]]:
    sections = {
        "vulnerabilities": [],
        "exposures": [],
        "intelligence_leads": [],
        "infrastructure_observations": [],
    }
    for row in data.get("vulnerabilities", []) or []:
        if not isinstance(row, dict):
            continue
        family = str(row.get("finding_family", "vulnerability") or "vulnerability")
        if family == "vulnerability":
            sections["vulnerabilities"].append(row)
        elif family == "exposure":
            sections["exposures"].append(row)
        else:
            sections["intelligence_leads"].append(row)
    for row in data.get("infrastructure_observations", []) or []:
        if isinstance(row, dict):
            sections["infrastructure_observations"].append(row)
    for row in data.get("takeover_records", []) or []:
        if not isinstance(row, dict):
            continue
        copy = _apply_canonical_finding_semantics(dict(row), "takeover")
        status = str(copy.get("status", "") or "").upper()
        if status in {"VULNERABLE", "POTENTIAL", "LIKELY_VULNERABLE"}:
            sections["exposures"].append(copy)
    for row in data.get("interesting_endpoints", []) or []:
        if isinstance(row, dict):
            sections["exposures"].append(_apply_canonical_finding_semantics(dict(row), "exposure"))
    for row in data.get("potential_secrets", []) or []:
        if not isinstance(row, dict):
            continue
        copy = _apply_canonical_finding_semantics(dict(row), "potential_secret")
        classification = str(copy.get("classification", "") or "")
        if classification in {"probable_secret_exposure", "strong_passive_exposure"}:
            sections["exposures"].append(copy)
        else:
            sections["intelligence_leads"].append(copy)
    for row in data.get("developer_references", []) or []:
        if isinstance(row, dict):
            sections["intelligence_leads"].append(_apply_canonical_finding_semantics(dict(row), "developer_reference"))
    for row in data.get("high_value_targets", []) or []:
        if isinstance(row, dict):
            sections["intelligence_leads"].append(_apply_canonical_finding_semantics(dict(row), "high_value_target"))
    return sections


def _top_findings(data: Dict[str, Any]) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    def append_finding(row: Dict[str, Any]) -> None:
        row = _apply_canonical_finding_semantics(row, str(row.get("type", "finding") or "finding"))
        observation_type = str(row.get("observation_type", "") or "")
        evidence_text = str(row.get("evidence", "") or "").lower()
        asset_text = _asset_text(row)
        actionability = {
            "vulnerability": 1.0,
            "takeover": 0.98,
            "potential_secret": 0.92,
            "high_value_target": 0.72,
            "correlation": 0.74,
            "exposure": 0.78,
            "infrastructure_observation": 0.42,
            "developer_reference": 0.58,
            "intelligence_lead": 0.48,
            "exposure_hint": 0.22,
        }.get(str(row.get("type", "finding")), 0.45)
        freshness_bonus = {
            "current_passive": 20.0,
            "recent_passive": 11.0,
            "historical_only": 2.0,
        }.get(str(row.get("observation_recency", "historical_only")), 0.0)
        ownership_bonus = {
            "first_party": 16.0,
            "mixed": 7.0,
            "third_party": 0.0,
        }.get(str(row.get("ownership_scope", "first_party")), 0.0)
        tier_bonus = {
            "confirmed_passive_evidence": 14.0,
            "supported_passive_inference": 8.0,
            "derived_exposure": 3.0,
            "intelligence_lead": 1.0,
            "historical_or_weak_signal": 0.0,
        }.get(str(row.get("evidence_tier", "historical_or_weak_signal")), 0.0)
        family_penalty = {
            "exposure_hint": -16.0,
            "intelligence_lead": -10.0,
            "developer_reference": -8.0,
            "high_value_target": -4.0,
        }.get(str(row.get("type", "finding")), 0.0)
        if str(row.get("type", "finding")) == "high_value_target":
            if _strong_hvt(row):
                family_penalty += 10.0
            elif _weak_hvt(row):
                family_penalty -= 10.0
        if str(row.get("type", "finding")) == "infrastructure_observation":
            family_penalty += {
                "exposed_service": 2.0,
                "observed_open_port": -8.0,
                "passive_service_fingerprint": -12.0,
                "origin_candidate": -16.0,
                "first_party_infra_signal": -8.0,
                "public_attack_surface_hint": -8.0,
                "provider_edge_observation": -18.0,
            }.get(observation_type, -2.0)
        if str(row.get("type", "finding")) == "exposure":
            family_penalty += {
                "admin": 8.0,
                "auth": 8.0,
                "graphql": 6.0,
                "api": 6.0,
                "internal": 6.0,
                "metadata": -12.0,
                "endpoint": -8.0,
            }.get(observation_type, 0.0)
            if _generic_metadata_asset(asset_text):
                family_penalty -= 12.0
            if str(row.get("observation_recency", "") or "") == "historical_only":
                family_penalty -= 6.0
        if str(row.get("type", "finding")) == "potential_secret":
            if ".env" in asset_text or "config" in asset_text:
                family_penalty -= 4.0
        if str(row.get("type", "finding")) == "developer_reference":
            if any(marker in asset_text for marker in (".env", ".map", "swagger", "openapi", "graphql")):
                family_penalty += 6.0
            if _generic_metadata_asset(asset_text):
                family_penalty -= 8.0
        row["priority_score"] = round(
            (_severity_rank(row.get("severity", "INFO")) * 22.0)
            + (float(row.get("confidence", 0.0) or 0.0) * 35.0)
            + (_priority_multiplier(row) * 30.0),
            2,
        )
        row["ranking_score"] = round(
            row["priority_score"]
            + (actionability * 24.0)
            + freshness_bonus
            + ownership_bonus
            + tier_bonus,
            2,
        )
        row["ranking_score"] = round(
            row["ranking_score"] + family_penalty,
            2,
        )
        findings.append(row)

    for v in data.get("vulnerabilities", []) or []:
        sev = _passive_effective_severity(v, "vulnerability")
        classification = _finding_classification(v, "evidenced")
        confidence = float(v.get("confidence", 0.72 if classification == "evidenced" else 0.64) or 0.0)
        if sev in {"CRITICAL", "HIGH"}:
            finding_type = _finding_family(v, "vulnerability")
            append_finding({
                "type": finding_type,
                "severity": sev,
                "title": normalize_text(v.get("title") or v.get("cve_id") or "High-risk vulnerability"),
                "asset": v.get("affected_asset", ""),
                "confidence": round(max(0.2, min(confidence, 0.99)), 3),
                "evidence": normalize_text(v.get("description", "")),
                "source": v.get("source", ""),
                "first_seen": v.get("first_seen", ""),
                "last_seen": v.get("last_seen", ""),
                "classification": classification,
                "third_party_context": bool(v.get("third_party_context", False)),
                "first_party": _is_first_party(v),
                "evidence_type": _evidence_type(v, "vulnerability"),
                "finding_family": finding_type,
                "why_prioritized": "High-confidence passive evidence on a target-relevant asset",
            })
    for t in data.get("takeover_records", []) or []:
        status = str(t.get("status", "")).upper()
        if status in {"VULNERABLE", "POTENTIAL", "LIKELY_VULNERABLE"}:
            sev = str(t.get("severity", "HIGH" if status == "VULNERABLE" else "MEDIUM")).upper()
            append_finding({
                "type": "takeover",
                "severity": sev,
                "title": normalize_text(f"Takeover exposure on {t.get('subdomain', '')}"),
                "asset": t.get("subdomain", ""),
                "confidence": 0.85 if status == "VULNERABLE" else 0.7,
                "evidence": normalize_text(t.get("evidence", "")),
                "source": t.get("source", ""),
                "first_seen": t.get("first_seen", ""),
                "last_seen": t.get("last_seen", ""),
                "classification": "evidenced" if status == "VULNERABLE" else "probable",
                "evidence_type": "direct_passive",
                "why_prioritized": "Actionable takeover signal on first-party asset",
            })
    for c in data.get("correlations", []) or []:
        sev = _passive_effective_severity(c, "correlation")
        classification = _finding_classification(c, "probable")
        if sev in {"CRITICAL", "HIGH"}:
            conf = float(c.get("confidence", 0.0) or 0.0)
            if conf <= 0:
                conf = 0.82 if sev == "CRITICAL" else 0.72
            append_finding({
                "type": "correlation",
                "severity": sev,
                "title": normalize_text(c.get("title", "High-risk correlation")),
                "asset": ", ".join(c.get("assets", [])[:3]) if isinstance(c.get("assets", []), list) else "",
                "confidence": max(0.25, min(0.99, conf)),
                "evidence": normalize_text(c.get("detail", "")),
                "source": c.get("source", "correlation_engine"),
                "first_seen": c.get("first_seen", ""),
                "last_seen": c.get("last_seen", ""),
                "classification": classification,
                "third_party_context": bool(c.get("third_party_context", False)),
                "first_party": _is_first_party(c),
                "evidence_type": "derived_passive",
                "why_prioritized": "Multiple passive signals align on the same asset",
            })
    wayback = data.get("wayback_urls", {}) or {}
    if isinstance(wayback, dict):
        for hit in (wayback.get("sensitive_path_hits", []) or [])[:40]:
            if not isinstance(hit, dict):
                continue
            url = str(hit.get("url", "") or "")
            if not url:
                continue
            append_finding({
                "type": "exposure_hint",
                "severity": str(hit.get("severity", "LOW")).upper(),
                "title": normalize_text(f"Archived sensitive path hint: {hit.get('tag', 'path')}"),
                "asset": url[:160],
                "confidence": 0.45,
                "evidence": normalize_text(hit.get("evidence", "path_pattern_from_archive_index")),
                "source": hit.get("source", "wayback/commoncrawl_index"),
                "first_seen": "",
                "last_seen": "",
                "classification": "hint",
                "historical_only": True,
                "current_passive": False,
                "third_party_context": False,
                "first_party": True,
                "evidence_type": "archival_passive",
                "why_prioritized": "Archived path indicates potentially interesting historical surface",
            })
    for secret in data.get("potential_secrets", []) or []:
        if not isinstance(secret, dict):
            continue
        confidence = float(secret.get("confidence", 0.0) or 0.0)
        classification = _finding_classification(secret, "suspicious_secret_reference")
        if confidence < 0.75 or classification not in {"probable_secret_exposure", "strong_passive_exposure", "suspicious_secret_reference"}:
            continue
        append_finding({
            "type": "potential_secret",
            "severity": (
                "HIGH"
                if classification == "strong_passive_exposure" and confidence >= 0.9
                else "MEDIUM"
                if classification in {"probable_secret_exposure", "strong_passive_exposure"}
                else "LOW"
            ),
            "title": normalize_text(f"Potential secret exposed via passive source: {secret.get('secret_type', 'secret')}"),
            "asset": secret.get("location", ""),
            "confidence": round(max(0.25, min(confidence, 0.99)), 3),
            "evidence": normalize_text(secret.get("evidence", "")),
            "source": secret.get("source", "passive_artifact_intelligence"),
            "first_seen": secret.get("first_seen", ""),
            "last_seen": secret.get("last_seen", ""),
            "classification": classification,
            "third_party_context": bool(secret.get("third_party_context", False)),
            "first_party": _is_first_party(secret),
            "observation_recency": _recency_bucket(secret),
            "evidence_type": _evidence_type(secret, "potential_secret"),
            "why_prioritized": "Secret-looking material appears in passive evidence and survives allowlist downgrades",
        })
    strong_devref_categories = {"config_exposure", "credentials", "source_map", "swagger", "openapi", "graphql", "manifest", "build_metadata"}
    for ref in data.get("developer_references", []) or []:
        if not isinstance(ref, dict):
            continue
        confidence = float(ref.get("confidence", 0.0) or 0.0)
        category = str(ref.get("category", "") or "").lower()
        location = str(ref.get("location", "") or "")
        if confidence < 0.58:
            continue
        if category not in strong_devref_categories and not any(location.lower().endswith(ext) for ext in (".map", ".env", ".yaml", ".yml", ".json")):
            continue
        append_finding({
            "type": "developer_reference",
            "severity": "MEDIUM" if category in {"config_exposure", "credentials", "source_map"} else "LOW",
            "title": normalize_text(f"Developer-facing passive artifact: {category or 'developer_surface'}"),
            "asset": location or ref.get("host", ""),
            "confidence": round(max(0.25, min(confidence, 0.99)), 3),
            "evidence": normalize_text(ref.get("evidence", "") or location),
            "source": ref.get("source", "passive_artifact_intelligence"),
            "classification": ref.get("classification", "passive"),
            "third_party_context": bool(ref.get("third_party_context", False)),
            "first_party": _is_first_party(ref),
            "observation_recency": _recency_bucket(ref),
            "evidence_type": _evidence_type(ref, "developer_reference"),
            "observation_type": category or "developer_surface",
            "why_prioritized": "Passive developer-facing artifact may reveal build, configuration, or integration surface",
        })
    for target in data.get("high_value_targets", []) or []:
        if not isinstance(target, dict):
            continue
        score = int(target.get("score", 0) or 0)
        if score < 44:
            continue
        append_finding({
            "type": "high_value_target",
            "severity": "MEDIUM" if score < 78 else "HIGH",
            "title": normalize_text(f"High-value passive target candidate: {target.get('host', '')}"),
            "asset": target.get("host", ""),
            "confidence": round(float(target.get("confidence", 0.64) or 0.64), 3),
            "evidence": normalize_text(", ".join(target.get("reasons", [])[:4])),
            "source": "passive_artifact_intelligence",
            "first_seen": "",
            "last_seen": "",
            "classification": target.get("classification", "passive"),
            "third_party_context": bool(target.get("third_party_context", False)),
            "first_party": _is_first_party(target),
            "observation_recency": _recency_bucket(target),
            "evidence_type": "derived_passive",
            "why_prioritized": "Multiple passive bug-bounty signals converge on the same host",
        })
    for obs in data.get("infrastructure_observations", []) or []:
        if not isinstance(obs, dict):
            continue
        obs_type = str(obs.get("type", "") or "infrastructure_observation")
        confidence = float(obs.get("confidence", 0.0) or 0.0)
        severity = str(obs.get("severity", "LOW") or "LOW").upper()
        if confidence < 0.64 and severity not in {"HIGH", "CRITICAL"}:
            continue
        if obs_type == "provider_edge_observation":
            continue
        if _ownership_scope(obs) == "third_party" and severity not in {"HIGH", "CRITICAL"}:
            continue
        append_finding({
            "type": "infrastructure_observation",
            "severity": severity,
            "title": normalize_text(obs.get("title", "Passive infrastructure observation")),
            "asset": obs.get("asset", ""),
            "confidence": round(max(0.2, min(confidence or 0.6, 0.99)), 3),
            "evidence": normalize_text(obs.get("description", "")),
            "source": obs.get("source", "ip_intelligence"),
            "classification": obs.get("classification", "passive"),
            "third_party_context": bool(obs.get("third_party_context", False)),
            "first_party": _is_first_party(obs),
            "observation_recency": _recency_bucket(obs),
            "evidence_type": _evidence_type(obs, "infrastructure_observation"),
            "ownership_scope": _ownership_scope(obs),
            "observation_type": obs_type,
            "why_prioritized": "Passive infrastructure evidence expands attack-surface understanding without direct target contact",
        })
    for endpoint in data.get("interesting_endpoints", []) or []:
        if not isinstance(endpoint, dict):
            continue
        priority = int(endpoint.get("priority_score", 0) or 0)
        confidence = float(endpoint.get("confidence", 0.0) or 0.0)
        asset_text = _asset_text(endpoint)
        if priority < 28 and confidence < 0.68:
            continue
        if _generic_metadata_asset(asset_text) and priority < 40:
            continue
        append_finding({
            "type": "exposure",
            "severity": "MEDIUM" if priority >= 34 else "LOW",
            "title": normalize_text(f"Interesting passive endpoint surfaced: {endpoint.get('category', 'endpoint')}"),
            "asset": endpoint.get("url", "") or endpoint.get("host", ""),
            "confidence": round(max(0.25, min(confidence or 0.6, 0.99)), 3),
            "evidence": normalize_text(", ".join(endpoint.get("reasons", [])[:4]) or endpoint.get("evidence", "")),
            "source": endpoint.get("source", "passive_artifact_intelligence"),
            "classification": endpoint.get("classification", "passive"),
            "third_party_context": bool(endpoint.get("third_party_context", False)),
            "first_party": _is_first_party(endpoint),
            "observation_recency": _recency_bucket(endpoint),
            "evidence_type": _evidence_type(endpoint, "exposure"),
            "observation_type": str(endpoint.get("category", "endpoint") or "endpoint"),
            "why_prioritized": "Endpoint looks operationally useful for passive triage and bug-bounty follow-up",
        })
    sev_rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    findings.sort(key=lambda f: (
        -float(f.get("ranking_score", f.get("priority_score", 0.0))),
        sev_rank.get(str(f.get("severity", "INFO")), 9),
        -float(f.get("confidence", 0.0)),
    ))
    deduped: List[Dict[str, Any]] = []
    seen = set()
    seen_assets: Dict[str, str] = {}
    family_counts: Dict[tuple, int] = {}
    type_counts: Dict[str, int] = {}
    historical_hints = 0
    infra_type_counts: Dict[str, int] = {}
    story_family_counts: Dict[tuple[str, str], int] = {}
    for finding in findings:
        key = (
            str(finding.get("type", "")),
            str(finding.get("severity", "")),
            str(finding.get("asset", "")),
            str(finding.get("title", "")),
        )
        if key in seen:
            continue
        finding_type = str(finding.get("type", ""))
        type_cap = {
            "high_value_target": 2,
            "infrastructure_observation": 1,
            "developer_reference": 2,
            "exposure_hint": 2,
        }.get(finding_type, 3)
        if type_counts.get(finding_type, 0) >= type_cap:
            continue
        asset_key = str(finding.get("asset", "") or "")
        prior_type = seen_assets.get(asset_key, "")
        if asset_key and prior_type and finding_type in {"potential_secret", "developer_reference", "exposure", "exposure_hint"} and prior_type in {"potential_secret", "developer_reference", "exposure", "exposure_hint"}:
            continue
        if finding_type == "high_value_target":
            family_asset = _normalized_story_family(asset_key)
            family_key = (finding_type, family_asset)
            if family_asset and story_family_counts.get(family_key, 0) >= 1:
                continue
        family = (str(finding.get("type", "")), str(finding.get("severity", "")))
        cap = 2 if str(finding.get("type", "")) == "exposure_hint" else 3
        if family_counts.get(family, 0) >= cap:
            continue
        if str(finding.get("type", "")) == "infrastructure_observation":
            obs_type = str(finding.get("observation_type", "") or "")
            obs_cap = 1 if obs_type in {"origin_candidate", "public_attack_surface_hint", "first_party_infra_signal", "passive_service_fingerprint"} else 2
            if infra_type_counts.get(obs_type, 0) >= obs_cap:
                continue
        if str(finding.get("type", "")) == "exposure_hint":
            if historical_hints >= 2:
                continue
            if deduped and len(deduped) >= 3 and historical_hints >= 1:
                continue
            historical_hints += 1
        seen.add(key)
        if asset_key and asset_key not in seen_assets:
            seen_assets[asset_key] = finding_type
        family_counts[family] = family_counts.get(family, 0) + 1
        if finding_type == "high_value_target":
            family_asset = _normalized_story_family(asset_key)
            if family_asset:
                family_key = (finding_type, family_asset)
                story_family_counts[family_key] = story_family_counts.get(family_key, 0) + 1
        type_counts[finding_type] = type_counts.get(finding_type, 0) + 1
        if str(finding.get("type", "")) == "infrastructure_observation":
            obs_type = str(finding.get("observation_type", "") or "")
            infra_type_counts[obs_type] = infra_type_counts.get(obs_type, 0) + 1
        deduped.append(finding)
    if deduped:
        return deduped[:12]
    fallback: List[Dict[str, Any]] = []
    for v in data.get("vulnerabilities", []) or []:
        if not isinstance(v, dict):
            continue
        if not str(v.get("description", "") or "").strip():
            continue
        fallback.append(_apply_canonical_finding_semantics({
            "type": _finding_family(v, "vulnerability"),
            "severity": _passive_effective_severity(v, "vulnerability"),
            "title": normalize_text(v.get("title") or v.get("cve_id") or "Passive finding"),
            "asset": v.get("affected_asset", ""),
            "confidence": float(v.get("confidence", 0.58) or 0.58),
            "evidence": normalize_text(v.get("description", "")),
            "source": v.get("source", ""),
            "classification": _finding_classification(v, "probable"),
            "why_prioritized": "Fallback surfaced because the report contains supported passive evidence.",
            "evidence_type": _evidence_type(v, "vulnerability"),
            "first_seen": v.get("first_seen", ""),
            "last_seen": v.get("last_seen", ""),
            "first_party": _is_first_party(v),
            "third_party_context": bool(v.get("third_party_context", False)),
        }, "vulnerability"))
    for endpoint in data.get("interesting_endpoints", []) or []:
        if not isinstance(endpoint, dict):
            continue
        if int(endpoint.get("priority_score", 0) or 0) < 24:
            continue
        fallback.append(_apply_canonical_finding_semantics({
            "type": "exposure",
            "severity": "MEDIUM" if int(endpoint.get("priority_score", 0) or 0) >= 34 else "LOW",
            "title": normalize_text(f"Interesting passive endpoint surfaced: {endpoint.get('category', 'endpoint')}"),
            "asset": endpoint.get("url", "") or endpoint.get("host", ""),
            "confidence": float(endpoint.get("confidence", 0.6) or 0.6),
            "evidence": normalize_text(", ".join(endpoint.get("reasons", [])[:4]) or endpoint.get("evidence", "")),
            "source": endpoint.get("source", ""),
            "classification": endpoint.get("classification", "passive"),
            "why_prioritized": "Fallback surfaced because archive/dork evidence produced actionable endpoint candidates.",
            "first_party": _is_first_party(endpoint),
            "third_party_context": bool(endpoint.get("third_party_context", False)),
            "observation_recency": _recency_bucket(endpoint),
            "evidence_type": _evidence_type(endpoint, "exposure"),
        }, "exposure"))
    for target in data.get("high_value_targets", []) or []:
        if not isinstance(target, dict):
            continue
        if int(target.get("score", 0) or 0) < 45:
            continue
        fallback.append(_apply_canonical_finding_semantics({
            "type": "high_value_target",
            "severity": "MEDIUM",
            "title": normalize_text(f"High-value passive target candidate: {target.get('host', '')}"),
            "asset": target.get("host", ""),
            "confidence": float(target.get("confidence", 0.64) or 0.64),
            "evidence": normalize_text(", ".join(target.get("reasons", [])[:4])),
            "source": "passive_artifact_intelligence",
            "classification": target.get("classification", "passive"),
            "why_prioritized": "Fallback surfaced because multiple passive signals converge on the same host.",
            "first_party": _is_first_party(target),
            "third_party_context": bool(target.get("third_party_context", False)),
            "observation_recency": _recency_bucket(target),
            "evidence_type": "derived_passive",
        }, "high_value_target"))
    for obs in data.get("infrastructure_observations", []) or []:
        if not isinstance(obs, dict):
            continue
        if str(obs.get("type", "")) in {"provider_edge_observation"}:
            continue
        fallback.append(_apply_canonical_finding_semantics({
            "type": "infrastructure_observation",
            "severity": str(obs.get("severity", "LOW") or "LOW").upper(),
            "title": normalize_text(obs.get("title", "Passive infrastructure observation")),
            "asset": obs.get("asset", ""),
            "confidence": float(obs.get("confidence", 0.62) or 0.62),
            "evidence": normalize_text(obs.get("description", "")),
            "source": obs.get("source", "ip_intelligence"),
            "classification": obs.get("classification", "passive"),
            "why_prioritized": "Fallback surfaced because passive infrastructure telemetry adds meaningful attack-surface context.",
            "first_party": _is_first_party(obs),
            "third_party_context": bool(obs.get("third_party_context", False)),
            "observation_recency": _recency_bucket(obs),
            "evidence_type": _evidence_type(obs, "infrastructure_observation"),
            "observation_type": str(obs.get("type", "") or ""),
        }, "infrastructure_observation"))
    if any(str(row.get("type", "")) in {"exposure", "high_value_target", "developer_reference", "infrastructure_observation"} for row in fallback):
        fallback = [
            row for row in fallback
            if not (str(row.get("type", "")) == "vulnerability" and str(row.get("severity", "INFO")).upper() in {"LOW", "INFO"})
        ]
    fallback_type_priority = {
        "exposure": 5,
        "high_value_target": 4,
        "developer_reference": 3,
        "infrastructure_observation": 2,
        "vulnerability": 1,
    }
    fallback.sort(key=lambda row: (
        -fallback_type_priority.get(str(row.get("type", "")), 0),
        -float(row.get("ranking_score", row.get("confidence", 0.0))),
        sev_rank.get(str(row.get("severity", "INFO")), 9),
        -float(row.get("confidence", 0.0)),
        str(row.get("asset", "")),
    ))
    return fallback[:6]


def _entities(data: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "subdomains": data.get("subdomains", []) or [],
        "emails": data.get("emails", []) or [],
        "technologies": data.get("technologies", []) or [],
        "certificates": data.get("ssl_info", []) or [],
        "ips": data.get("ip_records", []) or [],
        "infrastructure_observations": data.get("infrastructure_observations", []) or [],
        "asn": data.get("asn_intelligence", {}) or {},
        "asn_intelligence": data.get("asn_intelligence", {}) or {},
        "social_footprint": data.get("social_footprint") or {},
        "org": {"whois": data.get("whois_data", {}) or {}},
        "organizations": _organization_entities(data),
        "cloud": data.get("cloud_assets", []) or [],
        "reputation": data.get("reputation_data", {}) or {},
        "history": data.get("wayback_urls", {}) or {},
        "vulnerabilities": data.get("vulnerabilities", []) or [],
        "interesting_endpoints": data.get("interesting_endpoints", []) or [],
        "potential_secrets": data.get("potential_secrets", []) or [],
        "developer_references": data.get("developer_references", []) or [],
        "high_value_targets": data.get("high_value_targets", []) or [],
        "asset_clusters": data.get("asset_clusters", {}) or {},
        "email_security": data.get("email_security") or {},
        "takeover_candidates": data.get("takeover_records", []) or [],
        "historical_ips": (data.get("scan_context") or {}).get("historical_ips", []),
    }


def _organization_entities(data: Dict[str, Any]) -> List[Dict[str, Any]]:
    orgs: Dict[str, Dict[str, Any]] = {}

    def add_org(name: Any, source: str, *, confidence: float, extra: Dict[str, Any] | None = None) -> None:
        label = normalize_text(str(name or "")).strip()
        if not label:
            return
        key = label.lower()
        row = orgs.setdefault(
            key,
            {
                "name": label,
                "sources": [],
                "confidence": 0.0,
            },
        )
        if source not in row["sources"]:
            row["sources"].append(source)
        row["confidence"] = round(max(float(row.get("confidence", 0.0) or 0.0), confidence), 3)
        if extra:
            for extra_key, extra_value in extra.items():
                if extra_value not in (None, "", [], {}):
                    row[extra_key] = extra_value

    whois = data.get("whois_data", {}) or {}
    if isinstance(whois, dict):
        for key in ("org", "organization", "registrant_org", "registrant_organization", "registrar"):
            add_org(whois.get(key, ""), "whois", confidence=0.72)

    for ip_rec in data.get("ip_records", []) or []:
        if not isinstance(ip_rec, dict):
            continue
        add_org(
            ip_rec.get("org", ""),
            "ip_intelligence",
            confidence=0.76,
            extra={"country": ip_rec.get("country", ""), "asn": ip_rec.get("asn", "")},
        )

    asn_intel = data.get("asn_intelligence", {}) or {}
    if isinstance(asn_intel, dict):
        rows = asn_intel.get("list", []) if isinstance(asn_intel.get("list", []), list) else []
        for row in rows:
            if not isinstance(row, dict):
                continue
            add_org(
                row.get("org") or row.get("name", ""),
                "asn_intelligence",
                confidence=0.84,
                extra={"asn": row.get("asn", ""), "country": row.get("country", "")},
            )

    social = data.get("social_footprint", {}) or {}
    if isinstance(social, dict):
        github_org = social.get("github_org", {}) if isinstance(social.get("github_org", {}), dict) else {}
        add_org(
            github_org.get("name", ""),
            "github_org",
            confidence=0.66,
            extra={"location": github_org.get("location", ""), "blog": github_org.get("blog", "")},
        )
        for app in social.get("ios_apps", []) or []:
            if isinstance(app, dict):
                add_org(app.get("developer", ""), "itunes", confidence=0.52)

    org_list = list(orgs.values())
    org_list.sort(key=lambda row: (-float(row.get("confidence", 0.0)), str(row.get("name", ""))))
    return org_list[:40]


def _errors_summary(errors: List[Dict[str, Any]]) -> Dict[str, Any]:
    by_source: Dict[str, int] = {}
    by_module: Dict[str, int] = {}
    by_kind: Dict[str, int] = {}
    for err in errors:
        src = str((err or {}).get("source", "unknown"))
        mod = str((err or {}).get("module", "unknown"))
        kind = str((err or {}).get("kind", "unknown"))
        by_source[src] = by_source.get(src, 0) + 1
        by_module[mod] = by_module.get(mod, 0) + 1
        by_kind[kind] = by_kind.get(kind, 0) + 1
    return {
        "total": len(errors),
        "by_source": by_source,
        "by_module": by_module,
        "by_kind": by_kind,
    }


def _entity_graph(data: Dict[str, Any]) -> Dict[str, Any]:
    nodes: List[Dict[str, Any]] = []
    edges: List[Dict[str, Any]] = []
    def _edge(frm: str, to: str, relation: str, source: str, confidence: float = 0.7) -> Dict[str, Any]:
        return {
            "source": frm,
            "target": to,
            "from": frm,
            "to": to,
            "rel": relation,
            "relation": relation,
            "type": relation,
            "evidence_source": source,
            "source_confidence": round(float(confidence), 3),
        }

    domain = str(data.get("domain", ""))
    if domain:
        nodes.append({"id": f"domain:{domain}", "type": "domain", "label": domain})
    technologies = data.get("technologies", []) or []
    for s in data.get("subdomains", []) or []:
        name = str((s or {}).get("name", ""))
        if not name:
            continue
        sid = f"subdomain:{name}"
        nodes.append({"id": sid, "type": "subdomain", "label": name, "confidence": (s or {}).get("confidence", 0)})
        if domain:
            edges.append(_edge(f"domain:{domain}", sid, "contains", "subdomain_enumerator", float((s or {}).get("confidence", 0.7) or 0.7)))
        for src in (s or {}).get("sources", []) or []:
            src_id = f"source:{src}"
            nodes.append({"id": src_id, "type": "source", "label": src})
            edges.append(_edge(sid, src_id, "seen_in", str(src), float((s or {}).get("confidence", 0.65) or 0.65)))
        for ip in ((s or {}).get("ips", []) or []) + ((s or {}).get("resolved_ips", []) or []):
            ip_s = _normalize_ip(ip)
            if not ip_s:
                continue
            ip_node = f"ip:{ip_s}"
            nodes.append({"id": ip_node, "type": "ip", "label": ip_s})
            edges.append(_edge(sid, ip_node, "resolves_to", "subdomain_resolution", float((s or {}).get("confidence", 0.75) or 0.75)))
    for cert in data.get("ssl_info", []) or []:
        if not isinstance(cert, dict):
            continue
        cert_id_val = (
            cert.get("fingerprint")
            or cert.get("serial_number")
            or cert.get("common_name")
            or cert.get("subject")
            or ""
        )
        if not cert_id_val:
            continue
        cert_id = f"cert:{cert_id_val}"
        nodes.append({"id": cert_id, "type": "certificate", "label": str(cert.get("common_name") or cert.get("subject") or cert_id_val)})
        cert_hosts = set()
        for key in ("common_name", "subject_cn", "subject"):
            host = str(cert.get(key, "")).strip().lower().lstrip("*.")
            if host:
                cert_hosts.add(host)
        for san_key in ("san", "san_dns", "sans", "san_entries"):
            san_values = cert.get(san_key, [])
            if isinstance(san_values, list):
                for host in san_values:
                    host_n = str(host).strip().lower().lstrip("*.")
                    if host_n:
                        cert_hosts.add(host_n)
        for host in cert_hosts:
            sid = f"subdomain:{host}"
            nodes.append({"id": sid, "type": "subdomain", "label": host})
            edges.append(_edge(cert_id, sid, "cert_for", "certificate_intelligence", 0.82))
    wayback = data.get("wayback_urls", {}) or {}
    if isinstance(wayback, dict):
        wb_urls = []
        for key in ("interesting", "urls", "all", "all_urls"):
            candidate = wayback.get(key, [])
            if isinstance(candidate, list):
                wb_urls.extend(candidate[:200])
        for entry in wb_urls:
            url = entry.get("url", "") if isinstance(entry, dict) else str(entry)
            host = ""
            try:
                host = str(urlparse(url).hostname or "").lower()
            except Exception:
                host = ""
            if not url:
                continue
            archive_id = f"archive:{url[:120]}"
            nodes.append({"id": archive_id, "type": "archive", "label": url})
            if host:
                sid = f"subdomain:{host}"
                nodes.append({"id": sid, "type": "subdomain", "label": host})
                edges.append(_edge(sid, archive_id, "archived_url", "web_archive", 0.75))
            elif domain:
                edges.append(_edge(f"domain:{domain}", archive_id, "archived_url", "web_archive", 0.72))
    for asset in data.get("cloud_assets", []) or []:
        if not isinstance(asset, dict):
            continue
        label = str(asset.get("name") or asset.get("asset_type") or "cloud_asset")
        node_id = f"cloud:{label}"
        classification = str(asset.get("classification", "heuristic") or "heuristic")
        confidence = float(asset.get("confidence", 0.5) or 0.5)
        relation = "cloud_asset_evidence" if classification in {"evidenced", "probable"} else "cloud_asset_heuristic"
        nodes.append({"id": node_id, "type": "cloud_asset", "label": label, "classification": classification, "confidence": confidence})
        linked_host = str(asset.get("subdomain") or asset.get("domain") or asset.get("host") or "").lower()
        if linked_host:
            sid = f"subdomain:{linked_host}"
            nodes.append({"id": sid, "type": "subdomain", "label": linked_host})
            edges.append(_edge(sid, node_id, relation, str(asset.get("source", "cloud_assets")), confidence))
        elif domain:
            edges.append(_edge(f"domain:{domain}", node_id, relation, str(asset.get("source", "cloud_assets")), confidence))
    for e in data.get("emails", []) or []:
        addr = str((e or {}).get("email", ""))
        if not addr:
            continue
        eid = f"email:{addr}"
        nodes.append({"id": eid, "type": "email", "label": addr, "confidence": (e or {}).get("confidence", 0)})
        if domain:
            email_host = addr.rsplit("@", 1)[-1].strip().lower() if "@" in addr else ""
            if email_host == domain or email_host.endswith("." + domain):
                edges.append(_edge(f"domain:{domain}", eid, "owns", "email_discovery", float((e or {}).get("confidence", 0.62) or 0.62)))
        for attrib in (e or {}).get("source_attribution", []) or []:
            ref_url = str((attrib or {}).get("ref_url", "") or "")
            if not ref_url:
                continue
            archive_id = f"archive:{ref_url[:120]}"
            nodes.append({"id": archive_id, "type": "archive", "label": ref_url})
            edges.append(_edge(eid, archive_id, "email_evidence", str((attrib or {}).get("source", "email_discovery")), float((attrib or {}).get("confidence", 0.6) or 0.6)))
    social_profiles = ((data.get("social_footprint", {}) or {}).get("profiles", {}) or {}) if isinstance(data.get("social_footprint", {}), dict) else {}
    if isinstance(social_profiles, dict):
        for platform, profile_url in social_profiles.items():
            url = str(profile_url or "").strip()
            if not url:
                continue
            social_id = f"social:{platform}:{url[:100]}"
            nodes.append({"id": social_id, "type": "social_profile", "label": url, "platform": str(platform)})
            if domain:
                edges.append(_edge(f"domain:{domain}", social_id, "social_profile", "social_footprint", 0.76))
    for tech in technologies:
        if not isinstance(tech, dict):
            continue
        tech_name = normalize_text(str(tech.get("name", "") or "")).strip()
        if not tech_name:
            continue
        tech_id = f"technology:{tech_name.lower()}"
        nodes.append({
            "id": tech_id,
            "type": "technology",
            "label": tech_name,
            "category": str(tech.get("category", "") or ""),
            "confidence": str(tech.get("confidence", "") or ""),
            "version": str(tech.get("version", "") or ""),
        })
        if domain:
            edges.append(_edge(f"domain:{domain}", tech_id, "uses_technology", str((tech.get("sources", []) or ["technology_detection"])[0]), 0.74))
    for ip_rec in data.get("ip_records", []) or []:
        if not isinstance(ip_rec, dict):
            continue
        ip = str(ip_rec.get("ip", "") or "").strip()
        if not ip:
            continue
        ip_node = f"ip:{ip}"
        nodes.append({"id": ip_node, "type": "ip", "label": ip})
        asn = str(ip_rec.get("asn", "") or "").strip().upper()
        if asn:
            asn_norm = asn if asn.startswith("AS") else f"AS{asn}"
            asn_node = f"asn:{asn_norm}"
            nodes.append({"id": asn_node, "type": "asn", "label": asn_norm})
            edges.append(_edge(ip_node, asn_node, "announced_by", "ip_intelligence", 0.86))
        rdns = str(ip_rec.get("rdns", "") or "").strip().lower()
        if rdns:
            sid = f"subdomain:{rdns}"
            nodes.append({"id": sid, "type": "subdomain", "label": rdns})
            edges.append(_edge(sid, ip_node, "resolves_to", "ip_intelligence", 0.8))
        org_name = normalize_text(str(ip_rec.get("org", "") or "")).strip()
        if org_name:
            org_id = f"org:{org_name[:100]}"
            nodes.append({"id": org_id, "type": "organization", "label": org_name})
            edges.append(_edge(ip_node, org_id, "operated_by", "ip_intelligence", 0.78))
    asn_intel = data.get("asn_intelligence", {}) or {}
    if isinstance(asn_intel, dict):
        asn_rows: List[Tuple[str, Dict[str, Any]]] = []
        by_asn = asn_intel.get("by_asn", {}) if isinstance(asn_intel.get("by_asn", {}), dict) else {}
        if by_asn:
            for asn_key, asn_meta in by_asn.items():
                if isinstance(asn_meta, dict):
                    asn_rows.append((str(asn_key or ""), asn_meta))
        else:
            for asn_key, asn_meta in asn_intel.items():
                if asn_key in {"list", "providers"}:
                    continue
                if isinstance(asn_meta, dict):
                    asn_rows.append((str(asn_key or ""), asn_meta))
        for asn_key, asn_meta in asn_rows:
            asn_norm = str(asn_key or asn_meta.get("asn", "")).strip().upper()
            if not asn_norm:
                continue
            if not asn_norm.startswith("AS"):
                asn_norm = f"AS{asn_norm}"
            asn_node = f"asn:{asn_norm}"
            label = str((asn_meta or {}).get("name") or (asn_meta or {}).get("org") or asn_norm)
            nodes.append({"id": asn_node, "type": "asn", "label": label})
            if domain:
                edges.append(_edge(f"domain:{domain}", asn_node, "uses_asn", "asn_intelligence", 0.78))
            org_name = str((asn_meta or {}).get("org") or (asn_meta or {}).get("name") or "").strip()
            if org_name:
                org_id = f"org:{org_name[:100]}"
                nodes.append({"id": org_id, "type": "organization", "label": org_name})
                edges.append(_edge(asn_node, org_id, "operated_by", "asn_intelligence", 0.82))
    for org in _organization_entities(data):
        if not isinstance(org, dict):
            continue
        org_name = normalize_text(str(org.get("name", "") or "")).strip()
        if not org_name:
            continue
        org_id = f"org:{org_name[:100]}"
        nodes.append({"id": org_id, "type": "organization", "label": org_name, "confidence": float(org.get("confidence", 0.0) or 0.0)})
        for source_name in org.get("sources", []) or []:
            src_id = f"source:{source_name}"
            nodes.append({"id": src_id, "type": "source", "label": str(source_name)})
            edges.append(_edge(org_id, src_id, "seen_in", str(source_name), float(org.get("confidence", 0.7) or 0.7)))
        if domain:
            edges.append(_edge(f"domain:{domain}", org_id, "associated_with", "organization_correlation", float(org.get("confidence", 0.72) or 0.72)))
    whois = data.get("whois_data", {}) or {}
    if isinstance(whois, dict):
        for key in ("org", "organization", "registrant_org", "registrant_organization", "registrar"):
            org_name = normalize_text(str(whois.get(key, "") or "")).strip()
            if not org_name or not domain:
                continue
            org_id = f"org:{org_name[:100]}"
            nodes.append({"id": org_id, "type": "organization", "label": org_name})
            edges.append(_edge(f"domain:{domain}", org_id, "registered_to", "whois", 0.74))
    for v in data.get("vulnerabilities", []) or []:
        if not isinstance(v, dict):
            continue
        vid = str(v.get("cve_id") or v.get("title") or "").strip()
        if not vid:
            continue
        node_id = f"finding:{vid[:90]}"
        nodes.append({"id": node_id, "type": "finding", "label": str(v.get("title") or vid), "severity": str(v.get("severity", "LOW"))})
        asset = str(v.get("affected_asset", "") or "").strip().lower().lstrip("*.")
        if asset:
            target_node = f"subdomain:{asset}" if "." in asset else f"domain:{asset}"
            nodes.append({"id": target_node, "type": "subdomain" if "." in asset else "domain", "label": asset})
            edges.append(_edge(target_node, node_id, "has_finding", str(v.get("source", "vuln_engine")), float(v.get("confidence", 0.75) or 0.75)))
    uniq_nodes = {n["id"]: n for n in nodes}
    return {"nodes": list(uniq_nodes.values()), "edges": edges}


def _coverage_score(data: Dict[str, Any], completeness: Dict[str, Any], coverage: Dict[str, Any]) -> float:
    comp = float(completeness.get("overall_percent", 0))
    effective_source_diversity = 0.0
    weighted_source_bonus = 0.0
    for module_name, module in (coverage or {}).items():
        if str(module_name).startswith("_") or not isinstance(module, dict):
            continue
        sources = (module or {}).get("sources", {})
        if not isinstance(sources, dict):
            continue
        module_seen = 0.0
        for source_name, source_data in sources.items():
            if not isinstance(source_data, dict):
                continue
            status = str(source_data.get("status", "ok") or "ok").lower()
            if status in {"fail", "failed", "timeout", "error"}:
                continue
            weight = source_weight(str(source_name))
            module_seen += weight
            weighted_source_bonus += min(
                12.0,
                float(source_data.get("items_aceptados", source_data.get("items_parseados", 0)) or 0) * weight * 0.08,
            )
        effective_source_diversity += min(8.0, module_seen)
    src_component = min(100.0, (effective_source_diversity * 5.0) + weighted_source_bonus)
    findings_component = min(100.0, len(data.get("top_findings", [])) * 6.0)
    return round((comp * 0.55) + (src_component * 0.3) + (findings_component * 0.15), 1)


def _analyst_summary(data: Dict[str, Any], summary: Dict[str, int], risk_details: Dict[str, Any]) -> Dict[str, Any]:
    subdomains = int(summary.get("subdomains", 0) or 0)
    first_party_hvts = [
        row for row in (data.get("high_value_targets", []) or [])
        if isinstance(row, dict) and bool(row.get("first_party", True))
    ]
    strong_hvts = [row for row in first_party_hvts if _strong_hvt(row)]
    exposures = [row for row in (data.get("interesting_endpoints", []) or []) if isinstance(row, dict)]
    strong_exposures = [
        row for row in exposures
        if str(row.get("category", "") or "") in {"admin", "auth", "graphql", "api", "internal"}
        and str(row.get("observation_recency", "") or "") != "historical_only"
    ]
    secrets = [
        row for row in (data.get("potential_secrets", []) or [])
        if isinstance(row, dict) and str(row.get("classification", "") or "") in {"probable_secret_exposure", "strong_passive_exposure"}
    ]
    devrefs = [
        row for row in (data.get("developer_references", []) or [])
        if isinstance(row, dict) and float(row.get("confidence", 0.0) or 0.0) >= 0.58
    ]
    bullets: List[str] = []
    if subdomains >= 5000:
        bullets.append(f"Large passive namespace recovered: {subdomains} subdomains.")
    elif subdomains >= 500:
        bullets.append(f"Broad passive namespace recovered: {subdomains} subdomains.")
    elif subdomains > 0:
        bullets.append(f"Passive host inventory recovered: {subdomains} subdomains.")
    else:
        bullets.append("No credible subdomains survived passive validation; apex-only evidence remains the primary story.")
    if strong_hvts:
        bullets.append(f"{len(strong_hvts)} high-value target(s) show multi-signal convergence from passive artifacts.")
    elif first_party_hvts:
        bullets.append(f"{len(first_party_hvts)} high-value target candidate(s) were ranked from hostname and infrastructure convergence.")
    if strong_exposures:
        bullets.append(f"{len(strong_exposures)} current or recent analyst-useful endpoint exposure(s) surfaced.")
    elif exposures:
        bullets.append(f"{len(exposures)} archived endpoint exposure(s) remain useful for historical triage.")
    if secrets:
        bullets.append(f"{len(secrets)} passive secret exposure signal(s) survived weak-artifact downgrades.")
    if devrefs:
        bullets.append(f"{len(devrefs)} developer-facing artifact(s) may reveal build or integration surface.")
    return {
        "headline": bullets[0] if bullets else "Passive surface summary unavailable.",
        "bullets": bullets[:4],
        "focus": "first_party_passive_evidence",
        "risk_evidence_count": int(risk_details.get("evidence_count", 0) or 0),
    }


def _quick_wins(data: Dict[str, Any], top_findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    wins: List[Dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()

    def push(kind: str, title: str, asset: str, detail: str, severity: str) -> None:
        asset_text = normalize_text(asset)
        key = (str(kind), asset_text)
        if key in seen or not asset_text:
            return
        seen.add(key)
        wins.append({
            "kind": kind,
            "title": normalize_text(title),
            "asset": asset_text,
            "detail": normalize_text(detail)[:220],
            "severity": str(severity or "LOW").upper(),
        })

    for row in (data.get("takeover_records", []) or []):
        if not isinstance(row, dict):
            continue
        status = str(row.get("status", "") or "").upper()
        if status in {"VULNERABLE", "LIKELY_VULNERABLE", "POTENTIAL"}:
            push(
                "takeover_candidate",
                f"Takeover candidate on {row.get('subdomain', '')}",
                str(row.get("subdomain", "") or ""),
                str(row.get("evidence", "") or "Dangling provider mapping detected."),
                "HIGH" if status == "VULNERABLE" else "MEDIUM",
            )
    for row in (data.get("interesting_endpoints", []) or []):
        if not isinstance(row, dict):
            continue
        category = str(row.get("category", "") or "")
        if category not in {"admin", "auth", "graphql", "api", "internal"}:
            continue
        push(
            "endpoint_exposure",
            f"Review {category} endpoint exposure",
            str(row.get("url", "") or row.get("host", "")),
            ", ".join(row.get("reasons", [])[:3]) if isinstance(row.get("reasons", []), list) else str(row.get("evidence", "") or ""),
            "MEDIUM",
        )
    for row in (data.get("potential_secrets", []) or []):
        if not isinstance(row, dict):
            continue
        classification = str(row.get("classification", "") or "")
        if classification not in {"probable_secret_exposure", "strong_passive_exposure"}:
            continue
        push(
            "secret_exposure",
            f"Investigate passive {row.get('secret_type', 'secret')} exposure",
            str(row.get("location", "") or ""),
            str(row.get("match_preview", "") or row.get("evidence", "") or ""),
            "HIGH" if classification == "strong_passive_exposure" else "MEDIUM",
        )
    wayback = data.get("wayback_urls", {}) or {}
    if isinstance(wayback, dict):
        for row in (wayback.get("sensitive_files", []) or [])[:10]:
            asset = str(row.get("url", "") or "") if isinstance(row, dict) else str(row or "")
            if asset:
                push("archive_sensitive", "Inspect sensitive archived file", asset, "Archived sensitive file path preserved in passive corpus.", "MEDIUM")
    for row in (top_findings or [])[:8]:
        if not isinstance(row, dict):
            continue
        push(
            str(row.get("type", "finding") or "finding"),
            str(row.get("title", "") or "Priority finding"),
            str(row.get("asset", "") or ""),
            str(row.get("why_prioritized", "") or row.get("evidence", "") or ""),
            str(row.get("severity", "LOW") or "LOW"),
        )
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    wins.sort(key=lambda row: (severity_order.get(str(row.get("severity", "INFO")), 9), str(row.get("title", ""))))
    return wins[:5]


def _executive_overview(data: Dict[str, Any], top_findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    high_value_targets = [
        {
            "host": row.get("host", ""),
            "score": int(row.get("score", 0) or 0),
            "reasons": list((row.get("reasons", []) or [])[:3]),
        }
        for row in (data.get("high_value_targets", []) or [])
        if isinstance(row, dict)
    ][:5]
    artifact_preview = []
    for row in (data.get("developer_references", []) or [])[:3]:
        if isinstance(row, dict):
            artifact_preview.append({
                "kind": "developer_artifact",
                "label": str(row.get("category", "developer_reference") or "developer_reference"),
                "asset": str(row.get("location", "") or row.get("host", "")),
            })
    for row in (data.get("interesting_endpoints", []) or [])[:3]:
        if isinstance(row, dict):
            artifact_preview.append({
                "kind": "passive_endpoint",
                "label": str(row.get("category", "endpoint") or "endpoint"),
                "asset": str(row.get("url", "") or row.get("host", "")),
            })
    top_preview = [
        {
            "type": row.get("type", ""),
            "title": row.get("title", ""),
            "asset": row.get("asset", ""),
            "severity": row.get("severity", "INFO"),
        }
        for row in (top_findings or [])[:6]
    ]
    return {
        "priority_findings": top_preview,
        "priority_targets": high_value_targets,
        "priority_artifacts": artifact_preview[:6],
        "quick_wins": _quick_wins(data, top_findings),
    }


def _parse_seen_date(value: Any) -> datetime | None:
    if value is None:
        return None
    raw = str(value).strip()
    if not raw:
        return None
    raw = raw.replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(raw)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except ValueError:
        pass
    normalized = raw.replace("T", " ").split("+", 1)[0]
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
        try:
            dt = datetime.strptime(normalized, fmt).replace(tzinfo=timezone.utc)
            return dt
        except ValueError:
            continue
    return None


def _freshness_weight(first_seen: Any, last_seen: Any) -> float:
    now = datetime.now(timezone.utc)
    seen = _parse_seen_date(last_seen) or _parse_seen_date(first_seen)
    if seen is None:
        return 0.6
    age_days = max(0.0, (now - seen).total_seconds() / 86400.0)
    if age_days <= 30:
        return 1.0
    if age_days <= 90:
        return 0.8
    if age_days <= 365:
        return 0.6
    return 0.4


def _risk_score_details(data: Dict[str, Any], summary: Dict[str, int]) -> Dict[str, Any]:
    sev_weight = {"CRITICAL": 11.0, "HIGH": 6.5, "MEDIUM": 3.2, "LOW": 1.0, "INFO": 0.3}
    risk = 0.0
    evidence_count = 0
    weighted_events = 0
    by_type = {"vulnerability": 0, "takeover": 0, "correlation": 0}
    by_severity = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for v in data.get("vulnerabilities", []) or []:
        if not isinstance(v, dict):
            continue
        evidence = str(v.get("description", "") or "").strip()
        if not evidence:
            continue
        sev = _passive_effective_severity(v, "vulnerability")
        classification = _finding_classification(v, "evidenced")
        conf = float(v.get("confidence", 0.72 if classification == "evidenced" else 0.64) or 0.0)
        class_mult = {
            "confirmed": 1.0,
            "evidenced": 1.0,
            "probable": 0.62,
            "probable_secret_exposure": 0.62,
            "strong_passive_exposure": 0.78,
            "passive": 0.45,
            "suspicious_secret_reference": 0.32,
            "weak_artifact": 0.18,
            "heuristic": 0.25,
            "hint": 0.18,
        }.get(classification, 0.5)
        fresh = _freshness_weight(v.get("first_seen"), v.get("last_seen"))
        risk += sev_weight.get(sev, 1.0) * max(0.18, min(conf, 1.0)) * fresh * class_mult * _priority_multiplier(v)
        evidence_count += 1
        weighted_events += 1
        by_type["vulnerability"] += 1
        by_severity[sev if sev in by_severity else "INFO"] += 1
    for t in data.get("takeover_records", []) or []:
        if not isinstance(t, dict):
            continue
        evidence = str(t.get("evidence", "") or "").strip()
        if not evidence:
            continue
        status = str(t.get("status", "")).upper()
        fresh = _freshness_weight(t.get("first_seen"), t.get("last_seen"))
        if status == "VULNERABLE":
            risk += 8.5 * fresh * _priority_multiplier(t)
            by_severity["HIGH"] += 1
        elif status in {"POTENTIAL", "LIKELY_VULNERABLE"}:
            risk += 3.4 * fresh * _priority_multiplier(t)
            by_severity["MEDIUM"] += 1
        else:
            continue
        evidence_count += 1
        weighted_events += 1
        by_type["takeover"] += 1
    for c in data.get("correlations", []) or []:
        if not isinstance(c, dict):
            continue
        detail = str(c.get("detail", "") or "").strip()
        if not detail:
            continue
        sev = _passive_effective_severity(c, "correlation")
        fresh = _freshness_weight(c.get("first_seen"), c.get("last_seen"))
        if sev in {"CRITICAL", "HIGH", "MEDIUM"}:
            classification = _finding_classification(c, "probable")
            corr_conf = float(c.get("confidence", 0.7) or 0.7)
            class_mult = 1.0 if classification in {"evidenced", "confirmed"} else (0.54 if classification == "probable" else 0.24)
            risk += sev_weight.get(sev, 1.0) * fresh * max(0.22, min(corr_conf, 1.0)) * class_mult * _priority_multiplier(c)
            evidence_count += 1
            weighted_events += 1
            by_type["correlation"] += 1
            by_severity[sev] += 1
    for obs in data.get("infrastructure_observations", []) or []:
        if not isinstance(obs, dict):
            continue
        sev = str(obs.get("severity", "LOW") or "LOW").upper()
        if sev not in {"CRITICAL", "HIGH", "MEDIUM", "LOW"}:
            sev = "LOW"
        conf = float(obs.get("confidence", 0.62) or 0.62)
        class_mult = 0.62 if str(obs.get("classification", "passive")) in {"probable", "passive"} else 0.45
        risk += sev_weight.get(sev, 1.0) * max(0.2, min(conf, 1.0)) * class_mult * 0.55 * _priority_multiplier(obs)
        evidence_count += 1
        weighted_events += 1
        by_type.setdefault("infrastructure_observation", 0)
        by_type["infrastructure_observation"] += 1
        by_severity[sev] += 1
    for target in data.get("high_value_targets", []) or []:
        if not isinstance(target, dict):
            continue
        score = int(target.get("score", 0) or 0)
        if score < 55:
            continue
        conf = float(target.get("confidence", 0.68) or 0.68)
        risk += min(3.5, (score / 100.0) * max(0.25, min(conf, 1.0)) * 4.0)
        evidence_count += 1
        weighted_events += 1
        by_type.setdefault("high_value_target", 0)
        by_type["high_value_target"] += 1
        by_severity["MEDIUM" if score < 78 else "HIGH"] += 1
    for secret in data.get("potential_secrets", []) or []:
        if not isinstance(secret, dict):
            continue
        classification = str(secret.get("classification", "") or "")
        if classification not in {"probable_secret_exposure", "strong_passive_exposure"}:
            continue
        conf = float(secret.get("confidence", 0.0) or 0.0)
        risk += (3.2 if classification == "strong_passive_exposure" else 1.8) * max(0.25, min(conf, 1.0)) * _priority_multiplier(secret)
        evidence_count += 1
        weighted_events += 1
        by_type.setdefault("potential_secret", 0)
        by_type["potential_secret"] += 1
        by_severity["HIGH" if classification == "strong_passive_exposure" else "MEDIUM"] += 1
    endpoint_rows = [row for row in (data.get("interesting_endpoints", []) or []) if isinstance(row, dict)]
    meaningful_current_endpoints = 0
    for row in endpoint_rows:
        category = str(row.get("category", "") or "endpoint")
        if category not in {"admin", "auth", "graphql", "api", "internal"}:
            continue
        recency = _recency_bucket(row)
        meaningful_current_endpoints += 1
        risk += 0.95 if recency == "current_passive" else 0.55 if recency == "recent_passive" else 0.25
    devref_rows = [row for row in (data.get("developer_references", []) or []) if isinstance(row, dict)]
    for row in devref_rows:
        category = str(row.get("category", "") or "").lower()
        conf = float(row.get("confidence", 0.0) or 0.0)
        if conf < 0.58:
            continue
        if category in {"config_exposure", "credentials", "source_map", "swagger", "openapi", "graphql", "manifest", "build_metadata"}:
            risk += 0.55
            evidence_count += 1
            weighted_events += 1
            by_type.setdefault("developer_reference", 0)
            by_type["developer_reference"] += 1
            by_severity["LOW" if category not in {"config_exposure", "credentials"} else "MEDIUM"] += 1
    subs_count = int(summary.get("subdomains", 0) or 0)
    infra_first_party = len([
        row for row in (data.get("infrastructure_observations", []) or [])
        if isinstance(row, dict) and _ownership_scope(row) == "first_party"
    ])
    hvt_count = len([row for row in (data.get("high_value_targets", []) or []) if isinstance(row, dict) and int(row.get("score", 0) or 0) >= 48])
    strong_hvt_count = len([
        row for row in (data.get("high_value_targets", []) or [])
        if isinstance(row, dict) and _strong_hvt(row) and int(row.get("score", 0) or 0) >= 42
    ])
    strong_devrefs = len([
        row for row in (data.get("developer_references", []) or [])
        if isinstance(row, dict)
        and float(row.get("confidence", 0.0) or 0.0) >= 0.58
        and str(row.get("category", "") or "").lower() in {"config_exposure", "credentials", "source_map", "swagger", "openapi", "graphql", "manifest", "build_metadata"}
    ])
    strong_secret_count = len([
        row for row in (data.get("potential_secrets", []) or [])
        if isinstance(row, dict) and str(row.get("classification", "") or "") in {"probable_secret_exposure", "strong_passive_exposure"}
    ])
    source_diversity = 0
    for module_metrics in (data.get("source_metrics", {}) or {}).values():
        if not isinstance(module_metrics, dict):
            continue
        source_diversity += len([
            row for row in module_metrics.values()
            if isinstance(row, dict) and str(row.get("status", "ok")) in {"ok", "partial", "derived", "derived_ok"}
        ])
    surface_depth_bonus = 0.0
    if subs_count >= 80:
        surface_depth_bonus += 1.0
    if subs_count >= 300:
        surface_depth_bonus += 2.0
    if subs_count >= 500:
        surface_depth_bonus += 1.0
    if subs_count >= 800:
        surface_depth_bonus += 1.0
    if subs_count >= 1000:
        surface_depth_bonus += 3.0
    if subs_count >= 4000:
        surface_depth_bonus += 3.5
    if subs_count >= 7000:
        surface_depth_bonus += 3.0
    if infra_first_party >= 5:
        surface_depth_bonus += 1.5
    if infra_first_party >= 12:
        surface_depth_bonus += 1.5
    if hvt_count >= 6:
        surface_depth_bonus += 1.5
    if hvt_count >= 15:
        surface_depth_bonus += 2.0
    if strong_hvt_count >= 1:
        surface_depth_bonus += 1.0
    if strong_hvt_count >= 2:
        surface_depth_bonus += 2.0
    if strong_hvt_count >= 5:
        surface_depth_bonus += 2.0
    if meaningful_current_endpoints >= 1:
        surface_depth_bonus += 0.8
    if meaningful_current_endpoints >= 2:
        surface_depth_bonus += 1.0
    if strong_secret_count >= 1:
        surface_depth_bonus += 1.5
    if strong_devrefs >= 2:
        surface_depth_bonus += 1.5
    if source_diversity >= 10:
        surface_depth_bonus += 1.0
    if source_diversity >= 25:
        surface_depth_bonus += 1.5
    risk += min(18.0, surface_depth_bonus)
    evidence_bonus = min(7.0, evidence_count * 0.55) if evidence_count > 0 else 0.0
    evidence_exposures = min(int(summary.get("exposures", 0) or 0), evidence_count)
    if evidence_exposures > 0:
        risk += min(3.0, evidence_exposures * 0.25)
    risk += evidence_bonus
    # Penalize noisy scans where source error ratio is high, so weak evidence cannot dominate.
    src_items = 0
    src_errors = 0
    for module_metrics in (data.get("source_metrics", {}) or {}).values():
        if not isinstance(module_metrics, dict):
            continue
        for m in module_metrics.values():
            if not isinstance(m, dict):
                continue
            src_items += int(m.get("items_obtenidos", m.get("items_parseados", m.get("items_aceptados", 0))) or 0)
            src_errors += int(m.get("errores", 0) or 0)
    reliability = 1.0
    if (src_items + src_errors) > 0:
        err_rate = src_errors / max(1, src_items + src_errors)
        reliability = max(0.85, 1.0 - (err_rate * 0.25))
        risk *= reliability
    score = round(min(100.0, max(0.0, risk)), 1)
    explain_bits = []
    if int(summary.get("ports", 0) or 0) > 0:
        explain_bits.append(f"{int(summary.get('ports', 0) or 0)} open ports")
    if int(summary.get("subdomains", 0) or 0) > 0:
        explain_bits.append(f"{int(summary.get('subdomains', 0) or 0)} subdomains")
    if int(summary.get("vulns", 0) or 0) > 0:
        explain_bits.append(f"{int(summary.get('vulns', 0) or 0)} vulnerability findings")
    if int(summary.get("archive_urls", 0) or 0) > 0:
        explain_bits.append(f"{int(summary.get('archive_urls', 0) or 0)} archive URLs")
    explain_short = "Passive evidence weighted by strength, confidence and freshness."
    if explain_bits:
        explain_short = f"Driven by: {', '.join(explain_bits[:4])}."
    return {
        "score": score,
        "explain_short": explain_short,
        "formula": "sum(adjusted_severity * confidence * freshness * classification_factor) + bounded evidence bonus",
        "evidence_count": evidence_count,
        "evidence_exposures": evidence_exposures,
        "weighted_events": weighted_events,
        "source_reliability_factor": round(reliability, 4),
        "counts_by_type": by_type,
        "counts_by_severity": by_severity,
    }


def _risk_level(score: float) -> str:
    if score >= 85:
        return "CRITICAL"
    if score >= 68:
        return "HIGH"
    if score >= 40:
        return "MEDIUM"
    return "LOW"


def _sanitize_interesting_archive_paths(rows: Any) -> List[Dict[str, Any]]:
    sanitized: List[Dict[str, Any]] = []
    seen: set[str] = set()
    for row in list(rows or []):
        if not isinstance(row, dict):
            continue
        url = normalize_text(str(row.get("url", "") or "")).strip()
        if not url:
            continue
        parts = _artifact_url_parts(
            url,
            host_hint=str(row.get("host", "") or ""),
            path_hint=str(row.get("path", "") or ""),
        )
        if _artifact_is_low_value_noise(parts):
            continue
        if not _artifact_has_strong_signal(parts):
            continue
        if url in seen:
            continue
        seen.add(url)
        sanitized.append(row)
    return sanitized


def _web_archive_export(data: Dict[str, Any]) -> Dict[str, Any]:
    """Export structured web archive data with preserved totals and fallback coverage."""
    wayback = data.get("wayback_urls", {}) or {}
    domain = normalize_text(str(data.get("domain", "") or "")).strip().lower()
    if not isinstance(wayback, dict):
        return {
            "total": 0,
            "total_retrieved": 0,
            "total_categorized": 0,
            "scope_filtered_out": 0,
            "js_files": [],
            "api_endpoints": [],
            "admin_paths": [],
            "sensitive_files": [],
            "documents": [],
            "interesting_paths": [],
            "uncategorized_urls": [],
            "all_urls": [],
            "query_params": [],
            "api_endpoint_profiles": [],
            "historical_robots": [],
            "historical_sitemaps": [],
        }
    js_files = _normalize_archive_bucket(wayback.get("js_files", []) or [], domain)
    api_endpoints = _normalize_archive_bucket(wayback.get("api_endpoints", []) or [], domain)
    admin_paths = _normalize_archive_bucket(wayback.get("admin_paths", []) or [], domain)
    sensitive_files = _normalize_archive_bucket(wayback.get("sensitive_files", []) or [], domain)
    documents = _normalize_archive_bucket(wayback.get("documents", []) or [], domain)
    interesting_paths = _sanitize_interesting_archive_paths(_normalize_archive_bucket(
        wayback.get("interesting_paths", []) or wayback.get("interesting", []) or [],
        domain,
    ))
    all_urls = _normalize_archive_bucket(
        wayback.get("all_urls", []) or wayback.get("all", []) or wayback.get("urls", []) or [],
        domain,
    )
    categorized_seen: set[str] = set()
    for bucket in (js_files, api_endpoints, admin_paths, sensitive_files, documents, interesting_paths):
        for row in bucket:
            categorized_seen.add(str(row.get("url", "")))
    uncategorized_urls = [row for row in all_urls if str(row.get("url", "")) not in categorized_seen]
    total_retrieved = _safe_int(wayback.get("total_urls"), len(all_urls) or _archive_urls_count(data))
    total_categorized = sum(
        len(bucket)
        for bucket in (js_files, api_endpoints, admin_paths, sensitive_files, documents, interesting_paths)
    )
    total = max(total_retrieved, len(all_urls), total_categorized)
    raw_population = max(_archive_urls_count(data), _safe_len(wayback.get("all", [])), _safe_len(wayback.get("all_urls", [])))
    return {
        "total": total,
        "total_retrieved": total_retrieved,
        "total_categorized": total_categorized,
        "scope_filtered_out": max(0, raw_population - len(all_urls)),
        "js_files": js_files,
        "api_endpoints": api_endpoints,
        "admin_paths": admin_paths,
        "sensitive_files": sensitive_files,
        "documents": documents,
        "interesting_paths": interesting_paths,
        "uncategorized_urls": uncategorized_urls,
        "all_urls": all_urls,
        "query_params": _normalize_archive_query_params(wayback.get("query_params", []) or []),
        "api_endpoint_profiles": wayback.get("api_endpoint_profiles", []) or [],
        "historical_robots": wayback.get("historical_robots", []) or [],
        "historical_sitemaps": wayback.get("historical_sitemaps", []) or [],
    }


def build_canonical_report(result: Any) -> Dict[str, Any]:
    data = _to_dict(result)
    _normalize_vulnerability_records(data)
    _normalize_takeover_records(data)
    _normalize_correlation_records(data)
    _normalize_bug_bounty_rows(data)
    _derive_infrastructure_observations(data)
    backfilled_ips = _backfill_ip_records_from_subdomains(data)
    # Normalize ip_records so both "open_ports" and "ports" keys are always populated
    for rec in data.get("ip_records", []) or []:
        if isinstance(rec, dict):
            if not rec.get("ports") and rec.get("open_ports"):
                rec["ports"] = rec["open_ports"]
            elif not rec.get("open_ports") and rec.get("ports"):
                rec["open_ports"] = rec["ports"]
    ctx = data.get("scan_context", {}) if isinstance(data.get("scan_context", {}), dict) else {}
    policy_flags = ctx.get("policy", {})
    coverage = _coverage_summary(data.get("source_metrics", {}) or {})
    source_scoring = _source_scoring(data.get("source_metrics", {}) or {}, data)
    source_intelligence = build_source_intelligence(data)
    subdomain_inventory = ctx.get("subdomain_inventory", {}) if isinstance(ctx.get("subdomain_inventory", {}), dict) else {}
    provider_summary = ctx.get("provider_summary", {}) if isinstance(ctx.get("provider_summary", {}), dict) else {}
    coverage_provider_summary = coverage.get("_provider_summary", {}) if isinstance(coverage, dict) else {}
    if not provider_summary:
        provider_summary = {
            "ready": int(ctx.get("api_key_summary", {}).get("ready_services_count", 0) or 0),
            "success": int(coverage_provider_summary.get("success", 0) or 0),
            "partial": int(coverage_provider_summary.get("partial", 0) or 0),
            "failed": int(coverage_provider_summary.get("failed", 0) or 0),
            "missing_credentials": int(ctx.get("api_key_summary", {}).get("missing_services_count", 0) or 0),
            "skipped": int(coverage_provider_summary.get("skipped", 0) or 0),
            "premium_success_count": int(coverage_provider_summary.get("premium_success_count", 0) or 0),
        }
    provider_summary.setdefault("skipped", int(coverage_provider_summary.get("skipped", 0) or 0))
    provider_summary.setdefault("premium_success_count", int(coverage_provider_summary.get("premium_success_count", 0) or 0))
    provider_summary.setdefault("api_enabled_count", int(provider_summary.get("ready", 0)))
    provider_summary.setdefault("passive_open_count", max(0, int(provider_summary.get("success", 0)) - int(provider_summary.get("premium_success_count", 0))))
    provider_summary["total_considered"] = int(
        provider_summary.get("success", 0)
        + provider_summary.get("partial", 0)
        + provider_summary.get("failed", 0)
        + provider_summary.get("missing_credentials", 0)
    )
    ctx["provider_summary"] = provider_summary
    sections = {s: _section_completeness(data, s, ctx) for s in SECTION_FIELD_MAP.keys()}
    overall_pct = round(sum(v["percent"] for v in sections.values()) / max(1, len(sections)), 1)
    missing_fields = []
    for s, item in sections.items():
        for f in item["fields"]:
            if not f["present"]:
                missing_fields.append({
                    "section": s,
                    "field": f["field"],
                    "reason": item["reason"] or "empty",
                })
    errors = list(data.get("errors", []) or [])
    if backfilled_ips:
        errors.append({
            "module": "IP Intelligence",
            "source": "report_builder_backfill",
            "kind": "ip_records_backfilled_from_subdomains",
            "message_short": f"Backfilled {backfilled_ips} IP record(s) from subdomain-resolved IPs for report consistency.",
        })
    raw_summary = data.get("summary", _summary_contract(data))
    if not isinstance(raw_summary, dict):
        raw_summary = _summary_contract(data)
    elif data.get("summary") is not None:
        missing_summary_keys = [k for k in SUMMARY_KEYS if k not in raw_summary]
        if missing_summary_keys:
            errors.append({
                "module": "ui",
                "source": "report_builder",
                "kind": "ui_schema_defaulted",
                "message_short": f"Input summary missing keys: {', '.join(missing_summary_keys)}",
                "missing_keys": missing_summary_keys,
            })
    computed_summary = _summary_contract(data)
    summary = _enforce_summary_contract({**raw_summary, **computed_summary}, errors)
    archive_export = _web_archive_export(data)
    artifact_inventory = _artifact_inventory(data, archive_export)
    raw_preservation = _raw_preservation_summary(data, summary)
    data["archive_urls"] = archive_export.get("all_urls", []) or []
    data["archive_summary"] = {
        "total": int(archive_export.get("total", 0) or 0),
        "total_retrieved": int(archive_export.get("total_retrieved", 0) or 0),
        "total_categorized": int(archive_export.get("total_categorized", 0) or 0),
        "scope_filtered_out": int(archive_export.get("scope_filtered_out", 0) or 0),
    }
    data["raw_preservation"] = raw_preservation
    raw_entity_graph = data.get("entity_graph", {}) if isinstance(data.get("entity_graph", {}), dict) else {}
    finding_sections = _finding_sections(data)
    canonical = {
        "report_version": REPORT_VERSION,
        "schema_version": SCHEMA_VERSION,
        "scan_id": data.get("scan_id", ""),
        "domain": data.get("domain", ""),
        "scan_date": data.get("scan_date", ""),
        "mode": data.get("mode", ""),
        "policy": policy_flags,
        "sources_enabled": ctx.get("enabled_modules", []),
        "sources_disabled": ctx.get("disabled_modules", []),
        "scan_context": ctx,
        "runtime": {
            "duration_seconds": float(data.get("duration_seconds", 0.0) or 0.0),
            "scan_date": data.get("scan_date", ""),
            "providers": provider_summary,
        },
        "sources_status": coverage,
        "completeness": {
            "overall_percent": overall_pct,
            "sections": sections,
            "missing_fields": missing_fields,
            "unrendered_fields": sorted(k for k in data.keys() if k not in RENDERED_FIELDS),
        },
        "coverage_by_source": data.get("source_metrics", {}) or {},
        "source_scoring": source_scoring,
        "source_intelligence": source_intelligence,
        "source_overlaps": source_intelligence.get("overlaps", []),
        "subdomain_inventory": {
            "raw_discovered_count": int(subdomain_inventory.get("raw_discovered_count", len(data.get("subdomains", []) or [])) or 0),
            "unique_normalized_count": int(subdomain_inventory.get("unique_normalized_count", len(data.get("subdomains", []) or [])) or 0),
            "accepted_final_count": int(subdomain_inventory.get("accepted_final_count", len(data.get("subdomains", []) or [])) or 0),
            "rejected_noise_count": int(subdomain_inventory.get("rejected_noise_count", 0) or 0),
            "wildcard_suspected_count": int(subdomain_inventory.get("wildcard_suspected_count", len([row for row in (data.get("subdomains", []) or []) if isinstance(row, dict) and bool(row.get("wildcard_candidate"))])) or 0),
            "high_confidence_count": int(subdomain_inventory.get("high_confidence_count", source_intelligence.get("summary", {}).get("quality_buckets", {}).get("high_confidence", 0)) or 0),
            "medium_confidence_count": int(subdomain_inventory.get("medium_confidence_count", source_intelligence.get("summary", {}).get("quality_buckets", {}).get("medium_confidence", 0)) or 0),
            "noisy_count": int(subdomain_inventory.get("noisy_count", source_intelligence.get("summary", {}).get("quality_buckets", {}).get("noisy", 0)) or 0),
            "confidence_buckets": subdomain_inventory.get("confidence_buckets", source_intelligence.get("summary", {}).get("quality_buckets", {})),
        },
        "policy_blocked_sources": _policy_blocked_sources(data.get("source_metrics", {}) or {}),
        "top_findings": _top_findings(data),
        "bug_bounty": _bug_bounty_summary(data, artifact_inventory),
        "findings": finding_sections,
        "dorks": data.get("dorks", []) or [],
        "web_archive": archive_export,
        "archive_urls": data.get("archive_urls", []) or [],
        "archive_summary": data.get("archive_summary", {}) or {},
        "entities": _entities(data),
        "entity_graph": raw_entity_graph if raw_entity_graph else _entity_graph(data),
        "scores": _component_scores(data.get("scores", {}) or {}),
        "social_footprint": data.get("social_footprint") or {},
        "asn_intelligence": data.get("asn_intelligence") or {},
        "reputation": data.get("reputation_data") or {},
        "email_security": data.get("email_security") or {},
        "whois_data": data.get("whois_data") or {},
        "dns_records": data.get("dns_records") or [],
        # Keep critical infrastructure inventory accessible at the top level for UI/API consumers.
        "ip_records": data.get("ip_records") or [],
        "historical_ips": data.get("historical_ips") or (data.get("scan_context") or {}).get("historical_ips") or [],
        "takeover_candidates": data.get("takeover_records") or [],
        "errors": errors,
        "errors_summary": _errors_summary(errors),
        "summary": summary,
        "raw_preservation": raw_preservation,
        # Keep raw payload for backward compatibility.
        "data": data,
    }
    canonical["coverage_score"] = _coverage_score(canonical, canonical["completeness"], coverage)
    risk_details = _risk_score_details(data, summary)
    canonical["risk_score"] = risk_details.get("score", 0.0)
    _sc = canonical.get("scores", {})
    if "overall" not in _sc:
        _ov = round(float(_sc.get("attack_surface",0))*0.30 + float(_sc.get("vulnerability",0))*0.35 + float(_sc.get("exposure",0))*0.20 + float(_sc.get("technology_risk",0))*0.15, 1)
        _sc["overall"] = _ov
        _sc["risk_level"] = "critical" if _ov>=75 else "high" if _ov>=50 else "medium" if _ov>=25 else "low"
        canonical["scores"] = _sc
    canonical["risk_level"] = str(canonical["scores"].get("risk_level", _risk_level(float(canonical["risk_score"]))).lower())
    canonical["risk_details"] = risk_details
    canonical["analyst_summary"] = _analyst_summary(data, summary, risk_details)
    canonical["executive_overview"] = _executive_overview(data, canonical["top_findings"])
    return canonical


def _full_static_has_value(value: Any) -> bool:
    return value not in (None, "", [], {}, ())


def _full_static_coalesce(*values: Any) -> Any:
    for value in values:
        if _full_static_has_value(value):
            return value
    return ""


def _full_static_text(value: Any) -> str:
    if value is None or value == "":
        return ""
    if isinstance(value, bool):
        return "Yes" if value else "No"
    if isinstance(value, (int, float)):
        return normalize_text(str(value))
    if isinstance(value, dict):
        preferred = _full_static_coalesce(
            value.get("url"),
            value.get("name"),
            value.get("title"),
            value.get("value"),
        )
        if preferred:
            return _full_static_text(preferred)
        parts: List[str] = []
        for key, child in value.items():
            if not _full_static_has_value(child):
                continue
            rendered = _full_static_text(child)
            if rendered:
                parts.append(f"{key}: {rendered}")
            if len(parts) >= 4:
                break
        return normalize_text("; ".join(parts))
    if isinstance(value, (list, tuple, set)):
        parts: List[str] = []
        seen: set[str] = set()
        for child in value:
            rendered = _full_static_text(child)
            if not rendered or rendered in seen:
                continue
            seen.add(rendered)
            parts.append(rendered)
        return normalize_text(", ".join(parts))
    return normalize_text(str(value))


def _full_static_archive_row(row: Any) -> Dict[str, str]:
    if isinstance(row, dict):
        return {
            "url": _full_static_text(row.get("url")),
            "timestamp": _full_static_text(row.get("timestamp")),
            "status_code": _full_static_text(row.get("status_code")),
            "mime_type": _full_static_text(row.get("mime_type")),
        }
    return {
        "url": _full_static_text(row),
        "timestamp": "",
        "status_code": "",
        "mime_type": "",
    }


def _full_static_artifact_row(row: Any) -> Dict[str, str]:
    if not isinstance(row, dict):
        return {
            "type": "",
            "subtype": "",
            "label": _full_static_text(row),
            "url": _full_static_text(row),
            "source": "",
            "classification": "",
            "confidence": "",
            "recency": "",
            "evidence": "",
        }
    return {
        "type": _full_static_text(row.get("type")),
        "subtype": _full_static_text(row.get("subtype")),
        "label": _full_static_text(_full_static_coalesce(row.get("label"), row.get("asset"), row.get("url"))),
        "url": _full_static_text(row.get("url")),
        "source": _full_static_text(row.get("source")),
        "classification": _full_static_text(row.get("classification")),
        "confidence": _full_static_text(row.get("confidence")),
        "recency": _full_static_text(row.get("observation_recency")),
        "evidence": _full_static_text(row.get("evidence")),
    }


def _full_static_source_rows(metrics: Any) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    if not isinstance(metrics, dict):
        return rows
    summary_fields = {
        "items_obtenidos",
        "items_parseados",
        "items_aceptados",
        "items_descartados_por_dedupe",
        "items_descartados_por_filtro",
        "errores",
        "latencia_ms",
        "latencia_ms_promedio",
        "status",
        "sources",
        "source_status_counts",
    }
    for module_name, module_payload in metrics.items():
        if not isinstance(module_payload, dict):
            continue
        source_map = module_payload.get("sources")
        if not isinstance(source_map, dict):
            source_map = {
                key: value
                for key, value in module_payload.items()
                if isinstance(value, dict) and key not in summary_fields
            }
        if not source_map:
            source_map = {"summary": module_payload}
        for source_name, source_payload in source_map.items():
            if not isinstance(source_payload, dict):
                continue
            rows.append({
                "module": normalize_text(str(module_name).replace("_", " ").title()),
                "source": normalize_text(str(source_name)),
                "status": normalize_text(str(source_payload.get("status", ""))),
                "accepted": _safe_int(source_payload.get("items_aceptados", 0), 0),
                "parsed": _safe_int(source_payload.get("items_parseados", source_payload.get("items_obtenidos", 0)), 0),
                "obtained": _safe_int(source_payload.get("items_obtenidos", source_payload.get("items_parseados", 0)), 0),
                "errors": _safe_int(source_payload.get("errores", 0), 0),
                "latency_ms": _safe_int(source_payload.get("latencia_ms", source_payload.get("latencia_ms_promedio", 0)), 0),
            })
    rows.sort(key=lambda row: (str(row.get("module", "")), str(row.get("source", ""))))
    return rows


def build_full_static_report_context(canonical_report: Dict[str, Any]) -> Dict[str, Any]:
    report = canonical_report if isinstance(canonical_report, dict) else {}
    data = report.get("data", {}) if isinstance(report.get("data", {}), dict) else {}
    summary = report.get("summary", {}) if isinstance(report.get("summary", {}), dict) else {}
    risk_details = report.get("risk_details", {}) if isinstance(report.get("risk_details", {}), dict) else {}
    completeness = report.get("completeness", {}) if isinstance(report.get("completeness", {}), dict) else {}
    scan_context = report.get("scan_context", data.get("scan_context", {}))
    scan_context = scan_context if isinstance(scan_context, dict) else {}
    provider_summary = scan_context.get("provider_summary", {})
    provider_summary = provider_summary if isinstance(provider_summary, dict) else {}
    analyst_summary = report.get("analyst_summary", {})
    analyst_summary = analyst_summary if isinstance(analyst_summary, dict) else {}
    executive_overview = report.get("executive_overview", {})
    executive_overview = executive_overview if isinstance(executive_overview, dict) else {}
    bug_bounty = report.get("bug_bounty", {}) if isinstance(report.get("bug_bounty", {}), dict) else {}
    artifact_inventory = bug_bounty.get("artifact_inventory", {}) if isinstance(bug_bounty.get("artifact_inventory", {}), dict) else {}
    artifact_summary = artifact_inventory.get("summary", {}) if isinstance(artifact_inventory.get("summary", {}), dict) else {}
    artifact_suppressed = artifact_inventory.get("suppressed_noise", {}) if isinstance(artifact_inventory.get("suppressed_noise", {}), dict) else {}

    subdomains = data.get("subdomains", []) if isinstance(data.get("subdomains", []), list) else []
    emails = data.get("emails", []) if isinstance(data.get("emails", []), list) else []
    ip_records = data.get("ip_records", []) if isinstance(data.get("ip_records", []), list) else []
    ssl_info = data.get("ssl_info", []) if isinstance(data.get("ssl_info", []), list) else []
    technologies = data.get("technologies", []) if isinstance(data.get("technologies", []), list) else []
    vulnerabilities = data.get("vulnerabilities", []) if isinstance(data.get("vulnerabilities", []), list) else []
    dorks = data.get("dorks", []) if isinstance(data.get("dorks", []), list) else []
    cloud_assets = data.get("cloud_assets", []) if isinstance(data.get("cloud_assets", []), list) else []
    asn_intelligence = report.get("asn_intelligence", data.get("asn_intelligence", {}))
    asn_intelligence = asn_intelligence if isinstance(asn_intelligence, dict) else {}

    archive = report.get("web_archive", {}) if isinstance(report.get("web_archive", {}), dict) else {}
    archive_rows_raw = archive.get("all_urls", [])
    if not isinstance(archive_rows_raw, list):
        archive_rows_raw = report.get("archive_urls", []) if isinstance(report.get("archive_urls", []), list) else []
    if not isinstance(archive_rows_raw, list):
        archive_rows_raw = data.get("archive_urls", []) if isinstance(data.get("archive_urls", []), list) else []
    archive_total = _safe_int(archive.get("total_retrieved", archive.get("total", len(archive_rows_raw))), len(archive_rows_raw))
    archive_truncated = archive_total > FULL_STATIC_ARCHIVE_THRESHOLD
    archive_rows_rendered = archive_rows_raw[:FULL_STATIC_ARCHIVE_RENDER_LIMIT] if archive_truncated else archive_rows_raw

    return {
        "scan": {
            "domain": _full_static_text(_full_static_coalesce(data.get("domain"), report.get("domain"))),
            "scan_id": _full_static_text(_full_static_coalesce(data.get("scan_id"), report.get("scan_id"))),
            "scan_date": _full_static_text(_full_static_coalesce(data.get("scan_date"), report.get("scan_date"))),
            "mode": _full_static_text(_full_static_coalesce(data.get("mode"), report.get("mode"))),
            "duration_seconds": round(float(data.get("duration_seconds", report.get("runtime", {}).get("duration_seconds", 0.0)) or 0.0), 2),
            "risk_score": report.get("risk_score", 0),
            "risk_level": normalize_text(str(report.get("risk_level", "low")).upper()),
            "coverage_score": report.get("coverage_score", 0),
            "completeness_percent": completeness.get("overall_percent", 0),
            "report_version": _full_static_text(report.get("report_version", "")),
            "schema_version": _full_static_text(report.get("schema_version", "")),
        },
        "summary_cards": [
            {"label": "Subdomains", "value": _safe_int(summary.get("subdomains"), len(subdomains))},
            {"label": "Emails", "value": _safe_int(summary.get("emails"), len(emails))},
            {"label": "Infrastructure", "value": _safe_int(summary.get("ips"), len(ip_records))},
            {"label": "Certificates", "value": _safe_int(summary.get("certs"), len(ssl_info))},
            {"label": "Technologies", "value": _safe_int(summary.get("technologies"), len(technologies))},
            {"label": "Vulnerabilities", "value": _safe_int(summary.get("vulns"), len(vulnerabilities))},
            {"label": "Dorks", "value": _safe_int(summary.get("dorks"), len(dorks))},
            {"label": "Cloud Assets", "value": _safe_int(summary.get("cloud_assets"), len(cloud_assets))},
            {"label": "Archive URLs", "value": archive_total},
        ],
        "provider_summary": {
            "ready": _safe_int(provider_summary.get("ready"), 0),
            "success": _safe_int(provider_summary.get("success"), 0),
            "partial": _safe_int(provider_summary.get("partial"), 0),
            "failed": _safe_int(provider_summary.get("failed"), 0),
            "missing_credentials": _safe_int(provider_summary.get("missing_credentials"), 0),
            "skipped": _safe_int(provider_summary.get("skipped"), 0),
        },
        "risk_details": {
            "explain_short": _full_static_text(risk_details.get("explain_short", "")),
            "formula": _full_static_text(risk_details.get("formula", "")),
            "evidence_count": _safe_int(risk_details.get("evidence_count"), 0),
        },
        "analyst_summary": {
            "headline": _full_static_text(analyst_summary.get("headline", "")),
            "bullets": [
                _full_static_text(item)
                for item in (analyst_summary.get("bullets", []) or [])
                if _full_static_has_value(item)
            ],
        },
        "executive_overview": {
            "story": _full_static_text(executive_overview.get("story", "")),
            "priority_findings": [
                _full_static_text(item)
                for item in (executive_overview.get("priority_findings", []) or [])
                if _full_static_has_value(item)
            ],
            "quick_wins": [
                _full_static_text(item)
                for item in (executive_overview.get("quick_wins", []) or [])
                if _full_static_has_value(item)
            ],
        },
        "top_findings": [
            {
                "severity": normalize_text(str(row.get("severity", "INFO")).upper()),
                "title": _full_static_text(_full_static_coalesce(row.get("title"), row.get("cve_id"), row.get("type"))),
                "asset": _full_static_text(_full_static_coalesce(row.get("asset"), row.get("affected_asset"), row.get("location"))),
                "source": _full_static_text(row.get("source", "")),
                "confidence": _full_static_text(row.get("confidence", "")),
                "evidence": _full_static_text(_full_static_coalesce(row.get("evidence"), row.get("why_prioritized"), row.get("description"))),
            }
            for row in (report.get("top_findings", []) or [])
            if isinstance(row, dict)
        ],
        "subdomains": {
            "count": len(subdomains),
            "rows": [
                {
                    "host": _full_static_text(_full_static_coalesce(row.get("name"), row.get("subdomain"), row.get("host"))),
                    "ips": _full_static_text(_full_static_coalesce(row.get("ips"), row.get("resolved_ips"), row.get("ip_addresses"))),
                    "ports": _full_static_text(_full_static_coalesce(row.get("ports"), row.get("open_ports"))),
                    "sources": _full_static_text(_full_static_coalesce(row.get("sources"), row.get("source_attribution"))),
                    "tags": _full_static_text(row.get("tags")),
                    "status": _full_static_text(_full_static_coalesce(row.get("status"), row.get("takeover_status"), row.get("confidence"))),
                }
                for row in subdomains
                if isinstance(row, dict)
            ],
        },
        "emails": {
            "count": len(emails),
            "rows": [
                {
                    "email": _full_static_text(row.get("email")),
                    "role": _full_static_text(_full_static_coalesce(row.get("role"), row.get("role_category"))),
                    "sources": _full_static_text(_full_static_coalesce(row.get("sources"), row.get("source_attribution"))),
                    "confidence": _full_static_text(row.get("confidence")),
                }
                for row in emails
                if isinstance(row, dict)
            ],
            "pattern": _full_static_text((data.get("email_pattern", {}) if isinstance(data.get("email_pattern", {}), dict) else {}).get("pattern", "")),
        },
        "infrastructure": {
            "count": len(ip_records),
            "rows": [
                {
                    "ip": _full_static_text(row.get("ip")),
                    "org": _full_static_text(_full_static_coalesce(row.get("org"), row.get("organization"))),
                    "asn": _full_static_text(row.get("asn")),
                    "country": _full_static_text(_full_static_coalesce(row.get("country"), row.get("city"))),
                    "ports": _full_static_text(_full_static_coalesce(row.get("open_ports"), row.get("ports"))),
                    "provider": _full_static_text(_full_static_coalesce(row.get("cloud_provider"), row.get("provider"), row.get("cdn"))),
                    "tags": _full_static_text(row.get("tags")),
                }
                for row in ip_records
                if isinstance(row, dict)
            ],
        },
        "asn": {
            "count": len(asn_intelligence),
            "rows": [
                {
                    "asn": _full_static_text(_full_static_coalesce(details.get("asn"), asn_key)),
                    "name": _full_static_text(_full_static_coalesce(details.get("name"), details.get("org"), details.get("description"))),
                    "country": _full_static_text(details.get("country")),
                    "ipv4_ranges": _full_static_text(_full_static_coalesce(details.get("total_ipv4_ranges"), details.get("ipv4_ranges"))),
                }
                for asn_key, details in sorted(asn_intelligence.items(), key=lambda item: str(item[0]))
                if isinstance(details, dict)
            ],
        },
        "ssl": {
            "count": len(ssl_info),
            "rows": [
                {
                    "subject": _full_static_text(_full_static_coalesce(row.get("common_name"), row.get("subject"))),
                    "issuer": _full_static_text(row.get("issuer")),
                    "expires": _full_static_text(_full_static_coalesce(row.get("not_after"), row.get("expiry"), row.get("expires"))),
                    "sans": _full_static_text(_full_static_coalesce(row.get("san_entries"), row.get("sans"))),
                }
                for row in ssl_info
                if isinstance(row, dict)
            ],
        },
        "technologies": {
            "count": len(technologies),
            "rows": [
                {
                    "name": _full_static_text(row.get("name")),
                    "category": _full_static_text(row.get("category")),
                    "version": _full_static_text(row.get("version")),
                    "evidence": _full_static_text(_full_static_coalesce(row.get("evidence"), row.get("sources"))),
                }
                for row in technologies
                if isinstance(row, dict)
            ],
        },
        "vulnerabilities": {
            "count": len(vulnerabilities),
            "rows": [
                {
                    "severity": normalize_text(str(row.get("severity", "INFO")).upper()),
                    "identifier": _full_static_text(_full_static_coalesce(row.get("cve_id"), row.get("id"), row.get("title"))),
                    "title": _full_static_text(row.get("title")),
                    "asset": _full_static_text(_full_static_coalesce(row.get("affected_asset"), row.get("affected_host"), row.get("asset"))),
                    "source": _full_static_text(row.get("source")),
                    "evidence": _full_static_text(_full_static_coalesce(row.get("description"), row.get("remediation"), row.get("references"))),
                }
                for row in vulnerabilities
                if isinstance(row, dict)
            ],
        },
        "dorks": {
            "count": len(dorks),
            "rows": [
                {
                    "severity": normalize_text(str(row.get("severity", "INFO")).upper()),
                    "source": _full_static_text(row.get("source")),
                    "category": _full_static_text(row.get("category")),
                    "reference": _full_static_text(_full_static_coalesce(row.get("url"), row.get("query"), row.get("file"))),
                    "snippet": _full_static_text(_full_static_coalesce(row.get("snippet"), row.get("query"))),
                }
                for row in dorks
                if isinstance(row, dict)
            ],
        },
        "cloud_assets": {
            "count": len(cloud_assets),
            "rows": [
                {
                    "asset_type": _full_static_text(_full_static_coalesce(row.get("asset_type"), row.get("type"))),
                    "name": _full_static_text(_full_static_coalesce(row.get("name"), row.get("bucket"), row.get("host"))),
                    "location": _full_static_text(_full_static_coalesce(row.get("url"), row.get("location"), row.get("region"))),
                    "classification": _full_static_text(_full_static_coalesce(row.get("classification"), row.get("provider"))),
                    "public": _full_static_text(_full_static_coalesce(row.get("public"), row.get("exposure"))),
                }
                for row in cloud_assets
                if isinstance(row, dict)
            ],
        },
        "artifacts": {
            "summary": {
                "high_value_files": _safe_int(artifact_summary.get("high_value_files"), len(artifact_inventory.get("high_value_files", []) or [])),
                "archived_files": _safe_int(artifact_summary.get("archived_files"), len(artifact_inventory.get("archived_files", []) or [])),
                "interesting_endpoints": _safe_int(artifact_summary.get("interesting_endpoints"), len(artifact_inventory.get("interesting_endpoints", []) or [])),
                "artifact_hints": _safe_int(artifact_summary.get("artifact_hints"), len(artifact_inventory.get("artifact_hints", []) or [])),
                "internal_references": _safe_int(artifact_summary.get("internal_references"), len(artifact_inventory.get("internal_references", []) or [])),
                "suppressed_noise": _safe_int(artifact_summary.get("suppressed_noise"), _safe_int(artifact_suppressed.get("count"), 0)),
            },
            "suppressed_noise": {
                "count": _safe_int(artifact_suppressed.get("count"), 0),
                "static_assets": _safe_int(artifact_suppressed.get("static_assets"), 0),
                "generic_archive_urls": _safe_int(artifact_suppressed.get("generic_archive_urls"), 0),
                "duplicates": _safe_int(artifact_suppressed.get("duplicates"), 0),
            },
            "high_value_files": [_full_static_artifact_row(row) for row in (artifact_inventory.get("high_value_files", []) or [])],
            "archived_files": [_full_static_artifact_row(row) for row in (artifact_inventory.get("archived_files", []) or [])],
            "interesting_endpoints": [_full_static_artifact_row(row) for row in (artifact_inventory.get("interesting_endpoints", []) or [])],
            "artifact_hints": [_full_static_artifact_row(row) for row in (artifact_inventory.get("artifact_hints", []) or [])],
            "internal_references": [_full_static_artifact_row(row) for row in (artifact_inventory.get("internal_references", []) or [])],
        },
        "archive": {
            "total": archive_total,
            "rendered_count": len(archive_rows_rendered),
            "truncated": archive_truncated,
            "notice": (
                f"Archive inventory contains {archive_total:,} URLs. This HTML includes the first {len(archive_rows_rendered):,} URLs for readability; use the JSON export for the full list."
                if archive_truncated else ""
            ),
            "rows": [_full_static_archive_row(row) for row in archive_rows_rendered],
        },
        "coverage": {
            "available": True,
            "rows": _full_static_source_rows(report.get("coverage_by_source", {}) or data.get("source_metrics", {})),
        },
    }

