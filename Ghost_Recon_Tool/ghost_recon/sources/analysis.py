from __future__ import annotations

from collections import Counter, defaultdict
from typing import Any, Dict, Iterable, List, Set, Tuple

from ghost_recon.sources.registry import SOURCE_CATALOG

HIGH_CONFIDENCE_SOURCES = {
    "crt.sh", "ct_logs", "ctsearch", "securitytrails", "virustotal", "fullhunt", "chaos", "censys", "whoisxml", "mnemonic_pdns",
}
NOISY_SOURCES = {"jldc", "anubisdb", "commoncrawl"}
MASSIVE_SOURCES = {"jldc", "anubisdb"}


def _is_keyed_source(source_name: str) -> bool:
    spec = SOURCE_CATALOG.get(str(source_name).strip())
    return bool(spec.requires_keys) if spec else False


def _normalize_sources(values: Iterable[Any]) -> List[str]:
    seen: Set[str] = set()
    out: List[str] = []
    for value in values or []:
        source = str(value or "").strip()
        if not source or source in seen:
            continue
        seen.add(source)
        out.append(source)
    return out


def source_quality_bucket(source_name: str) -> str:
    source = str(source_name or "").strip().lower()
    if source in HIGH_CONFIDENCE_SOURCES:
        return "high_confidence"
    if source in NOISY_SOURCES:
        return "noisy"
    return "medium_confidence"


def source_weight(source_name: str) -> float:
    bucket = source_quality_bucket(source_name)
    if source_name in MASSIVE_SOURCES:
        return 0.35
    if bucket == "high_confidence":
        return 1.0
    if bucket == "noisy":
        return 0.55
    return 0.8


def _finding_confidence_bucket(row: Dict[str, Any]) -> str:
    try:
        confidence = float(row.get("confidence", 0.0) or 0.0)
    except (TypeError, ValueError):
        confidence = 0.0
    explicit = str(row.get("confidence_bucket", "") or "").strip().lower()
    if explicit in {"high_confidence", "medium_confidence", "noisy"}:
        return explicit
    if confidence >= 0.82:
        return "high_confidence"
    if confidence >= 0.58:
        return "medium_confidence"
    return "noisy"


def _collect_finding_sources(data: Dict[str, Any]) -> Dict[str, List[str]]:
    findings: Dict[str, List[str]] = {}

    for row in data.get("subdomains", []) or []:
        if isinstance(row, dict):
            host = str(row.get("name", "") or "").strip().lower()
            if host:
                findings[f"subdomain:{host}"] = _normalize_sources(row.get("sources", []) or [])

    for row in data.get("emails", []) or []:
        if isinstance(row, dict):
            email = str(row.get("email", "") or "").strip().lower()
            if email:
                findings[f"email:{email}"] = _normalize_sources(row.get("sources", []) or [])

    for row in data.get("technologies", []) or []:
        if isinstance(row, dict):
            key = str(row.get("name", "") or "").strip().lower()
            if key:
                findings[f"technology:{key}"] = _normalize_sources(row.get("sources", []) or [])

    for row in data.get("ssl_info", []) or []:
        if isinstance(row, dict):
            subject = str(row.get("subject", "") or "").strip().lower()
            if subject:
                findings[f"cert:{subject}"] = _normalize_sources(row.get("ct_sources", []) or row.get("sources", []) or [])

    for row in data.get("dns_records", []) or []:
        if isinstance(row, dict):
            dns_type = str(row.get("type", "") or "").strip().upper()
            name = str(row.get("name", "") or "").strip().lower()
            value = str(row.get("value", "") or "").strip().lower()
            source = str(row.get("source", "") or "").strip()
            if dns_type and name and value and source:
                findings[f"dns:{dns_type}:{name}:{value}"] = [source]

    for row in data.get("vulnerabilities", []) or []:
        if isinstance(row, dict):
            title = str(row.get("cve_id") or row.get("title") or "").strip()
            source = str(row.get("source", "") or "").strip()
            if title and source:
                findings[f"vulnerability:{title}"] = [source]

    return findings


def _collect_finding_rows(data: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    rows: Dict[str, Dict[str, Any]] = {}
    for row in data.get("subdomains", []) or []:
        if isinstance(row, dict):
            host = str(row.get("name", "") or "").strip().lower()
            if host:
                rows[f"subdomain:{host}"] = dict(row)
    for row in data.get("emails", []) or []:
        if isinstance(row, dict):
            email = str(row.get("email", "") or "").strip().lower()
            if email:
                rows[f"email:{email}"] = dict(row)
    for row in data.get("technologies", []) or []:
        if isinstance(row, dict):
            key = str(row.get("name", "") or "").strip().lower()
            if key:
                rows[f"technology:{key}"] = dict(row)
    for row in data.get("ssl_info", []) or []:
        if isinstance(row, dict):
            subject = str(row.get("subject", "") or "").strip().lower()
            if subject:
                rows[f"cert:{subject}"] = dict(row)
    return rows


def build_source_intelligence(data: Dict[str, Any]) -> Dict[str, Any]:
    finding_sources = _collect_finding_sources(data if isinstance(data, dict) else {})
    finding_rows = _collect_finding_rows(data if isinstance(data, dict) else {})
    per_source_total: Counter[str] = Counter()
    per_source_unique: Counter[str] = Counter()
    per_source_shared: Counter[str] = Counter()
    per_source_api_only: Counter[str] = Counter()
    per_source_overlap: Counter[str] = Counter()
    per_source_exclusive: Counter[str] = Counter()
    per_source_corroborated: Counter[str] = Counter()
    per_source_noisy: Counter[str] = Counter()
    overlap_pairs: Counter[Tuple[str, str]] = Counter()

    multi_source_findings = 0
    api_only_findings = 0
    source_to_findings: Dict[str, Set[str]] = defaultdict(set)
    finding_details: List[Dict[str, Any]] = []

    for finding_id, sources in finding_sources.items():
        normalized = _normalize_sources(sources)
        if not normalized:
            continue
        is_api_only = all(_is_keyed_source(source) for source in normalized)
        row = finding_rows.get(finding_id, {})
        confidence_bucket = _finding_confidence_bucket(row)
        first_seen_source = str(
            row.get("first_seen_source")
            or ((row.get("source_attribution", []) or [{}])[0].get("source", "") if isinstance(row.get("source_attribution", []), list) and row.get("source_attribution", []) else "")
            or normalized[0]
        ).strip()
        if len(normalized) > 1:
            multi_source_findings += 1
        if is_api_only:
            api_only_findings += 1
        for source in normalized:
            per_source_total[source] += 1
            source_to_findings[source].add(finding_id)
            if is_api_only:
                per_source_api_only[source] += 1
            if confidence_bucket == "noisy":
                per_source_noisy[source] += 1
        if len(normalized) == 1:
            per_source_unique[normalized[0]] += 1
            per_source_exclusive[normalized[0]] += 1
        else:
            for source in normalized:
                per_source_shared[source] += 1
                per_source_overlap[source] += len(normalized) - 1
                per_source_corroborated[source] += 1
            ordered = sorted(normalized)
            for idx, left in enumerate(ordered):
                for right in ordered[idx + 1 :]:
                    overlap_pairs[(left, right)] += 1
        finding_details.append({
            "finding_id": finding_id,
            "sources": normalized,
            "first_seen_source": first_seen_source,
            "api_only": is_api_only,
            "confidence_bucket": confidence_bucket,
        })

    by_source: Dict[str, Dict[str, Any]] = {}
    all_sources = sorted(set(per_source_total) | set(source_to_findings))
    for source in all_sources:
        total = int(per_source_total.get(source, 0))
        unique = int(per_source_unique.get(source, 0))
        shared = int(per_source_shared.get(source, 0))
        api_only = int(per_source_api_only.get(source, 0))
        overlap_with_others = int(per_source_overlap.get(source, 0))
        overlap_ratio = round(shared / max(1, total), 4)
        effective_weight = source_weight(source)
        unique_ratio = round(unique / max(1, total), 4)
        by_source[source] = {
            "source": source,
            "requires_key": _is_keyed_source(source),
            "findings_total": total,
            "findings_unique": unique,
            "uniques_contributed": unique,
            "findings_shared": shared,
            "overlap_with_others": overlap_with_others,
            "api_only_findings": api_only,
            "multi_source_ratio": overlap_ratio,
            "overlap_ratio": overlap_ratio,
            "unique_ratio": unique_ratio,
            "uniqueness_ratio": unique_ratio,
            "exclusive_findings_count": int(per_source_exclusive.get(source, 0)),
            "corroborated_findings_count": int(per_source_corroborated.get(source, 0)),
            "noisy_findings_count": int(per_source_noisy.get(source, 0)),
            "quality_bucket": source_quality_bucket(source),
            "effective_weight": effective_weight,
            "massive_source": source in MASSIVE_SOURCES,
            "api_backed": _is_keyed_source(source),
            "sample_findings": sorted(source_to_findings.get(source, set()))[:10],
            "evidence_examples": sorted(source_to_findings.get(source, set()))[:3],
        }

    top_overlaps = [
        {"left": left, "right": right, "shared_findings": int(count)}
        for (left, right), count in overlap_pairs.most_common(20)
    ]
    ranking = sorted(
        by_source.values(),
        key=lambda row: (
            -int(row.get("findings_unique", 0)),
            -int(row.get("findings_total", 0)),
            str(row.get("source", "")),
        ),
    )
    return {
        "summary": {
            "finding_count": len(finding_sources),
            "multi_source_findings": multi_source_findings,
            "api_only_findings": api_only_findings,
            "sources_seen": len(by_source),
            "keyed_sources_seen": sum(1 for row in by_source.values() if row.get("requires_key")),
            "non_keyed_sources_seen": sum(1 for row in by_source.values() if not row.get("requires_key")),
            "quality_buckets": {
                "high_confidence": sum(1 for row in finding_details if row.get("confidence_bucket") == "high_confidence"),
                "medium_confidence": sum(1 for row in finding_details if row.get("confidence_bucket") == "medium_confidence"),
                "noisy": sum(1 for row in finding_details if row.get("confidence_bucket") == "noisy"),
            },
            "exclusive_findings_count": sum(1 for row in finding_details if len(row.get("sources", [])) == 1),
            "corroborated_findings_count": sum(1 for row in finding_details if len(row.get("sources", [])) > 1),
            "noisy_findings_count": sum(1 for row in finding_details if row.get("confidence_bucket") == "noisy"),
        },
        "by_source": by_source,
        "ranking": ranking,
        "overlaps": top_overlaps,
        "finding_details_preview": sorted(
            finding_details,
            key=lambda row: (
                row.get("confidence_bucket") != "high_confidence",
                not row.get("api_only"),
                row.get("finding_id", ""),
            ),
        )[:200],
    }


def compare_run_payloads(before: Dict[str, Any], after: Dict[str, Any]) -> Dict[str, Any]:
    before_data = (before or {}).get("data", before or {})
    after_data = (after or {}).get("data", after or {})
    before_findings = _collect_finding_sources(before_data if isinstance(before_data, dict) else {})
    after_findings = _collect_finding_sources(after_data if isinstance(after_data, dict) else {})

    before_ids = set(before_findings)
    after_ids = set(after_findings)
    gained = sorted(after_ids - before_ids)
    lost = sorted(before_ids - after_ids)
    gained_api_only = [
        finding_id
        for finding_id in gained
        if all(_is_keyed_source(source) for source in after_findings.get(finding_id, []))
    ]

    before_inventory = ((before_data if isinstance(before_data, dict) else {}).get("scan_context", {}) or {}).get("subdomain_inventory", {})
    after_inventory = ((after_data if isinstance(after_data, dict) else {}).get("scan_context", {}) or {}).get("subdomain_inventory", {})
    before_unique = int(before_inventory.get("unique_normalized_count", len((before_data if isinstance(before_data, dict) else {}).get("subdomains", []) or [])) or 0)
    after_unique = int(after_inventory.get("unique_normalized_count", len((after_data if isinstance(after_data, dict) else {}).get("subdomains", []) or [])) or 0)
    before_raw = int(before_inventory.get("raw_discovered_count", before_unique) or 0)
    after_raw = int(after_inventory.get("raw_discovered_count", after_unique) or 0)
    before_rejected = int(before_inventory.get("rejected_noise_count", 0) or 0)
    after_rejected = int(after_inventory.get("rejected_noise_count", 0) or 0)
    before_high = int(before_inventory.get("high_confidence_count", 0) or 0)
    after_high = int(after_inventory.get("high_confidence_count", 0) or 0)
    before_medium = int(before_inventory.get("medium_confidence_count", 0) or 0)
    after_medium = int(after_inventory.get("medium_confidence_count", 0) or 0)
    before_noisy = int(before_inventory.get("noisy_count", 0) or 0)
    after_noisy = int(after_inventory.get("noisy_count", 0) or 0)
    before_subs = {
        str((row or {}).get("name", "")).strip().lower()
        for row in ((before_data if isinstance(before_data, dict) else {}).get("subdomains", []) or [])
        if isinstance(row, dict) and str((row or {}).get("name", "")).strip()
    }
    after_subs = {
        str((row or {}).get("name", "")).strip().lower()
        for row in ((after_data if isinstance(after_data, dict) else {}).get("subdomains", []) or [])
        if isinstance(row, dict) and str((row or {}).get("name", "")).strip()
    }
    after_cov = (after or {}).get("coverage_by_source", {}) if isinstance(after, dict) else {}
    before_cov = (before or {}).get("coverage_by_source", {}) if isinstance(before, dict) else {}
    before_sources = {str(source) for module in before_cov.values() if isinstance(module, dict) for source in (module.get("sources", {}) if isinstance(module.get("sources", {}), dict) else {}).keys()}
    after_sources = {str(source) for module in after_cov.values() if isinstance(module, dict) for source in (module.get("sources", {}) if isinstance(module.get("sources", {}), dict) else {}).keys()}
    failed_providers = sorted({
        str(source)
        for module in after_cov.values()
        if isinstance(module, dict)
        for source, src_data in (module.get("sources", {}) if isinstance(module.get("sources", {}), dict) else {}).items()
        if isinstance(src_data, dict) and str(src_data.get("status", "")).lower() in {"fail", "failed", "timeout", "error"}
    })
    before_provider_summary = ((before_data if isinstance(before_data, dict) else {}).get("scan_context", {}) or {}).get("provider_summary", {})
    after_provider_summary = ((after_data if isinstance(after_data, dict) else {}).get("scan_context", {}) or {}).get("provider_summary", {})
    before_si_summary = ((before or {}).get("source_intelligence", {}) or {}).get("summary", {})
    after_si_summary = ((after or {}).get("source_intelligence", {}) or {}).get("summary", {})

    return {
        "before_finding_count": len(before_ids),
        "after_finding_count": len(after_ids),
        "before_total_raw": before_raw,
        "after_total_raw": after_raw,
        "before_total_unique": before_unique,
        "after_total_unique": after_unique,
        "before_total_accepted": int(before_inventory.get("accepted_final_count", len(before_subs)) or 0),
        "after_total_accepted": int(after_inventory.get("accepted_final_count", len(after_subs)) or 0),
        "before_rejected_noise": before_rejected,
        "after_rejected_noise": after_rejected,
        "before_high_confidence": before_high,
        "after_high_confidence": after_high,
        "before_medium_confidence": before_medium,
        "after_medium_confidence": after_medium,
        "before_noisy": before_noisy,
        "after_noisy": after_noisy,
        "before_coverage_score": float((before or {}).get("coverage_score", 0) or 0),
        "after_coverage_score": float((after or {}).get("coverage_score", 0) or 0),
        "before_exclusive_findings_count": int(before_si_summary.get("exclusive_findings_count", 0) or 0),
        "after_exclusive_findings_count": int(after_si_summary.get("exclusive_findings_count", 0) or 0),
        "before_api_only_findings_count": int(before_si_summary.get("api_only_findings", 0) or 0),
        "after_api_only_findings_count": int(after_si_summary.get("api_only_findings", 0) or 0),
        "percent_improvement_unique": round(((after_unique - before_unique) / max(1, before_unique)) * 100.0, 2),
        "gained_findings": gained,
        "lost_findings": lost,
        "gained_api_only_findings": gained_api_only,
        "run_b_exclusive_subdomains": sorted(after_subs - before_subs),
        "sources_gained": sorted(set(source for fid in gained for source in after_findings.get(fid, []))),
        "sources_lost": sorted(set(source for fid in lost for source in before_findings.get(fid, []))),
        "newly_activated_sources": sorted(after_sources - before_sources),
        "failed_providers_after": failed_providers,
        "before_provider_summary": before_provider_summary,
        "after_provider_summary": after_provider_summary,
    }


__all__ = ["build_source_intelligence", "compare_run_payloads", "source_quality_bucket", "source_weight"]
