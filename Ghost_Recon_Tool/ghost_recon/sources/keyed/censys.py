from __future__ import annotations

from typing import Any, Set


def parse_censys_subdomains(payload: Any, domain: str) -> Set[str]:
    out: Set[str] = set()
    if not isinstance(payload, dict):
        return out
    apex = domain.lower()
    hits = ((payload.get("result") or {}).get("hits") or []) if isinstance(payload.get("result"), dict) else []
    for hit in hits:
        if not isinstance(hit, dict):
            continue
        for name in hit.get("names", []) or []:
            host = str(name or "").strip().lower().strip(".").lstrip("*.")
            if host.endswith(apex) and host != apex:
                out.add(host)
        rdns = hit.get("reverse_dns", {})
        if isinstance(rdns, dict):
            rdns = rdns.get("reverse_dns", [])
        for name in rdns or []:
            host = str(name or "").strip().lower().strip(".").lstrip("*.")
            if host.endswith(apex) and host != apex:
                out.add(host)
    return out
