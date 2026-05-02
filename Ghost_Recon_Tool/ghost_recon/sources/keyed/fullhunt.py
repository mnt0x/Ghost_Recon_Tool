from __future__ import annotations

from typing import Any, Set


def parse_fullhunt_subdomains(payload: Any, domain: str) -> Set[str]:
    out: Set[str] = set()
    if not isinstance(payload, dict):
        return out
    apex = domain.lower()
    for sub in payload.get("hosts", []) or []:
        host = str(sub or "").strip().lower().strip(".").lstrip("*.")
        if host.endswith(apex) and host != apex:
            out.add(host)
    return out
