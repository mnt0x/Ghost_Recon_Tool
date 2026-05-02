from __future__ import annotations

from typing import Any, Set


def parse_securitytrails_subdomains(payload: Any, domain: str) -> Set[str]:
    out: Set[str] = set()
    if not isinstance(payload, dict):
        return out
    apex = domain.lower()
    for sub in payload.get("subdomains", []) or []:
        label = str(sub or "").strip().lower().strip(".")
        if not label:
            continue
        host = f"{label}.{apex}" if not label.endswith(apex) else label
        if host.endswith(apex) and host != apex:
            out.add(host)
    return out
