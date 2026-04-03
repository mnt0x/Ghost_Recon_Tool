from __future__ import annotations

from typing import Any, Set


def parse_virustotal_subdomains(payload: Any, domain: str) -> Set[str]:
    out: Set[str] = set()
    for item in (payload or {}).get("data", []) if isinstance(payload, dict) else []:
        host = str((item or {}).get("id", "")).strip().lower().lstrip("*.")
        if host.endswith(domain.lower()) and host != domain.lower():
            out.add(host)
    return out
