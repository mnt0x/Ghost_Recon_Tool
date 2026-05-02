from __future__ import annotations

from typing import Any, Set


def parse_hunter_emails(payload: Any, domain: str) -> Set[str]:
    out: Set[str] = set()
    if not isinstance(payload, dict):
        return out
    apex = domain.lower()
    for item in ((payload.get("data") or {}).get("emails") or []) if isinstance(payload.get("data"), dict) else []:
        addr = str((item or {}).get("value", "")).strip().lower()
        if "@" not in addr:
            continue
        if addr.endswith("@" + apex) or addr.endswith("." + apex):
            out.add(addr)
    return out
