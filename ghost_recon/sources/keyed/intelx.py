from __future__ import annotations

from typing import Any, Set


def parse_intelx_emails(payload: Any, domain: str) -> Set[str]:
    out: Set[str] = set()
    apex = domain.lower()
    selectors = []
    if isinstance(payload, dict):
        selectors = payload.get("selectors", []) or []
    elif isinstance(payload, list):
        selectors = payload
    for sel in selectors:
        if isinstance(sel, dict):
            val = str(sel.get("selectorvalue", "")).strip().lower()
        else:
            val = str(sel or "").strip().lower()
        if "@" not in val:
            continue
        if val.endswith("@" + apex) or val.endswith("." + apex):
            out.add(val)
    return out
