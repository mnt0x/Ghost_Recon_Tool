from __future__ import annotations

from typing import Any, Set


def parse_shodan_cve_ids(payload: Any) -> Set[str]:
    out: Set[str] = set()
    if not isinstance(payload, dict):
        return out
    vulns = payload.get("vulns", []) or []
    if isinstance(vulns, dict):
        vulns = list(vulns.keys())
    for cve in vulns:
        val = str(cve or "").strip().upper()
        if val.startswith("CVE-"):
            out.add(val)
    return out
