from __future__ import annotations

from datetime import datetime
from typing import Any, List


_COMMONCRAWL_FALLBACK_INDEXES = [
    "CC-MAIN-2026-12",
    "CC-MAIN-2026-08",
    "CC-MAIN-2026-04",
    "CC-MAIN-2025-51",
    "CC-MAIN-2025-43",
    "CC-MAIN-2025-38",
    "CC-MAIN-2025-33",
]


async def latest_commoncrawl_indexes(
    get_json,
    *,
    mode: str = "balanced",
    fallback: List[str] | None = None,
) -> List[str]:
    """Return latest CommonCrawl index IDs in descending recency order.

    `get_json` is an awaitable callable returning parsed JSON for the provided URL.
    This indirection keeps the helper testable and decoupled from aiohttp internals.
    """
    wanted = {"fast": 3, "balanced": 5, "deep": 5, "turbo": 2}.get(str(mode or "balanced"), 5)
    base = list(fallback or _COMMONCRAWL_FALLBACK_INDEXES)
    try:
        payload = await get_json("https://index.commoncrawl.org/collinfo.json")
    except Exception:
        payload = None
    if not isinstance(payload, list):
        return base[:wanted]

    rows: List[tuple[float, str]] = []
    for entry in payload:
        if not isinstance(entry, dict):
            continue
        idx = str(entry.get("id", "") or "").strip()
        if not idx.startswith("CC-MAIN-"):
            continue
        sort_key = 0.0
        from_raw = str(entry.get("from", "") or "").strip()
        if from_raw:
            with_from = from_raw.replace("Z", "+00:00")
            try:
                sort_key = datetime.fromisoformat(with_from).timestamp()
            except ValueError:
                sort_key = 0.0
        # FIXED: sort CommonCrawl indexes by crawl recency instead of display name so deep mode uses the latest five indexes.
        rows.append((sort_key, idx))
    rows.sort(key=lambda item: (item[0], item[1]), reverse=True)

    indexes: List[str] = []
    seen = set()
    for _, idx in rows:
        if idx in seen:
            continue
        seen.add(idx)
        indexes.append(idx)
    for idx in base:
        if idx not in seen:
            indexes.append(idx)
    return indexes[:wanted]
