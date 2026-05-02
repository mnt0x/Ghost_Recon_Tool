"""Text decoding helpers for robust UTF-8 handling and mojibake recovery."""

from __future__ import annotations

from typing import Optional


_MOJIBAKE_TOKENS = (
    "Ã¢â‚¬â€",
    "Ã¢â‚¬â€œ",
    "Ã¢â‚¬",
    "Ã‚",
    "Ãƒ",
    "Ã°Å¸",
    "Ã¢Å“",
    "Ã¢â€ ",
    "â€”",
    "â€“",
    "â€™",
    "â€œ",
    "â€\x9d",
    "Â·",
    "ðŸ",
    "\u00e2\u0080\u0094",
    "\u00e2\u0080\u0093",
    "\u00e2\u0080\u0099",
    "\u00e2\u0080\u009c",
    "\u00e2\u0080\u009d",
    "\u00c2\u00b7",
    "\u00f0\u009f",
    "\u00c3",
)
_COMMON_REPLACEMENTS = {
    "ÃƒÂ¡": "á",
    "ÃƒÂ©": "é",
    "ÃƒÂ­": "í",
    "ÃƒÂ³": "ó",
    "ÃƒÂº": "ú",
    "ÃƒÂ": "Á",
    "Ãƒâ€°": "É",
    "ÃƒÂ": "Í",
    "Ãƒâ€œ": "Ó",
    "ÃƒÅ¡": "Ú",
    "ÃƒÂ±": "ñ",
    "Ãƒâ€˜": "Ñ",
    "ÃƒÂ¼": "ü",
    "ÃƒÅ“": "Ü",
    "Ã¡": "á",
    "Ã©": "é",
    "Ã­": "í",
    "Ã³": "ó",
    "Ãº": "ú",
    "Ã": "Á",
    "Ã‰": "É",
    "Ã": "Í",
    "Ã“": "Ó",
    "Ãš": "Ú",
    "Ã±": "ñ",
    "Ã‘": "Ñ",
    "Ã¼": "ü",
    "Ãœ": "Ü",
    "Ã¢â‚¬â€": "—",
    "Ã¢â‚¬â€œ": "–",
    "Ã¢â‚¬Å“": "“",
    "Ã¢â‚¬Â": "”",
    "Ã¢â‚¬Ëœ": "‘",
    "Ã¢â‚¬â„¢": "’",
    "Ã¢â‚¬Â¦": "…",
    "Ã¢â‚¬Â¢": "•",
    "Ã‚Â·": "·",
    "Ã‚ ": " ",
    "\u00e2\u0080\u0094": "—",
    "\u00e2\u0080\u0093": "–",
    "\u00e2\u0080\u0099": "’",
    "\u00e2\u0080\u009c": "“",
    "\u00e2\u0080\u009d": "”",
    "\u00c2\u00b7": "·",
    "\u00f0\u009f\u008e\u00af": "🎯",
}


def _mojibake_score(value: str) -> int:
    if not value:
        return 0
    return sum(value.count(tok) for tok in _MOJIBAKE_TOKENS)


def normalize_text(value: object) -> str:
    """Normalize text inputs and repair common mojibake safely."""
    if value is None:
        return ""
    if isinstance(value, bytes):
        text = value.decode("utf-8", errors="replace")
    else:
        text = str(value)
    if not text:
        return ""

    text = text.replace("\r\n", "\n").replace("\r", "\n")
    base_score = _mojibake_score(text)
    if base_score == 0:
        return text

    candidates = [text]
    for src in ("latin-1", "cp1252"):
        try:
            repaired = text.encode(src, errors="ignore").decode("utf-8", errors="ignore")
            if repaired:
                candidates.append(repaired)
        except (UnicodeEncodeError, UnicodeDecodeError):
            continue

    mapped = text
    for bad, good in _COMMON_REPLACEMENTS.items():
        mapped = mapped.replace(bad, good)
    candidates.append(mapped)

    best = min(candidates, key=_mojibake_score)
    fixed = best if _mojibake_score(best) < base_score else text
    for _ in range(2):
        if _mojibake_score(fixed) == 0:
            break
        try:
            reparsed = fixed.encode("latin-1", errors="ignore").decode("utf-8", errors="ignore")
        except Exception:
            break
        if reparsed and _mojibake_score(reparsed) < _mojibake_score(fixed):
            fixed = reparsed
        else:
            break
    return fixed.replace("\r\n", "\n").replace("\r", "\n")


def fix_mojibake(value: object) -> str:
    """Backward-compatible alias used across existing modules/tests."""
    return normalize_text(value)


async def read_response_text(response, fallback_encoding: Optional[str] = "utf-8") -> str:
    """Decode HTTP body using declared charset + safe fallbacks, then repair mojibake."""
    raw = await response.read()
    encodings = []
    charset = getattr(response, "charset", None)
    if charset:
        encodings.append(charset)
    get_encoding = getattr(response, "get_encoding", None)
    if callable(get_encoding):
        try:
            enc = get_encoding()
            if enc:
                encodings.append(enc)
        except Exception:
            pass
    if fallback_encoding:
        encodings.append(fallback_encoding)
    encodings.extend(["utf-8", "cp1252", "latin-1"])
    seen = set()
    for enc in encodings:
        if not enc or enc in seen:
            continue
        seen.add(enc)
        try:
            return normalize_text(raw.decode(enc))
        except UnicodeDecodeError:
            continue
    return normalize_text(raw.decode("utf-8", errors="replace"))
