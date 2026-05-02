"""Domain validation/normalization helpers."""

from __future__ import annotations

import re
from urllib.parse import urlparse

_DOMAIN_RE = re.compile(r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$")
_HOST_TOKEN_RE = re.compile(r"^(?:[a-z0-9_](?:[a-z0-9_\-]{0,61}[a-z0-9_])?\.)+[a-z0-9\-]{2,63}$", re.I)


def normalize_domain(raw: str) -> str:
    domain = (raw or "").strip().lower()
    domain = re.sub(r"^https?://", "", domain)
    domain = domain.split("/")[0]
    return domain.strip(".")


def is_valid_domain(raw: str) -> bool:
    return bool(_DOMAIN_RE.match(normalize_domain(raw)))


def normalize_hostname(host: str) -> str:
    h = str(host or "").strip().strip("[](){}<>\"'")
    if not h:
        return ""
    if "://" in h:
        try:
            h = urlparse(h).hostname or ""
        except Exception:
            return ""
    else:
        h = h.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0].strip()
        if "@" in h:
            h = h.rsplit("@", 1)[-1]
        if h.count(":") == 1:
            maybe_host, maybe_port = h.rsplit(":", 1)
            if maybe_port.isdigit():
                h = maybe_host
    while h.startswith("*."):
        h = h[2:]
    h = h.rstrip(".").lower()
    if not h:
        return ""
    if any(ch.isspace() for ch in h) or "," in h:
        return ""
    try:
        h = h.encode("idna").decode("ascii")
    except Exception:
        return ""
    return h


def looks_like_hostname(host: str) -> bool:
    h = normalize_hostname(host)
    return bool(h and _HOST_TOKEN_RE.match(h))
