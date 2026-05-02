"""Canonical normalization helpers shared across modules."""

from __future__ import annotations

import hashlib
import re
from enum import Enum
from urllib.parse import urlparse, urlunparse

from ghost_recon.utils.domain import looks_like_hostname, normalize_domain, normalize_hostname


_EMAIL_LOCAL_RE = re.compile(r"^[a-z0-9!#$%&'*+/=?^_`{|}~.-]{1,64}$", re.I)


class DropReason(str, Enum):
    EMPTY = "empty"
    INVALID_HOSTNAME = "invalid_hostname"
    OUT_OF_SCOPE = "out_of_scope"
    APEX_DOMAIN = "apex_domain"
    DEDUPE = "dedupe"
    INVALID_EMAIL = "invalid_email"


def normalize_subdomain(host: str) -> str:
    cleaned = (host or "").strip().lstrip(".")
    if cleaned.startswith("*."):
        cleaned = cleaned[2:]
    return normalize_hostname(cleaned)


def normalize_email(email: str) -> str:
    e = (email or "").strip().strip(".,;:<>\"'()[]{}").lower()
    if e.startswith("mailto:"):
        e = e[7:]
    if "@" not in e:
        return ""
    local, _, domain = e.rpartition("@")
    if not local:
        return ""
    local = local.strip().strip(".")
    if not local or ".." in local or not _EMAIL_LOCAL_RE.match(local):
        return ""
    host = normalize_hostname(domain)
    if not host or "." not in host or not looks_like_hostname(host):
        return ""
    return f"{local}@{host}"


def normalize_url(url: str) -> str:
    try:
        u = urlparse((url or "").strip())
        scheme = (u.scheme or "https").lower()
        host = normalize_hostname(u.hostname or "")
        if not host:
            return ""
        port = f":{u.port}" if u.port else ""
        netloc = f"{host}{port}"
        path = u.path or "/"
        return urlunparse((scheme, netloc, path, "", u.query or "", ""))
    except Exception:
        return ""


def canonical_entity_id(kind: str, value: str) -> str:
    raw = f"{(kind or '').strip().lower()}::{(value or '').strip().lower()}".encode("utf-8", "ignore")
    return hashlib.sha256(raw).hexdigest()[:20]


__all__ = [
    "DropReason",
    "normalize_domain",
    "normalize_subdomain",
    "normalize_email",
    "normalize_url",
    "canonical_entity_id",
]
