"""Web security helpers for local admin endpoints."""

from __future__ import annotations

import hashlib
import hmac
import os
import secrets


def load_or_create_admin_token() -> str:
    token = os.environ.get("GRT_ADMIN_TOKEN", "").strip()
    if token:
        return token
    token = secrets.token_urlsafe(24)
    os.environ["GRT_ADMIN_TOKEN"] = token
    return token


def constant_time_equals(a: str, b: str) -> bool:
    return hmac.compare_digest((a or "").encode(), (b or "").encode())


def token_fingerprint(token: str) -> str:
    if not token:
        return "unset"
    return hashlib.sha256(token.encode()).hexdigest()[:10]
