"""Centralized API key store with safe masking and layered loading."""

from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any, Dict, Iterable, Optional, Tuple


DEFAULT_STORE_PATH = Path("data") / "apikeys.json"
DEFAULT_DOTENV_PATH = Path(".env")

PROVIDER_ENV_MAP: Dict[str, str] = {
    "chaos": "GRT_CHAOS",
    "virustotal": "GRT_VIRUSTOTAL",
    "github_token": "GRT_GITHUB_TOKEN",
    "bevigil": "GRT_BEVIGIL",
    "otx": "GRT_OTX",
}

ENV_VAR_ALIASES: Dict[str, str] = {}

PROVIDER_LABELS: Dict[str, str] = {
    "chaos": "Chaos",
    "virustotal": "VirusTotal",
    "github_token": "GitHub Token",
    "bevigil": "BeVigil",
    "otx": "AlienVault OTX",
}

SERVICE_DEFINITIONS: Dict[str, Dict[str, Any]] = {
    "chaos": {
        "label": "Chaos",
        "credentials": ("chaos",),
        "doc_url": "https://chaos.projectdiscovery.io/",
        "description": "Passive subdomain enumeration.",
    },
    "virustotal": {
        "label": "VirusTotal",
        "credentials": ("virustotal",),
        "doc_url": "https://www.virustotal.com/gui/user/apikey",
        "description": "Subdomains, reputation and passive enrichment.",
    },
    "github": {
        "label": "GitHub Token",
        "credentials": ("github_token",),
        "doc_url": "https://github.com/settings/tokens",
        "description": "GitHub code and developer-reference searches.",
    },
    "bevigil": {
        "label": "BeVigil",
        "credentials": ("bevigil",),
        "doc_url": "https://osint.bevigil.com/",
        "description": "Subdomain and mobile exposure enrichment.",
    },
    "otx": {
        "label": "AlienVault OTX",
        "credentials": ("otx",),
        "doc_url": "https://otx.alienvault.com/settings",
        "description": "Threat intel and pulse enrichment.",
    },
}

SOURCE_ALIASES: Dict[str, str] = {
    "github_token": "github",
}

KEY_ALIASES: Dict[str, str] = {
    "chaos": "chaos",
    "virustotal": "virustotal",
    "vt": "virustotal",
    "github": "github_token",
    "github_token": "github_token",
    "bevigil": "bevigil",
    "otx": "otx",
}

PROVIDER_VALIDATION: Dict[str, re.Pattern[str]] = {
    "chaos": re.compile(r"^[A-Za-z0-9_\-]{8,256}$"),
    "virustotal": re.compile(r"^[A-Za-z0-9]{16,128}$"),
}


class KeystoreWriteError(OSError):
    """Raised when API key persistence cannot be completed safely."""


def normalize_keys(raw: Optional[Dict[str, Any]]) -> Dict[str, str]:
    out: Dict[str, str] = {}
    if not isinstance(raw, dict):
        return out
    env_to_provider = {v: k for k, v in PROVIDER_ENV_MAP.items()}
    env_to_provider.update(ENV_VAR_ALIASES)
    for key, value in raw.items():
        if value is None:
            continue
        sval = str(value).strip()
        if not sval:
            continue
        k = str(key).strip()
        provider = KEY_ALIASES.get(k.lower())
        if not provider and k in env_to_provider:
            provider = env_to_provider[k]
        if provider:
            out[provider] = sval
    return out


def load_dotenv_values(path: Optional[Path] = None) -> Dict[str, str]:
    dotenv_path = path or DEFAULT_DOTENV_PATH
    if not dotenv_path.exists():
        return {}
    raw: Dict[str, str] = {}
    try:
        for line in dotenv_path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            raw[key.strip()] = value.strip().strip('"').strip("'")
    except OSError:
        return {}
    return normalize_keys(raw)


def redact(value: str) -> str:
    if not value:
        return ""
    if len(value) <= 4:
        return "*" * len(value)
    return ("*" * (len(value) - 4)) + value[-4:]


def _load_file_store(path: Path) -> Dict[str, str]:
    if not path.exists():
        return {}
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    if not isinstance(raw, dict):
        return {}
    return normalize_keys(raw)


def _load_keyring_store() -> Dict[str, str]:
    try:
        import keyring  # type: ignore
    except Exception:
        return {}
    loaded: Dict[str, str] = {}
    for provider in PROVIDER_ENV_MAP:
        try:
            val = keyring.get_password("ghost_recon_tool", provider)  # type: ignore[attr-defined]
        except Exception:
            val = None
        if val:
            loaded[provider] = str(val).strip()
    return loaded


def load_key_layers(
    *,
    store_path: Optional[Path] = None,
    dotenv_path: Optional[Path] = None,
    in_memory: Optional[Dict[str, Any]] = None,
) -> Tuple[Dict[str, str], Dict[str, str]]:
    """Load keys and track their effective source.

    Priority: in_memory > keyring > file store > environment > .env
    """
    resolved_store_path = store_path or DEFAULT_STORE_PATH
    file_vals = _load_file_store(resolved_store_path)
    keyring_vals = _load_keyring_store()
    mem_vals = normalize_keys(in_memory or {})
    dotenv_vals = load_dotenv_values(dotenv_path)
    env_candidates = {env: os.environ.get(env, "") for env in PROVIDER_ENV_MAP.values()}
    env_candidates.update({env: os.environ.get(env, "") for env in ENV_VAR_ALIASES})
    env_vals = normalize_keys(env_candidates)

    merged: Dict[str, str] = {}
    sources: Dict[str, str] = {}
    for label, values in (
        ("dotenv", dotenv_vals),
        ("environment", env_vals),
        ("local_store", file_vals),
        ("keyring", keyring_vals),
        ("web_session", mem_vals),
    ):
        for provider, value in values.items():
            merged[provider] = value
            sources[provider] = label
    return merged, sources


def load_keys(
    *,
    store_path: Optional[Path] = None,
    dotenv_path: Optional[Path] = None,
    in_memory: Optional[Dict[str, Any]] = None,
) -> Dict[str, str]:
    keys, _ = load_key_layers(
        store_path=store_path,
        dotenv_path=dotenv_path,
        in_memory=in_memory,
    )
    return keys


def save_keys(
    updates: Dict[str, str],
    *,
    store_path: Optional[Path] = None,
    delete_providers: Iterable[str] = (),
) -> Dict[str, str]:
    resolved_store_path = store_path or DEFAULT_STORE_PATH
    normalized_updates = normalize_keys(updates)
    existing = _load_file_store(resolved_store_path)
    to_delete = {KEY_ALIASES.get(str(k).lower(), str(k).lower()) for k in delete_providers}
    for provider in to_delete:
        existing.pop(provider, None)
    existing.update(normalized_updates)
    try:
        resolved_store_path.parent.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise KeystoreWriteError(
            f"Unable to create API key store directory at {resolved_store_path.parent}: {exc}"
        ) from exc
    try:
        resolved_store_path.write_text(json.dumps(existing, indent=2, ensure_ascii=False), encoding="utf-8")
    except OSError as exc:
        raise KeystoreWriteError(
            f"Unable to write API key store at {resolved_store_path}: {exc}"
        ) from exc
    try:
        os.chmod(resolved_store_path, 0o600)
    except OSError:
        pass

    try:
        import keyring  # type: ignore
    except Exception:
        return existing
    for provider in to_delete:
        try:
            keyring.delete_password("ghost_recon_tool", provider)  # type: ignore[attr-defined]
        except Exception:
            continue
    for provider, value in normalized_updates.items():
        try:
            keyring.set_password("ghost_recon_tool", provider, value)  # type: ignore[attr-defined]
        except Exception:
            continue
    return existing


def provider_status(keys: Dict[str, str], sources: Optional[Dict[str, str]] = None) -> Dict[str, Dict[str, str]]:
    status: Dict[str, Dict[str, str]] = {}
    for provider, env_var in PROVIDER_ENV_MAP.items():
        val = str(keys.get(provider, "") or "")
        status[provider] = {
            "provider": provider,
            "label": PROVIDER_LABELS.get(provider, provider.replace("_", " ").title()),
            "env_var": env_var,
            "present": "true" if bool(val) else "false",
            "masked_hint": redact(val),
            "source": str((sources or {}).get(provider, "")),
        }
    return status


def summarize_services(keys: Dict[str, str]) -> Dict[str, Any]:
    configured_credentials = sorted([provider for provider in PROVIDER_ENV_MAP if keys.get(provider)])
    services = []
    ready = []
    missing = []
    partial = []
    for service_key, meta in SERVICE_DEFINITIONS.items():
        credentials = tuple(meta.get("credentials", ()))
        present = [credential for credential in credentials if keys.get(credential)]
        missing_credentials = [credential for credential in credentials if credential not in present]
        is_ready = bool(credentials) and not missing_credentials
        is_partial = bool(present) and bool(missing_credentials)
        service_row = {
            "service": service_key,
            "label": str(meta.get("label", service_key)),
            "credentials": credentials,
            "present_credentials": tuple(present),
            "missing_credentials": tuple(missing_credentials),
            "ready": is_ready,
            "partial": is_partial,
            "doc_url": str(meta.get("doc_url", "")),
            "description": str(meta.get("description", "")),
        }
        services.append(service_row)
        if is_ready:
            ready.append(service_row)
        else:
            missing.append(service_row)
            if is_partial:
                partial.append(service_row)
    return {
        "configured_credentials": configured_credentials,
        "configured_credentials_count": len(configured_credentials),
        "credentials_total": len(PROVIDER_ENV_MAP),
        "services": services,
        "ready_services": ready,
        "ready_services_count": len(ready),
        "missing_services": missing,
        "missing_services_count": len(missing),
        "partial_services": partial,
        "partial_services_count": len(partial),
    }


def source_to_required_credentials(source_name: str, env_vars: Iterable[str] = ()) -> Tuple[str, ...]:
    key = SOURCE_ALIASES.get(source_name, source_name)
    meta = SERVICE_DEFINITIONS.get(key)
    if meta:
        return tuple(meta.get("credentials", ()))
    env_to_provider = {env_var: provider for provider, env_var in PROVIDER_ENV_MAP.items()}
    resolved = [env_to_provider[env_var] for env_var in env_vars if env_var in env_to_provider]
    if resolved:
        return tuple(resolved)
    alias = KEY_ALIASES.get(str(source_name).lower(), str(source_name).lower())
    return (alias,) if alias in PROVIDER_ENV_MAP else ()


def validate_provider_value(provider: str, value: str) -> Tuple[bool, str]:
    norm_provider = KEY_ALIASES.get(str(provider).lower(), str(provider).lower())
    sval = str(value or "").strip()
    if not sval:
        return False, "empty"
    rx = PROVIDER_VALIDATION.get(norm_provider)
    if rx is None:
        if len(sval) < 8 or len(sval) > 512:
            return False, "length_out_of_range"
        return True, "ok"
    if rx.match(sval):
        return True, "ok"
    return False, "invalid_format"
