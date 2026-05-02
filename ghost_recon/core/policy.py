"""Policy engine for passive-first execution."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from urllib.parse import urlparse
import contextvars


class ModuleMode(str, Enum):
    PASSIVE = "PASSIVE"
    SEMI = "SEMI"
    ACTIVE = "ACTIVE"


@dataclass(slots=True)
class ScanPolicy:
    passive_only: bool = True
    allow_active: bool = False
    allow_target_requests: bool = False
    allow_insecure_http_fallback: bool = False

    def allows_module(self, mode: ModuleMode) -> bool:
        if mode is ModuleMode.PASSIVE:
            return True
        if mode is ModuleMode.SEMI:
            return not self.passive_only
        if mode is ModuleMode.ACTIVE:
            return self.allow_active and (not self.passive_only)
        return False


CURRENT_POLICY: contextvars.ContextVar[ScanPolicy] = contextvars.ContextVar(
    "current_policy", default=ScanPolicy()
)
CURRENT_TARGET: contextvars.ContextVar[str] = contextvars.ContextVar(
    "current_target", default=""
)

OSINT_HOST_ALLOWLIST_SUFFIXES = (
    "crt.sh",
    "certspotter.com",
    "dns.google",
    "cloudflare-dns.com",
    "www.circl.lu",
    "doh.opendns.com",
    "otx.alienvault.com",
    "urlscan.io",
    "web.archive.org",
    "archive.org",
    "index.commoncrawl.org",
    "rdap.org",
    "search.censys.io",
    "api.bgpview.io",
    "ipinfo.io",
    "internetdb.shodan.io",
    "api.hackertarget.com",
    "api.mnemonic.no",
    "api.virustotal.com",
    "virustotal.com",
    "phonebook.cz",
    "dnshistory.org",
    "api.fullhunt.io",
    "chaos.projectdiscovery.io",
    "api.certspotter.com",
    "r.jina.ai",
    "api.first.org",
    "api.fastly.com",
    "ip-ranges.amazonaws.com",
    "gstatic.com",
    "download.microsoft.com",
    "urlhaus-api.abuse.ch",
    "threatfox-api.abuse.ch",
    "api.securitytrails.com",
    "fullhunt.io",
    "dns.projectdiscovery.io",
    "api.binaryedge.io",
    "api.riskiq.net",
    "api.zoomeye.hk",
    "fofa.info",
    "ctsearch.entrust.com",
    "columbus.elmasy.com",
    "subdomainfinder.c99.nl",
    "subdomains.whoisxmlapi.com",
    "domains.whoisxmlapi.com",
    "leakix.net",
    "dnsdumpster.com",
    "searchdns.netcraft.com",
    "dns.bufferover.run",
    "dnsrepo.ninja",
    "osint.bevigil.com",
    "api.threatbook.io",
    "api.github.com",
    "grep.app",
    "api.sublist3r.com",
    "shrewdeye.app",
    "pulsedive.com",
)


def set_scan_context(policy: ScanPolicy, target_domain: str) -> tuple[contextvars.Token, contextvars.Token]:
    return CURRENT_POLICY.set(policy), CURRENT_TARGET.set((target_domain or "").lower().strip("."))


def reset_scan_context(tokens: tuple[contextvars.Token, contextvars.Token]) -> None:
    policy_token, target_token = tokens
    CURRENT_POLICY.reset(policy_token)
    CURRENT_TARGET.reset(target_token)


def _host(url: str) -> str:
    try:
        return (urlparse(url).hostname or "").lower().strip(".")
    except Exception:
        return ""


def is_target_url(url: str, target_domain: str) -> bool:
    host = _host(url)
    target = (target_domain or "").lower().strip(".")
    if not host or not target:
        return False
    if any(host == d or host.endswith("." + d) for d in OSINT_HOST_ALLOWLIST_SUFFIXES):
        return False
    return host == target or host.endswith("." + target)


def target_request_allowed(url: str) -> bool:
    policy = CURRENT_POLICY.get()
    if policy.allow_target_requests:
        return True
    return not is_target_url(url, CURRENT_TARGET.get())
