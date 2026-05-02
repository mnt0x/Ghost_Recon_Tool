from __future__ import annotations

from dataclasses import asdict
from typing import Any, Dict, Iterable, Mapping, Optional

from .models import SourceSpec
from ghost_recon.core.keystore import source_to_required_credentials
from .runtime_support import runtime_support_for_source


def _spec(
    name: str,
    category: str,
    hosts: Iterable[str],
    *,
    requires_keys: bool = False,
    requires_target_requests: bool = False,
    env_vars: Iterable[str] = (),
    default_enabled: bool = True,
    mode: str = "PASSIVE",
    rate_limit: int = 12,
    timeout: int = 25,
    retries: int = 2,
    notes: str = "",
) -> SourceSpec:
    return SourceSpec(
        name=name,
        category=category,
        hosts=tuple(hosts),
        requires_keys=requires_keys,
        requires_target_requests=requires_target_requests,
        env_vars=tuple(env_vars),
        default_enabled=default_enabled,
        mode=mode,
        rate_limit=rate_limit,
        timeout=timeout,
        retries=retries,
        notes=notes,
    )


SOURCE_CATALOG: Dict[str, SourceSpec] = {
    # Passive no-key
    "crt.sh": _spec("crt.sh", "ct", ["crt.sh"], notes="CT logs primary"),
    "certspotter": _spec("certspotter", "ct", ["api.certspotter.com"], notes="CT API"),
    "wayback": _spec("wayback", "history", ["web.archive.org"]),
    "wayback_host_hints": _spec("wayback_host_hints", "history", ["web.archive.org"], notes="Archive snapshot host extraction"),
    "commoncrawl": _spec("commoncrawl", "history", ["index.commoncrawl.org"], default_enabled=False, notes="Disabled by default: consistently times out, zero data loss vs wayback"),
    "urlscan": _spec("urlscan", "intel", ["urlscan.io"]),
    "urlscan_pages": _spec("urlscan_pages", "intel", ["urlscan.io"]),
    "otx": _spec("otx", "intel", ["otx.alienvault.com"]),
    "otx_passive_dns": _spec("otx_passive_dns", "intel", ["otx.alienvault.com"], notes="OTX passive DNS"),
    # bufferover removed — discontinued
    "bufferover_dns": _spec("bufferover_dns", "subdomains", ["dns.bufferover.run"], notes="BufferOver passive DNS"),
    "jldc": _spec("jldc", "subdomains", ["jldc.me"]),
    "anubisdb": _spec("anubisdb", "subdomains", ["jonlu.ca"]),
    "rapiddns": _spec("rapiddns", "subdomains", ["rapiddns.io"]),
    # rapiddns_pages removed — duplicates rapiddns
    # threatcrowd removed — offline since 2022
    # threatminer removed — offline
    "hackertarget": _spec("hackertarget", "subdomains", ["api.hackertarget.com"]),
    "hackertarget_dns": _spec("hackertarget_dns", "subdomains", ["api.hackertarget.com"]),
    # FIXED: keep direct runtime sources explicitly cataloged so SourceRegistry does not auto-register them with incorrect policy metadata.
    "hackertarget_subdomain": _spec("hackertarget_subdomain", "subdomains", ["api.hackertarget.com"], default_enabled=False, notes="Disabled by default: duplicate/brittle HackerTarget passive subdomain feed"),
    "circl_pdns": _spec("circl_pdns", "subdomains", ["www.circl.lu"], notes="CIRCL passive DNS"),
    "mnemonic_pdns": _spec("mnemonic_pdns", "subdomains", ["api.mnemonic.no"]),
    "dnshistory": _spec("dnshistory", "subdomains", ["dnshistory.org"]),
    "dnsgrep": _spec("dnsgrep", "subdomains", ["www.dnsgrep.nl"], default_enabled=False, notes="Disabled by default: endpoint frequently unavailable"),
    "shrewdeye": _spec("shrewdeye", "subdomains", ["shrewdeye.app"], default_enabled=False, notes="Disabled by default: endpoint inactive"),
    "sublist3r": _spec("sublist3r", "subdomains", ["api.sublist3r.com"], default_enabled=False, notes="Unreliable public API; disabled by default for production"),
    "grep_app": _spec("grep_app", "subdomains", ["grep.app"], default_enabled=False, notes="JS-heavy search source; disabled by default for production"),
    "github_code": _spec("github_code", "subdomains", ["api.github.com", "github.com"]),
    "wayback_cdx": _spec("wayback_cdx", "history", ["web.archive.org"], notes="Wayback CDX host extraction"),
    "wayback_cdx_full": _spec("wayback_cdx_full", "history", ["web.archive.org"], notes="Expanded Wayback CDX extraction"),
    "netcraft": _spec("netcraft", "subdomains", ["searchdns.netcraft.com"], default_enabled=False, notes="Often requires heavy rendering; disabled by default for production"),
    "leakix": _spec("leakix", "subdomains", ["leakix.net"]),
    "dnsdumpster": _spec("dnsdumpster", "subdomains", ["dnsdumpster.com"], default_enabled=False, notes="Disabled by default: passive public endpoint unstable"),
    "dnsrepo": _spec("dnsrepo", "subdomains", ["dnsrepo.ninja"]),
    # sonar_fdns removed — omnisint.io shut down
    "ctsearch": _spec("ctsearch", "subdomains", ["ctsearch.entrust.com"]),
    "ctsearch_google": _spec("ctsearch_google", "ct", ["transparencyreport.google.com"], notes="Google Transparency Report CT search"),
    "columbus": _spec("columbus", "subdomains", ["columbus.elmasy.com"]),
    "c99": _spec("c99", "subdomains", ["subdomainfinder.c99.nl"], default_enabled=False, notes="Fragile public endpoint; disabled by default for production"),
    "whoisxml": _spec("whoisxml", "subdomains", ["domains.whoisxmlapi.com"]),
    "vt_unauth": _spec("vt_unauth", "subdomains", ["www.virustotal.com"]),
    "phonebook_subs": _spec("phonebook_subs", "subdomains", ["phonebook.cz"]),
    "alienvault_otx": _spec("alienvault_otx", "subdomains", ["otx.alienvault.com"], notes="AlienVault OTX passive DNS"),
    "alienvault_pulse": _spec("alienvault_pulse", "subdomains", ["otx.alienvault.com"], notes="AlienVault OTX URL-list host extraction"),
    "subdomaincenter": _spec("subdomaincenter", "subdomains", ["api.subdomain.center"]),
    "he_bgp": _spec("he_bgp", "subdomains", ["bgp.he.net"], notes="Hurricane Electric BGP DNS view"),
    "myssl": _spec("myssl", "subdomains", ["myssl.com"]),
    "digitorus": _spec("digitorus", "subdomains", ["certificatedetails.com"]),
    "bevigil_free": _spec("bevigil_free", "subdomains", ["osint.bevigil.com"], notes="Bevigil unauthenticated endpoint"),
    "hackertarget_rev": _spec("hackertarget_rev", "subdomains", ["api.hackertarget.com"], notes="HackerTarget reverse host search"),
    "hackertarget_reverseip": _spec("hackertarget_reverseip", "subdomains", ["api.hackertarget.com"], notes="HackerTarget reverse IP host expansion"),
    "doh_wordlist": _spec("doh_wordlist", "subdomains", ["cloudflare-dns.com"], notes="Passive DoH wordlist confirmation"),
    "sitedossier": _spec("sitedossier", "subdomains", ["www.sitedossier.com"], default_enabled=False, notes="Disabled by default: endpoint inactive"),
    "urlscan_subs": _spec("urlscan_subs", "subdomains", ["urlscan.io"], notes="URLScan domain search"),
    "dnsbufferover": _spec("dnsbufferover", "subdomains", ["dns.bufferover.run"]),
    "sslmate_certs": _spec("sslmate_certs", "subdomains", ["api.certspotter.com"], notes="SSLMate CertSpotter CT log feed"),
    "riddler": _spec("riddler", "subdomains", ["riddler.io"], default_enabled=False, notes="Disabled: riddler.io passive DNS search is offline"),
    "omnisint": _spec("omnisint", "subdomains", ["sonar.omnisint.io"], default_enabled=False, notes="Disabled: Omnisint/ODIN passive endpoint is shut down"),
    "google_ct": _spec("google_ct", "ct", ["transparencyreport.google.com"], notes="Google Certificate Transparency report"),
    "trickest": _spec("trickest", "subdomains", ["dns.trickest.io"], default_enabled=False, notes="Disabled by default: endpoint inactive"),
    "wayback_subdomains": _spec("wayback_subdomains", "history", ["web.archive.org"], notes="Wayback CDX subdomain host extraction"),
    "bevigil": _spec(
        "bevigil",
        "subdomains",
        ["osint.bevigil.com"],
        requires_keys=True,
        env_vars=("GRT_BEVIGIL",),
    ),
    "whois_html": _spec("whois_html", "whois", ["www.whois.com", "who.is"]),
    "ct_logs": _spec("ct_logs", "emails", ["crt.sh"]),
    "pgp_keys": _spec("pgp_keys", "emails", ["keyserver.ubuntu.com", "keys.openpgp.org"]),
    "phonebook": _spec("phonebook", "emails", ["phonebook.cz"]),
    "email_format": _spec("email_format", "emails", ["www.email-format.com"]),
    "skymem": _spec("skymem", "emails", ["www.skymem.info"]),
    "paste_sites": _spec("paste_sites", "emails", ["psbdmp.ws"]),
    "commoncrawl_mailto": _spec("commoncrawl_mailto", "emails", ["index.commoncrawl.org"], default_enabled=False, notes="Disabled by default: consistently times out"),
    "wayback_mailto": _spec("wayback_mailto", "emails", ["web.archive.org"], notes="Wayback archived mailto extraction"),
    "wayback_contacts": _spec("wayback_contacts", "emails", ["web.archive.org"]),
    "wayback_snapshots": _spec("wayback_snapshots", "emails", ["web.archive.org"], default_enabled=False, notes="Disabled by default: consistently times out"),
    "commoncrawl_index": _spec("commoncrawl_index", "emails", ["index.commoncrawl.org"], default_enabled=False, notes="Disabled by default: consistently times out"),
    "github_code_emails": _spec(
        "github_code_emails",
        "emails",
        ["api.github.com", "github.com"],
        requires_keys=True,
        env_vars=("GRT_GITHUB_TOKEN",),
        notes="GitHub code search requires authentication",
    ),
    "github_commits": _spec("github_commits", "emails", ["api.github.com", "github.com"]),
    "github_issues": _spec("github_issues", "emails", ["api.github.com", "github.com"]),
    "target_page": _spec(
        "target_page",
        "emails",
        ["web.archive.org"],
        requires_target_requests=False,
        notes="Uses Wayback Machine archived homepage snapshots — passive, no direct target request",
    ),
    "security_txt": _spec(
        "security_txt",
        "emails",
        ["web.archive.org"],
        requires_target_requests=False,
        notes="Uses Wayback Machine archived security.txt — passive, no direct target request",
    ),
    "urlhaus": _spec("urlhaus", "reputation", ["urlhaus-api.abuse.ch"]),
    "threatfox": _spec("threatfox", "reputation", ["threatfox-api.abuse.ch"]),
    "phishtank": _spec("phishtank", "reputation", ["checkurl.phishtank.com"]),
    "talos": _spec("talos", "reputation", ["talosintelligence.com"]),
    "pulsedive": _spec("pulsedive", "reputation", ["pulsedive.com"]),
    "spamhaus_dbl": _spec("spamhaus_dbl", "reputation", ["spamhaus.org"]),
    "surbl": _spec("surbl", "reputation", ["surbl.org"]),
    "crunchbase": _spec("crunchbase", "social", ["www.crunchbase.com"]),
    "facebook": _spec("facebook", "social", ["www.facebook.com"]),
    "github": _spec("github", "social", ["github.com"]),
    "linkedin": _spec("linkedin", "social", ["www.linkedin.com"]),
    "twitter": _spec("twitter", "social", ["twitter.com", "x.com"]),
    "youtube": _spec("youtube", "social", ["www.youtube.com"]),
    "github_org": _spec("github_org", "social", ["api.github.com", "github.com"], notes="Public GitHub organization metadata"),
    "github_repos": _spec("github_repos", "social", ["api.github.com", "github.com"], notes="Public GitHub repository metadata"),
    "itunes": _spec("itunes", "social", ["itunes.apple.com"], notes="App-store brand footprint"),
    "npm": _spec("npm", "social", ["registry.npmjs.org", "www.npmjs.com"], notes="Package ecosystem brand footprint"),
    "urlscan_social": _spec("urlscan_social", "social", ["urlscan.io"], notes="Social profile extraction from URLScan indexed results"),
    "shodan_internetdb": _spec("shodan_internetdb", "ip_intel", ["internetdb.shodan.io"], notes="Passive Shodan InternetDB enrichment"),
    "ipinfo": _spec("ipinfo", "ip_intel", ["ipinfo.io"]),
    "bgpview": _spec("bgpview", "ip_intel", ["api.bgpview.io"]),
    "greynoise": _spec("greynoise", "ip_intel", ["api.greynoise.io"]),
    "grayhatwarfare": _spec("grayhatwarfare", "cloud", ["buckets.grayhatwarfare.com"]),
    "docker_hub": _spec("docker_hub", "cloud", ["hub.docker.com"]),
    "virustotal": _spec(
        "virustotal", "subdomains", ["www.virustotal.com", "www.virustotal.com"],
        requires_keys=True, env_vars=("GRT_VIRUSTOTAL",)
    ),
    "chaos": _spec("chaos", "subdomains", ["dns.projectdiscovery.io"], requires_keys=True, env_vars=("GRT_CHAOS",)),
}


PROFILE_DISABLED: Dict[str, set[str]] = {
    "conservative": {"rapiddns_pages", "urlscan_pages", "commoncrawl_mailto", "commoncrawl_index", "wayback_snapshots", "dnshistory"},
    "balanced": set(),
    "aggressive": set(),
}


_KEYED_HINTS = {
    "virustotal", "chaos", "bevigil",
}


def _infer_category(source_name: str) -> str:
    n = (source_name or "").lower()
    if any(k in n for k in ("ct", "crt", "cert", "certspotter")):
        return "ct"
    if any(k in n for k in ("mail", "email", "hunter", "pgp")):
        return "emails"
    if any(k in n for k in ("archive", "wayback", "commoncrawl")):
        return "history"
    if any(k in n for k in ("vuln", "takeover", "nuclei")):
        return "vulns"
    if any(k in n for k in ("ip", "asn", "shodan")):
        return "ip_intel"
    if any(k in n for k in ("social", "twitter", "linkedin", "github", "facebook")):
        return "social"
    if any(k in n for k in ("reputation", "threat", "otx", "urlhaus")):
        return "reputation"
    return "subdomains"


def _infer_requires_target_requests(source_name: str) -> bool:
    n = (source_name or "").lower()
    return n in {"target_page", "security_txt"} or "target" in n


def _auto_register_source(source_name: str) -> SourceSpec:
    name = (source_name or "").strip()
    n = name.lower()
    spec = _spec(
        name,
        _infer_category(n),
        [],
        requires_keys=(n in _KEYED_HINTS),
        requires_target_requests=_infer_requires_target_requests(n),
        notes="Auto-registered from runtime sources_map; review recommended.",
    )
    SOURCE_CATALOG[name] = spec
    return spec


class SourceRegistry:
    def __init__(
        self,
        *,
        profile: str = "balanced",
        enable: Optional[Iterable[str]] = None,
        disable: Optional[Iterable[str]] = None,
        api_keys: Optional[Mapping[str, str]] = None,
        force_no_keys: bool = False,
        allow_target_requests: bool = False,
    ):
        self.profile = (profile or "balanced").lower().strip()
        if self.profile not in PROFILE_DISABLED:
            self.profile = "balanced"
        self._enabled_overrides = {x.strip() for x in (enable or []) if x.strip()}
        self._disabled_overrides = {x.strip() for x in (disable or []) if x.strip()}
        self.api_keys = dict(api_keys or {})
        self.force_no_keys = force_no_keys
        self.allow_target_requests = bool(allow_target_requests)
        self.status_by_source: Dict[str, str] = {}

    def clone(self) -> "SourceRegistry":
        return SourceRegistry(
            profile=self.profile,
            enable=set(self._enabled_overrides),
            disable=set(self._disabled_overrides),
            api_keys=dict(self.api_keys),
            force_no_keys=self.force_no_keys,
            allow_target_requests=self.allow_target_requests,
        )

    def enable_source(self, name: str) -> None:
        n = (name or "").strip()
        if not n:
            return
        self._enabled_overrides.add(n)
        self._disabled_overrides.discard(n)

    def disable_source(self, name: str) -> None:
        n = (name or "").strip()
        if not n:
            return
        self._disabled_overrides.add(n)
        self._enabled_overrides.discard(n)

    def list_sources(self) -> list[dict[str, Any]]:
        rows = []
        for name, spec in sorted(SOURCE_CATALOG.items()):
            runtime_support = runtime_support_for_source(name)
            rows.append({
                **asdict(spec),
                "runtime_support": runtime_support,
                "runnable": runtime_support == "direct",
                "status": self.effective_status(name),
            })
        return rows

    def effective_status(self, source_name: str) -> str:
        spec = SOURCE_CATALOG.get(source_name) or _auto_register_source(source_name)
        runtime_support = runtime_support_for_source(source_name)
        if runtime_support == "metadata_only":
            return "metadata_only"
        if runtime_support == "indirect":
            return "indirect_runtime"
        if source_name in self._disabled_overrides:
            return "disabled"
        if source_name in PROFILE_DISABLED.get(self.profile, set()) and source_name not in self._enabled_overrides:
            return "disabled_by_profile"
        if not spec.default_enabled and source_name not in self._enabled_overrides:
            return "disabled_default"
        if spec.requires_target_requests and not self.allow_target_requests:
            return "blocked_target_requests_policy"
        if spec.requires_keys:
            if self.force_no_keys:
                return "disabled_no_keys_mode"
            required_credentials = source_to_required_credentials(source_name, spec.env_vars)
            if not required_credentials:
                aliases = {
                    source_name,
                    source_name.replace("-", "_"),
                    source_name.replace("_", ""),
                }
                has_key = any(bool(self.api_keys.get(a, "")) for a in aliases)
            else:
                has_key = all(bool(self.api_keys.get(credential, "")) for credential in required_credentials)
            if not has_key:
                return "skipped_missing_key"
        return "ok"

    def should_run(self, source_name: str) -> tuple[bool, str]:
        st = self.effective_status(source_name)
        return st == "ok", st

    def filter_sources(self, sources_map: Dict[str, Any]) -> tuple[Dict[str, Any], Dict[str, str]]:
        selected: Dict[str, Any] = {}
        statuses: Dict[str, str] = {}
        for name, fn in sources_map.items():
            if name not in SOURCE_CATALOG:
                _auto_register_source(name)
            run, status = self.should_run(name)
            statuses[name] = status
            if run:
                selected[name] = fn
        self.status_by_source.update(statuses)
        return selected, statuses


def list_sources(
    *,
    profile: str = "balanced",
    enable: Optional[Iterable[str]] = None,
    disable: Optional[Iterable[str]] = None,
    api_keys: Optional[Mapping[str, str]] = None,
    allow_target_requests: bool = False,
) -> list[dict[str, Any]]:
    return SourceRegistry(
        profile=profile,
        enable=enable,
        disable=disable,
        api_keys=api_keys,
        allow_target_requests=allow_target_requests,
    ).list_sources()
