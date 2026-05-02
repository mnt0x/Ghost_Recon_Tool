"""HTTP utility for secure async requests."""

from __future__ import annotations

import asyncio
import time
from collections import defaultdict, deque
from dataclasses import dataclass
from typing import Optional
import contextvars
import threading

import aiohttp

from ghost_recon.core.policy import target_request_allowed


@dataclass(slots=True)
class HttpConfig:
    timeout: int = 20
    retries: int = 2
    backoff_base: float = 0.35
    per_host_limit: int = 8
    rate_limit_per_sec: int = 12
    source_failure_threshold: int = 5
    source_cooldown_seconds: int = 60
    same_request_cooldown_ms: int = 250


CURRENT_SOURCE: contextvars.ContextVar[str] = contextvars.ContextVar("current_source", default="")
CURRENT_HTTP_GUARD: contextvars.ContextVar["HttpGuard | None"] = contextvars.ContextVar("current_http_guard", default=None)
CURRENT_SCAN_ID: contextvars.ContextVar[str] = contextvars.ContextVar("current_scan_id", default="")


def set_current_source(source_name: str) -> contextvars.Token:
    return CURRENT_SOURCE.set((source_name or "").strip())


def reset_current_source(token: contextvars.Token) -> None:
    CURRENT_SOURCE.reset(token)


def get_http_guard() -> "HttpGuard":
    guard = CURRENT_HTTP_GUARD.get()
    return guard or DEFAULT_HTTP_GUARD


def set_current_http_guard(guard: "HttpGuard") -> contextvars.Token:
    return CURRENT_HTTP_GUARD.set(guard)


def reset_current_http_guard(token: contextvars.Token) -> None:
    CURRENT_HTTP_GUARD.reset(token)


def set_current_scan_id(scan_id: str) -> contextvars.Token:
    return CURRENT_SCAN_ID.set((scan_id or "").strip())


def reset_current_scan_id(token: contextvars.Token) -> None:
    CURRENT_SCAN_ID.reset(token)


class SlidingRateLimiter:
    def __init__(self, rate_limit_per_sec: int):
        self.rate_limit_per_sec = max(rate_limit_per_sec, 1)
        self._events: deque[float] = deque()
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        async with self._lock:
            now = time.monotonic()
            while self._events and now - self._events[0] > 1.0:
                self._events.popleft()
            if len(self._events) >= self.rate_limit_per_sec:
                sleep_for = max(0.01, 1.0 - (now - self._events[0]))
                await asyncio.sleep(sleep_for)
                now = time.monotonic()
                while self._events and now - self._events[0] > 1.0:
                    self._events.popleft()
            self._events.append(time.monotonic())


class HttpGuard:
    def __init__(self, config: Optional[HttpConfig] = None):
        self.config = config or HttpConfig()
        self._host_sems: dict[str, asyncio.Semaphore] = defaultdict(
            lambda: asyncio.Semaphore(self.config.per_host_limit)
        )
        self._rate = SlidingRateLimiter(self.config.rate_limit_per_sec)
        self._source_rates: dict[str, SlidingRateLimiter] = defaultdict(
            lambda: SlidingRateLimiter(self.config.rate_limit_per_sec)
        )
        self._source_failures: dict[str, int] = defaultdict(int)
        self._source_open_until: dict[str, float] = defaultdict(float)
        self._source_limits: dict[str, int] = defaultdict(lambda: 8)
        self._source_sems: dict[str, asyncio.Semaphore] = defaultdict(lambda: asyncio.Semaphore(8))
        self._source_scan_limits: dict[tuple[str, str], int] = {}
        self._source_scan_sems: dict[tuple[str, str], asyncio.Semaphore] = {}
        self._recent_requests: dict[tuple[str, str, str], float] = defaultdict(float)
        self._active_scans: set[str] = set()
        self._active_scans_lock = threading.Lock()

    def _set_source_limit(self, source_name: str, new_limit: int) -> None:
        lim = max(2, min(32, int(new_limit)))
        self._source_limits[source_name] = lim
        self._source_sems[source_name] = asyncio.Semaphore(lim)

    def source_state(self, source_name: str) -> dict:
        name = (source_name or "").strip().lower()
        open_until = float(self._source_open_until.get(name, 0.0))
        now = time.monotonic()
        return {
            "source": name,
            "circuit_open": now < open_until,
            "circuit_seconds_left": max(0.0, round(open_until - now, 3)),
            "failure_count": int(self._source_failures.get(name, 0)),
            "concurrency_limit": int(self._source_limits.get(name, 8)),
            "rate_limit_per_sec": int(self.config.rate_limit_per_sec),
        }

    def register_scan(self, scan_id: str) -> None:
        sid = (scan_id or "").strip()
        if not sid:
            return
        with self._active_scans_lock:
            self._active_scans.add(sid)

    def unregister_scan(self, scan_id: str) -> None:
        sid = (scan_id or "").strip()
        if not sid:
            return
        with self._active_scans_lock:
            self._active_scans.discard(sid)

    def active_scan_count(self) -> int:
        with self._active_scans_lock:
            return max(1, len(self._active_scans))

    def _source_scan_limit(self, source_name: str, scan_id: str) -> int:
        source_key = (source_name or "").strip().lower()
        scan_key = (scan_id or "").strip()
        if not source_key or not scan_key:
            return self._source_limits.get(source_key, 8)
        return max(1, int(self._source_limits.get(source_key, 8)))

    def _source_scan_sem(self, source_name: str, scan_id: str) -> Optional[asyncio.Semaphore]:
        source_key = (source_name or "").strip().lower()
        scan_key = (scan_id or "").strip()
        if not source_key or not scan_key:
            return None
        key = (source_key, scan_key)
        limit = self._source_scan_limit(source_key, scan_key)
        current = self._source_scan_limits.get(key)
        if current != limit:
            self._source_scan_limits[key] = limit
            self._source_scan_sems[key] = asyncio.Semaphore(limit)
        return self._source_scan_sems[key]

    async def request(
        self,
        session: aiohttp.ClientSession,
        method: str,
        url: str,
        *,
        timeout: Optional[int] = None,
        headers: Optional[dict] = None,
        allow_redirects: bool = True,
        data=None,
        json=None,
        **kwargs,
    ) -> Optional[aiohttp.ClientResponse]:
        if not target_request_allowed(url):
            return None
        source_name = (kwargs.pop("source_name", "") or CURRENT_SOURCE.get() or "").strip().lower()
        scan_id = CURRENT_SCAN_ID.get().strip()
        ssl_verify = kwargs.pop("ssl", True)
        if source_name:
            now = time.monotonic()
            if now < self._source_open_until[source_name]:
                return None
            req_key = (source_name, method.upper(), url)
            last_req = self._recent_requests.get(req_key, 0.0)
            if (now - last_req) * 1000.0 < self.config.same_request_cooldown_ms:
                await asyncio.sleep(self.config.same_request_cooldown_ms / 1000.0)
            self._recent_requests[req_key] = time.monotonic()
        t = timeout or self.config.timeout
        retries = self.config.retries
        host = ""
        try:
            host = (aiohttp.client_reqrep.URL(url).host or "").lower()
        except Exception:
            host = ""
        sem = self._host_sems[host]
        source_sem = self._source_sems[source_name]
        source_scan_sem = self._source_scan_sem(source_name, scan_id)

        for attempt in range(retries + 1):
            try:
                if source_name:
                    await self._source_rates[source_name].acquire()
                else:
                    await self._rate.acquire()
                async with sem:
                    if source_scan_sem is not None:
                        async with source_scan_sem:
                            resp = await session.request(
                                method.upper(),
                                url,
                                timeout=aiohttp.ClientTimeout(total=t),
                                headers=headers,
                                allow_redirects=allow_redirects,
                                data=data,
                                json=json,
                                ssl=ssl_verify,
                                **kwargs,
                            )
                    else:
                        async with source_sem:
                            resp = await session.request(
                                method.upper(),
                                url,
                                timeout=aiohttp.ClientTimeout(total=t),
                                headers=headers,
                                allow_redirects=allow_redirects,
                                data=data,
                                json=json,
                                ssl=ssl_verify,
                                **kwargs,
                            )
                    if source_name:
                        st = int(getattr(resp, "status", 0) or 0)
                        if st in {429, 503}:
                            self._set_source_limit(source_name, self._source_limits[source_name] - 1)
                        elif 200 <= st < 300 and attempt == 0:
                            self._set_source_limit(source_name, self._source_limits[source_name] + 1)
                    return resp
            except (aiohttp.ClientError, asyncio.TimeoutError):
                if source_name:
                    self._source_failures[source_name] += 1
                    self._set_source_limit(source_name, self._source_limits[source_name] - 1)
                    if self._source_failures[source_name] >= self.config.source_failure_threshold:
                        self._source_open_until[source_name] = time.monotonic() + self.config.source_cooldown_seconds
                        self._source_failures[source_name] = 0
                if attempt >= retries:
                    return None
                await asyncio.sleep(self.config.backoff_base * (2**attempt))
        if source_name:
            self._source_failures[source_name] = 0
        return None

    async def get(
        self,
        session: aiohttp.ClientSession,
        url: str,
        *,
        timeout: Optional[int] = None,
        headers: Optional[dict] = None,
        allow_redirects: bool = True,
        **kwargs,
    ) -> Optional[aiohttp.ClientResponse]:
        return await self.request(
            session,
            "GET",
            url,
            timeout=timeout,
            headers=headers,
            allow_redirects=allow_redirects,
            **kwargs,
        )

    async def post(
        self,
        session: aiohttp.ClientSession,
        url: str,
        *,
        timeout: Optional[int] = None,
        headers: Optional[dict] = None,
        allow_redirects: bool = True,
        data=None,
        json=None,
        **kwargs,
    ) -> Optional[aiohttp.ClientResponse]:
        return await self.request(
            session,
            "POST",
            url,
            timeout=timeout,
            headers=headers,
            allow_redirects=allow_redirects,
            data=data,
            json=json,
            **kwargs,
        )


DEFAULT_HTTP_GUARD = HttpGuard()


def configure_http_guard(config: HttpConfig) -> None:
    global DEFAULT_HTTP_GUARD
    DEFAULT_HTTP_GUARD = HttpGuard(config=config)
