"""Concurrent scan manager for queued/running/cancelled scan lifecycle."""

from __future__ import annotations

import asyncio
import contextlib
import os
import time
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Dict, List, Optional


ScanRunner = Callable[[str, Callable[[str, Dict[str, Any]], Awaitable[None]]], Awaitable[Dict[str, Any]]]


@dataclass
class ScanState:
    scan_id: str
    domain: str
    mode: str
    status: str = "queued"
    started_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)
    ended_at: float = 0.0
    phase: str = ""
    progress: int = 0
    total_modules: int = 0
    completed_modules: int = 0
    counters: Dict[str, int] = field(default_factory=dict)
    phase_started_at: Dict[str, float] = field(default_factory=dict)
    phase_durations: Dict[str, float] = field(default_factory=dict)
    module_states: Dict[str, str] = field(default_factory=dict)
    providers: Dict[str, int] = field(default_factory=lambda: {"success": 0, "partial": 0, "failed": 0})
    result_paths: Dict[str, str] = field(default_factory=dict)
    errors: List[Dict[str, Any]] = field(default_factory=list)
    events: List[Dict[str, Any]] = field(default_factory=list)


class ScanManager:
    def __init__(
        self,
        *,
        max_concurrent_scans: Optional[int] = None,
        keep_last_n_scans: int = 20,
    ):
        self.max_concurrent_scans = int(max_concurrent_scans or int(os.environ.get("GRT_MAX_SCANS", "3")))
        self.max_concurrent_scans = max(1, min(8, self.max_concurrent_scans))
        self.keep_last_n_scans = max(5, int(keep_last_n_scans))
        self._semaphore = asyncio.Semaphore(self.max_concurrent_scans)
        self._states: Dict[str, ScanState] = {}
        self._tasks: Dict[str, asyncio.Task[Any]] = {}
        self._subscribers: Dict[str, List[asyncio.Queue]] = {}
        self._lock = asyncio.Lock()

    async def submit(self, scan_id: str, domain: str, mode: str, runner: ScanRunner) -> ScanState:
        async with self._lock:
            state = ScanState(scan_id=scan_id, domain=domain, mode=mode, status="queued")
            self._states[scan_id] = state
            self._subscribers.setdefault(scan_id, [])
            task = asyncio.create_task(self._run_scan(scan_id, runner))
            self._tasks[scan_id] = task
            await self._publish(scan_id, "start", {"scan_id": scan_id, "domain": domain, "mode": mode, "status": "queued"})
            return state

    async def _run_scan(self, scan_id: str, runner: ScanRunner) -> None:
        state = self._states.get(scan_id)
        if not state:
            return
        try:
            async with self._semaphore:
                state.status = "running"
                state.updated_at = time.time()
                await self._publish(scan_id, "phase", {"name": "Queue", "status": "done", "scan_id": scan_id})
                await self._publish(scan_id, "phase", {"name": "Execution", "status": "running", "scan_id": scan_id})
                result_meta = await runner(scan_id, lambda et, data: self._publish(scan_id, et, data))
                state.result_paths = {
                    "report_json": str(result_meta.get("report_json", "")),
                    "report_txt": str(result_meta.get("report_txt", "")),
                    "report_html": str(result_meta.get("report_html", "")),
                    "report_html_standalone": str(result_meta.get("report_html_standalone", "")),
                }
                state.status = "done"
                state.ended_at = time.time()
                state.updated_at = time.time()
                await self._publish(scan_id, "phase", {"name": "Execution", "status": "done", "scan_id": scan_id})
                await self._publish(scan_id, "saved", {"scan_id": scan_id, **state.result_paths})
        except asyncio.CancelledError:
            state.status = "cancelled"
            state.ended_at = time.time()
            state.updated_at = time.time()
            await self._publish(scan_id, "cancelled", {"scan_id": scan_id, "message": "Scan cancelled"})
            raise
        except Exception as exc:
            state.status = "failed"
            state.ended_at = time.time()
            state.updated_at = time.time()
            msg = str(exc)[:240]
            state.errors.append({"message_short": msg, "time": state.updated_at})
            await self._publish(scan_id, "error", {"scan_id": scan_id, "message": msg})
        finally:
            await self._prune_history()

    async def _publish(self, scan_id: str, event_type: str, data: Dict[str, Any]) -> None:
        state = self._states.get(scan_id)
        if not state:
            return
        payload = dict(data)
        payload.setdefault("scan_id", scan_id)
        if event_type == "start":
            state.total_modules = int(payload.get("total_modules", 0) or 0)
            enabled_modules = payload.get("enabled_modules", [])
            if isinstance(enabled_modules, list):
                for name in enabled_modules:
                    module_name = str(name or "").strip()
                    if module_name:
                        state.module_states.setdefault(module_name, "pending")
        if event_type == "phase":
            state.phase = str(payload.get("name", ""))
            phase_name = str(payload.get("name", "") or "")
            phase_status = str(payload.get("status", "") or "")
            count = int(payload.get("count", 0) or 0)
            now = time.time()
            counter_map = {
                "Subdomain Enumeration": "subdomains",
                "Email Discovery": "emails",
                "IP Intelligence": "ips",
                "Vulnerability Intelligence": "vulns",
                "SSL Intelligence": "certs",
                "Web Archive": "archive_urls",
                "Passive Artifact Intelligence": "artifacts",
            }
            if phase_status == "running" and phase_name:
                state.phase_started_at[phase_name] = now
                state.module_states[phase_name] = "running"
            if phase_status == "done" and phase_name not in {"Queue", "Execution"}:
                started = float(state.phase_started_at.get(phase_name, state.started_at) or state.started_at)
                state.phase_durations[phase_name] = round(max(0.0, now - started), 2)
                payload.setdefault("duration_seconds", state.phase_durations[phase_name])
                state.completed_modules += 1
                state.module_states[phase_name] = "done"
                if state.total_modules > 0:
                    state.progress = min(99, int((state.completed_modules / max(1, state.total_modules)) * 100))
                counter_key = counter_map.get(phase_name)
                if counter_key:
                    state.counters[counter_key] = count
                if phase_name == "IP Intelligence":
                    state.counters["ports"] = int(payload.get("ports", state.counters.get("ports", 0)) or 0)
            elif phase_status in {"failed", "timeout", "skipped", "cancelled"} and phase_name:
                state.module_states[phase_name] = phase_status
            elif phase_status == "running" and state.total_modules > 0 and state.progress == 0:
                state.progress = 1
        if event_type in {"source_metrics", "source_coverage"}:
            providers = {"success": 0, "partial": 0, "failed": 0}
            sources = payload.get("sources", {})
            if isinstance(sources, dict):
                for src_data in sources.values():
                    if not isinstance(src_data, dict):
                        continue
                    status = str(src_data.get("status", "ok") or "ok").lower()
                    if status in {"ok", "derived_ok"}:
                        providers["success"] += 1
                    elif status in {"partial", "timeout_partial", "fail_partial", "derived"}:
                        providers["partial"] += 1
                    elif status not in {"blocked_missing_api_key", "blocked_target_requests_policy"}:
                        providers["failed"] += 1
            for key, value in providers.items():
                state.providers[key] = state.providers.get(key, 0) + value
        if event_type == "complete":
            summary = payload.get("summary", {})
            if isinstance(summary, dict):
                state.counters.update({
                    "subdomains": int(summary.get("subdomains", 0) or 0),
                    "emails": int(summary.get("emails", 0) or 0),
                    "vulns": int(summary.get("vulns", 0) or 0),
                    "ips": int(summary.get("ips", summary.get("ip_records", 0)) or 0),
                    "ports": int(summary.get("ports", 0) or 0),
                    "certs": int(summary.get("certs", 0) or 0),
                    "archive_urls": int(summary.get("archive_urls", 0) or 0),
                })
            state.progress = max(state.progress, 99)
        if event_type == "saved":
            state.progress = 100
            if not state.ended_at:
                state.ended_at = time.time()
        state.updated_at = time.time()
        state.events.append({"event": event_type, "data": payload, "ts": state.updated_at})
        if len(state.events) > 300:
            state.events = state.events[-300:]
        for q in list(self._subscribers.get(scan_id, [])):
            try:
                q.put_nowait({"event": event_type, "data": payload})
            except asyncio.QueueFull:
                continue

    async def subscribe(self, scan_id: str, replay: bool = True) -> asyncio.Queue:
        queue: asyncio.Queue = asyncio.Queue(maxsize=512)
        self._subscribers.setdefault(scan_id, []).append(queue)
        if replay and scan_id in self._states:
            for evt in self._states[scan_id].events[-100:]:
                await queue.put(dict(evt))
        return queue

    def unsubscribe(self, scan_id: str, queue: asyncio.Queue) -> None:
        subs = self._subscribers.get(scan_id, [])
        if queue in subs:
            subs.remove(queue)

    def get_state(self, scan_id: str) -> Optional[Dict[str, Any]]:
        state = self._states.get(scan_id)
        if not state:
            return None
        now = time.time()
        end_ts = state.ended_at or now
        return {
            "scan_id": state.scan_id,
            "domain": state.domain,
            "mode": state.mode,
            "status": state.status,
            "started_at": state.started_at,
            "updated_at": state.updated_at,
            "duration_seconds": round(max(0.0, end_ts - state.started_at), 2),
            "phase": state.phase,
            "progress": state.progress,
            "total_modules": state.total_modules,
            "completed_modules": state.completed_modules,
            "counters": dict(state.counters),
            "phase_durations": dict(state.phase_durations),
            "module_states": dict(state.module_states),
            "providers": dict(state.providers),
            "result_paths": dict(state.result_paths),
            "errors": [dict(row) for row in state.errors[-10:]],
        }

    def list_scans(self) -> List[Dict[str, Any]]:
        items = [self.get_state(scan_id) for scan_id in self._states]
        rows = [row for row in items if row]
        rows.sort(key=lambda row: float(row.get("started_at", 0)), reverse=True)
        return rows

    async def cancel(self, scan_id: str) -> bool:
        task = self._tasks.get(scan_id)
        state = self._states.get(scan_id)
        if not task or not state:
            return False
        if state.status in {"done", "failed", "cancelled"}:
            return False
        task.cancel()
        with contextlib.suppress(BaseException):
            await task
        return True

    async def _prune_history(self) -> None:
        states_sorted = sorted(self._states.values(), key=lambda s: s.started_at, reverse=True)
        if len(states_sorted) <= self.keep_last_n_scans:
            return
        for state in states_sorted[self.keep_last_n_scans :]:
            if state.status in {"running", "queued"}:
                continue
            scan_id = state.scan_id
            self._states.pop(scan_id, None)
            self._tasks.pop(scan_id, None)
            self._subscribers.pop(scan_id, None)
