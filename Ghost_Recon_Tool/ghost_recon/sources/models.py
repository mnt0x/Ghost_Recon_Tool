from __future__ import annotations

from dataclasses import dataclass, field
from typing import Tuple


@dataclass(slots=True)
class SourceSpec:
    name: str
    category: str
    hosts: Tuple[str, ...] = field(default_factory=tuple)
    requires_keys: bool = False
    requires_target_requests: bool = False
    env_vars: Tuple[str, ...] = field(default_factory=tuple)
    default_enabled: bool = True
    mode: str = "PASSIVE"
    rate_limit: int = 12
    timeout: int = 25
    retries: int = 2
    notes: str = ""
