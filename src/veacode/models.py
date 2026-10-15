"""Small, dependency-free contracts shared by controller and CLI adapters."""

from collections.abc import Callable
from dataclasses import asdict, dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Any, Protocol


class FailureKind(StrEnum):
    QUOTA = "quota"
    RATE_LIMIT = "rate_limit"
    NETWORK = "network"
    AUTH = "auth"
    BALANCE = "balance"
    UNAVAILABLE = "unavailable"
    TIMEOUT = "timeout"
    PERMISSION = "permission"
    PROTOCOL = "protocol"
    PROCESS = "process"
    CANCELLED = "cancelled"


@dataclass(frozen=True)
class Route:
    name: str
    harness: str
    model: str
    provider: str
    billing: str
    effort: str | None = None
    profile: str | None = None
    executable: str | None = None
    timeout_seconds: float = 900
    env: dict[str, str] = field(default_factory=dict)

    def public(self) -> dict[str, Any]:
        result = asdict(self)
        result["env"] = {key: "<configured>" for key in self.env}
        return result


@dataclass(frozen=True)
class RunRequest:
    task_id: str
    phase: str
    prompt: str
    workspace: Path
    run_dir: Path
    read_only: bool = False


@dataclass
class AdapterResult:
    success: bool
    text: str = ""
    failure: FailureKind | None = None
    message: str = ""
    session_id: str | None = None
    usage: dict[str, Any] = field(default_factory=dict)
    observed_model: str | None = None
    exit_code: int | None = None


EventCallback = Callable[[dict[str, Any]], None]
StartedCallback = Callable[[int], None]


class Adapter(Protocol):
    def run(
        self,
        route: Route,
        request: RunRequest,
        on_event: EventCallback,
        on_started: StartedCallback,
    ) -> AdapterResult: ...
