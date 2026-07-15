from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class CanonicalAction:
    action_id: str
    tool: str
    target: str
    arguments: dict[str, Any]
    kind: str = "baseline"
    priority: str = "P2"
    sources: list[str] = field(default_factory=list)
    strategy_ids: list[str] = field(default_factory=list)
    idempotency_key: str = ""
    requires_approval: bool = False
    status: str = "pending"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ActionBudget:
    max_actions: int
    proposed_actions: int = 0
    started_actions: int = 0
    filtered_actions: int = 0

    def to_dict(self) -> dict[str, int]:
        return asdict(self)


@dataclass
class WorkflowPolicy:
    mode: str = "interactive"
    max_tool_calls: int = 8
    max_escalation: int = 2
    stop_on_proof: bool = True

    def __post_init__(self):
        if self.mode not in {"interactive", "guided", "autopilot"}:
            raise ValueError("mode must be interactive, guided, or autopilot")
        if self.max_tool_calls < 1:
            raise ValueError("max_tool_calls must be positive")

    def to_dict(self):
        return asdict(self)
