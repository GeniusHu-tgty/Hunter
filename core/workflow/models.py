from __future__ import annotations
from dataclasses import asdict, dataclass


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
