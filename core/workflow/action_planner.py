from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from typing import Any

from .models import CanonicalAction


class ActionPlanner:
    PRIORITY = {"P0": 0, "P1": 1, "P2": 2}
    KIND_TO_TOOL = {
        "authentication_bypass": "hunter_auto_access_control",
        "authentication": "hunter_auto_access_control",
        "sqli": "hunter_auto_sqli",
        "sqli_xss": "hunter_auto_sqli",
        "xss": "hunter_auto_xss",
        "information_disclosure": "hunter_auto_access_control",
        "file_upload": "hunter_auto_access_control",
        "api_access_control": "hunter_auto_access_control",
        "ssrf_open_redirect": "hunter_auto_ssrf",
        "registration": "hunter_auto_csrf",
        "baseline": "hunter_scan_plan",
    }
    TOOL_KINDS = {
        "hunter_auto_sqli": "sqli",
        "hunter_auto_xss": "xss",
        "hunter_auto_ssrf": "ssrf_open_redirect",
        "hunter_auto_ssti": "ssti",
        "hunter_auto_xxe": "xxe",
        "hunter_auto_cmd": "command_injection",
        "hunter_auto_idor": "api_access_control",
        "hunter_auto_access_control": "api_access_control",
        "hunter_auto_csrf": "registration",
        "hunter_auto_jwt": "api_access_control",
        "hunter_auto_graphql": "graphql",
        "hunter_auto_websocket": "websocket",
        "hunter_auto_race": "race",
        "hunter_browser_navigate": "authentication",
        "hunter_scan_plan": "baseline",
        "hunter_session_execute_chain": "authentication",
    }

    def plan(
        self,
        general_queue: Sequence[Mapping[str, Any]] | None,
        reasoned_queue: Sequence[Mapping[str, Any]] | None,
        *,
        modules: Sequence[str] | None = None,
        requested_phases: Sequence[str] | None = None,
        max_actions: int = 8,
        completed_keys: Sequence[str] | set[str] | None = None,
    ) -> dict[str, Any]:
        actions = self._canonicalize(general_queue, "attack-surface")
        actions.extend(self._canonicalize(reasoned_queue, "reasoner"))
        merged = self._deduplicate(actions)
        selected: list[dict[str, Any]] = []
        filtered: list[dict[str, Any]] = []
        completed = {str(value) for value in (completed_keys or [])}
        allowed_modules = {
            str(value).casefold() for value in (modules or ["all"])
        }
        phases = {
            str(value).casefold() for value in (requested_phases or [])
        }
        budget = max(0, int(max_actions))

        for action in sorted(
            merged,
            key=lambda item: (
                self.PRIORITY.get(item.priority, 2),
                item.tool,
                item.target,
                item.idempotency_key,
            ),
        ):
            reason = self._filter_reason(
                action,
                allowed_modules=allowed_modules,
                requested_phases=phases,
                completed=completed,
            )
            if reason:
                filtered.append({**action.to_dict(), "reason": reason})
                continue
            if len(selected) >= budget:
                filtered.append(
                    {**action.to_dict(), "reason": "budget_exhausted"}
                )
                continue
            selected.append(action.to_dict())

        return {
            "actions": selected,
            "filtered_actions": filtered,
            "budget": {
                "max_actions": budget,
                "proposed_actions": len(merged),
                "started_actions": len(selected),
                "filtered_actions": len(filtered),
            },
        }

    def _canonicalize(
        self,
        queue: Sequence[Mapping[str, Any]] | None,
        source: str,
    ) -> list[CanonicalAction]:
        output: list[CanonicalAction] = []
        for raw in queue or []:
            if not isinstance(raw, Mapping):
                continue
            item = dict(raw)
            nested_actions = item.get("actions")
            if (
                isinstance(nested_actions, Sequence)
                and not isinstance(nested_actions, (str, bytes))
                and nested_actions
            ):
                output.extend(
                    self._canonicalize_nested(item, nested_actions, source)
                )
                continue
            output.append(self._canonical_action(item, source))
        return output

    def _canonicalize_nested(
        self,
        strategy: Mapping[str, Any],
        actions: Sequence[Any],
        source: str,
    ) -> list[CanonicalAction]:
        output: list[CanonicalAction] = []
        strategy_id = str(strategy.get("strategy_id") or "")
        for raw in actions:
            if not isinstance(raw, Mapping):
                continue
            action = dict(raw)
            params = dict(action.get("params") or {})
            if action.get("param"):
                params.setdefault("param", action["param"])
            output.append(
                self._canonical_action(
                    {
                        "tool": action.get("tool"),
                        "kind": action.get("kind"),
                        "priority": action.get("priority"),
                        "target": (
                            params.get("target")
                            or params.get("target_url")
                            or strategy.get("target")
                            or ""
                        ),
                        "arguments": params,
                        "strategy_id": strategy_id,
                        "status": (
                            action.get("status")
                            or strategy.get("status")
                            or "pending"
                        ),
                    },
                    source,
                )
            )
        return output

    def _canonical_action(
        self,
        item: Mapping[str, Any],
        source: str,
    ) -> CanonicalAction:
        arguments = dict(
            item.get("arguments")
            or item.get("tool_args")
            or {}
        )
        target = str(
            item.get("target")
            or arguments.get("target")
            or arguments.get("target_url")
            or ""
        )
        requested_kind = str(item.get("kind") or "")
        tool = str(
            item.get("tool")
            or self.KIND_TO_TOOL.get(requested_kind)
            or "hunter_scan_plan"
        )
        kind = str(
            requested_kind
            or self.TOOL_KINDS.get(tool)
            or "baseline"
        )
        parameters = item.get("parameters") or []
        if (
            "param" not in arguments
            and isinstance(parameters, Sequence)
            and not isinstance(parameters, (str, bytes))
            and parameters
        ):
            arguments["param"] = str(parameters[0])
        arguments.pop("target_url", None)
        arguments["target"] = target
        priority = str(item.get("priority") or "P2")
        strategy_id = str(item.get("strategy_id") or "")
        canonical = json.dumps(
            {
                "tool": tool,
                "target": target,
                "arguments": arguments,
                "kind": kind,
            },
            sort_keys=True,
            separators=(",", ":"),
            default=str,
        )
        key = hashlib.sha256(canonical.encode()).hexdigest()
        return CanonicalAction(
            action_id=f"act-{key[:16]}",
            tool=tool,
            target=target,
            arguments=arguments,
            kind=kind,
            priority=priority,
            sources=[source],
            strategy_ids=[strategy_id] if strategy_id else [],
            idempotency_key=key,
            status=str(item.get("status") or "pending"),
        )

    def _deduplicate(
        self,
        actions: Sequence[CanonicalAction],
    ) -> list[CanonicalAction]:
        merged: dict[str, CanonicalAction] = {}
        for action in actions:
            current = merged.get(action.idempotency_key)
            if current is None:
                merged[action.idempotency_key] = action
                continue
            current.sources = sorted(set(current.sources + action.sources))
            current.strategy_ids = sorted(
                set(current.strategy_ids + action.strategy_ids)
            )
            if self.PRIORITY.get(action.priority, 2) < self.PRIORITY.get(
                current.priority,
                2,
            ):
                current.priority = action.priority
        return list(merged.values())

    @staticmethod
    def _filter_reason(
        action: CanonicalAction,
        *,
        allowed_modules: set[str],
        requested_phases: set[str],
        completed: set[str],
    ) -> str:
        if action.idempotency_key in completed:
            return "already_completed"
        if requested_phases == {"recon"}:
            return "phase_excluded"
        if (
            "all" not in allowed_modules
            and action.kind.casefold() not in allowed_modules
        ):
            return "module_excluded"
        return ""
