from __future__ import annotations

from dataclasses import dataclass, field, replace
from typing import Any


@dataclass(frozen=True)
class Identity:
    namespace: str
    cookies: dict[str, str] = field(default_factory=dict)
    bearer_token: str = ""
    refresh_token: str = ""
    csrf_token: str = ""
    user_agent: str = ""
    final_url: str = ""
    storage_state: dict[str, Any] = field(default_factory=dict)

    def headers(self) -> dict[str, str]:
        headers: dict[str, str] = {}
        if self.bearer_token:
            headers["Authorization"] = f"Bearer {self.bearer_token}"
        if self.csrf_token:
            headers["X-CSRF-Token"] = self.csrf_token
        if self.user_agent:
            headers["User-Agent"] = self.user_agent
        return headers


class IdentityPool:
    """Named identity namespaces shared by BrowserPool and RequestBroker."""

    def __init__(self) -> None:
        self._identities = {"anonymous": Identity("anonymous")}
        self._current = "anonymous"

    def register(self, namespace: str, **values: Any) -> Identity:
        if not namespace or namespace != namespace.strip():
            raise ValueError("identity namespace must be non-empty")
        allowed = {"cookies", "bearer_token", "refresh_token", "csrf_token", "user_agent", "final_url", "storage_state"}
        unknown = set(values) - allowed
        if unknown:
            raise ValueError(f"unsupported identity fields: {sorted(unknown)}")
        identity = Identity(namespace, **values)
        self._identities[namespace] = identity
        return identity

    def switch(self, namespace: str) -> Identity:
        if namespace not in self._identities:
            raise KeyError(f"unknown identity namespace: {namespace}")
        self._current = namespace
        return self._identities[namespace]

    @property
    def current(self) -> Identity:
        return self._identities[self._current]

    def import_browser_context(self, namespace: str, context: dict[str, Any]) -> Identity:
        identity = self._identities.get(namespace, Identity(namespace))
        cookies = dict(identity.cookies)
        cookies.update({str(key): str(value) for key, value in dict(context.get("cookies", {})).items()})
        imported = replace(
            identity,
            cookies=cookies,
            user_agent=str(context.get("user_agent", identity.user_agent)),
            final_url=str(context.get("final_url", identity.final_url)),
            storage_state=dict(context.get("storage_state", identity.storage_state)),
        )
        self._identities[namespace] = imported
        return imported
