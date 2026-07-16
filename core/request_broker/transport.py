from __future__ import annotations

from typing import Any


class AsyncHttpxRaceTransport:
    """HTTP/2 transport owned by the Broker boundary for race experiments."""

    def __init__(self) -> None:
        self.client: Any | None = None

    async def _get_client(self) -> Any:
        if self.client is None:
            try:
                import httpx
            except ImportError as exc:
                raise RuntimeError("httpx[http2] is required for race experiments") from exc
            self.client = httpx.AsyncClient(http2=True, verify=False)
        return self.client

    async def request(self, spec: dict[str, Any], *, phase: str, index: int = 0) -> dict[str, Any]:
        del phase, index
        client = await self._get_client()
        kwargs: dict[str, Any] = {
            "headers": dict(spec.get("headers") or {}),
            "params": spec.get("params"),
            "follow_redirects": False,
            "timeout": float(spec.get("timeout") or 10),
        }
        if "json" in spec:
            kwargs["json"] = spec["json"]
        elif "body" in spec:
            kwargs["content"] = spec["body"]
        elif "data" in spec:
            kwargs["data"] = spec["data"]
        response = await client.request(str(spec.get("method") or "GET").upper(), spec["url"], **kwargs)
        return {
            "status": response.status_code,
            "body": response.text[:10000],
            "headers": dict(response.headers),
            "http_version": response.http_version,
        }

    async def aclose(self) -> None:
        if self.client is not None:
            await self.client.aclose()
