import asyncio

from mcp.shared.memory import create_connected_server_and_client_session

import mcp_server


def test_hunter_mcp_transport_returns_structured_content_without_json_string_wrapper():
    async def exercise():
        async with create_connected_server_and_client_session(mcp_server.mcp) as client:
            tools = (await client.list_tools()).tools
            tool = next(
                item
                for item in tools
                if item.name == "hunter_workspace_health"
            )
            result = await client.call_tool("hunter_workspace_health", {})
            return tool, result

    tool, result = asyncio.run(exercise())

    assert tool.outputSchema is None
    assert result.structuredContent["tool"] == "hunter_workspace_health"
    assert result.structuredContent["status"] == "ok"
    assert "result" not in result.structuredContent
    assert result.content[0].text == "hunter_workspace_health: ok"
