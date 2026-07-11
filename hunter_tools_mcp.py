"""Compatibility launcher for the complete Hunter Tools MCP server.

The complete tool registry lives in mcp_server.py. This file intentionally
creates no second FastMCP instance; old launch paths delegate to the one true
hunter_tools server.
"""

from mcp_server import *  # noqa: F401,F403
from mcp_server import main


if __name__ == "__main__":
    main()
