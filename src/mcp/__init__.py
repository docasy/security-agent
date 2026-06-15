"""MCP (Model Context Protocol) — 2026 Agent 岗位核心考点

面试必问：
1. MCP 协议解决了什么问题？（工具集成的标准化，类比 USB-C）
2. 为什么不用传统的 Function Calling？（工具与 Agent 解耦，跨平台复用）
3. MCP Server 的通信方式？（stdio / SSE，本项目用 stdio）
"""

from src.mcp.client import MCPClientManager
from src.mcp.langchain_bridge import mcp_to_langchain_tools
