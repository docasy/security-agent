"""
================================================================================
MCP → LangChain 工具桥接层
================================================================================

【这个文件是干什么的】
将 MCP 协议定义的工具动态转换为 LangChain 兼容的 Tool 对象。
这个桥接层的存在意义：MCP 工具和 LangChain 工具是两个不同的接口标准，
需要适配器模式（Adapter Pattern）来桥接。

【面试重点——经典设计模式】
这是一个典型的"适配器模式"（Adapter Pattern）实现:
- 被适配者（Adaptee）: MCP 工具（MCPTool dataclass）
- 目标接口（Target）: LangChain Tool（@tool 装饰的函数）
- 适配器（Adapter）: 本文件中的桥接逻辑

画在简历/面试白板上：
  ┌──────────┐     ┌──────────────┐     ┌──────────────┐
  │  LLM     │────▶│ LangChain    │────▶│ MCP Server   │
  │function  │     │ @tool 函数    │     │ (nmap/whatweb│
  │_call()   │     │ (桥接适配层)  │     │  /exploitdb) │
  └──────────┘     └──────────────┘     └──────────────┘
     标准 FC           LangChain 生态       MCP 标准协议

【面试追问：为什么要动态注册工具而不用静态定义？】
动态注册的优势:
  1. 新增 MCP Server 后，工具自动可用，不需要手动写 LangChain tool 代码
  2. 工具定义有单一数据源（MCP Server），避免 LangChain side 和 MCP side 不一致
  3. 符合 DRY 原则 —— 不需要在多个地方重复定义同一个工具

静态定义的劣势:
  1. 每加一个工具就要写一个新的 @tool 函数
  2. 工具定义在两个地方（MCP Server + LangChain Agent），容易不同步
  3. 代码冗余，维护成本高
================================================================================
"""

import json
from functools import partial
from typing import Any

from langchain_core.tools import tool as lc_tool

from src.mcp.client import MCPClientManager, MCPTool


async def mcp_to_langchain_tools(manager: MCPClientManager) -> list:
    """
    将 MCP Client Manager 中发现的所有工具转换为 LangChain Tool 列表。

    这是动态工具注册的核心函数：
    1. 从 manager 获取所有已发现的 MCP 工具（已经在 start_all 时完成发现）
    2. 遍历每个工具，创建一个对应的 LangChain @tool 函数
    3. 函数内部调用 manager.call_tool() 转发到 MCP Server

    参数:
      manager: 已初始化（已调用 start_all）的 MCP Client Manager

    返回:
      LangChain Tool 对象列表，可直接传给 create_react_agent 等 LangGraph API

    使用示例:
      async with MCPClientManager() as mcp:
          tools = await mcp_to_langchain_tools(mcp)
          agent = create_react_agent(model, tools)
    """
    mcp_tools = await manager.discover_tools()
    langchain_tools = []

    for key, mcp_tool in mcp_tools.items():
        server_name = mcp_tool.server_name
        tool_name = mcp_tool.tool_name

        # ================================================================
        # 动态创建 LangChain tool 函数
        # ================================================================
        # 核心技巧：用 functools.partial 将 manager 和 server_name/tool_name
        # 绑定到函数中，形成闭包。每个 LangChain tool 函数在调用时，
        # 自动将参数转发到对应的 MCP Server。

        async def make_tool_call(
            _manager: MCPClientManager,
            _server: str,
            _tool: str,
            **kwargs,
        ) -> str:
            """
            实际执行 MCP 工具调用的函数。

            这个函数被 partial 绑定后成为 LangChain @tool 的实体。
            LLM 调用时自动传入 kwargs（从 function_call.arguments 解析而来），
            然后这里转发给 MCP Manager → MCP Server。
            """
            result = await _manager.call_tool(_server, _tool, kwargs)
            return result

        # 使用 partial 绑定前三个参数（manager, server_name, tool_name）
        # 这样生成的函数签名只剩 **kwargs，正好匹配 LangChain tool 的接口
        tool_func = partial(make_tool_call, manager, server_name, tool_name)

        # 设置函数名 —— LangChain 用函数名作为工具的唯一标识
        # 命名规范: mcp_{server}_{tool}，如 mcp_nmap_scan_ports
        tool_func.__name__ = f"mcp_{server_name}_{tool_name}"

        # 设置函数文档 —— LLM 通过 __doc__ 了解工具的用途和参数
        # 这是 LangChain 判断什么时候调用这个工具的关键依据
        tool_func.__doc__ = mcp_tool.description

        # ================================================================
        # 设置函数参数类型注解
        # ================================================================
        # LangChain 需要 __annotations__ 来生成 OpenAI Function Calling 的
        # parameters schema。这里从 MCP 工具的 JSON Schema 转换为 Python 类型注解。
        #
        # JSON Schema type → Python type 映射:
        #   string  → str
        #   integer → int
        #   number  → float
        #   boolean → bool
        #   array   → list
        props = mcp_tool.input_schema.get("properties", {})
        annotations = {}
        for pname, prop in props.items():
            ptype = prop.get("type", "string")
            type_map = {
                "string": str,
                "integer": int,
                "number": float,
                "boolean": bool,
                "array": list,
            }
            annotations[pname] = type_map.get(ptype, str)
        tool_func.__annotations__ = annotations

        # LangChain 的 @tool 装饰器会读取 __name__、__doc__、__annotations__
        # 并自动生成 OpenAI Function Calling 所需的 JSON Schema
        wrapped = lc_tool(tool_func)
        langchain_tools.append(wrapped)

    return langchain_tools
