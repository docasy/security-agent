"""
================================================================================
MCP Client Manager — 多 MCP Server 连接管理器
================================================================================

【这个文件是干什么的】
管理多个 MCP Server 的完整生命周期：启动、工具发现、调用路由、优雅关闭。
是整个系统 MCP 集成层的中枢。

【面试重点】
这是面试官最可能深挖的文件，因为它展示了你的架构设计能力。
核心考点：
1. 为什么需要 Client Manager？（多 Server 管理、生命周期、工具发现统一入口）
2. stdio vs SSE 通信选择？（stdio 适合本地工具，SSE 适合远程服务）
3. 为什么用 mock 模式？（解耦开发和演示环境，没有系统工具也能完整展示）
4. 工具发现的机制？（Agent 启动时自动 list_tools，动态注册到 LLM tool registry）

【设计决策——为什么用 MCP 而不是直接在 Agent 里调 subprocess？】
传统方式:  Agent → subprocess.run("nmap -p 80 target")  → 解析文本输出
MCP 方式:   Agent → MCP Client → MCP Server (nmap) → 结构化响应 → Agent

MCP 方式的核心优势:
  - 解耦: 换一个扫描工具（比如从 nmap 换成 masscan）不需要改 Agent 代码
  - 复用: 同一个 nmap MCP Server 可以被多个 Agent 项目共享
  - 安全: MCP Server 可以在受限环境中运行（最小权限、网络隔离）
  - 标准化: 所有工具用同一个协议暴露，Agent 不需要为每个工具写适配代码

【架构图（面试时可以画在白板上）】
┌─────────────┐     ┌──────────────────┐     ┌──────────────┐
│  LLM Agent  │────▶│ MCPClientManager │────▶│ nmap Server  │
│  (analyzer) │     │                  │     │ (进程1:stdio) │
└─────────────┘     │ - start_all()    │     └──────────────┘
                    │ - discover_tools │     ┌──────────────┐
                    │ - call_tool()    │────▶│exploitdb Serv│
                    │ - stop_all()     │     │ (进程2:stdio) │
                    └──────────────────┘     └──────────────┘
                                             ┌──────────────┐
                                             │ whatweb Serv │
                                             │ (进程3:stdio) │
                                             └──────────────┘
================================================================================
"""

import asyncio
import os
import sys
from dataclasses import dataclass, field
from typing import Any, Optional

# ============================================================================
# Mock 模式：环境变量控制
# ============================================================================
# MCP_MOCK_MODE 环境变量设为 1 时，不启动真实 MCP Server 进程，
# 而是直接从 Python 模块读取工具定义，调用 mock 函数返回结果。
# 设计原因：
# 1. 面试演示不需要安装系统工具，能直接跑起来
# 2. 开发阶段减少依赖，focus 在 Agent 逻辑上
# 3. CI/CD 环境可能没有 nmap 等工具
MOCK_MODE = os.getenv("MCP_MOCK_MODE", "1") == "1"

# ============================================================================
# MCP SDK 导入
# ============================================================================
try:
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client
    HAS_MCP_SDK = True
except ImportError:
    HAS_MCP_SDK = False


# ============================================================================
# 数据结构定义
# ============================================================================

@dataclass
class MCPServerConfig:
    """
    MCP Server 的配置信息。

    【面试考点：为什么用 dataclass 而不是 dict？】
    dataclass 有类型提示、IDE 自动补全、字段级文档。
    在生产项目中，类型安全能防止拼写错误导致的运行时 bug。
    这也是面试中能展示你 Python 基本功的地方。
    """
    name: str          # Server 名称，用作工具名的前缀（如 nmap.scan_ports）
    module: str        # Python 模块路径，用于 mock 模式导入或真实模式启动子进程
    description: str   # 给开发者看的描述，日志和人阅读用
    enabled: bool = True  # 是否启用，可以在配置文件中禁用不需要的 Server


# ============================================================================
# 注册所有可用的 MCP Server
# ============================================================================
# 这是系统的"工具注册表"。新增一个 MCP Server 只需要：
# 1. 创建 Server 文件（如 src/mcp/servers/new_tool_server.py）
# 2. 在这里加一行配置
# Agent 代码完全不需要改动，因为工具发现是动态的。
# 这就是 MCP 协议最大的工程价值——工具和 Agent 完全解耦。

REGISTERED_SERVERS = [
    MCPServerConfig(
        name="nmap",
        module="src.mcp.servers.nmap_server",
        description="端口扫描、服务版本检测、OS 指纹识别、NSE 漏洞扫描",
    ),
    MCPServerConfig(
        name="exploitdb",
        module="src.mcp.servers.exploitdb_server",
        description="Exploit-DB 漏洞利用数据库检索（按关键词/CVE/EDB-ID）",
    ),
    MCPServerConfig(
        name="whatweb",
        module="src.mcp.servers.whatweb_server",
        description="Web 技术栈指纹识别、CMS 检测、管理入口发现",
    ),
]


@dataclass
class MCPTool:
    """
    MCP 工具的标准化描述。

    这个 dataclass 是 MCP 工具定义在系统内部的表示。
    它把 MCP 协议的 Tool 对象（来自 mcp.types）转换为
    系统内部统一的格式，方便后续转换为 LangChain tool。

    【面试考点：为什么要做这个转换？】
    不同 Agent 框架（LangChain、AutoGen、CrewAI）对工具的定义格式不同。
    MCPTool 是系统内部的"标准格式"，可以用 Bridge 模式转换为各种框架的格式。
    这样切换 Agent 框架时只需要改 Bridge，不需要改 Server。
    """
    server_name: str       # 工具所属的 MCP Server 名称
    tool_name: str         # 工具名称
    description: str       # 工具的功能描述
    input_schema: dict     # JSON Schema 格式的参数定义


class MCPClientManager:
    """
    多 MCP Server 的连接管理器。

    【核心职责】
    1. 启动/停止所有 MCP Server 进程
    2. 统一发现所有 Server 提供的工具
    3. 提供统一的工具调用接口
    4. 在 mock 模式下用内存数据直接返回结果

    【使用方式】
        # 方式 1: 异步上下文管理器（推荐）
        async with MCPClientManager() as manager:
            tools = await manager.discover_tools()
            result = await manager.call_tool("nmap", "scan_ports", {"target": "127.0.0.1"})

        # 方式 2: 手动管理
        manager = MCPClientManager()
        await manager.start_all()
        # ... 使用 ...
        await manager.stop_all()
    """

    def __init__(self, servers: list[MCPServerConfig] = None, mock: bool = None):
        """
        初始化管理器。

        参数:
          servers: 要管理的 Server 配置列表，默认使用 REGISTERED_SERVERS
          mock: 是否强制使用 mock 模式，默认读环境变量 MCP_MOCK_MODE
        """
        self.servers = servers or REGISTERED_SERVERS
        self.mock = mock if mock is not None else MOCK_MODE
        # _sessions: 保存每个 Server 的 MCP 会话对象，用于通信
        self._sessions: dict[str, ClientSession] = {}
        # _transports: 保存每个 Server 的 stdio 传输层，用于清理
        # 注意：这里不用 async with 管理 transport，而是手动 __aenter__/__aexit__
        # 因为 transport 的生命周期是整个 Agent 运行期间，不是单次调用
        self._transports: dict[str, Any] = {}
        # _tools: 所有 Server 的工具汇总，key 格式为 "server_name.tool_name"
        self._tools: dict[str, MCPTool] = {}

    # ========================================================================
    # 上下文管理器接口
    # ========================================================================

    async def __aenter__(self):
        """
        进入 async with 块时自动调用。
        这样设计是为了让使用方写起来简洁：
            async with MCPClientManager() as mcp:
                # mcp 已经连接好，直接使用
        """
        await self.start_all()
        return self

    async def __aexit__(self, *args):
        """
        退出 async with 块时自动调用。
        保证即使发生异常也会关闭所有连接，不会泄漏进程。
        """
        await self.stop_all()

    # ========================================================================
    # 连接管理
    # ========================================================================

    async def start_all(self):
        """
        启动所有注册的 MCP Server。

        【启动流程】
        1. 检查 MCP SDK 是否已安装
           - 已安装 → 启动真实 MCP Server 子进程
           - 未安装 → 进入 mock 模式，从 Python 模块读取工具定义
        2. 对每个 Server: 启动进程 → 建立 stdio 连接 → 初始化会话 → 发现工具
        3. 某个 Server 启动失败不影响其他 Server

        【面试追问：为什么每个 MCP Server 是独立进程？】
        - 进程隔离：一个工具崩溃不影响其他工具和 Agent 主进程
        - 安全隔离：敏感工具（如数据库操作）可以在受限用户下运行
        - 独立扩展：可以分布在不同机器上（改 stdio 为 HTTP/SSE 即可）
        - 独立开发：不同团队可以独立开发和测试各自的 MCP Server
        """
        if not HAS_MCP_SDK:
            print(
                "[MCP] MCP SDK 未安装，自动切换到内存 mock 模式。\n"
                "[MCP] mock 模式下无需安装 nmap/whatweb/searchsploit 等系统工具。\n"
                "[MCP] 要使用真实模式: pip install mcp && 安装对应系统工具 && 设 MCP_MOCK_MODE=0",
                file=sys.stderr,
            )
            await self._start_mock()
            return

        # 并行启动所有 Server（用 asyncio.gather 并发执行）
        # 注意：这里没有用 gather，而是逐个启动，因为启动顺序可能影响日志可读性
        for server in self.servers:
            if not server.enabled:
                continue
            try:
                await self._start_server(server)
            except Exception as e:
                print(f"[MCP] ⚠ 启动 {server.name} 失败: {e}", file=sys.stderr)
                print(f"[MCP]    该 Server 将被跳过，不影响其他 Server 运行", file=sys.stderr)

    async def _start_mock(self):
        """
        以 mock 模式注册工具（不启动真实子进程）。

        直接从 Python 模块导入 TOOLS 定义列表，注册到内部 _tools 字典。
        这样 Agent 仍然能"看到"所有工具并进行调用，
        但实际执行走的是 mock 数据，不需要安装任何系统工具。
        """
        for server in self.servers:
            if not server.enabled:
                continue
            try:
                # 动态导入各 Server 模块的工具定义
                if server.name == "nmap":
                    from src.mcp.servers.nmap_server import NMAP_TOOLS
                    await self._register_mock_tools(server.name, NMAP_TOOLS)
                elif server.name == "exploitdb":
                    from src.mcp.servers.exploitdb_server import EXPLOITDB_TOOLS
                    await self._register_mock_tools(server.name, EXPLOITDB_TOOLS)
                elif server.name == "whatweb":
                    from src.mcp.servers.whatweb_server import WHATWEB_TOOLS
                    await self._register_mock_tools(server.name, WHATWEB_TOOLS)
            except Exception as e:
                print(f"[MCP] Mock 注册 {server.name} 失败: {e}", file=sys.stderr)

    async def _register_mock_tools(self, server_name: str, tool_defs: list):
        """
        将 MCP 工具定义列表注册到内部的 _tools 字典。

        工具的 key 格式为 "server_name.tool_name"，
        例如 "nmap.scan_ports", "exploitdb.search_exploits"。
        这种命名空间设计避免了不同 Server 之间的工具名冲突。
        """
        for tool in tool_defs:
            key = f"{server_name}.{tool.name}"
            self._tools[key] = MCPTool(
                server_name=server_name,
                tool_name=tool.name,
                description=tool.description,
                input_schema=tool.inputSchema,
            )

    async def _start_server(self, server: MCPServerConfig):
        """
        启动单个 MCP Server 子进程并建立 stdio 连接。

        【技术细节——为什么手动管理 transport 而不是 async with？】
        async with stdio_client(params) as (read, write):
            # ... 连接在这个代码块结束时就被关闭了

        使用 async with 的话，连接生命周期仅限于 with 块内。
        但我们需要在整个 Agent 运行期间保持连接，所以改为手动管理:
        1. 调用 transport.__aenter__() 获取读写流
        2. 保存 transport 引用到 _transports 字典
        3. 在 stop_all() 中调用 transport.__aexit__() 清理
        """
        mock_flag = "--mock" if self.mock else ""

        # StdioServerParameters 定义了如何启动 MCP Server 子进程
        params = StdioServerParameters(
            command=sys.executable,              # 用当前 Python 解释器
            args=["-m", server.module] + ([mock_flag] if mock_flag else []),
            # -m 表示以模块方式运行，等同于 python -m src.mcp.servers.nmap_server
        )

        # 创建 stdio 传输层
        transport = stdio_client(params)
        read, write = await transport.__aenter__()
        self._transports[server.name] = transport  # 保存引用，后续清理用

        # 创建 MCP 会话并初始化（握手、协议版本协商等）
        session = ClientSession(read, write)
        await session.initialize()
        self._sessions[server.name] = session

        # 工具发现：调用 Server 的 list_tools() 获取所有可用工具
        tools_result = await session.list_tools()
        for tool in tools_result.tools:
            key = f"{server.name}.{tool.name}"
            self._tools[key] = MCPTool(
                server_name=server.name,
                tool_name=tool.name,
                description=tool.description,
                input_schema=tool.inputSchema,
            )

    # ========================================================================
    # 工具发现
    # ========================================================================

    async def discover_tools(self) -> dict[str, MCPTool]:
        """
        返回所有已发现的 MCP 工具。

        返回的字典 key 为 "server_name.tool_name"，value 为 MCPTool 对象。
        这个字典可以直接传给 LangChain Bridge 转换为 LangChain tool 格式。

        【面试追问：工具发现是静态的还是动态的？】
        动态的。每次 start_all() 时重新从 MCP Server 获取最新工具列表。
        这意味着可以在运行时新增 MCP Server 或更新工具定义，
        不需要重启 Agent 主进程（实际业务中可能需要 notify Agent 刷新工具列表）。
        """
        return self._tools

    # ========================================================================
    # 工具调用
    # ========================================================================

    async def call_tool(self, server_name: str, tool_name: str, arguments: dict) -> str:
        """
        调用指定 Server 的指定工具。

        参数:
          server_name: MCP Server 名称（如 "nmap"）
          tool_name: 工具名称（如 "scan_ports"）
          arguments: 工具参数字典（如 {"target": "192.168.1.1", "ports": "1-1000"}）

        返回:
          工具执行结果的文本内容。

        【调用流程】
        1. 判断是 mock 模式还是真实模式
        2. Mock 模式 → 直接调用 mock 函数（在内存中完成）
        3. 真实模式 → 通过 MCP session 向 Server 子进程发送请求 → 等待响应
        """
        key = f"{server_name}.{tool_name}"

        if self.mock or server_name not in self._sessions:
            # Mock 模式: 调用预设的 mock 函数
            return await self._call_tool_mock(server_name, tool_name, arguments)

        # 真实模式: 通过 MCP 协议发送请求
        session = self._sessions[server_name]
        result = await session.call_tool(tool_name, arguments)
        # 提取第一个 content 的文本内容
        return result.content[0].text if result.content else ""

    async def _call_tool_mock(self, server_name: str, tool_name: str, arguments: dict) -> str:
        """
        Mock 模式下的工具调用。

        直接调用各 Server 模块中的 mock 函数，返回预设的模拟数据。
        不需要启动子进程，不需要安装系统工具。

        【mock 数据的设计原则】
        mock 返回的数据模拟真实场景，和 nmap/whatweb/exploitdb 的真实输出格式一致。
        这样后续的 LLM 分析逻辑在 mock 和真实模式下都能正常工作，
        切换只需要改一个环境变量。
        """
        if server_name == "nmap":
            from src.mcp.servers.nmap_server import MOCK_RESPONSES, _build_nmap_args
            _, mock_key = _build_nmap_args(tool_name, arguments)
            return MOCK_RESPONSES[mock_key](arguments.get("target", ""), arguments)
        elif server_name == "exploitdb":
            from src.mcp.servers.exploitdb_server import (
                _mock_search, _mock_info, MOCK_DB,
            )
            if tool_name == "search_exploits":
                return _mock_search(arguments["query"])
            elif tool_name == "get_exploit_info":
                return _mock_info(arguments["edb_id"])
            elif tool_name == "search_by_cve":
                return _mock_search(arguments["cve_id"])
            elif tool_name == "list_recent_exploits":
                limit = arguments.get("limit", 10)
                return "\n".join(
                    f"  [{e['id']}] {e['title']} ({e['date']})"
                    for e in MOCK_DB[:limit]
                )
        elif server_name == "whatweb":
            from src.mcp.servers.whatweb_server import MOCK_RESPONSES
            return MOCK_RESPONSES[tool_name](
                arguments.get("url", ""),
                arguments.get("aggression", "normal"),
            )

        return f"[MCP] 未知工具: {server_name}.{tool_name}"

    # ========================================================================
    # 清理
    # ========================================================================

    async def stop_all(self):
        """
        优雅关闭所有 MCP Server 连接和进程。

        【清理顺序很重要】
        1. 先关闭会话（发送 MCP 协议的关闭消息）
        2. 再关闭传输层（关闭 stdin/stdout 管道，子进程会自动退出）
        3. 清空内存状态

        如果顺序反了（先关传输再关会话），会话可能发送不了关闭消息，
        子进程可能会变成孤儿进程。虽然 stdio 传输中关闭 stdin 通常会让子进程自动退出，
        但规范的清理流程体现工程素养。
        """
        # 第一步：关闭所有 MCP 会话
        for name, session in self._sessions.items():
            try:
                await session.close()
            except Exception:
                pass  # 会话可能已经关闭，忽略错误

        # 第二步：关闭所有传输层（这会关闭子进程的 stdin/stdout）
        for name, transport in self._transports.items():
            try:
                await transport.__aexit__(None, None, None)
            except Exception:
                pass

        # 第三步：清空内存状态
        self._sessions.clear()
        self._transports.clear()
        self._tools.clear()

    # ========================================================================
    # 辅助方法
    # ========================================================================

    def get_tools_summary(self) -> str:
        """
        获取所有工具的摘要文本，用于注入 LLM 上下文。

        这个方法返回一段 Markdown 格式的工具列表，
        可以直接拼接到 Agent 的 system prompt 或 user message 中。
        LLM 看到这个列表后，就能知道有哪些工具可以调用。

        【为什么不是 JSON 而是 Markdown？】
        因为这段文本是给 LLM 读的（不是给程序解析的），
        Markdown 格式对 LLM 更友好，LLM 在 pre-training 中见过大量 Markdown。
        """
        lines = ["## 可用 MCP 渗透测试工具"]
        lines.append("下面是通过 MCP 协议连接的外部渗透测试工具：\n")
        for key, tool in self._tools.items():
            lines.append(f"- **{key}**: {tool.description}")
        return "\n".join(lines)
