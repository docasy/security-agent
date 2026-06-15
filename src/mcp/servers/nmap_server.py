"""
================================================================================
Nmap MCP Server — 端口扫描与服务检测
================================================================================

【这个文件是干什么的】
将 nmap（业内标准的网络扫描器）封装为一个符合 MCP 协议的独立服务。
通过 stdio（标准输入输出）与 AI Agent 通信，让 LLM 能"操作"真实的渗透测试工具。

【面试常问：为什么 nmap 要做成 MCP Server 而不是直接在 Agent 里 subprocess.run？】
1. 进程隔离 —— nmap 崩溃不会拖垮 Agent 主进程
2. 跨项目复用 —— 这个 MCP Server 可以被任何支持 MCP 的 Agent 框架调用
3. 标准化接口 —— Agent 不需要知道底层工具怎么装、参数怎么拼，只看到统一 Tool 列表
4. 权限控制 —— 可以在 MCP Server 层做鉴权（生产环境加 token 验证），Agent 层不需要关心

【MCP 协议基础】
MCP (Model Context Protocol) 是 Anthropic 提出的 AI 工具调用标准协议。
可以理解为 AI 界的 USB-C —— 不管 Agent 用什么框架，只要符合 MCP 标准就能用同一批工具。
通信方式有两种：stdio（标准输入输出，本项目使用）和 SSE（Server-Sent Events，适合远程）。

【Mock 模式 vs 真实模式】
Mock 模式用于演示 —— 不需要在机器上安装 nmap，返回预设的模拟数据。
这在面试时非常实用：面试官可以直接看到系统跑起来而不用担心环境问题。
设置方式：启动时加 --mock 参数，或设环境变量 MCP_MOCK_MODE=1

启动方式（独立进程）：
  python -m src.mcp.servers.nmap_server              # 真实模式（需装 nmap）
  python -m src.mcp.servers.nmap_server --mock       # 演示模式（无需装 nmap）
================================================================================
"""

import asyncio
import subprocess
import sys
import os

# 确保项目根目录在 sys.path 中
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", ".."))

# ============================================================================
# MCP SDK 导入 — 这是 2026 年 Agent 岗位的标配技能
# ============================================================================
# 面试时注意：mcp 包的版本迭代快，不同版本的 import 路径可能略有差异。
# 这里的 import 基于 mcp >= 1.0.0 版本。如果装的是旧版（0.x），API 会不同。
try:
    from mcp.server import Server          # MCP Server 基类
    from mcp.server.stdio import stdio_server  # stdio 传输层（读 stdin、写 stdout）
    from mcp.types import Tool, TextContent    # MCP 标准类型定义
    HAS_MCP = True  # SDK 已安装
except ImportError:
    HAS_MCP = False  # SDK 未安装，后面会给出提示

# 检查命令行参数，决定是否进入 mock 演示模式
MOCK_MODE = "--mock" in sys.argv


# ============================================================================
# 工具定义（Tools Schema）
# ============================================================================
# 面试重点：MCP 的 Tool 定义包含 name、description、inputSchema 三个字段。
# inputSchema 使用 JSON Schema 格式描述参数 —— 这和 OpenAI Function Calling 的
# function.parameters 格式一致，保证了协议的兼容性。
# LLM 通过 list_tools() 获取这些定义，然后根据用户指令决定调用哪个工具。

NMAP_TOOLS = [
    Tool(
        name="scan_ports",
        description=(
            "对目标 IP/域名执行 TCP 端口扫描，返回开放端口列表和服务名称。"
            "这是渗透测试的第一步（侦察），了解目标暴露了多少攻击面。"
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "目标 IP 地址或域名，如 192.168.1.1 或 example.com",
                },
                "ports": {
                    "type": "string",
                    "description": (
                        "端口范围，默认 1-1000（常见端口）。"
                        "可选: top-100（最常用100个）, 1-65535（全端口，较慢）, "
                        "或指定端口如 80,443,3306,8080"
                    ),
                    "default": "1-1000",
                },
            },
            # required 数组标记必填参数 —— LLM 看到这个就知道 target 必须提供
            "required": ["target"],
        },
    ),
    Tool(
        name="detect_services",
        description=(
            "对目标进行服务版本检测，识别运行的服务名称和精确版本号。"
            "比 scan_ports 更详细，但花的时间也更长（nmap 的 -sV 参数）。"
            "版本号是后续查找已知漏洞的关键输入。"
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "目标 IP 地址或域名",
                },
                "ports": {
                    "type": "string",
                    "description": (
                        "要检测的端口，多个用逗号分隔，如 '22,80,443,3306'。"
                        "留空则对常见端口做检测。建议先用 scan_ports 发现端口后再精确检测。"
                    ),
                },
            },
            "required": ["target"],
        },
    ),
    Tool(
        name="os_fingerprint",
        description=(
            "尝试识别目标操作系统类型和内核版本（nmap 的 -O 参数）。"
            "注意：此功能通常需要 root/管理员权限才能获得最准确的结果。"
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "目标 IP 地址（不支持域名，因为 OS 检测基于 TCP/IP 栈特征）",
                },
            },
            "required": ["target"],
        },
    ),
    Tool(
        name="vuln_scan",
        description=(
            "使用 nmap NSE (Nmap Scripting Engine) 脚本进行漏洞扫描。"
            "NSE 是 nmap 的插件系统，有数百个官方漏洞检测脚本。"
            "常见用途：检测心脏滴血(Heartbleed)、SSL/TLS 配置缺陷、SMB 漏洞等。"
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "目标 IP 或域名",
                },
                "category": {
                    "type": "string",
                    "description": (
                        "漏洞类别:\n"
                        "- vuln: 通用漏洞检测（CVE-2014-0160 心脏滴血等）\n"
                        "- ssl: SSL/TLS 配置问题（过期证书、弱加密套件）\n"
                        "- http: Web 相关漏洞（SQL注入点扫描等）\n"
                        "- auth: 认证相关检测（弱口令、默认凭证）\n"
                        "- default: 默认安全脚本集合"
                    ),
                    "enum": ["vuln", "ssl", "http", "auth", "default"],
                    "default": "vuln",
                },
            },
            "required": ["target"],
        },
    ),
]


# ============================================================================
# Mock 数据 — 演示模式下返回的模拟结果
# ============================================================================
# 设计思路：mock 数据不是随便编的，而是模拟了一次真实的渗透测试流程。
# 从端口扫描 → 服务识别 → OS 检测 → 漏洞发现，每个阶段的数据都互相关联。
# 例如：scan_ports 发现了 8080/tcp (Tomcat)，detect_services 确认是 Tomcat 9.0.58，
# vuln_scan 就顺理成章地提示可能存在 Log4Shell。
# 这种数据的连贯性能让面试官看到你理解真实的渗透测试工作流。

MOCK_RESPONSES = {
    "scan_ports": lambda target, args: (
        f"端口扫描结果: {target}\n"
        "PORT      STATE    SERVICE\n"
        "22/tcp    open     ssh              # 远程管理端口\n"
        "80/tcp    open     http             # Web 服务\n"
        "443/tcp   open     https            # 加密 Web 服务\n"
        "3306/tcp  open     mysql            # 数据库！暴露在公网是严重风险\n"
        "8080/tcp  open     http-proxy       # 可能是应用服务器管理面板\n"
        "8443/tcp  filtered https-alt        # 被防火墙过滤，可能只对内网开放\n\n"
        "扫描总结: 发现 5 个开放端口，1 个被过滤。\n"
        "高危发现: 3306(MySQL)和 8080(管理面板)直接暴露非常危险。\n"
        "建议: 立即检查 3306 是否需要公网访问，8080 是否有认证保护。"
    ),
    "detect_services": lambda target, args: (
        f"服务版本检测: {target}\n"
        "PORT      STATE    SERVICE  VERSION\n"
        "22/tcp    open     ssh      OpenSSH 8.2p1 (Ubuntu Linux; protocol 2.0)\n"
        "80/tcp    open     http     Apache httpd 2.4.41 ((Ubuntu))\n"
        "443/tcp   open     https    Apache httpd 2.4.41 (SSL)\n"
        "3306/tcp  open     mysql    MySQL 5.7.38\n"
        "8080/tcp  open     http     Apache Tomcat 9.0.58\n\n"
        "版本风险分析:\n"
        "  ⚠ OpenSSH 8.2p1 — 存在用户枚举漏洞 (CVE-2018-15473)\n"
        "  ⚠ Apache 2.4.41 — 相较于最新版有多个安全更新\n"
        "  🔴 MySQL 5.7.38 — 多个已知漏洞，建议升级到 8.0+\n"
        "  🔴 Tomcat 9.0.58 — 依赖的 Log4j 版本可能受 Log4Shell 影响\n"
    ),
    "os_fingerprint": lambda target, args: (
        f"OS 指纹识别结果: {target}\n"
        "Device type:   general purpose (服务器)\n"
        "Running:       Linux 4.X|5.X (较新内核)\n"
        "OS CPE:        cpe:/o:linux:linux_kernel:4 ~ cpe:/o:linux:linux_kernel:5\n"
        "OS details:    Linux 4.15 - 5.19 (具体版本无法精确定位)\n"
        "Network Distance: 推测为云服务器（响应延迟 < 1ms）\n"
        "置信度: 92%\n\n"
        "说明: 92% 的置信度意味着很可能判断正确。如果置信度低于 80%，\n"
        "面试时可以说你会在报告中标注不确定性，避免误判。"
    ),
    "vuln_scan": lambda target, args: (
        f"NSE 漏洞扫描结果: {target}\n"
        "nmap --script vuln 检测结果:\n"
        "| CVE-2014-0160 | Heartbleed (OpenSSL心脏滴血)  | NOT VULNERABLE |\n"
        "| CVE-2016-2183 | SWEET32 (SSL 3DES生日攻击)   | VULNERABLE     | 🔴\n"
        "| CVE-2021-44228| Log4Shell (Log4j JNDI注入)   | 需手动验证      | 🟡\n"
        "| CVE-2021-34473| ProxyShell (Exchange RCE)     | NOT DETECTED   |\n"
        "| ssl-poodle    | POODLE (SSLv3降级攻击)        | NOT VULNERABLE |\n\n"
        "漏洞总结:\n"
        "  🔴 确认漏洞 1 个: SWEET32 — 中间人攻击可解密 SSL 通信\n"
        "  🟡 待验证 1 个: Log4Shell — 如果 Tomcat 使用受影响 Log4j 版本则极其危险\n"
        "  ⚠ 注意: NSE 扫描可能有误报，建议用专用工具二次验证"
    ),
}


# ============================================================================
# 底层实现：执行真实的 nmap 命令
# ============================================================================

def _run_nmap(args: list[str]) -> str:
    """
    执行 nmap 命令行工具。

    【面试注意】
    这里直接用 subprocess 调用外部命令，而不是用 python-nmap 库。
    为什么？因为：
    1. subprocess 更通用 —— 不依赖第三方 Python 库是否维护
    2. MCP Server 本身就是"外部工具的包装层"，subprocess 是合理选择
    3. 生产环境可以改成 Docker 容器内执行，安全隔离更好
    """
    if MOCK_MODE:
        return ""  # mock 模式不走真实命令

    try:
        # 执行 nmap，超时 120 秒——全端口扫描可能要很久
        result = subprocess.run(
            ["nmap"] + args,
            capture_output=True,  # 捕获 stdout 和 stderr
            text=True,            # 以文本而非字节返回
            timeout=120,
        )
        return result.stdout + (result.stderr if result.stderr else "")
    except FileNotFoundError:
        return "[错误] 未找到 nmap。安装方式: apt install nmap (Linux) 或 brew install nmap (macOS)"
    except subprocess.TimeoutExpired:
        return "[错误] nmap 扫描超时 (120秒)。如果扫描全端口(1-65535)，建议分批次进行。"
    except Exception as e:
        return f"[错误] nmap 执行失败: {e}"


def _build_nmap_args(tool_name: str, arguments: dict) -> tuple[list[str], str]:
    """
    将 MCP 工具调用参数转换为 nmap 命令行参数。

    【面试考点：参数映射的设计】
    不同工具的参数差异很大（端口范围、脚本名称、扫描强度），
    通过一个统一的映射函数来处理比写四个 if-elif 块更清晰。
    返回值: (nmap命令行参数列表, mock数据查找键)

    nmap 参数速查（面试时能说出这几个很加分）:
      -p      指定端口范围
      -sV     服务版本检测（Service Version detection）
      -O      操作系统指纹识别（OS fingerprinting）
      -T4     时间模板（T0最慢最隐蔽, T5最快最容易被发现）
      --open  只显示开放的端口
      --script 指定 NSE 脚本
    """
    target = arguments["target"]

    if tool_name == "scan_ports":
        ports = arguments.get("ports", "1-1000")
        # -T4 是速度模板，平衡了速度和隐蔽性
        # --open 只展示开放端口，过滤掉 closed/filtered，输出更清晰
        return (["-p", ports, "-T4", "--open", target], "scan_ports")

    elif tool_name == "detect_services":
        ports = arguments.get("ports", "")
        args = [
            "-sV",                    # Service Version detection
            "--version-intensity", "5", # 版本检测强度(0-9)，5是默认值
            "-T4",
        ]
        if ports:
            args.extend(["-p", ports])  # 如果指定了端口就只扫那些端口
        args.append(target)
        return (args, "detect_services")

    elif tool_name == "os_fingerprint":
        # -O 需要 root 权限才能获取原始 socket 信息
        # --osscan-guess 在不确定时会给出最佳猜测（用百分数标注置信度）
        return (["-O", "--osscan-guess", "-T4", target], "os_fingerprint")

    elif tool_name == "vuln_scan":
        # 不同类别的 NSE 脚本位于不同的分类下
        category = arguments.get("category", "vuln")
        script_map = {
            "vuln": "vuln",      # 通用漏洞检测
            "ssl": "ssl-*",      # SSL/TLS 脚本族
            "http": "http-*",    # HTTP 脚本族
            "auth": "auth-*",    # 认证脚本族
            "default": "default", # nmap 默认安全脚本
        }
        script = script_map.get(category, "vuln")
        # --script vuln 会运行所有 vuln 类别下的 NSE 脚本
        # -sV 配合 --script 使用，因为很多漏洞检测需要先知道服务版本
        return (["-sV", "--script", script, "-T4", target], "vuln_scan")

    return ([], "")  # 不应该到这儿


# ============================================================================
# MCP Server 主入口
# ============================================================================

async def main():
    """
    启动 MCP Server 并进入 stdio 事件循环。

    【面试重点：MCP Server 的生命周期】
    1. 创建 Server 实例，指定名称（用于日志和错误追踪）
    2. 注册两个核心 handler：
       - list_tools(): 告诉 Agent "我有哪些工具可以用"
       - call_tool():  实际执行工具调用
    3. 创建 stdio 传输层 —— 读 stdin 接收请求，写 stdout 返回结果
    4. server.run() 是阻塞式事件循环，会一直运行直到 stdin 关闭

    【面试追问：stdio vs HTTP/SSE？】
    - stdio: 适合本地工具（如 nmap），简单、不需要端口管理、天然隔离
    - SSE/HTTP: 适合远程工具（如云端 API），可以多个 Agent 通过网络共享
    """
    if not HAS_MCP:
        print(
            "❌ MCP SDK 未安装。请运行: pip install mcp\n"
            "如果已安装但仍有问题，检查版本: pip show mcp\n"
            "本项目基于 mcp >= 1.0.0",
            file=sys.stderr,
        )
        sys.exit(1)

    # 创建 Server 实例 — 这个名字会显示在 MCP 客户端日志中
    server = Server("nmap-mcp-server")

    @server.list_tools()
    async def handle_list_tools():
        """
        工具发现回调 —— Agent 连接到 Server 后首先调用这个方法。

        【面试考点：工具发现机制】
        类比：MCP 的工具发现就像 USB 设备的"枚举"过程。
        插上设备 → 系统询问"你是什么设备？支持什么功能？"
        MCP Client 连接 → 调用 list_tools() → 得到工具列表 → 注册给 LLM

        返回值是 Tool 对象列表，每个 Tool 包含:
        - name: LLM 在 function_call 中使用的工具名
        - description: LLM 判断何时调用该工具的语义描述
        - inputSchema: JSON Schema 格式的参数定义
        """
        return NMAP_TOOLS

    @server.call_tool()
    async def handle_call_tool(name: str, arguments: dict):
        """
        工具执行回调 —— Agent 决定调用某个工具时触发。

        工作流程:
        1. LLM 输出 function_call: {name: "scan_ports", arguments: {target: "x.x.x.x"}}
        2. MCP Client 收到后，调用这个 call_tool handler
        3. Handler 找到对应工具，转换参数，执行命令，返回结果给 LLM

        LLM 收到结果后会决定: 继续调用其他工具、还是直接输出结论。
        这就是 ReACT（Reasoning + Acting）的完整循环。
        """
        # 第一步：把 MCP 工具名映射到 nmap 命令行参数
        args_list, mock_key = _build_nmap_args(name, arguments)

        # 第二步：执行（真实命令或 mock 数据）
        if MOCK_MODE:
            # mock 模式: 返回预设的、有意义的模拟数据
            # 这是面试演示的关键 —— 不需要装 nmap 就能看到完整流程
            result = MOCK_RESPONSES[mock_key](arguments["target"], arguments)
        else:
            # 真实模式: 调用系统安装的 nmap
            result = _run_nmap(args_list)

        # 第三步：包装为标准 MCP 响应格式
        # TextContent 是 MCP 协议定义的内容类型之一（还有 ImageContent、ResourceContent 等）
        return [TextContent(type="text", text=result)]

    # 创建并启动 stdio 传输层
    # create_initialization_options() 返回 Server 的能力声明（支持的协议版本等）
    options = server.create_initialization_options()

    # stdio_server() 返回一个异步上下文管理器，封装了 stdin/stdout 的读写
    async with stdio_server() as (read_stream, write_stream):
        # server.run() 是核心事件循环：持续从 read_stream 读取请求，处理后写入 write_stream
        # 这会阻塞当前协程直到 stdin 被关闭（进程收到 EOF）
        await server.run(read_stream, write_stream, options)


# Python 入口：当直接运行此文件时启动 MCP Server
if __name__ == "__main__":
    asyncio.run(main())
