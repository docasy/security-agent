"""
================================================================================
WhatWeb MCP Server — Web 技术栈指纹识别
================================================================================

【这个文件是干什么的】
将 WhatWeb（Web 技术栈指纹识别工具）封装为 MCP Server。
WhatWeb 能识别网站使用了什么 CMS、Web 服务器、JavaScript 框架、CDN、分析工具等。
这些信息是渗透测试的关键输入 —— 知道 WordPress 5.8.3 + PHP 7.4 后，
就能去 ExploitDB 搜索这两个版本的已知漏洞。

【面试常问：为什么 Web 指纹识别这么重要？】
渗透测试中，"信息收集"决定了后续攻击的成功率。WhatWeb 能在 10 秒内告诉你：
- 什么 CMS（WordPress / Drupal / Joomla）→ 知道了CMS就知道常见的攻击路径
- 什么版本 → 有了版本就能查 CVE、搜 exploitdb
- 用了什么插件 → 插件漏洞是 Wordpress 最常见的攻击入口
- 有没有 WAF（Web 应用防火墙）→ 决定了攻击手法要不要绕过

这就像入室盗窃前先"踩点"：看看有几扇门、什么锁、有没有摄像头。

【面试追问：为什么用 WhatWeb 而不用 Wappalyzer？】
两者功能类似，但 WhatWeb 更偏重安全审计而非前端开发。
WhatWeb 的规则库有一千多条匹配规则，能检测到更多隐藏的组件。
而且 WhatWeb 是 Ruby 写的命令行工具，更适合作 MCP Server 封装。

启动方式：
  python -m src.mcp.servers.whatweb_server              # 真实模式（需装 whatweb）
  python -m src.mcp.servers.whatweb_server --mock       # 演示模式
================================================================================
"""

import asyncio
import subprocess
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", ".."))

try:
    from mcp.server import Server
    from mcp.server.stdio import stdio_server
    from mcp.types import Tool, TextContent
    HAS_MCP = True
except ImportError:
    HAS_MCP = False

MOCK_MODE = "--mock" in sys.argv


# ============================================================================
# 工具定义
# ============================================================================
# 这四个工具覆盖了 Web 信息收集的完整流程：
# fingerprint_web → 告诉我们"这网站用了什么技术栈"
# detect_cms    → 进一步确认"具体是什么 CMS、有哪些插件"
# find_login_pages → 找"管理的入口在哪"
# check_technologies → 验证"特定技术是否存在、版本多少"
# 面试时能画出一个信息收集的 MECE 树会很加分。

WHATWEB_TOOLS = [
    Tool(
        name="fingerprint_web",
        description=(
            "识别目标网站的完整技术栈，包括：Web 服务器、编程语言、CMS、"
            "前端框架、JavaScript 库、CDN 服务、SEO 插件、第三方嵌入等。"
            "这是 Web 渗透测试的第一步——了解目标用了什么技术。"
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "url": {
                    "type": "string",
                    "description": "目标 URL，必须包含协议头。如 https://example.com（不是 example.com）",
                },
                "aggression": {
                    "type": "string",
                    "description": (
                        "扫描强度:\n"
                        "- stealth (隐蔽): 最少请求，不易触发 WAF 告警\n"
                        "- normal (默认): 平衡速度和深度\n"
                        "- aggressive (激进): 发送更多探测请求，可能触发安全告警"
                    ),
                    "enum": ["stealth", "normal", "aggressive"],
                    "default": "normal",
                },
            },
            "required": ["url"],
        },
    ),
    Tool(
        name="detect_cms",
        description=(
            "专门检测目标网站是否使用已知 CMS（内容管理系统），"
            "如 WordPress、Drupal、Joomla、DedeCMS 等，并尝试获取版本号和已安装插件。"
            "CMS 识别很重要，因为 CMS 漏洞是 Web 安全中最常见的攻击入口之一。"
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "url": {
                    "type": "string",
                    "description": "目标 URL，必须包含 http:// 或 https://",
                },
            },
            "required": ["url"],
        },
    ),
    Tool(
        name="find_login_pages",
        description=(
            "发现目标网站的管理后台、登录页面、控制面板等敏感入口。"
            "常见入口包括: /wp-admin, /phpmyadmin, /administrator, /cpanel 等。"
            "这些入口如果暴露在公网且使用了弱口令，是最容易被攻击的薄弱点。"
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "url": {
                    "type": "string",
                    "description": "目标 URL",
                },
            },
            "required": ["url"],
        },
    ),
    Tool(
        name="check_technologies",
        description=(
            "检查目标是否使用了指定的技术栈（如 jQuery 版本、PHP 版本、Apache 版本等）。"
            "用于漏洞关联 —— 比如检查 PHP 版本是否为 7.4（已停止安全更新的 EOL 版本）。"
            "通常在前几个工具返回结果后，用这个工具做精确验证。"
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "url": {
                    "type": "string",
                    "description": "目标 URL，必须包含 http:// 或 https://",
                },
                "technologies": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": (
                        "要检查的技术列表。常见项:\n"
                        "- 'jquery': jQuery JavaScript 库\n"
                        "- 'php': PHP 版本\n"
                        "- 'apache': Apache HTTP Server\n"
                        "- 'nginx': Nginx Web Server\n"
                        "- 'wordpress': WordPress CMS\n"
                        "- 'bootstrap': Bootstrap CSS 框架\n"
                        "留空则检测所有已知技术"
                    ),
                },
            },
            "required": ["url"],
        },
    ),
]


# ============================================================================
# Mock 数据 — 模拟一次真实的 Web 指纹识别过程
# ============================================================================
# Mock 数据场景: 模拟扫描一个 WordPress 企业官网。
# 这个场景在真实渗透测试中非常常见 —— 大量企业网站用 WordPress。
# 数据中包含了: CMS 信息、插件列表、版本风险提示。
# 面试时你可以说："我设计的 mock 数据模拟了一次真实的 WordPress 站点侦察，
# 从 CMS 版本检测到插件枚举，再到登录入口发现，是一条完整的侦察链。"

MOCK_RESPONSES = {
    "fingerprint_web": lambda url, agg: (
        f"Web 指纹识别结果: {url}\n"
        "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
        "[服务器层]\n"
        "  Web Server    Apache HTTP Server 2.4.41 (Ubuntu)\n"
        "  SSL/TLS       Let's Encrypt (免费证书，说明运维自动化程度不错)\n"
        "  CDN           Cloudflare (流量经过 Cloudflare，可能隐藏了真实 IP)\n\n"
        "[应用层]\n"
        "  CMS           WordPress 5.8.3 (最新稳定版是 6.x，已落后 2+ 大版本)\n"
        "  Language      PHP 7.4.33 (⚠ 2022年11月已停止安全更新，属于 EOL 版本)\n"
        "  Database      推测为 MySQL (WordPress 默认)\n\n"
        "[前端层]\n"
        "  JS Library    jQuery 3.6.0, Bootstrap 4.5.2\n"
        "  CSS           Custom CSS (Astra 主题)\n\n"
        "[第三方服务]\n"
        "  Analytics     Google Analytics UA-XXXXXXXX (Universal Analytics, 已废弃)\n"
        "  SEO           Yoast SEO 17.8\n"
        "  地图           Google Maps API\n\n"
        "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
        "综合风险: 🟡 MEDIUM\n"
        "主要关注点:\n"
        "  1. WordPress 5.8.3 缺少多个安全补丁\n"
        "  2. PHP 7.4 已 EOL，不再接收安全更新\n"
        "  3. Cloudflare 可能隐藏了真实服务器 IP（需要进一步绕过）\n"
        "  4. jQuery 3.6.0 和 Bootstrap 4.5.2 有已知漏洞但影响较小"
    ),
    "detect_cms": lambda url, agg: (
        f"CMS 深度检测结果: {url}\n"
        "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
        "  CMS          WordPress 5.8.3\n"
        "  Theme        Astra 3.7.0 (流行主题，约100万+活跃安装)\n"
        "  Editor       检测到 Gutenberg 块编辑器\n\n"
        "已发现的插件 (Plugins):\n"
        "  - Elementor 3.5.0       [页面构建器, 500万+安装]\n"
        "  - WooCommerce 6.1.0     [电商插件, 500万+安装]\n"
        "  - Contact Form 7 5.5.3  [联系表单, 500万+安装]\n"
        "  - Akismet 4.2.1         [反垃圾评论, 默认安装]\n"
        "  - Yoast SEO 17.8        [SEO插件, 500万+安装]\n\n"
        "风险分析:\n"
        "  🔴 WooCommerce 6.1.0 — 电商插件，如果被注入可直接窃取订单数据\n"
        "  🟡 Elementor 3.5.0 — 历史上多个 RCE 漏洞 (CVE-2022-1329等)\n"
        "  🟡 Contact Form 7 — 上传功能可能被滥用\n"
        "  ℹ 这么多知名插件说明网站维护较规范，但插件越多攻击面越大\n\n"
        "下一步建议:\n"
        "  1. 用 wpscan 进一步枚举用户和漏洞（WordPress 专用扫描器）\n"
        "  2. 检查 /wp-content/plugins/ 目录是否允许文件列表\n"
        "  3. 检查是否有备份文件泄露 (wp-config.php.bak)"
    ),
    "find_login_pages": lambda url, agg: (
        f"敏感入口发现: {url}\n"
        "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
        "Web 入口:\n"
        "  ✅ {url}/wp-admin/             WordPress 管理后台 (200 OK — 可访问!)\n"
        "  ✅ {url}/wp-login.php           WordPress 登录页面\n"
        "  ✅ {url}/wp-login.php?action=register  注册页面开放\n"
        "  ✅ {url}/phpmyadmin/            phpMyAdmin (403 Forbidden — 有保护)\n"
        "  ✅ {url}:8080/manager/html      Tomcat Manager (200 OK — 有认证)\n\n"
        "管理服务:\n"
        "  ❌ {url}/cpanel/                未发现 (服务器可能不是 cPanel)\n"
        "  ❌ {url}/.git/                  未发现 (Git 目录未暴露，好事)\n"
        "  ❌ {url}/.env                   未发现 (环境变量文件未暴露，好事)\n\n"
        "关键发现:\n"
        "  🔴 /wp-admin 可直接访问 — 如果密码弱，攻击者可以直接登录后台\n"
        "  🔴 注册功能开放 — 可以注册用户账号进行提权攻击\n"
        "  🟢 Tomcat Manager 有认证 — 但需要确认是否为默认密码\n"
        "  🟢 常见敏感文件（.git, .env）未暴露，基本安全意识尚可"
    ),
    "check_technologies": lambda url, agg: (
        f"技术栈版本检测: {url}\n"
        "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
        "检测到的技术及版本:\n"
        "  ✅ jQuery      3.6.0   → 最新稳定版 3.7.x，差距不大，低风险\n"
        "  ⚠ Apache      2.4.41  → 最新版 2.4.62，有 20+ 个安全更新落后\n"
        "  🔴 PHP         7.4.33  → EOL! 2022-11-28 停止安全支持，需尽快升级\n"
        "  🔴 WordPress   5.8.3   → 最新版为 6.x，差距 2+ 大版本\n"
        "  ✅ Bootstrap   4.5.2   → 虽然不是最新但无严重安全风险\n\n"
        "CVSS 关联分析 (基于已知 CVE):\n"
        "  - PHP 7.4.x: 历史累计 30+ CVE，其中 5 个评分 9.0+\n"
        "  - Apache 2.4.41: CVE-2021-41773 (路径穿越), CVE-2021-40438 (SSRF)\n"
        "  - WordPress 5.8.3: CVE-2022-21661 (SQL注入, CVSS 7.5)\n\n"
        "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
        "综合建议: 技术栈整体偏旧，PHP 7.4 的 EOL 状态是最紧急的问题。\n"
        "建议升级路径: PHP 7.4 → PHP 8.2+ / WordPress 5.8 → 6.x / Apache 2.4.41 → 2.4.62+"
    ),
}


# ============================================================================
# 底层实现
# ============================================================================

def _run_whatweb(args: list[str]) -> str:
    """
    执行 WhatWeb 命令行工具。

    WhatWeb 是 Ruby 写的工具，需要 Ruby 运行时。
    常用参数:
      -a  aggression level (0-4, 越高越激进)
      --no-errors  抑制错误输出（把错误当正常信息处理，避免污染结果）
    """
    if MOCK_MODE:
        return ""
    try:
        result = subprocess.run(
            ["whatweb"] + args,
            capture_output=True,
            text=True,
            timeout=60,  # WhatWeb 通常很快，但激进模式可能较慢
        )
        return result.stdout or result.stderr
    except FileNotFoundError:
        return (
            "[错误] 未找到 whatweb。\n"
            "安装: apt install whatweb (Linux) 或 brew install whatweb (macOS)\n"
            "WhatWeb 需要 Ruby 运行时环境。"
        )
    except Exception as e:
        return f"[错误] whatweb 执行失败: {e}"


# ============================================================================
# MCP Server 主入口
# ============================================================================

async def main():
    """
    启动 WhatWeb MCP Server。

    【面试考点：三个 MCP Server 的协作顺序】
    nmap 先侦察（发现端口和服务）→ whatweb 深入 Web 层面（识别技术栈）
    → exploitdb 搜索漏洞利用（关联已知漏洞）。
    这三个 Server 各自独立，通过 Agent 的编排串联成完整的渗透测试流程。
    这就是 MCP 协议的优势：工具之间不需要互相知道对方的存在，
    Agent 作为"大脑"负责协调，工具作为"手脚"各司其职。
    """
    if not HAS_MCP:
        print("❌ MCP SDK 未安装。请运行: pip install mcp", file=sys.stderr)
        sys.exit(1)

    server = Server("whatweb-mcp-server")

    @server.list_tools()
    async def handle_list_tools():
        return WHATWEB_TOOLS

    @server.call_tool()
    async def handle_call_tool(name: str, arguments: dict):
        """执行 Web 指纹识别工具调用"""
        url = arguments["url"]

        if MOCK_MODE:
            # mock 模式下忽略 aggression 参数（mock 数据不区分扫描强度）
            aggression = arguments.get("aggression", "normal")
            result = MOCK_RESPONSES[name](url, aggression)
        else:
            # 真实模式: 转换 aggression 级别为 whatweb -a 参数
            # -a 0: 最轻微, -a 3: 默认, -a 4: 最激进
            agg_flag = {"stealth": "-a 0", "normal": "-a 3", "aggressive": "-a 4"}
            flag = agg_flag.get(arguments.get("aggression", "normal"), "-a 3")
            args = [flag, "--no-errors", url]
            result = _run_whatweb(args)

        return [TextContent(type="text", text=result)]

    options = server.create_initialization_options()
    async with stdio_server() as (read, write):
        await server.run(read, write, options)


if __name__ == "__main__":
    asyncio.run(main())
