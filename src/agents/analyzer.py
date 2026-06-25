"""威胁分析 Agent — 核心：使用 LLM + 工具调用分析安全告警"""

from langchain_openai import ChatOpenAI
from langchain_core.tools import tool
from langgraph.prebuilt import create_react_agent

from src.tools.virus_total import VirusTotalTool
from src.tools.cve_search import CVESearchTool
from src.skills.loader import loader


class ThreatAnalyzer:
    """
    威胁分析 Agent — 面试考点：
    1. ReACT (Reasoning + Acting) 范式：思考 → 行动 → 观察 → 思考...
    2. Function Calling：LLM 如何决定调用哪个工具
    3. Agent 循环终止条件
    """

    def __init__(self, model: ChatOpenAI):
        self.model = model
        self.vt = VirusTotalTool()
        self.cve = CVESearchTool()

    def create_agent(self):
        """构建 ReACT Agent"""

        @tool
        async def query_ip_reputation(ip: str) -> str:
            """查询 IP 地址在 VirusTotal 的威胁情报。参数 ip: IPv4 地址如 1.2.3.4"""
            try:
                result = await self.vt.lookup_ip(ip)
                return (
                    f"IP {ip} 威胁情报:\n"
                    f"  恶意: {result.malicious}, 可疑: {result.suspicious}, "
                    f"  无害: {result.harmless}, 未检测: {result.undetected}\n"
                    f"  详情: {result.permalink}"
                )
            except Exception as e:
                return f"VirusTotal 查询失败: {e}"

        @tool
        async def query_file_hash(hash_value: str) -> str:
            """查询文件哈希在 VirusTotal 的检测结果。参数 hash_value: SHA-256/SHA-1/MD5"""
            try:
                result = await self.vt.lookup_file(hash_value)
                return (
                    f"文件 {hash_value} 检测结果:\n"
                    f"  恶意: {result.malicious}, 可疑: {result.suspicious}, "
                    f"  无害: {result.harmless}\n"
                    f"  详情: {result.permalink}"
                )
            except Exception as e:
                return f"VirusTotal 查询失败: {e}"

        @tool
        async def search_cve(keyword: str) -> str:
            """搜索 CVE 漏洞数据库。参数 keyword: 产品名或漏洞关键词（如 'log4j', 'Apache'）"""
            try:
                results = await self.cve.search(keyword)
                if not results:
                    return f"未找到与 '{keyword}' 相关的 CVE"
                lines = [f"搜索 '{keyword}' 找到 {len(results)} 个相关漏洞:"]
                for r in results:
                    lines.append(
                        f"  [{r.severity}] {r.cve_id} (CVSS {r.cvss_score}): {r.description[:120]}..."
                    )
                return "\n".join(lines)
            except Exception as e:
                return f"CVE 查询失败: {e}"

        self._tools = [query_ip_reputation, query_file_hash, search_cve]
        # 用 agency-agent 的 Security Engineer Skill 定义注入系统角色
        # 替代原来 6 行的简短 system prompt，获得完整的 AppSec 方法论
        return create_react_agent(
            self.model, self._tools,
            state_modifier=self.system_prompt,  # ← 注入标准化 Skill
        )

    @property
    def tools(self):
        return self._tools

    @property
    def system_prompt(self) -> str:
        """
        从 agency-agents 仓库加载 Security Engineer 的标准化 Skill 定义，
        直接作为 system prompt 注入 LLM。

        Skill 包含：角色定位 + 对抗性思维框架 + OWASP 方法论 + 8 条铁律 + 输出模板
        是原来简短手写 prompt 的全面升级。
        """
        return loader.load("security-engineer")
