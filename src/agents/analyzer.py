"""威胁分析 Agent — 核心：使用 LLM + 工具调用分析安全告警"""

from langchain_openai import ChatOpenAI
from langchain_core.tools import tool
from langgraph.prebuilt import create_react_agent

from src.tools.virus_total import VirusTotalTool
from src.tools.cve_search import CVESearchTool


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
        return create_react_agent(self.model, self._tools)

    @property
    def tools(self):
        return self._tools

    @property
    def system_prompt(self) -> str:
        return (
            "你是一名资深安全分析师（SOC Analyst），负责对安全告警进行初步研判。\n"
            "你的工作流程：\n"
            "1. 理解告警内容，提取关键 IOC（IP/域名/哈希）\n"
            "2. 调用 VirusTotal 查询 IOC 的威胁情报\n"
            "3. 调用 CVE 搜索关联漏洞\n"
            "4. 给出研判结论：误报(False Positive) / 需关注(Suspicious) / 确认威胁(Confirmed Threat)\n"
            "5. 建议下一步行动"
        )
