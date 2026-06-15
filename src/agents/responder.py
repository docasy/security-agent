"""事件响应 Agent — 根据分析结果生成自动化响应建议"""

from langchain_openai import ChatOpenAI
from langchain_core.messages import SystemMessage, HumanMessage


class IncidentResponder:
    """
    事件响应 Agent — 面试考点：
    1. Playbook 驱动的自动化响应
    2. 什么可以自动执行，什么必须人工确认
    """

    def __init__(self, model: ChatOpenAI):
        self.model = model

    async def generate_response_plan(self, analysis_result: str) -> str:
        """根据分析结果生成响应计划"""
        prompt = f"""你是一名安全事件响应专家。根据以下威胁分析结果，生成具体的响应计划。

分析结果:
{analysis_result}

请按以下格式输出响应计划:
1. **立即措施** (必须 30 分钟内完成)
2. **短期遏制** (2-24 小时)
3. **根除方案** (24-72 小时)
4. **恢复步骤**
5. **事后复盘建议**

注意：标出哪些步骤可以自动化执行，哪些必须人工确认。"""

        response = await self.model.ainvoke([HumanMessage(content=prompt)])
        return response.content

    @property
    def system_prompt(self) -> str:
        return (
            "你是一名安全事件响应专家，专注于在安全事件发生后制定可执行的响应计划。\n"
            "原则：安全第一，在不清楚影响范围时采取保守策略。\n"
            "区分自动化操作和人工决策：\n"
            "- 可自动化：防火墙封禁IP、账号禁用、日志收集\n"
            "- 需人工：数据恢复、法务通知、对外披露\n"
        )
