"""事件响应 Agent — 根据分析结果生成自动化响应建议"""

from langchain_openai import ChatOpenAI
from langchain_core.messages import SystemMessage, HumanMessage

from src.skills.loader import loader


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
        """
        从 agency-agents 加载 Incident Response Commander 标准化 Skill。
        444 行专业应急响应方法论，替代原来 5 行简短 prompt。

        Skill 包含：SEV1-SEV4 分级框架、ICS 角色模型、
        事后复盘流程、on-call 最佳实践。
        """
        return loader.load("incident-response-commander")
