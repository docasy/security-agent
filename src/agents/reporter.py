"""报告生成 Agent — 将分析结果和响应计划整合成结构化报告"""

from datetime import datetime, timezone
from langchain_openai import ChatOpenAI
from langchain_core.messages import HumanMessage


class ReportGenerator:
    """
    报告生成 Agent — 面试考点：为什么需要单独的 Reporter Agent？
    答：职责分离。分析 Agent 关注"是什么"，响应 Agent 关注"怎么做"，
    Reporter 关注"如何呈现给不同受众"（技术团队 vs 管理层）。
    """

    def __init__(self, model: ChatOpenAI):
        self.model = model

    async def generate_report(
        self,
        alert_data: str,
        analysis_result: str,
        response_plan: str,
    ) -> str:
        """生成结构化安全事件报告"""
        prompt = f"""你是一名安全报告撰写专家。请将以下信息整合成一份专业的安全事件分析报告。

## 原始告警
{alert_data}

## 分析结果
{analysis_result}

## 响应计划
{response_plan}

请按以下结构输出 Markdown 报告:
---
# 安全事件分析报告

## 1. 事件概述
- 事件ID
- 发现时间
- 严重级别 (Critical/High/Medium/Low)
- 当前状态

## 2. 告警详情
- 告警来源
- IOC (失陷指标) 列表
- 受影响资产

## 3. 分析过程
- 威胁情报查询结果
- 关联漏洞信息
- ATT&CK 技战术映射

## 4. 影响评估
- 影响范围
- 数据泄露风险
- 业务影响

## 5. 响应行动
- 已执行措施
- 待执行措施
- 自动化/人工分类

## 6. 建议与总结
---"""

        response = await self.model.ainvoke([HumanMessage(content=prompt)])
        return response.content

    @property
    def system_prompt(self) -> str:
        return (
            "你是一名安全报告撰写专家。职责是将安全事件的技术细节转化为"
            "清晰、可操作的结构化报告。\n"
            "报告原则：\n"
            "1. 技术团队关注细节和可操作性\n"
            "2. 管理层关注影响范围和业务风险\n"
            "3. 所有 IOC 必须明确列出\n"
            "4. 使用 MITRE ATT&CK 框架进行技战术映射"
        )
