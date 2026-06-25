"""
================================================================================
LangGraph 多 Agent 工作流 — 面试核心考点文件
================================================================================

【这个文件是干什么的】
这是整个系统的"指挥中心"。使用 LangGraph 的 StateGraph 定义了
安全分析的完整流程，包括两条路径：
  路径 A — 告警分析: RAG检索 → 威胁分析(ReACT) → 响应计划 → 报告生成
  路径 B — 渗透测试: MCP工具链扫描 → 漏洞关联 → 综合分析 → 报告生成

两条路径在"响应计划"节点汇合，共享后续的报告生成流程。

【面试常问问题清单（按频率排序）】
1. "为什么用 LangGraph 而不是 LangChain 的 AgentExecutor？"
   答: AgentExecutor 是黑盒循环，你控制不了 Agent 的执行流程。
   LangGraph 的 StateGraph 给你显式的状态管理和图编排能力，
   每个节点做什么、数据怎么流转、条件如何分支，都写在一张图里。

2. "StateGraph 的状态管理机制是怎样的？"
   答: 用 TypedDict 定义状态结构，用 Annotated 指定每个字段的 reducer
   （如 add 追加消息、默认覆盖）。每个节点接收当前状态，返回部分更新，
   LangGraph 自动合并。

3. "条件路由怎么做？"
   答: add_conditional_edges() 根据状态字段返回下一个节点名，
   实现了 LangChain 做不到的动态分支。

4. "为什么三个 Agent 而不是一个？"
   答: 职责分离（Single Responsibility）。分析、响应、报告是三种不同的能力，
   分开后每个 Agent 的 system prompt 更精炼，不容易出错。
   而且可以独立替换 —— 比如换一个更好的 Reporter 不影响 Analyzer。

5. **"MCP 工具如何集成到 LangGraph 工作流？"（2026 新考点）**
   答: 在 run_pentest 节点中，通过 MCPClientManager 连接 MCP Server。
   PentestAgent 协调工具调用链（nmap → whatweb → exploitdb），
   将扫描结果写入状态，后续节点基于这些结果做分析。

【架构图（面试时画这个会很加分）】
                      ┌──────────────┐
                      │  POST /analyze│  POST /pentest
                      └──────┬───────┘
                             │
                      ┌──────▼───────┐
                      │  route_entry │  ← 根据 task_type 分发
                      └──┬───────┬───┘
                         │       │
              task="alert"│       │task="pentest"
                         │       │
              ┌──────────▼──┐ ┌──▼────────────┐
              │ RAG 知识检索 │ │ MCP 渗透测试   │
              │ (ChromaDB)  │ │ nmap→whatweb  │
              └──────┬──────┘ │ →exploitdb    │
                     │        └──┬────────────┘
              ┌──────▼──────┐   │
              │ 威胁分析     │   │
              │ (ReACT+VT)  │   │
              └──────┬──────┘   │
                     └────┬─────┘
                     ┌────▼─────┐
                     │ 响应计划  │  ← 两条路径在此汇合
                     └────┬─────┘
                     ┌────▼─────┐
                     │ 生成报告  │
                     └────┬─────┘
                          │
                       ┌──▼──┐
                       │ END │
                       └─────┘
================================================================================
"""

from typing import TypedDict, Annotated, Literal, Optional
from operator import add
import os

from langgraph.graph import StateGraph, END
from langgraph.checkpoint.memory import MemorySaver
from langchain_core.messages import HumanMessage, AIMessage, BaseMessage
from langchain_openai import ChatOpenAI

from src.agents.analyzer import ThreatAnalyzer
from src.agents.responder import IncidentResponder
from src.agents.reporter import ReportGenerator
from src.agents.pentest_agent import PentestAgent
from src.rag.knowledge_base import SecurityKnowledgeBase
from src.mcp.client import MCPClientManager


# ============================================================================
# 状态定义 — LangGraph 的核心概念
# ============================================================================

class SecurityAgentState(TypedDict):
    """
    LangGraph 状态定义。

    【面试考点：TypedDict vs Pydantic BaseModel？】
    LangGraph 使用 TypedDict 而不是 Pydantic，因为：
    1. TypedDict 更轻量，序列化开销小
    2. LangGraph 内部使用 Annotated 做 reducer 合并
    3. Pydantic 的验证在状态更新时会带来额外延迟

    【面试考点：Annotated + add 是什么意思？】
    messages 字段使用 Annotated[..., add]，意思是"每次更新时追加而非覆盖"。
    其他字段没有 Annotated，默认为"覆盖式更新"。
    这是 LangGraph 的核心机制 —— Reducer 模式。
    """
    # messages 使用 add reducer：每次节点返回新消息时追加到列表，不覆盖
    messages: Annotated[list[BaseMessage], add]

    # 任务类型：区分两条执行路径
    # "alert" → 告警分析路径  |  "pentest" → 渗透测试路径
    task_type: str

    # 告警分析相关字段
    alert_data: str              # 原始安全告警内容
    rag_context: str             # RAG 检索到的安全知识上下文

    # 渗透测试相关字段
    target: str                  # 渗透测试目标（IP/域名/URL）
    pentest_findings: dict       # MCP 工具链收集的原始扫描结果
      # 结构: {"ports": "...", "services": "...", "vulnerabilities": "...",
      #        "web_fingerprint": "...", "exploits": [...]}

    # 中间结果
    analysis_result: str         # 威胁分析或渗透测试的综合结果

    # 输出
    response_plan: str           # 响应计划（P0/P1/P2/P3 时间线）
    final_report: str            # 最终 Markdown 报告

    # 控制流
    severity: str                # 事件严重级别（Critical/High/Medium/Low）
    next_step: str               # 条件路由的关键字段

    # 多轮对话追问
    # 用户通过 /chat/{thread_id} 追问某个 Agent 时写入
    followup_question: str       # 用户的追问内容
    followup_reply: str          # Agent 的回复
    followup_target_agent: str   # 追问路由到哪个 Agent:
      # "analyzer" | "pentest" | "responder" | "reporter" | "auto"：
      # "retrieve_knowledge" → 走 RAG 路径
      # "run_pentest" → 走渗透测试路径
      # "plan_response" → 进入响应计划
      # "generate_report" → 进入报告生成
      # "done" → 结束


# ============================================================================
# 工作流构建函数
# ============================================================================

def create_security_agent_workflow():
    """
    构建并编译 Security Agent 的 LangGraph 工作流。

    【返回值说明】
    返回的是编译后的 CompiledStateGraph 对象，
    可以调用 .ainvoke() 执行，或 .astream() 流式执行。

    【面试可能追问】
    Q: 为什么把 workflow 构建放在函数里而不是全局变量？
    A: 函数返回的是"新鲜的工作流实例"，每次调用重新创建节点和边。
       如果是全局变量，多次调用会共用同一个已编译的图，
       MemorySaver 的状态会互相污染。用工厂函数可以避免这个问题。
    """

    # ------------------------------------------------------------------
    # 初始化 LLM 和各 Agent 实例
    # ------------------------------------------------------------------
    # 面试考点：为什么 model 只创建一次然后传给所有 Agent？
    # 答：减少连接数和 Token 消耗。所有 Agent 共用同一个 LLM 实例，
    #    通过各自的 system prompt 实现不同的角色行为。
    #    这是"依赖注入"思想——Agent 不负责创建 model，由外部传入。

    # 从环境变量读模型名：DeepSeek 用 deepseek-chat，OpenAI 用 gpt-4o-mini
    model = ChatOpenAI(
        model=os.getenv("LLM_MODEL", "deepseek-chat"),
        temperature=0,
    )
    # temperature=0 的原因：安全分析需要确定性，不应该有"创意"。

    analyzer = ThreatAnalyzer(model)
    responder = IncidentResponder(model)
    reporter = ReportGenerator(model)
    kb = SecurityKnowledgeBase()

    # ==================================================================
    # 节点 0: 入口路由 —— 判断走哪条路径
    # ==================================================================

    async def route_entry(state: SecurityAgentState) -> dict:
        """
        入口节点：根据 task_type 设置 next_step，决定后续路径。

        这个节点是两条路径的分叉点：
        - task_type == "alert"  → 走告警分析路径
        - task_type == "pentest" → 走渗透测试路径

        【为什么需要这个节点而不是直接在条件函数里读 task_type？】
        因为条件函数（entry_router）是纯函数，不能是 async。
        如果未来入口逻辑变得复杂（比如需要查数据库、调 API），
        放在这个节点里就自然支持了。
        """
        task_type = state.get("task_type", "alert")
        if task_type == "pentest":
            return {"next_step": "run_pentest"}
        return {"next_step": "retrieve_knowledge"}

    def entry_router(state: SecurityAgentState) -> Literal["retrieve_knowledge", "run_pentest"]:
        """
        入口条件路由 —— 根据 next_step 字段返回下一个节点名。

        LangGraph 的条件路由机制：
        1. StateGraph 调用这个函数
        2. 函数返回一个字符串（目标节点名）
        3. StateGraph 跳转到对应节点

        【面试考点：为什么 Literal 类型注解很重要？】
        Literal["retrieve_knowledge", "run_pentest"] 告诉类型检查器
        这个函数只能返回这两个值之一。如果代码写错了返回了别的值，
        IDE/类型检查器会直接报错。这在大型项目中能防止运行时 bug。
        """
        next_step = state.get("next_step", "retrieve_knowledge")
        if next_step == "run_pentest":
            return "run_pentest"
        return "retrieve_knowledge"

    # ==================================================================
    # 节点 1: RAG 知识检索（仅告警分析路径）
    # ==================================================================

    async def retrieve_knowledge(state: SecurityAgentState) -> dict:
        """
        从 ChromaDB 安全知识库检索相关知识。

        【面试考点：为什么检索放在分析之前？】
        这是 RAG（Retrieval-Augmented Generation）的标准模式：
        - 检索相关文档 → 注入 LLM 上下文 → LLM 基于增强的上下文生成
        - 好处：减少幻觉、提高准确性、提供可溯源依据

        【面试考点：为什么 k=3？】
        Top-K 检索的精度 vs 召回权衡：
        - k 太小（如 k=1）：可能漏掉相关信息（召回低）
        - k 太大（如 k=10）：会引入噪声（精度低），且 Token 消耗大
        - k=3 是经验值，在大多数场景下平衡了精度和召回
        """
        try:
            kb.load()
            docs = kb.query(state["alert_data"], k=3)
            ctx = "\n---\n".join(
                f"[知识来源: {d.metadata['source']}]\n{d.page_content}" for d in docs
            )
        except Exception as e:
            # DeepSeek 等非 OpenAI API 不支持 embedding，RAG 降级跳过
            ctx = f"[RAG 检索跳过: {e}]"
        return {"rag_context": ctx}

    # ==================================================================
    # 节点 2A: 威胁分析（告警分析路径）
    # ==================================================================

    async def analyze_threat(state: SecurityAgentState) -> dict:
        """
        使用 ReACT Agent 分析安全告警。

        【面试考点：ReACT vs 单轮 Function Calling？】
        单轮 FC: LLM 收到消息 → 调一次工具 → 返回结果 → 结束
        ReACT:   LLM 收到消息 → 思考 → 调工具 → 观察结果 → 再思考 → (可能再调工具)
        安全分析经常需要多步调查（查IP → 发现可疑 → 查CVE → 确认漏洞），
        ReACT 的循环机制更适合这种场景。
        """
        agent = analyzer.create_agent()

        prompt = f"""请分析以下安全告警。

告警内容:
{state["alert_data"]}

相关知识库参考（来自 ATT&CK / CVE / OWASP 知识库）:
{state.get("rag_context", "无相关知识库参考")}

请按照你的 system prompt 中的流程进行分析。"""

        result = await agent.ainvoke({"messages": [HumanMessage(content=prompt)]})
        last_msg = result["messages"][-1].content
        return {
            "analysis_result": last_msg,
            "next_step": "plan_response",
        }

    # ==================================================================
    # 节点 2B: 渗透测试扫描（渗透测试路径）
    # ==================================================================

    async def run_pentest(state: SecurityAgentState) -> dict:
        """
        通过 MCP 协议调用渗透测试工具链执行侦察。

        【面试重点——这个节点是 2026 最大的加分项】
        面试官问"你怎么把 MCP 集成到项目里的"，答案就是这个节点。

        工作流程:
        1. 从 state 获取渗透目标
        2. 创建 PentestAgent（自动初始化 MCP 连接）
        3. PentestAgent 按序协调各 MCP Server:
           nmap -p 1-1000 → nmap -sV → nmap --script vuln → whatweb → exploitdb
        4. 将原始扫描结果 + LLM 生成的综合报告写入状态

        【面试追问：为什么渗透测试工具要独立进程？】
        1. 安全隔离：nmap 扫描可能被目标 WAF/IDS 检测到，不应影响 Agent 主进程
        2. 权限分离：MCP Server 可以以受限用户运行（如不允许访问数据库）
        3. 资源隔离：全端口扫描会消耗大量网络资源，独立进程不影响 Agent 响应
        """
        target = state.get("target", "")
        if not target:
            return {
                "pentest_findings": {},
                "analysis_result": "错误: 未提供渗透测试目标。请在请求中指定 target 字段。",
            }

        # PentestAgent 内部会通过 MCPClientManager 连接所有 MCP Server
        pentest = PentestAgent(model)

        # 分步扫描 — 返回原始数据
        findings = await pentest.run_with_mcp_tools(target)

        # 用 LLM 综合所有发现生成可读报告
        report = await pentest.generate_report_from_findings(target, findings)

        return {
            "pentest_findings": findings,
            "analysis_result": report,  # 渗透测试综合报告作为 analysis_result
            "next_step": "plan_response",
        }

    # ==================================================================
    # 节点 3: 响应计划（两条路径汇合点）
    # ==================================================================

    async def plan_response(state: SecurityAgentState) -> dict:
        """
        根据分析结果（无论是告警分析还是渗透测试）生成响应计划。

        这是两条路径的汇合点 —— 不管分析结果怎么来的，
        到了这里统一生成结构化的响应行动计划。

        【设计模式：Strategy Pattern】
        虽然两条路径共享这个节点，但在内部通过 task_type 实现了
        略微不同的处理逻辑（渗透测试的报告格式和告警分析不同）。
        """
        task_type = state.get("task_type", "alert")
        analysis = state["analysis_result"]

        if task_type == "pentest":
            # 渗透测试报告中有具体的修复建议，responder 会据此生成可执行的响应时间线
            plan = await responder.generate_response_plan(
                f"[以下为渗透测试侦察结果]\n{analysis}"
            )
        else:
            # 告警分析结果，包含研判结论和 IOC
            plan = await responder.generate_response_plan(analysis)

        return {"response_plan": plan, "next_step": "generate_report"}

    # ==================================================================
    # 节点 4: 报告生成（终点前最后一步）
    # ==================================================================

    async def generate_final_report(state: SecurityAgentState) -> dict:
        """
        整合所有信息，生成最终的 Markdown 安全报告。

        这是工作流的最后一步。Reporter Agent 会将分析结果和响应计划
        整合为一份结构化报告，适用于不同受众（技术团队 + 管理层）。
        """
        task_type = state.get("task_type", "alert")

        report = await reporter.generate_report(
            alert_data=(
                state.get("target", "")
                if task_type == "pentest"
                else state.get("alert_data", "")
            ),
            analysis_result=state["analysis_result"],
            response_plan=state.get("response_plan", ""),
        )
        return {"final_report": report, "next_step": "done"}

    # ==================================================================
    # 节点 5: 多轮追问（/chat 端点用）
    # ==================================================================

    async def handle_followup(state: SecurityAgentState) -> dict:
        """
        处理多轮追问——根据追问内容路由给对应的 Agent。

        面试考点：
        1. 多 Agent 多轮对话怎么实现？（按领域路由追问到对应 Agent）
        2. 为什么不用通用 LLM 回答？（每个 Agent 有自己的工具和 skill，
           追问"IOC 关联"要调 VT API，追问"防护步骤"要调响应框架，通用 LLM 做不了）
        3. MemorySaver 的作用？（保存完整状态，追问时复用之前的分析结果）
        """
        question = state.get("followup_question", "")
        if not question:
            return {"followup_reply": "没有收到追问内容。"}

        target = state.get("followup_target_agent", "auto")
        task_type = state.get("task_type", "alert")

        # ---- 关键词路由：判断追问属于哪个 Agent 的领域 ----
        q_lower = question.lower()
        if target == "auto":
            # IOC/威胁/漏洞 相关 → ThreatAnalyzer
            if any(kw in q_lower for kw in ["ip", "ioc", "哈希", "域名", "cve", "病毒", "误报", "vt", "virustotal"]):
                target = "analyzer"
            # 端口/服务/指纹/扫描 相关 → PentestAgent
            elif any(kw in q_lower for kw in ["端口", "服务", "扫描", "指纹", "nmap", "whatweb", "exploitdb", "攻击面", "漏洞利用"]):
                target = "pentest"
            # 修复/封禁/响应/时间线 相关 → IncidentResponder
            elif any(kw in q_lower for kw in ["修复", "封禁", "响应", "计划", "措施", "p0", "p1", "步骤", "怎么办", "如何处置"]):
                target = "responder"
            # 报告/格式/总结 相关 → ReportGenerator
            elif any(kw in q_lower for kw in ["报告", "总结", "格式", "摘要"]):
                target = "reporter"
            # 默认给分析 Agent（最常见）
            else:
                target = "analyzer"

        # ---- 按领域调用对应 Agent ----
        analysis = state.get("analysis_result", "")
        response_plan = state.get("response_plan", "")
        target_info = state.get("target", "") or state.get("alert_data", "")

        if target == "analyzer":
            # ThreatAnalyzer 带工具回答追问（可以调 VT/CVE）
            agent_msg = (
                f"分析背景: {target_info}\n"
                f"之前的研判: {analysis[:800] if analysis else '暂无'}\n\n"
                f"用户追问: {question}\n\n"
                "基于你的安全分析专业知识回答。如果可以调用工具验证，请调用。"
            )
            agent_instance = analyzer.create_agent()
            result = await agent_instance.ainvoke(
                {"messages": [HumanMessage(content=agent_msg)]}
            )
            reply = result["messages"][-1].content

        elif target == "pentest":
            # PentestAgent 可以调 MCP 工具链
            pentest = PentestAgent(model)
            pentest.mcp = None  # reset，让 ensure_mcp 重新连接
            await pentest.ensure_mcp()
            findings = await pentest.run_with_mcp_tools(target_info)
            followup_report = await pentest.generate_report_from_findings(
                f"{target_info} - 追问: {question}", findings
            )
            reply = followup_report

        elif target == "responder":
            # IncidentResponder 生成更新的响应计划
            msg = (
                f"之前的分析: {analysis[:500] if analysis else '暂无'}\n"
                f"之前的响应计划: {response_plan[:500] if response_plan else '暂无'}\n\n"
                f"用户追问: {question}\n\n"
                "请基于你的应急响应专业知识，给出具体的、可执行的回答。"
            )
            plan = await responder.generate_response_plan(msg)
            reply = plan

        elif target == "reporter":
            # ReportGenerator 生成有针对性的报告片段
            msg = (
                f"分析内容: {analysis[:500] if analysis else '暂无'}\n"
                f"响应计划: {response_plan[:500] if response_plan else '暂无'}\n\n"
                f"用户追问: {question}\n\n"
                "请按你的报告结构回答这个问题。"
            )
            report = await reporter.generate_report(target_info, analysis, response_plan)
            reply = report

        else:
            reply = f"无法路由追问到合适的 Agent（target={target}）。"

        return {
            "followup_reply": reply,
            "followup_target_agent": target,
            "next_step": "done",
        }

    def followup_router(state: SecurityAgentState) -> Literal["handle_followup", END]:
        """如果收到了追问就进入追问节点，否则结束"""
        if state.get("followup_question", ""):
            return "handle_followup"
        return END

    # ==================================================================
    # 构建状态图
    # ==================================================================
    # 以下是 LangGraph StateGraph 的组装过程 ——
    # 节点 = 要执行的逻辑，边 = 执行顺序和数据流。

    # 1. 创建空的状态图
    workflow = StateGraph(SecurityAgentState)

    # 2. 添加所有节点 —— 每个节点是一个 async 函数
    workflow.add_node("route_entry", route_entry)
    workflow.add_node("retrieve_knowledge", retrieve_knowledge)
    workflow.add_node("analyze_threat", analyze_threat)
    workflow.add_node("run_pentest", run_pentest)
    workflow.add_node("plan_response", plan_response)
    workflow.add_node("generate_report", generate_final_report)
    workflow.add_node("handle_followup", handle_followup)  # ← 多轮追问节点

    # 3. 定义执行流程

    # 入口 → 条件路由到不同路径
    workflow.set_entry_point("route_entry")
    workflow.add_conditional_edges(
        "route_entry",
        entry_router,
        {
            "retrieve_knowledge": "retrieve_knowledge",  # 告警分析路径
            "run_pentest": "run_pentest",                # 渗透测试路径
        },
    )

    # 告警分析路径: RAG → 威胁分析 → 响应计划
    workflow.add_edge("retrieve_knowledge", "analyze_threat")
    workflow.add_edge("analyze_threat", "plan_response")

    # 渗透测试路径: 渗透扫描 → 响应计划
    workflow.add_edge("run_pentest", "plan_response")

    # 两条路径汇合: 响应计划 → 报告生成
    workflow.add_edge("plan_response", "generate_report")

    # 报告生成后：如果有追问就进入追问节点，否则结束
    workflow.add_conditional_edges(
        "generate_report",
        followup_router,
        {"handle_followup": "handle_followup", END: END},
    )
    workflow.add_edge("handle_followup", END)

    # 4. MemorySaver — 持久化状态存储
    # 【面试考点：MemorySaver 的作用？】
    # MemorySaver 保存每个 thread 的对话历史，支持：
    # - 断点续传：用户关闭浏览器后重新打开，Agent 记得之前在哪
    # - 人工介入：工作流暂停等待人工确认，确认后从暂停点继续
    # - 调试回放：可以回溯查看每一步的状态变化
    # 当前用 MemorySaver（内存存储），生产环境可换成 SqliteSaver 或 PostgresSaver
    memory = MemorySaver()

    # 5. 编译图并返回
    # compile() 会验证图结构的完整性（无孤立节点、无死循环等）
    return workflow.compile(checkpointer=memory)
