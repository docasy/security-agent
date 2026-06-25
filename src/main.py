"""
================================================================================
Security Agent API — FastAPI 服务入口
================================================================================

三个核心端点 + 三个增强端点：
  POST /analyze      → 告警分析（标准 JSON 响应）
  POST /analyze/stream → 告警分析（SSE 流式，实时推送每步进度）
  POST /pentest       → 渗透测试（标准 JSON 响应）
  POST /pentest/stream → 渗透测试（SSE 流式）
  GET  /analyses      → 分析历史列表
  GET  /analyses/{id} → 单条分析详情
  POST /chat/{thread_id} → 多轮对话追问

================================================================================
"""

import json
import os
import asyncio
from datetime import datetime, timezone

import uvicorn
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

load_dotenv()

from src.graph.workflow import create_security_agent_workflow
from src.storage.database import AnalysisRecord, get_db

# ============================================================================
# FastAPI 应用
# ============================================================================

app = FastAPI(
    title="Security Agent API",
    version="0.3.0",
    description=(
        "基于 LangGraph + MCP 协议的多智能体安全分析系统。\n\n"
        "**端点**:\n"
        "- `/analyze` / `/analyze/stream` — 告警分析（蓝队 SOC）\n"
        "- `/pentest` / `/pentest/stream` — 渗透测试（红队侦察）\n"
        "- `/chat/{thread_id}` — 多轮对话追问\n"
        "- `/analyses` — 分析历史（SQLite 持久化）"
    ),
)

workflow = None

async def get_workflow():
    global workflow
    if workflow is None:
        workflow = create_security_agent_workflow()
    return workflow


# ============================================================================
# 请求/响应模型
# ============================================================================

class AlertRequest(BaseModel):
    task_type: str = Field(default="alert", pattern="^(alert|pentest)$")
    alert_data: str = Field(default="", description="告警内容")
    target: str = Field(default="", description="渗透目标 IP/域名")
    thread_id: str = Field(default="default", description="会话 ID")


class AlertResponse(BaseModel):
    task_type: str
    analysis: str
    response_plan: str
    report: str
    analysis_id: int = Field(default=0, description="持久化记录 ID，可用于后续查询")


class ChatRequest(BaseModel):
    message: str = Field(..., description="追问内容")


class AnalysisListItem(BaseModel):
    id: int
    task_type: str
    thread_id: str
    input_data: str
    status: str
    created_at: str


# ============================================================================
# 标准端点（JSON 响应）
# ============================================================================

@app.post("/analyze", response_model=AlertResponse)
async def analyze_alert(req: AlertRequest):
    """告警分析 — 蓝队 SOC 研判"""
    wf = await get_workflow()

    config = {"configurable": {"thread_id": req.thread_id}}
    result = await wf.ainvoke({
        "task_type": "alert",
        "alert_data": req.alert_data,
        "messages": [],
    }, config=config)

    response = AlertResponse(
        task_type="alert",
        analysis=result.get("analysis_result", ""),
        response_plan=result.get("response_plan", ""),
        report=result.get("final_report", ""),
    )

    # ----- 自动持久化到 SQLite -----
    db = get_db()
    record_id = db.save(AnalysisRecord(
        task_type="alert",
        thread_id=req.thread_id,
        input_data=req.alert_data,
        analysis_result=response.analysis,
        response_plan=response.response_plan,
        final_report=response.report,
    ))
    response.analysis_id = record_id

    return response


@app.post("/pentest", response_model=AlertResponse)
async def run_pentest(req: AlertRequest):
    """渗透测试 — 红队 MCP 工具链侦察"""
    if not req.target and not req.alert_data:
        raise HTTPException(400, "渗透测试需要 target 字段（目标 IP/域名/URL）")

    wf = await get_workflow()
    target = req.target or req.alert_data

    config = {"configurable": {"thread_id": req.thread_id}}
    result = await wf.ainvoke({
        "task_type": "pentest",
        "target": target,
        "alert_data": req.alert_data,
        "messages": [],
    }, config=config)

    response = AlertResponse(
        task_type="pentest",
        analysis=result.get("analysis_result", ""),
        response_plan=result.get("response_plan", ""),
        report=result.get("final_report", ""),
    )

    # ----- 自动持久化 -----
    db = get_db()
    record_id = db.save(AnalysisRecord(
        task_type="pentest",
        thread_id=req.thread_id,
        input_data=target,
        analysis_result=response.analysis,
        response_plan=response.response_plan,
        final_report=response.report,
    ))
    response.analysis_id = record_id

    return response


# ============================================================================
# SSE 流式端点 — 实时推送每步进度
# ============================================================================

def _sse_event(data: dict) -> str:
    """格式化 SSE (Server-Sent Events) 消息"""
    return f"data: {json.dumps(data, ensure_ascii=False)}\n\n"


async def _stream_workflow(task_type: str, thread_id: str, alert_data: str, target: str):
    """
    通用工作流流式生成器。

    利用 LangGraph 的 astream() 方法，每完成一个节点就推一条 SSE 事件给前端。
    前端可以实时看到：「正在检索知识库… → 正在分析威胁… → 正在生成响应计划…」

    面试考点：
    1. LangGraph astream vs ainvoke？（astream 逐节点返回，适合长任务进度展示）
    2. SSE vs WebSocket？（SSE 单向服务器→客户端，更简单，Agent 场景够用）
    3. 为什么不用 asyncio.Queue？（astream 本身就是 async generator，直接迭代即可）
    """
    wf = await get_workflow()
    config = {"configurable": {"thread_id": thread_id}}
    state_input = {
        "task_type": task_type,
        "alert_data": alert_data,
        "target": target,
        "messages": [],
    }

    node_labels = {
        "route_entry": ("🔀 路由分发", "正在判断任务类型…"),
        "retrieve_knowledge": ("📚 RAG 检索", "正在从安全知识库检索相关知识…"),
        "analyze_threat": ("🔍 威胁分析", "ReACT Agent 正在提取 IOC 并查询威胁情报…"),
        "run_pentest": ("💣 渗透扫描", "MCP 工具链执行中: nmap → whatweb → exploitdb…"),
        "plan_response": ("📋 响应计划", "正在生成分阶段响应时间线 (P0→P3)…"),
        "generate_report": ("📝 生成报告", "正在整合所有信息为结构化报告…"),
    }

    final_result = {}

    # astream() 每次 yield 一个节点完成事件
    async for event in wf.astream(state_input, config=config):
        for node_name, node_output in event.items():
            label, desc = node_labels.get(node_name, (node_name, f"正在执行 {node_name}…"))

            # 合并节点输出到最终结果
            if isinstance(node_output, dict):
                final_result.update(node_output)

            yield _sse_event({
                "node": node_name,
                "label": label,
                "status": desc,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            })

    # 所有节点完成，推送最终结果
    analysis = final_result.get("analysis_result", "")
    plan = final_result.get("response_plan", "")
    report = final_result.get("final_report", "")

    # 持久化
    db = get_db()
    record_id = db.save(AnalysisRecord(
        task_type=task_type,
        thread_id=thread_id,
        input_data=target or alert_data,
        analysis_result=analysis,
        response_plan=plan,
        final_report=report,
    ))

    yield _sse_event({
        "node": "done",
        "label": "✅ 完成",
        "status": "分析完成",
        "analysis_id": record_id,
        "analysis": analysis,
        "response_plan": plan,
        "report": report,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    })


@app.post("/analyze/stream")
async def analyze_alert_stream(req: AlertRequest):
    """
    告警分析 — SSE 流式版本。

    前端用法:
    ```javascript
    const eventSource = new EventSource('/analyze/stream');
    eventSource.onmessage = (event) => {
      const data = JSON.parse(event.data);
      console.log(`[${data.label}] ${data.status}`);
      if (data.node === 'done') {
        // 显示最终报告
      }
    };
    ```

    注意：EventSource 不支持 POST，实际使用需要用 fetch + ReadableStream。
    此处提供 POST 端点供 curl 和程序调用。
    """
    return StreamingResponse(
        _stream_workflow("alert", req.thread_id, req.alert_data, req.target),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",  # 禁用 Nginx 缓冲
        },
    )


@app.post("/pentest/stream")
async def run_pentest_stream(req: AlertRequest):
    """渗透测试 — SSE 流式版本"""
    if not req.target and not req.alert_data:
        raise HTTPException(400, "渗透测试需要 target 字段")

    return StreamingResponse(
        _stream_workflow("pentest", req.thread_id, req.alert_data, req.target or req.alert_data),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


# ============================================================================
# 分析历史（SQLite 持久化）
# ============================================================================

@app.get("/analyses", response_model=list[AnalysisListItem])
async def list_analyses(limit: int = 20):
    """查询最近的分析记录列表"""
    db = get_db()
    return db.list_recent(limit)


@app.get("/analyses/{analysis_id}")
async def get_analysis(analysis_id: int):
    """查询单条分析记录的完整详情"""
    db = get_db()
    record = db.get_by_id(analysis_id)
    if not record:
        raise HTTPException(404, f"分析记录 {analysis_id} 不存在")
    return record


# ============================================================================
# 多轮对话 — 基于 MemorySaver 的追问
# ============================================================================

@app.post("/chat/{thread_id}")
async def chat_follow_up(thread_id: str, req: ChatRequest):
    """
    多轮对话追问端点。

    基于 LangGraph 的 MemorySaver，同一个 thread_id 的多次请求
    共享完整的对话历史状态。Agent 能"记住"之前的分析结果，
    用户可以追问「展开第三点」、「这个 IP 有没有关联域名」等。

    面试考点：
    1. MemorySaver 怎么实现多轮对话？（同一 thread_id 复用 configurable 配置）
    2. 和 ChatGPT 的多轮对话有什么不同？（Agent 的记忆包含工具调用结果和状态变化）
    3. 局限？（MemorySaver 存内存，重启丢失；生产应换 SqliteSaver 或 PostgresSaver）
    """
    wf = await get_workflow()
    config = {"configurable": {"thread_id": thread_id}}

    # 先检查是否有历史记录——从 SQLite 查该 thread 的最近分析
    db = get_db()
    history = db.list_by_thread(thread_id)

    # 如果没有任何历史，这个 thread 还没做过分析，引导用户先提交分析
    if not history:
        raise HTTPException(
            400,
            f"会话 {thread_id} 没有分析历史。请先用 /analyze 或 /pentest 提交初始分析，"
            f"然后用此端点追问。",
        )

    # 获取最近一次分析的摘要作为上下文
    last = history[-1]
    context = (
        f"[之前进行了{last['task_type']}分析]\n"
        f"目标/告警: {last['input_data']}\n"
        f"分析结果摘要: {last['analysis_result'][:500] if last['analysis_result'] else '无'}"
    )

    # 以新的 HumanMessage 继续对话
    prompt = f"""{context}

用户追问: {req.message}

请基于之前的分析结果回答用户的问题。如果问题需要调用工具，请调用相应工具获取最新信息。"""

    result = await wf.ainvoke(
        {"messages": [], "alert_data": prompt},
        config=config,
    )

    # 获取最后一条消息作为回复
    messages = result.get("messages", [])
    reply = messages[-1].content if messages else "无法生成回复"

    return {
        "thread_id": thread_id,
        "question": req.message,
        "reply": reply,
        "previous_analysis_id": last.get("id"),
    }


# ============================================================================
# 系统端点
# ============================================================================

@app.get("/health")
async def health():
    return {
        "status": "ok",
        "service": "Security Agent API",
        "version": "0.3.0",
        "mcp_mode": os.getenv("MCP_MOCK_MODE", "1"),
    }


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
