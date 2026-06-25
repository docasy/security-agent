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
    逐字流式工作流。用 astream_events() 替代 astream()，不仅推送节点完成事件，
    还推送 LLM 每生成一个 token 的内容。前端效果：文字像打字机一样逐字出现。

    面试考点：
    1. astream_events vs astream？（events 粒度到 token 级，stream 粒度到节点级）
    2. SSE 流式输出怎么实现？（async generator + StreamingResponse + text/event-stream）
    """
    wf = await get_workflow()
    config = {"configurable": {"thread_id": thread_id}}
    state_input = {
        "task_type": task_type,
        "alert_data": alert_data,
        "target": target,
        "messages": [],
    }

    final_result = {}
    current_node = ""

    # astream_events() 比 astream() 更细粒度：
    # - on_chat_model_stream: LLM 每输出一个 token 触发一次
    # - on_tool_start/end: 工具调用开始/结束
    # - 节点完成时也有对应事件
    async for event in wf.astream_events(state_input, config=config, version="v2"):
        kind = event["event"]

        # ---- LLM 逐 token 输出（核心：让前端看到打字机效果）----
        if kind == "on_chat_model_stream":
            chunk = event["data"]["chunk"]
            if hasattr(chunk, "content") and chunk.content:
                yield _sse_event({
                    "type": "token",
                    "content": chunk.content,
                    "node": current_node,
                })

        # ---- 工具调用 ----
        elif kind == "on_tool_start":
            yield _sse_event({
                "type": "tool_start",
                "tool": event["name"],
                "node": current_node,
            })
        elif kind == "on_tool_end":
            yield _sse_event({
                "type": "tool_end",
                "tool": event["name"],
                "node": current_node,
            })

        # ---- 节点完成（持久化最终结果）----
        elif kind == "on_chain_end":
            if event.get("name") in [
                "analyze_threat", "run_pentest", "plan_response", "generate_report",
                "retrieve_knowledge", "route_entry",
            ]:
                node_name = event["name"]
                current_node = node_name
                output = event["data"].get("output", {})
                if isinstance(output, dict):
                    final_result.update(output)

    # 最终结果
    analysis = final_result.get("analysis_result", "")
    plan = final_result.get("response_plan", "")
    report = final_result.get("final_report", "")

    db = get_db()
    record_id = db.save(AnalysisRecord(
        task_type=task_type, thread_id=thread_id,
        input_data=target or alert_data,
        analysis_result=analysis, response_plan=plan, final_report=report,
    ))

    yield _sse_event({
        "type": "done",
        "analysis_id": record_id,
        "analysis": analysis,
        "response_plan": plan,
        "report": report,
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
    多 Agent 多轮追问。

    不是简单的"LLM 聊天"——系统会分析追问内容的关键词，
    自动路由给对应的 Agent（ThreatAnalyzer / PentestAgent /
    IncidentResponder / ReportGenerator），由该 Agent
    带着自己的工具和 Skill 来处理追问。

    示例：
      "这个 IP 关联什么域名" → 路由给 ThreatAnalyzer（调 VT API）
      "帮我扫一下 8080 端口"  → 路由给 PentestAgent（调 MCP 工具链）
      "P0 响应步骤是什么"      → 路由给 IncidentResponder
    """
    wf = await get_workflow()

    # 从 SQLite 查该 thread 的历史，确认有分析记录
    db = get_db()
    history = db.list_by_thread(thread_id)
    if not history:
        raise HTTPException(
            400,
            f"会话 {thread_id} 没有分析历史。请先用 /analyze 或 /pentest 提交初始分析。",
        )

    last = history[-1]
    task_type = last["task_type"]
    target = last["input_data"]

    # 用 MemorySaver 恢复之前的状态，注入追问
    config = {"configurable": {"thread_id": thread_id}}

    # 注入追问字段，让 followup_router 路由到 handle_followup 节点
    result = await wf.ainvoke({
        "task_type": task_type,
        "target": target if task_type == "pentest" else "",
        "alert_data": "" if task_type == "pentest" else target,
        "followup_question": req.message,    # ← 写入追问
        "followup_target_agent": "auto",      # ← 自动路由
        "analysis_result": last.get("analysis_result", ""),
        "response_plan": last.get("response_plan", ""),
        "messages": [],
    }, config=config)

    reply = result.get("followup_reply", "无法生成回复")
    target_agent = result.get("followup_target_agent", "unknown")

    return {
        "thread_id": thread_id,
        "question": req.message,
        "routed_to_agent": target_agent,  # 告诉了用户追问给了哪个 Agent
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
