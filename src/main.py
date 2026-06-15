"""
================================================================================
Security Agent API — FastAPI 服务入口
================================================================================

【这个文件是干什么的】
FastAPI 应用的主入口。提供两个 REST API 端点：
- POST /analyze  → 告警分析（被动研判）
- POST /pentest  → 渗透测试扫描（主动侦察）

【设计决策——为什么选择 FastAPI？】
1. 原生异步支持（async/await）—— LangGraph 的 ainvoke 也是异步的
2. 自动生成 OpenAPI 文档（/docs）—— 面试演示时可以直接在浏览器里试 API
3. Pydantic 模型验证 —— 请求参数自动校验，减少手写验证代码
4. 高性能 —— 基于 Starlette，适合生产环境

【面试追问：为什么需要两个端点而不是一个端点加参数？】
两个端点让 API 语义更清晰：
- /analyze 是安全运营中心（SOC）场景——收到告警后研判
- /pentest 是安全服务场景——对授权目标执行主动侦察
两个操作的本质不同（被动 vs 主动），分开更符合 REST 最佳实践。
同时内部复用了同一个 LangGraph 工作流，只是入口路径不同。

启动方式:
  python -m src.main
  # 服务在 http://0.0.0.0:8000
  # Swagger 文档在 http://0.0.0.0:8000/docs
================================================================================
"""

import os
import uvicorn
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

# 加载 .env 文件中的环境变量（API Key 等）
load_dotenv()

from src.graph.workflow import create_security_agent_workflow


# ============================================================================
# FastAPI 应用实例
# ============================================================================

app = FastAPI(
    title="Security Agent API",
    version="0.2.0",
    description=(
        "基于 LangGraph + MCP 协议的多智能体安全分析系统。\n\n"
        "**双模式**:\n"
        "- `/analyze` — 告警分析（被动研判 SOC 场景）\n"
        "- `/pentest` — 渗透测试扫描（主动侦察，MCP 工具链）\n\n"
        "**MCP 工具链**: nmap (端口扫描) + whatweb (Web指纹) + exploitdb (漏洞利用搜索)"
    ),
)

# ============================================================================
# 全局工作流实例（单例模式）
# ============================================================================
# 使用懒初始化的单例：首次 API 调用时才创建，避免启动时就能发现问题。
# LangGraph 的 CompiledGraph 是线程安全的，可以被多个请求并发调用。

workflow = None  # 延迟创建（Lazy Initialization）


async def get_workflow():
    """
    获取或创建全局工作流实例。

    【面试考点：为什么用懒初始化而不是在模块加载时创建？】
    1. 导入时创建的话，如果配置有问题（如 API Key 未设置），
       import 就会报错，不方便调试
    2. 首次调用时才初始化，可以等到所有配置就绪
    3. 失败只影响单个请求，不会导致整个应用启动失败
    """
    global workflow
    if workflow is None:
        workflow = create_security_agent_workflow()
    return workflow


# ============================================================================
# 请求/响应模型（Pydantic）
# ============================================================================
# FastAPI 使用 Pydantic 进行请求验证和响应序列化。
# 面试时能说出 Pydantic v2 的新特性（model_validate, field_validator 等）会加分。

class AlertRequest(BaseModel):
    """
    安全分析请求体。

    task_type 字段控制走哪条工作流路径:
    - "alert"   → RAG → ReACT 分析 → 响应 → 报告
    - "pentest" → MCP 工具链扫描 → 漏洞关联 → 响应 → 报告
    """
    task_type: str = Field(
        default="alert",
        description="任务类型: alert (告警分析) 或 pentest (渗透测试)",
        pattern="^(alert|pentest)$",
    )
    alert_data: str = Field(
        default="",
        description="告警分析模式下的安全告警内容（如入侵检测日志、异常行为描述）",
    )
    target: str = Field(
        default="",
        description="渗透测试的目标 IP 地址、域名或 URL（pentest 模式必填）",
    )
    thread_id: str = Field(
        default="default",
        description="会话线程 ID。同一 thread_id 的多次请求共享对话历史和状态。",
    )


class AlertResponse(BaseModel):
    """
    安全分析响应体。

    三个主要输出字段分别对应工作流中三个 Agent 的输出：
    - analysis: ThreatAnalyzer 或 PentestAgent 的分析结果
    - response_plan: IncidentResponder 的响应计划
    - report: ReportGenerator 的最终结构化报告
    """
    task_type: str = Field(description="实际执行的任务类型")
    analysis: str = Field(description="威胁分析结果或渗透测试综合评估")
    response_plan: str = Field(description="分阶段的响应计划（P0/P1/P2/P3）")
    report: str = Field(description="完整的 Markdown 格式安全报告")


# ============================================================================
# API 端点
# ============================================================================

@app.post("/analyze", response_model=AlertResponse)
async def analyze_alert(req: AlertRequest):
    """
    **告警分析接口** — 安全运营中心（SOC）场景。

    接收安全告警文本，执行以下流程：
    1. RAG 检索相关知识（ATT&CK / CVE / OWASP）
    2. ReACT Agent 分析（提取 IOC → VirusTotal 查询 → CVE 关联）
    3. 生成响应计划（立即措施 → 短期遏制 → 根除方案 → 恢复 → 复盘）
    4. 输出结构化 Markdown 报告

    工作流路径: RAG检索 → 威胁分析(ReACT) → 响应计划 → 报告

    使用示例:
    ```bash
    curl -X POST http://localhost:8000/analyze \\
      -H "Content-Type: application/json" \\
      -d '{
        "task_type": "alert",
        "alert_data": "检测到来自 45.33.32.156 的异常登录行为，目标为生产服务器 web-01",
        "thread_id": "incident-001"
      }'
    ```
    """
    wf = await get_workflow()

    config = {"configurable": {"thread_id": req.thread_id}}
    result = await wf.ainvoke(
        {
            "task_type": "alert",
            "alert_data": req.alert_data,
            "messages": [],
        },
        config=config,
    )

    return AlertResponse(
        task_type="alert",
        analysis=result.get("analysis_result", ""),
        response_plan=result.get("response_plan", ""),
        report=result.get("final_report", ""),
    )


@app.post("/pentest", response_model=AlertResponse)
async def run_pentest(req: AlertRequest):
    """
    **渗透测试扫描接口** — 安全服务/红队场景。

    通过 MCP 协议调用渗透测试工具链，对目标执行自动化侦察：
    1. nmap 端口扫描 → 发现开放端口和服务
    2. nmap 服务版本检测 → 获取精确版本号
    3. nmap NSE 漏洞扫描 → 检测已知漏洞
    4. whatweb Web 指纹识别 → 识别 CMS/框架/技术栈
    5. exploitdb 漏洞利用搜索 → 根据版本关联已知漏洞利用
    6. LLM 综合报告生成

    工作流路径: MCP工具链扫描 → 响应计划 → 报告

    【安全声明】
    本工具仅执行信息收集和漏洞关联，不会执行任何实际攻击代码。
    请仅在获得书面授权的目标上使用。

    使用示例:
    ```bash
    curl -X POST http://localhost:8000/pentest \\
      -H "Content-Type: application/json" \\
      -d '{
        "task_type": "pentest",
        "target": "192.168.1.1",
        "thread_id": "pentest-001"
      }'
    ```
    """
    if not req.target and not req.alert_data:
        raise HTTPException(
            status_code=400,
            detail="渗透测试需要指定 target 字段（目标 IP/域名/URL）",
        )

    wf = await get_workflow()

    target = req.target or req.alert_data

    config = {"configurable": {"thread_id": req.thread_id}}
    result = await wf.ainvoke(
        {
            "task_type": "pentest",
            "target": target,
            "alert_data": req.alert_data,
            "messages": [],
        },
        config=config,
    )

    return AlertResponse(
        task_type="pentest",
        analysis=result.get("analysis_result", ""),
        response_plan=result.get("response_plan", ""),
        report=result.get("final_report", ""),
    )


# ============================================================================
# 系统端点
# ============================================================================

@app.get("/health")
async def health():
    """
    健康检查端点。

    用途：
    - Docker/K8s 存活探针（liveness probe）
    - 负载均衡器健康检查
    - 简单的服务可用性验证
    """
    return {
        "status": "ok",
        "service": "Security Agent API",
        "version": "0.2.0",
        "mcp_mode": os.getenv("MCP_MOCK_MODE", "1"),
    }


# ============================================================================
# 启动入口
# ============================================================================

if __name__ == "__main__":
    """
    直接运行此文件时启动 uvicorn 服务器。

    uvicorn 参数说明:
    - app: FastAPI 应用实例
    - host="0.0.0.0": 监听所有网络接口（允许外部访问）
    - port=8000: 默认端口

    开发环境也可以直接运行:
      uvicorn src.main:app --reload
    --reload 参数会使代码变更时自动重启服务。
    """
    uvicorn.run(app, host="0.0.0.0", port=8000)
