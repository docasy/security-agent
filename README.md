# Security Agent — AI-Powered Multi-Agent Security Analysis System

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/)
[![LangGraph](https://img.shields.io/badge/LangGraph-0.2+-purple.svg)](https://github.com/langchain-ai/langgraph)
[![MCP](https://img.shields.io/badge/MCP-1.0+-teal.svg)](https://modelcontextprotocol.io/)

基于 **LangGraph + MCP 协议** 的多智能体安全分析系统。这是我在 2026 年 AI Agent 实习面试的 portfolio 项目。

> **🎯 这个项目的核心价值在于它的架构设计（LangGraph 双路径编排 + MCP 工具链集成），而非具体的渗透测试功能。**

---

## ⚠️ Ethical Use Statement

**This is an educational project built for demonstrating AI Agent architecture design.**

- 所有渗透测试工具**默认运行在 mock 模式**（`MCP_MOCK_MODE=1`），不执行任何真实扫描
- 仅做信息收集和漏洞关联，**绝不执行**漏洞利用代码
- 仅用于 **面试作品展示 / 学术学习 / CTF 训练** 场景
- 在**未获得书面授权**的情况下，不要对任何目标使用真实工具模式
- 作者不对任何滥用行为承担责任

> If you are an interviewer viewing this: welcome! The highlights are the **LangGraph dual-path workflow architecture** and **MCP protocol integration pattern**. Feel free to ask me about any design decision in the code.

---

## 两种模式，一套代码

| 模式 | 视角 | 触发方式 | 工具链 |
|------|------|---------|--------|
| **告警分析** `/analyze` | 🔵 蓝队 (被动研判) | 接收安全告警文本 | RAG → ReACT → VirusTotal + CVE |
| **渗透测试** `/pentest` | 🔴 红队 (主动侦察) | 指定目标 IP/域名 | MCP 工具链: nmap → whatweb → exploitdb |

两条路径在 LangGraph 工作流中通过**条件路由**分流，在「响应计划」和「报告生成」阶段汇合。

## 系统架构

```
┌─────────────────────────────────────────────────────────┐
│                   FastAPI 网关层                        │
│              /analyze (蓝)  /pentest (红)               │
└──────────────────────┬──────────────────────────────────┘
                       │
┌──────────────────────▼──────────────────────────────────┐
│              LangGraph 编排层 (StateGraph)               │
│                                                        │
│  route_entry ──▶ 条件路由 (task_type)                   │
│       │                    │                            │
│       ▼ (alert)            ▼ (pentest)                  │
│  ┌─────────┐        ┌──────────────┐                   │
│  │RAG 检索 │        │MCP 工具链编排 │                   │
│  └────┬────┘        │nmap→whatweb  │                   │
│       │             │→exploitdb    │                   │
│  ┌────▼────┐        └──────┬───────┘                   │
│  │ReACT分析│               │                            │
│  └────┬────┘               │                            │
│       └─────────┬──────────┘                            │
│            ┌────▼─────┐                                  │
│            │ 响应计划  │ ← 两条路径在此汇合               │
│            └────┬─────┘                                  │
│            ┌────▼─────┐                                  │
│            │ 生成报告  │                                  │
│            └──────────┘                                  │
└─────────────────────────────────────────────────────────┘
                       │
         ┌─────────────┼─────────────┐
         ▼             ▼             ▼
    ┌─────────┐  ┌──────────┐  ┌──────────┐
    │  nmap   │  │ whatweb  │  │exploitdb │
    │  MCP    │  │  MCP     │  │  MCP     │
    │ Server  │  │ Server   │  │ Server   │
    │ (4工具) │  │ (4工具)  │  │ (4工具)  │
    └─────────┘  └──────────┘  └──────────┘
         独立进程      独立进程      独立进程
              MCP stdio 协议通信
```

## 四个 Agent

| Agent | 职责 | 范式 | 适用路径 |
|-------|------|------|---------|
| **ThreatAnalyzer** | 提取 IOC → VT 查杀 → CVE 关联 → 研判 | ReACT (思考⇄行动循环) | 蓝队 |
| **PentestAgent** | 协调 MCP 工具链执行渗透侦察 | MCP 编排 + LLM 驱动双模式 | 红队 |
| **IncidentResponder** | 生成分阶段响应计划 (P0→P3) | Prompt-driven | 共享 |
| **ReportGenerator** | 整合为结构化 Markdown 报告 | Prompt-driven | 共享 |

## 为什么选 LangGraph + MCP？

| 方式 | 耦合度 | 复用性 | 安全性 | 面试含金量 |
|------|--------|--------|--------|-----------|
| 直接 subprocess | 高 | 无 | 无 | ⭐ |
| LangChain Tool | 中 | 低 | 同进程 | ⭐⭐ |
| **LangGraph + MCP** | **低** | **高** | **进程隔离** | ⭐⭐⭐⭐⭐ |

## 快速开始

```bash
# 1. 克隆
git clone https://github.com/docasy/security-agent.git
cd security-agent

# 2. 安装依赖
pip install -r requirements.txt

# 3. 配置（mock 模式不需要 API Key 也能跑）
cp .env.example .env
# 可选: 编辑 .env 填入 OPENAI_API_KEY 以启用 LLM 功能

# 4. 启动
python -m src.main
# 服务运行在 http://localhost:8000
# Swagger: http://localhost:8000/docs

# 5. 测试告警分析
curl -X POST http://localhost:8000/analyze \
  -H "Content-Type: application/json" \
  -d '{"alert_data":"检测到来自 45.33.32.156 的异常登录","task_type":"alert"}'

# 6. 测试渗透扫描（mock 模式，无需装系统工具）
curl -X POST http://localhost:8000/pentest \
  -H "Content-Type: application/json" \
  -d '{"target":"192.168.1.1","task_type":"pentest"}'
```

## 项目结构

```
security-agent/
├── README.md                   ← 你正在看的
├── LICENSE                     ← MIT
├── requirements.txt
├── .env.example
├── .gitignore
├── 系统架构图.html              ← 可视化架构图
├── HelloAgents视角-项目分析报告.html
├── 项目流程与结构详解.html
├── 面试模拟30题-八股文+项目.html
└── src/
    ├── main.py                 ← FastAPI 入口 (双端点)
    ├── graph/
    │   └── workflow.py         ← LangGraph 双路径工作流 ⭐
    ├── agents/
    │   ├── analyzer.py         ← 威胁分析 (ReACT)
    │   ├── pentest_agent.py    ← 渗透测试 (MCP 编排)
    │   ├── responder.py        ← 响应计划
    │   └── reporter.py         ← 报告生成
    ├── mcp/                    ← MCP 协议层 (2026 核心)
    │   ├── client.py           ← 多 Server 连接管理器
    │   ├── langchain_bridge.py ← MCP→LangChain 桥接
    │   └── servers/
    │       ├── nmap_server.py
    │       ├── whatweb_server.py
    │       └── exploitdb_server.py
    ├── tools/
    │   ├── virus_total.py
    │   └── cve_search.py
    └── rag/
        └── knowledge_base.py   ← ChromaDB 安全知识库
```

## 技术栈

| 层级 | 选型 | 理由 |
|------|------|------|
| 编排 | **LangGraph** StateGraph | 显式状态管理 + 条件路由 |
| 工具协议 | **MCP** (Model Context Protocol) | 2026 行业标准，进程隔离 |
| LLM | OpenAI GPT-4o-mini | 安全分析需要确定性 (temperature=0) |
| RAG | ChromaDB + text-embedding-3-small | 轻量嵌入式向量库 |
| API | **FastAPI** | 异步原生支持 + 自动文档 |
| 渗透工具 | nmap / whatweb / searchsploit | 业界标准 (默认 mock) |
| 威胁情报 | VirusTotal API v3 + NVD CVE API | 权威数据源 |

## 面试速查

> 完整题库见 `面试模拟30题-八股文+项目.html`

| 面试官问 | 答题方向 |
|---------|---------|
| "为什么用 LangGraph" | 显式状态管理 + 条件路由 + 人在回路。对比 AgentExecutor 黑盒 |
| "MCP vs Function Calling" | MCP 是工具的 USB-C（标准化），FC 是 LLM 调工具的机制（执行层） |
| "你怎么保证质量" | Pydantic 输入验证 + mock 可重复测试 + 下一步补 pytest |
| "渗透测试的自动化边界" | AI 负责看见（侦察），人负责决定（攻击）。Agent 不扣扳机 |
| "这个项目最大亮点" | MCP × 安全垂直领域的组合在 GitHub 上极少见 |

---

📌 **Built for AI Agent Internship Interviews · 2026**
