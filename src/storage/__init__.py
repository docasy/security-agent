"""持久化存储模块 — SQLite 轻量分析历史 + 多轮对话上下文

面试考点：
1. 为什么选 SQLite？（原型阶段零部署，单文件数据库，生产可换 PostgreSQL）
2. 持久化的意义？（审计追溯、结果复用、多轮对话依赖历史上下文）
"""

from src.storage.database import AnalysisStore, get_db

__all__ = ["AnalysisStore", "get_db"]
