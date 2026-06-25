"""SQLite 分析结果持久化 — 每次分析自动记录，支持历史和查询

设计原则：
- 零部署依赖：SQLite 是 Python 内置库
- 轻量：单文件数据库，适合原型和演示
- 生产可迁移：表结构简单，改 PostgreSQL/MySQL 只需换 engine
- 自动记录：分析完成后自动写入，不需要手动调 API
"""

import sqlite3
import json
import os
import threading
from datetime import datetime, timezone
from typing import Optional
from dataclasses import dataclass, asdict

DB_PATH = os.getenv("ANALYSIS_DB_PATH", "./analyses.db")


@dataclass
class AnalysisRecord:
    """一次分析的结构化记录"""
    id: Optional[int] = None
    task_type: str = ""           # "alert" | "pentest"
    thread_id: str = "default"
    input_data: str = ""          # alert_data 或 target
    analysis_result: str = ""     # 分析结果
    response_plan: str = ""       # 响应计划
    final_report: str = ""        # 最终报告
    status: str = "completed"     # running | completed | failed
    created_at: str = ""


class AnalysisStore:
    """SQLite 分析记录存储"""

    def __init__(self, db_path: str = DB_PATH):
        self.db_path = db_path
        self._lock = threading.Lock()
        self._init_db()

    def _get_conn(self) -> sqlite3.Connection:
        """每个线程独立连接，带 row_factory 自动转换"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")  # 读写并发
        return conn

    def _init_db(self):
        """建表 — 首次自动执行"""
        with self._lock:
            conn = self._get_conn()
            conn.execute("""
                CREATE TABLE IF NOT EXISTS analyses (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    task_type TEXT NOT NULL DEFAULT 'alert',
                    thread_id TEXT NOT NULL DEFAULT 'default',
                    input_data TEXT DEFAULT '',
                    analysis_result TEXT DEFAULT '',
                    response_plan TEXT DEFAULT '',
                    final_report TEXT DEFAULT '',
                    status TEXT DEFAULT 'completed',
                    created_at TEXT DEFAULT (datetime('now'))
                )
            """)
            conn.commit()
            conn.close()

    def save(self, record: AnalysisRecord) -> int:
        """
        保存一条分析记录，返回自增 ID。

        在 main.py 的 /analyze 和 /pentest 响应前自动调用，
        分析结果从此不会丢失。
        """
        with self._lock:
            conn = self._get_conn()
            cursor = conn.execute("""
                INSERT INTO analyses
                    (task_type, thread_id, input_data, analysis_result,
                     response_plan, final_report, status)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                record.task_type,
                record.thread_id,
                record.input_data,
                record.analysis_result,
                record.response_plan,
                record.final_report,
                record.status or "completed",
            ))
            conn.commit()
            record_id = cursor.lastrowid
            conn.close()
            return record_id

    def get_by_id(self, analysis_id: int) -> Optional[dict]:
        """按 ID 查询单条记录"""
        conn = self._get_conn()
        row = conn.execute(
            "SELECT * FROM analyses WHERE id = ?", (analysis_id,)
        ).fetchone()
        conn.close()
        return dict(row) if row else None

    def list_recent(self, limit: int = 20) -> list[dict]:
        """最近 N 条记录，按时间倒序"""
        conn = self._get_conn()
        rows = conn.execute(
            "SELECT id, task_type, thread_id, input_data, status, created_at "
            "FROM analyses ORDER BY id DESC LIMIT ?",
            (limit,),
        ).fetchall()
        conn.close()
        return [dict(r) for r in rows]

    def list_by_thread(self, thread_id: str) -> list[dict]:
        """
        按会话线程查询所有历史 — 这是多轮对话的基础：
        同一个 thread_id 的多次分析构成一个完整的对话链。
        """
        conn = self._get_conn()
        rows = conn.execute(
            "SELECT * FROM analyses WHERE thread_id = ? ORDER BY id ASC",
            (thread_id,),
        ).fetchall()
        conn.close()
        return [dict(r) for r in rows]


# 全局单例
_db_instance: Optional[AnalysisStore] = None


def get_db() -> AnalysisStore:
    """获取全局数据库实例（懒初始化）"""
    global _db_instance
    if _db_instance is None:
        _db_instance = AnalysisStore()
    return _db_instance
