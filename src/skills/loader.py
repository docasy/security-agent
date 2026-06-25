"""技能加载器 — 从磁盘读取 agency-agent 的 Markdown Skill 文件，直接当 system prompt 用

设计原则：
- 不解析 Markdown：agency-agent 的 .md 文件从第二段开始就是 "You are **Security Engineer**..."
  对 LLM 说的话，原封不动注入 system prompt，保留原文的语气、结构和细节
- 缓存加载：同一个 skill 只读一次磁盘，后续调用直接返回缓存
- 优雅降级：如果 skill 文件不存在或加载失败，回退到内置的简化 prompt

面试考点：
1. 为什么直接当 system prompt 用？（agency-agent 的 Skill 定义本身就是对 LLM 说的话）
2. 和 RAG 注入 Skill 的区别？（这个是全局角色定义，RAG 是每次请求动态检索）
3. Token 成本怎么平衡？（skill 约 2000 token，但 GPT-4o-mini 便宜，行为提升 >> 成本增加）
"""

import os
import pathlib
from functools import lru_cache

# 默认 skill 仓库路径，可以通过环境变量覆盖
DEFAULT_SKILL_DIR = os.getenv(
    "AGENCY_AGENTS_DIR",
    "D:/Downloads/agency-agents",
)


class SkillsLoader:
    """从 agency-agents 仓库加载标准化 Agent Skill 定义"""

    def __init__(self, skill_dir: str = None):
        """
        参数:
          skill_dir: agency-agents 仓库的根目录。默认读环境变量 AGENCY_AGENTS_DIR，
                     未设置则用 DEFAULT_SKILL_DIR
        """
        base = pathlib.Path(skill_dir or DEFAULT_SKILL_DIR)
        self.engineering_dir = base / "engineering"
        self.specialized_dir = base / "specialized"

    def load(self, name: str) -> str:
        """加载指定 skill 的完整 Markdown 内容，直接当 system prompt 用"""
        return self._load_cached(name)

    @lru_cache(maxsize=8)
    def _load_cached(self, name: str) -> str:
        """
        带缓存的加载逻辑。
        查找顺序：engineering/ → specialized/ → 都找不到则抛异常
        """
        candidates = [
            self.engineering_dir / f"engineering-{name}.md",
            self.specialized_dir / f"{name}.md",
        ]

        for filepath in candidates:
            if filepath.exists():
                return filepath.read_text(encoding="utf-8")

        raise FileNotFoundError(
            f"Skill '{name}' not found. Searched:\n"
            + "\n".join(f"  - {fp}" for fp in candidates)
        )

    def load_or_default(self, name: str, fallback: str) -> str:
        """
        尝试加载 skill，失败时返回 fallback。
        用于 Reporter 这种没有匹配 skill 的情况。
        """
        try:
            return self.load(name)
        except FileNotFoundError:
            return fallback


# 全局单例 — 整个项目共用同一个 loader 实例
loader = SkillsLoader()
