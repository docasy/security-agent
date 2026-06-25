"""技能加载器 — 读取 agency-agent Skill 文件注入 system prompt

两种模式:
- load() → 默认精简版（去掉代码块、长表格），~50行，LLM响应快
- load_full() → 完整版，~300-500行，面试展示用

控制: SKILL_COMPACT_MODE=1 (默认精简) 或 0 (完整)
"""

import os
import pathlib
import re
from functools import lru_cache

DEFAULT_SKILL_DIR = os.getenv("AGENCY_AGENTS_DIR", "D:/Downloads/agency-agents")
USE_COMPACT = os.getenv("SKILL_COMPACT_MODE", "1") == "1"


class SkillsLoader:
    """从 agency-agents 仓库加载标准化 Agent Skill 定义"""

    def __init__(self, skill_dir: str = None):
        base = pathlib.Path(skill_dir or DEFAULT_SKILL_DIR)
        self.engineering_dir = base / "engineering"
        self.specialized_dir = base / "specialized"

    def load(self, name: str) -> str:
        """加载 skill。默认返回精简版（快），SKILL_COMPACT_MODE=0 返回完整版（慢但详细）"""
        if USE_COMPACT:
            return self._load_compact(name)
        return self._load_full(name)

    def load_full(self, name: str) -> str:
        """始终返回完整版 skill（面试用）"""
        return self._load_full(name)

    @lru_cache(maxsize=8)
    def _load_full(self, name: str) -> str:
        candidates = [
            self.engineering_dir / f"engineering-{name}.md",
            self.specialized_dir / f"{name}.md",
        ]
        for fp in candidates:
            if fp.exists():
                return fp.read_text(encoding="utf-8")
        raise FileNotFoundError(f"Skill '{name}' not found")

    @lru_cache(maxsize=8)
    def _load_compact(self, name: str) -> str:
        """精简版：去掉 front matter、代码块、长表格。保留角色、铁律、流程。"""
        full = self._load_full(name)
        # 去掉 YAML front matter
        content = re.sub(r'^---\s*\n.*?\n---\s*\n', '', full, flags=re.DOTALL)
        # 去掉 markdown 代码块 (``` ... ```)
        content = re.sub(r'```[\s\S]*?```', '', content)
        # 去掉超过 8 行的表格
        content = re.sub(r'\n(\|[^\n]+\|\n){9,}', '\n[table omitted]', content)
        # 去掉多余空行
        content = re.sub(r'\n{3,}', '\n\n', content)
        # 限制最大长度
        if len(content) > 4000:
            content = content[:4000]
        return content.strip()

    def load_or_default(self, name: str, fallback: str) -> str:
        try:
            return self.load(name)
        except FileNotFoundError:
            return fallback


loader = SkillsLoader()
