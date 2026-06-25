"""技能加载模块 — 从 agency-agents 仓库加载标准化 Agent Skill 定义

面试考点：
1. System Prompt 和 Skill 的本质关系？（Skill 是结构化的、可复用的 System Prompt）
2. 为什么用外部文件而不是硬编码？（解耦角色定义和代码，改角色行为不改代码）
3. 为什么用 lru_cache？（避免每次请求都读磁盘）
"""

from src.skills.loader import SkillsLoader, loader

__all__ = ["SkillsLoader", "loader"]
