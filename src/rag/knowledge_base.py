"""RAG 安全知识库 — 基于 ChromaDB 的 ATT&CK / CVE 语义检索"""

import os
from typing import Optional

from langchain_openai import OpenAIEmbeddings
from langchain_community.vectorstores import Chroma
from langchain_core.documents import Document


# 内置的安全知识种子数据（面试时能说出这些会被认为懂安全）
SEED_KNOWLEDGE = [
    {
        "content": (
            "MITRE ATT&CK is a knowledge base of adversary tactics and techniques. "
            "Tactics: Reconnaissance, Resource Development, Initial Access, Execution, "
            "Persistence, Privilege Escalation, Defense Evasion, Credential Access, "
            "Discovery, Lateral Movement, Collection, Command and Control, Exfiltration, Impact. "
            "Each tactic contains multiple techniques with unique IDs like T1059 (Command and Scripting Interpreter)."
        ),
        "source": "MITRE ATT&CK Framework",
    },
    {
        "content": (
            "CVE-2021-44228 (Log4Shell) is a critical RCE vulnerability in Apache Log4j2. "
            "CVSS 10.0. Affected versions: 2.0-beta9 to 2.14.1. "
            "JNDI features in log4j2 allow attackers to perform JNDI injection for RCE. "
            "Mitigation: upgrade to 2.16.0+ or set log4j2.formatMsgNoLookups=true."
        ),
        "source": "NVD",
    },
    {
        "content": (
            "CVE-2023-34362 (MOVEit Transfer SQL Injection) is a critical vulnerability in Progress MOVEit Transfer. "
            "CVSS 9.8. Allows unauthenticated SQL injection leading to RCE. "
            "Exploited by Cl0p ransomware group for data exfiltration. "
            "SHODAN search: http.title:'MOVEit' to identify exposed instances."
        ),
        "source": "NVD",
    },
    {
        "content": (
            "Phishing is the most common initial access vector (T1566). "
            "Indicators: suspicious sender domain, urgency in subject line, mismatched URLs, "
            "unexpected attachments. Defense: SPF/DKIM/DMARC, user training, email filtering. "
            "Spear phishing targets specific individuals using OSINT reconnaissance."
        ),
        "source": "Security Best Practices",
    },
    {
        "content": (
            "Ransomware attack lifecycle: 1) Initial access (phishing/RDP), 2) Reconnaissance, "
            "3) Credential dumping (T1003), 4) Lateral movement (T1021), "
            "5) Data exfiltration (T1041), 6) Encryption (T1486), 7) Ransom note. "
            "Detection: unusual SMB traffic, volume shadow copy deletion, mass file rename operations."
        ),
        "source": "Incident Response Playbook",
    },
    {
        "content": (
            "YARA rules are pattern-matching rules for malware identification. "
            "Rules consist of meta (metadata), strings (hex/text/regex patterns), and condition sections. "
            "Example condition: any of ($s1, $s2) and filesize < 500KB. "
            "YARA is the industry standard for malware classification and threat hunting."
        ),
        "source": "Malware Analysis",
    },
    {
        "content": (
            "OWASP Top 10 (2021): A01 Broken Access Control, A02 Cryptographic Failures, "
            "A03 Injection, A04 Insecure Design, A05 Security Misconfiguration, "
            "A06 Vulnerable Components, A07 Auth Failures, A08 Software & Data Integrity, "
            "A09 Logging & Monitoring Failures, A10 SSRF."
        ),
        "source": "OWASP",
    },
]


class SecurityKnowledgeBase:
    """安全领域 RAG 知识库 — 面试核心：你要能解释 RAG 的检索-增强-生成流程"""

    def __init__(self, persist_dir: Optional[str] = None):
        self.persist_dir = persist_dir or os.getenv("CHROMA_PERSIST_DIR", "./chroma_db")
        self.embeddings = OpenAIEmbeddings(model="text-embedding-3-small")
        self.vectorstore: Optional[Chroma] = None

    def build(self) -> Chroma:
        """构建知识库（首次运行） — 面试考点：Embedding 是什么？为什么用向量检索？"""
        docs = [
            Document(page_content=item["content"], metadata={"source": item["source"]})
            for item in SEED_KNOWLEDGE
        ]
        self.vectorstore = Chroma.from_documents(
            documents=docs,
            embedding=self.embeddings,
            persist_directory=self.persist_dir,
            collection_name="security_knowledge",
        )
        return self.vectorstore

    def load(self) -> Chroma:
        """加载已有知识库"""
        if self.vectorstore is None:
            self.vectorstore = Chroma(
                persist_directory=self.persist_dir,
                embedding_function=self.embeddings,
                collection_name="security_knowledge",
            )
        return self.vectorstore

    def query(self, question: str, k: int = 3) -> list[Document]:
        """检索相关知识 — 面试考点：为什么选 k=3？Top-K 检索的精度/召回权衡"""
        store = self.load()
        return store.similarity_search(question, k=k)

    def query_with_scores(self, question: str, k: int = 3) -> list[tuple[Document, float]]:
        """带相似度分数的检索"""
        store = self.load()
        return store.similarity_search_with_relevance_scores(question, k=k)
