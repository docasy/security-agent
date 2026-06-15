"""CVE 漏洞数据库检索工具 — 通过 NVD API 查询漏洞信息"""

import httpx
from typing import Optional
from pydantic import BaseModel


class CVEResult(BaseModel):
    """CVE 漏洞信息"""
    cve_id: str
    description: str
    cvss_score: Optional[float]
    severity: str  # NONE / LOW / MEDIUM / HIGH / CRITICAL
    published_date: str
    references: list[str]


class CVESearchTool:
    """封装 NVD (National Vulnerability Database) API"""

    def __init__(self):
        self.base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    async def search(self, keyword: str, limit: int = 5) -> list[CVEResult]:
        """按关键词搜索 CVE"""
        params = {
            "keywordSearch": keyword,
            "resultsPerPage": limit,
        }
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.get(self.base_url, params=params)
            resp.raise_for_status()
            data = resp.json()

        results = []
        for vuln in data.get("vulnerabilities", []):
            cve = vuln["cve"]
            metrics = cve.get("metrics", {}).get("cvssMetricV31", [])
            cvss = metrics[0]["cvssData"]["baseScore"] if metrics else None

            severity = "UNKNOWN"
            if cvss:
                if cvss >= 9.0:
                    severity = "CRITICAL"
                elif cvss >= 7.0:
                    severity = "HIGH"
                elif cvss >= 4.0:
                    severity = "MEDIUM"
                elif cvss > 0:
                    severity = "LOW"

            desc = ""
            for d in cve.get("descriptions", []):
                if d["lang"] == "en":
                    desc = d["value"]
                    break

            refs = [r["url"] for r in cve.get("references", [])[:3]]

            results.append(CVEResult(
                cve_id=cve["id"],
                description=desc,
                cvss_score=cvss,
                severity=severity,
                published_date=cve.get("published", ""),
                references=refs,
            ))

        return results

    async def get_cve_detail(self, cve_id: str) -> Optional[CVEResult]:
        """查询单个 CVE 详情"""
        results = await self.search(cve_id, limit=1)
        return results[0] if results else None

    @property
    def name(self) -> str:
        return "cve_search"

    @property
    def description(self) -> str:
        return (
            "Search the NVD CVE database for vulnerability information. "
            "Use this to look up CVEs by keyword or CVE ID."
        )
