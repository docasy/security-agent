"""VirusTotal API 工具 — 查询文件哈希、IP、域名、URL 的威胁情报"""

import os
import httpx
from typing import Optional
from pydantic import BaseModel


class VTResult(BaseModel):
    """VirusTotal 查询结果"""
    indicator: str
    type: str  # file / ip / domain / url
    malicious: int
    suspicious: int
    harmless: int
    undetected: int
    permalink: str


class VirusTotalTool:
    """封装 VirusTotal API v3"""

    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or os.getenv("VIRUSTOTAL_API_KEY", "")
        self.base_url = "https://www.virustotal.com/api/v3"
        self.headers = {"x-apikey": self.api_key, "Accept": "application/json"}

    async def _get(self, endpoint: str) -> dict:
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.get(f"{self.base_url}/{endpoint}", headers=self.headers)
            resp.raise_for_status()
            return resp.json()

    async def lookup_file(self, hash_value: str) -> VTResult:
        """查询文件哈希 (SHA-256 / SHA-1 / MD5)"""
        data = await self._get(f"files/{hash_value}")
        attrs = data["data"]["attributes"]
        stats = attrs["last_analysis_stats"]
        return VTResult(
            indicator=hash_value,
            type="file",
            malicious=stats.get("malicious", 0),
            suspicious=stats.get("suspicious", 0),
            harmless=stats.get("harmless", 0),
            undetected=stats.get("undetected", 0),
            permalink=f"https://www.virustotal.com/gui/file/{hash_value}",
        )

    async def lookup_ip(self, ip: str) -> VTResult:
        """查询 IP 地址"""
        data = await self._get(f"ip_addresses/{ip}")
        attrs = data["data"]["attributes"]
        stats = attrs["last_analysis_stats"]
        return VTResult(
            indicator=ip,
            type="ip",
            malicious=stats.get("malicious", 0),
            suspicious=stats.get("suspicious", 0),
            harmless=stats.get("harmless", 0),
            undetected=stats.get("undetected", 0),
            permalink=f"https://www.virustotal.com/gui/ip-address/{ip}",
        )

    async def lookup_domain(self, domain: str) -> VTResult:
        """查询域名"""
        data = await self._get(f"domains/{domain}")
        attrs = data["data"]["attributes"]
        stats = attrs["last_analysis_stats"]
        return VTResult(
            indicator=domain,
            type="domain",
            malicious=stats.get("malicious", 0),
            suspicious=stats.get("suspicious", 0),
            harmless=stats.get("harmless", 0),
            undetected=stats.get("undetected", 0),
            permalink=f"https://www.virustotal.com/gui/domain/{domain}",
        )

    @property
    def name(self) -> str:
        return "virus_total"

    @property
    def description(self) -> str:
        return (
            "Query VirusTotal threat intelligence for a file hash, IP address, "
            "or domain. Returns detection ratios across security vendors."
        )
