from __future__ import annotations

import time
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Optional

import requests


@dataclass
class OnlineVerdict:
    provider: str
    malicious: int = 0
    suspicious: int = 0
    harmless: int = 0
    undetected: int = 0
    total_engines: int = 0
    link: str = ""
    details: str = ""


class VirusTotalClient:
    BASE = "https://www.virustotal.com/api/v3"

    def __init__(self, api_key: str, timeout: int = 25):
        self.api_key = api_key
        self.timeout = timeout

    def _headers(self) -> Dict[str, str]:
        return {"x-apikey": self.api_key}

    def lookup_hash(self, sha256: str) -> Optional[OnlineVerdict]:
        url = f"{self.BASE}/files/{sha256}"
        r = requests.get(url, headers=self._headers(), timeout=self.timeout)
        if r.status_code == 404:
            return None
        r.raise_for_status()
        data = r.json()
        attrs = data.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {}) or {}

        total = 0
        for v in stats.values():
            if isinstance(v, int):
                total += v

        return OnlineVerdict(
            provider="VirusTotal",
            malicious=int(stats.get("malicious", 0)),
            suspicious=int(stats.get("suspicious", 0)),
            harmless=int(stats.get("harmless", 0)),
            undetected=int(stats.get("undetected", 0)),
            total_engines=total,
            link=f"https://www.virustotal.com/gui/file/{sha256}",
            details="hash report"
        )

    def submit_file(self, file_path: Path) -> str:
        url = f"{self.BASE}/files"
        with file_path.open("rb") as f:
            files = {"file": (file_path.name, f)}
            r = requests.post(url, headers=self._headers(), files=files, timeout=self.timeout)
        r.raise_for_status()
        j = r.json()
        return j.get("data", {}).get("id", "")

    def wait_analysis_and_fetch(self, analysis_id: str, sha256: str, max_wait_sec: int = 180) -> Optional[OnlineVerdict]:
        if not analysis_id:
            return self.lookup_hash(sha256)

        deadline = time.time() + max_wait_sec
        analysis_url = f"{self.BASE}/analyses/{analysis_id}"

        while time.time() < deadline:
            r = requests.get(analysis_url, headers=self._headers(), timeout=self.timeout)
            if r.status_code == 404:
                break
            r.raise_for_status()
            status = r.json().get("data", {}).get("attributes", {}).get("status", "")
            if status == "completed":
                break
            time.sleep(3)

        return self.lookup_hash(sha256)


class OPSWATClient:
    BASE = "https://api.metadefender.com/v4"

    def __init__(self, api_key: str, timeout: int = 25):
        self.api_key = api_key
        self.timeout = timeout

    def _headers(self) -> Dict[str, str]:
        return {"apikey": self.api_key}

    def lookup_hash(self, sha256: str) -> Optional[OnlineVerdict]:
        url = f"{self.BASE}/hash/{sha256}"
        r = requests.get(url, headers=self._headers(), timeout=self.timeout)
        if r.status_code == 404:
            return None
        r.raise_for_status()
        j = r.json()

        scan_results = (j.get("scan_results") or {})
        total = int(scan_results.get("total_avs") or 0)
        detected = int(scan_results.get("total_detected_avs") or 0)
        harmless = max(total - detected, 0)

        return OnlineVerdict(
            provider="OPSWAT",
            malicious=detected,
            suspicious=0,
            harmless=harmless,
            undetected=0,
            total_engines=total,
            link="",
            details="hash report"
        )