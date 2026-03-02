from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import magic
import pefile
import yara

from .online import OnlineVerdict, OPSWATClient, VirusTotalClient
from .utils import compute_hashes, extract_ascii_strings, safe_read_bytes


@dataclass
class Finding:
    category: str
    name: str
    severity: str  # low|medium|high
    details: str = ""


@dataclass
class ScanResult:
    file_path: Path
    file_size: int
    file_type: str
    hashes: Dict[str, str]
    is_pe: bool
    pe_info: Dict[str, str] = field(default_factory=dict)
    yara_matches: List[str] = field(default_factory=list)
    online_reports: List[OnlineVerdict] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)
    score: int = 0
    verdict: str = "UNKNOWN"  # SAFE/SUSPICIOUS/MALICIOUS/UNKNOWN


class SentinelScanner:
    def __init__(
        self,
        signatures_path: Optional[Path] = None,
        yara_rules_dir: Optional[Path] = None,
        max_string_bytes: int = 2 * 1024 * 1024,
        vt_key: Optional[str] = None,
        opswat_key: Optional[str] = None,
        online_submit: bool = False,
    ):
        self.signatures_path = signatures_path
        self.yara_rules_dir = yara_rules_dir
        self.max_string_bytes = max_string_bytes
        self.online_submit = online_submit

        self.signatures = self._load_signatures(signatures_path) if signatures_path else {"md5": {}, "sha256": {}}
        self.yara_rules = self._compile_yara_rules(yara_rules_dir) if yara_rules_dir else None

        self.vt = VirusTotalClient(vt_key) if vt_key else None
        self.opswat = OPSWATClient(opswat_key) if opswat_key else None

    def _load_signatures(self, path: Path) -> Dict[str, Dict[str, str]]:
        if not path.exists():
            return {"md5": {}, "sha256": {}}
        with path.open("r", encoding="utf-8") as f:
            data = json.load(f)
        data.setdefault("md5", {})
        data.setdefault("sha256", {})
        return data

    def _compile_yara_rules(self, rules_dir: Path) -> Optional[yara.Rules]:
        if not rules_dir.exists() or not rules_dir.is_dir():
            return None
        rule_files = sorted([p for p in rules_dir.glob("*.yar") if p.is_file()])
        if not rule_files:
            return None

        sources = {}
        for idx, rf in enumerate(rule_files, start=1):
            sources[f"rule_{idx}"] = rf.read_text(encoding="utf-8", errors="ignore")
        return yara.compile(sources=sources)

    def _get_file_type(self, path: Path) -> str:
        try:
            ms = magic.Magic(mime=False)
            return ms.from_file(str(path))
        except Exception:
            return "Unknown"

    def _try_parse_pe(self, path: Path) -> Tuple[bool, Dict[str, str], List[Finding]]:
        findings: List[Finding] = []
        pe_info: Dict[str, str] = {}
        try:
            pe = pefile.PE(str(path), fast_load=True)
            pe.parse_data_directories(directories=[])
            is_dll = bool(pe.FILE_HEADER.Characteristics & 0x2000)

            pe_info["Machine"] = hex(pe.FILE_HEADER.Machine)
            pe_info["NumberOfSections"] = str(pe.FILE_HEADER.NumberOfSections)
            pe_info["TimeDateStamp"] = str(pe.FILE_HEADER.TimeDateStamp)
            pe_info["Characteristics"] = hex(pe.FILE_HEADER.Characteristics)
            pe_info["IsDLL"] = "Yes" if is_dll else "No"
            pe_info["EntryPoint"] = hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint) if hasattr(pe, "OPTIONAL_HEADER") else "N/A"
            pe_info["ImageBase"] = hex(pe.OPTIONAL_HEADER.ImageBase) if hasattr(pe, "OPTIONAL_HEADER") else "N/A"

            suspicious_sections = 0
            for s in pe.sections:
                name = s.Name.rstrip(b"\x00").decode(errors="ignore").lower()
                if name in (".upx", "upx0", "upx1", ".aspack", ".themida", ".packed"):
                    suspicious_sections += 1
            if suspicious_sections:
                findings.append(Finding(
                    category="pe",
                    name="Packed/Obfuscated section names",
                    severity="medium",
                    details=f"Found {suspicious_sections} suspicious section name(s)."
                ))

            return True, pe_info, findings
        except pefile.PEFormatError:
            return False, {}, []
        except Exception as e:
            findings.append(Finding(category="pe", name="PE parse error", severity="low", details=str(e)))
            return False, {}, findings

    def _match_signatures(self, hashes: Dict[str, str]) -> List[Finding]:
        out: List[Finding] = []
        md5 = hashes.get("md5", "")
        sha256 = hashes.get("sha256", "")

        if md5 and md5 in self.signatures.get("md5", {}):
            out.append(Finding("signature", "Known MD5 signature match", "high", self.signatures["md5"][md5]))
        if sha256 and sha256 in self.signatures.get("sha256", {}):
            out.append(Finding("signature", "Known SHA-256 signature match", "high", self.signatures["sha256"][sha256]))
        return out

    def _run_yara(self, path: Path) -> Tuple[List[str], List[Finding]]:
        if not self.yara_rules:
            return [], []

        matches: List[str] = []
        findings: List[Finding] = []
        try:
            m = self.yara_rules.match(str(path), timeout=10)
            for match in m:
                matches.append(match.rule)
            if matches:
                findings.append(Finding("yara", "YARA match", "high", ", ".join(matches)))
        except yara.TimeoutError:
            findings.append(Finding("yara", "YARA timeout", "medium", "Rules matching timed out."))
        except Exception as e:
            findings.append(Finding("yara", "YARA error", "low", str(e)))

        return matches, findings

    def _scan_strings(self, path: Path, file_type: str) -> List[Finding]:
        findings: List[Finding] = []
        data = safe_read_bytes(path, self.max_string_bytes)
        strings = extract_ascii_strings(data, min_len=4)
        s_lower = [s.lower() for s in strings]

        suspicious_keywords = {
            "http://": ("Network indicator (http)", "medium"),
            "https://": ("Network indicator (https)", "medium"),
            "eval": ("Potential code execution (eval)", "medium"),
            "exec": ("Potential code execution (exec)", "medium"),
            "powershell": ("PowerShell usage", "high"),
            "cmd.exe": ("Windows shell usage", "high"),
            "/bin/sh": ("Unix shell usage", "high"),
            "socket": ("Network API indicator (socket)", "medium"),
            "connect": ("Network API indicator (connect)", "medium"),
            "wget ": ("Downloader usage (wget)", "high"),
            "curl ": ("Downloader usage (curl)", "high"),
            "base64": ("Encoding/obfuscation indicator (base64)", "medium"),
            "createremotethread": ("Process injection API indicator", "high"),
            "writeprocessmemory": ("Process injection API indicator", "high"),
            "virtualalloc": ("Memory allocation API indicator", "medium"),
        }

        hits = []
        for key, (label, sev) in suspicious_keywords.items():
            count = sum(1 for s in s_lower if key in s)
            if count:
                hits.append((label, sev, count))

        for label, sev, count in sorted(hits, key=lambda x: (-x[2], x[0]))[:12]:
            findings.append(Finding("strings", label, sev, f"Occurrences: {count}"))

        url_count = sum(1 for s in s_lower if "http://" in s or "https://" in s)
        if url_count >= 5:
            findings.append(Finding("strings", "High URL density", "medium", f"Found {url_count} URL strings (sampled)."))

        is_script_like = any(x in file_type.lower() for x in ["python", "javascript", "shell script", "php", "perl"])
        if is_script_like and (any("eval" in s for s in s_lower) or any("exec" in s for s in s_lower)):
            findings.append(Finding("heuristic", "Script with dynamic execution hints", "high", "Script-like file contains eval/exec."))

        return findings

    def _online_lookup(self, file_path: Path, sha256: str) -> List[OnlineVerdict]:
        reports: List[OnlineVerdict] = []

        if self.vt and sha256:
            vt_rep = self.vt.lookup_hash(sha256)
            if vt_rep is None and self.online_submit:
                analysis_id = self.vt.submit_file(file_path)
                vt_rep = self.vt.wait_analysis_and_fetch(analysis_id, sha256)
            if vt_rep:
                reports.append(vt_rep)

        if self.opswat and sha256:
            op_rep = self.opswat.lookup_hash(sha256)
            if op_rep:
                reports.append(op_rep)

        return reports

    def _score_and_verdict(self, findings: List[Finding]) -> Tuple[int, str]:
        score = 0
        for f in findings:
            if f.severity == "low":
                score += 10
            elif f.severity == "medium":
                score += 25
            elif f.severity == "high":
                score += 60

        if any(f.severity == "high" and f.category in ("signature", "yara", "online") for f in findings):
            return max(score, 90), "MALICIOUS"
        if score >= 90:
            return score, "MALICIOUS"
        if score >= 35:
            return score, "SUSPICIOUS"
        if score >= 1:
            return score, "SUSPICIOUS"
        return score, "SAFE"

    def scan(self, file_path: Path) -> ScanResult:
        p = file_path.expanduser().resolve()
        if not p.exists() or not p.is_file():
            raise FileNotFoundError(f"File not found: {p}")

        size = p.stat().st_size
        ftype = self._get_file_type(p)
        hashes = compute_hashes(p)

        is_pe, pe_info, pe_findings = self._try_parse_pe(p)
        sig_findings = self._match_signatures(hashes)
        yara_matches, yara_findings = self._run_yara(p)
        str_findings = self._scan_strings(p, ftype)

        findings: List[Finding] = []
        findings.extend(sig_findings)
        findings.extend(yara_findings)
        findings.extend(pe_findings)
        findings.extend(str_findings)

        online_reports = self._online_lookup(p, hashes.get("sha256", ""))

        for rep in online_reports:
            if rep.malicious > 0:
                findings.append(Finding(
                    category="online",
                    name=f"{rep.provider} detection",
                    severity="high",
                    details=f"malicious={rep.malicious} suspicious={rep.suspicious} engines={rep.total_engines} {rep.link}".strip()
                ))
            elif rep.suspicious > 0:
                findings.append(Finding(
                    category="online",
                    name=f"{rep.provider} suspicious",
                    severity="medium",
                    details=f"suspicious={rep.suspicious} engines={rep.total_engines} {rep.link}".strip()
                ))

        score, verdict = self._score_and_verdict(findings)

        return ScanResult(
            file_path=p,
            file_size=size,
            file_type=ftype,
            hashes=hashes,
            is_pe=is_pe,
            pe_info=pe_info,
            yara_matches=yara_matches,
            online_reports=online_reports,
            findings=findings,
            score=score,
            verdict=verdict,
        )