from __future__ import annotations

import argparse
import os
from pathlib import Path
from typing import Optional

from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn
from rich.table import Table
from rich.text import Text

from .scanner import ScanResult, SentinelScanner


ASCII_ART = r"""
   _____            _   _            _  _____                 
  / ____|          | | (_)          | |/ ____|                
 | (___   ___ _ __ | |_ _ _ __   ___| | (___   ___ __ _ _ __ 
  \___ \ / _ \ '_ \| __| | '_ \ / _ \ |\___ \ / __/ _` | '_ \
  ____) |  __/ | | | |_| | | | |  __/ |____) | (_| (_| | | | |
 |_____/ \___|_| |_|\__|_|_| |_|\___|_|_____/ \___\__,_|_| |_|
"""


def severity_color(sev: str) -> str:
    sev = sev.lower()
    if sev == "high":
        return "red"
    if sev == "medium":
        return "yellow"
    return "green"


def verdict_style(verdict: str) -> str:
    v = verdict.upper()
    if v == "SAFE":
        return "bold green"
    if v == "SUSPICIOUS":
        return "bold yellow"
    if v == "MALICIOUS":
        return "bold red"
    return "bold white"


def welcome(console: Console) -> None:
    panel = Panel.fit(
        Text(ASCII_ART, style="bold cyan"),
        title="[bold]SentinelScan[/bold]",
        subtitle="Static + Online File Threat Scanner",
        border_style="cyan",
    )
    console.print(panel)


def build_metadata_table(r: ScanResult) -> Table:
    t = Table(title="File Metadata", show_lines=True)
    t.add_column("Field", style="bold cyan", no_wrap=True)
    t.add_column("Value", style="white")
    t.add_row("Path", str(r.file_path))
    t.add_row("Size", f"{r.file_size:,} bytes")
    t.add_row("Type (magic)", r.file_type)
    t.add_row("MD5", r.hashes.get("md5", ""))
    t.add_row("SHA-256", r.hashes.get("sha256", ""))
    t.add_row("Is Windows PE", "Yes" if r.is_pe else "No")
    return t


def build_pe_table(r: ScanResult) -> Optional[Table]:
    if not r.is_pe or not r.pe_info:
        return None
    t = Table(title="PE Metadata (pefile)", show_lines=True)
    t.add_column("Key", style="bold cyan", no_wrap=True)
    t.add_column("Value", style="white")
    for k, v in r.pe_info.items():
        t.add_row(k, v)
    return t


def build_online_table(r: ScanResult) -> Optional[Table]:
    if not r.online_reports:
        return None
    t = Table(title="Online Reputation", show_lines=True)
    t.add_column("Provider", style="bold cyan", no_wrap=True)
    t.add_column("Malicious", justify="right")
    t.add_column("Suspicious", justify="right")
    t.add_column("Engines", justify="right")
    t.add_column("Link", style="dim")

    for rep in r.online_reports:
        mal = f"[red]{rep.malicious}[/red]" if rep.malicious else str(rep.malicious)
        sus = f"[yellow]{rep.suspicious}[/yellow]" if rep.suspicious else str(rep.suspicious)
        t.add_row(rep.provider, mal, sus, str(rep.total_engines), rep.link)
    return t


def build_findings_table(r: ScanResult) -> Table:
    t = Table(title="Findings", show_lines=True)
    t.add_column("Severity", style="bold", no_wrap=True)
    t.add_column("Category", style="cyan", no_wrap=True)
    t.add_column("Name", style="white")
    t.add_column("Details", style="dim")
    if not r.findings:
        t.add_row("[green]none[/green]", "-", "No findings", "")
        return t
    for f in r.findings:
        color = severity_color(f.severity)
        t.add_row(f"[{color}]{f.severity.upper()}[/{color}]", f.category, f.name, f.details or "")
    return t


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(prog="sentinelscan", description="SentinelScan - static + online scanner.")
    p.add_argument("--file", "-f", required=True, help="Path to the file to scan")

    p.add_argument("--signatures", "-s", default=None, help="Path to signatures.json (optional)")
    p.add_argument("--rules", "-r", default=None, help="Directory with .yar rules (optional)")
    p.add_argument("--max-bytes", type=int, default=2 * 1024 * 1024, help="Max bytes to sample for strings scan")

    p.add_argument("--vt-key", default=os.getenv("VT_API_KEY"), help="VirusTotal API key (or env VT_API_KEY)")
    p.add_argument("--opswat-key", default=os.getenv("OPSWAT_API_KEY"), help="OPSWAT API key (or env OPSWAT_API_KEY)")
    p.add_argument("--submit", action="store_true", help="If hash not found, submit file online (privacy risk).")

    return p.parse_args()


def main() -> None:
    console = Console()
    welcome(console)

    args = parse_args()
    file_path = Path(args.file)

    pkg_dir = Path(__file__).resolve().parent
    default_sigs = pkg_dir / "signatures.json"
    default_rules = pkg_dir / "yara_rules"

    sigs_path = Path(args.signatures).expanduser().resolve() if args.signatures else default_sigs
    rules_dir = Path(args.rules).expanduser().resolve() if args.rules else default_rules

    scanner = SentinelScanner(
        signatures_path=sigs_path if sigs_path.exists() else None,
        yara_rules_dir=rules_dir if rules_dir.exists() else None,
        max_string_bytes=args.max_bytes,
        vt_key=args.vt_key,
        opswat_key=args.opswat_key,
        online_submit=args.submit,
    )

    with Progress(
        SpinnerColumn(),
        TextColumn("[bold]Scanning[/bold]"),
        BarColumn(),
        TextColumn("{task.percentage:>3.0f}%"),
        TimeElapsedColumn(),
        console=console,
    ) as progress:
        task = progress.add_task("scan", total=100)
        progress.update(task, advance=10)
        try:
            progress.update(task, advance=20)
            result = scanner.scan(file_path)
            progress.update(task, advance=70)
        except FileNotFoundError as e:
            console.print(Panel(str(e), title="Error", border_style="red"))
            raise SystemExit(2)
        except Exception as e:
            console.print(Panel(f"{type(e).__name__}: {e}", title="Unhandled error", border_style="red"))
            raise SystemExit(3)

    console.print(build_metadata_table(result))
    pe_table = build_pe_table(result)
    if pe_table:
        console.print(pe_table)
    online_table = build_online_table(result)
    if online_table:
        console.print(online_table)
    console.print(build_findings_table(result))

    verdict_text = Text(f"VERDICT: {result.verdict}  (score: {result.score})", style=verdict_style(result.verdict))
    border = "green" if result.verdict == "SAFE" else "yellow" if result.verdict == "SUSPICIOUS" else "red"
    console.print(Panel(verdict_text, title="Final Result", border_style=border))

    if result.verdict == "SAFE":
        raise SystemExit(0)
    if result.verdict == "SUSPICIOUS":
        raise SystemExit(1)
    raise SystemExit(2)