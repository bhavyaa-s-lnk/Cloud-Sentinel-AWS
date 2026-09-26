from collections import Counter
from datetime import datetime, timezone
import json
import os
from pathlib import Path
from typing import List, Dict, Any
from colorama import Fore, Style, init
from jinja2 import Environment, FileSystemLoader

from models.finding import Finding, Severity

# Initialize colorama
init(autoreset=True)


class Reporter:
    """Orchestrates formatting and exporting of CloudSentinel audit findings."""

    def __init__(self, template_dir: str = None):
        if not template_dir:
            template_dir = str(Path(__file__).parent / "templates")
        self.jinja_env = Environment(loader=FileSystemLoader(template_dir), autoescape=True)

    def calculate_summary(self, findings: List[Finding]) -> Dict[str, Any]:
        sev_counts = Counter(f.severity for f in findings)
        service_counts = Counter(f.service for f in findings)

        critical = sev_counts.get(Severity.CRITICAL.value, 0)
        high = sev_counts.get(Severity.HIGH.value, 0)
        medium = sev_counts.get(Severity.MEDIUM.value, 0)
        low = sev_counts.get(Severity.LOW.value, 0)
        info = sev_counts.get(Severity.INFORMATIONAL.value, 0)

        # Deduct from 100 based on severity impact
        deductions = (critical * 20) + (high * 10) + (medium * 4) + (low * 1)
        score = max(0, 100 - deductions)

        return {
            "total_findings": len(findings),
            "critical_count": critical,
            "high_count": high,
            "medium_count": medium,
            "low_count": low,
            "info_count": info,
            "service_breakdown": dict(service_counts),
            "security_score": score
        }

    def print_terminal_summary(self, findings: List[Finding], metadata: Dict[str, Any]):
        summary = self.calculate_summary(findings)

        print("\n" + "=" * 70)
        print(Fore.CYAN + Style.BRIGHT + "  CLOUDSENTINEL // AWS SECURITY AUDIT REPORT")
        print("=" * 70)
        print(f"  Target Region: {metadata.get('region')} | Profile: {metadata.get('profile')}")
        print(f"  Scanned Services: {metadata.get('services')} | Mode: {metadata.get('mode')}")
        print("-" * 70)

        # Score display
        score = summary["security_score"]
        score_color = Fore.GREEN if score >= 80 else (Fore.YELLOW if score >= 60 else Fore.RED)
        print(f"  SECURITY POSTURE SCORE: {score_color}{Style.BRIGHT}{score}/100{Style.RESET_ALL}")
        print("-" * 70)

        # Severity breakdown
        print("  FINDINGS BREAKDOWN:")
        print(f"    {Fore.RED}CRITICAL:{Style.RESET_ALL}      {summary['critical_count']}")
        print(f"    {Fore.LIGHTRED_EX}HIGH:{Style.RESET_ALL}          {summary['high_count']}")
        print(f"    {Fore.YELLOW}MEDIUM:{Style.RESET_ALL}        {summary['medium_count']}")
        print(f"    {Fore.BLUE}LOW:{Style.RESET_ALL}           {summary['low_count']}")
        print(f"    TOTAL:         {summary['total_findings']}")
        print("-" * 70)

        print(Fore.CYAN + "  DETAILED FINDINGS:")
        for idx, f in enumerate(findings, 1):
            if f.severity == "CRITICAL":
                badge = f"{Fore.RED}[CRITICAL]{Style.RESET_ALL}"
            elif f.severity == "HIGH":
                badge = f"{Fore.LIGHTRED_EX}[HIGH]{Style.RESET_ALL}"
            elif f.severity == "MEDIUM":
                badge = f"{Fore.YELLOW}[MEDIUM]{Style.RESET_ALL}"
            else:
                badge = f"{Fore.BLUE}[LOW]{Style.RESET_ALL}"

            print(f"\n  {idx}. {badge} [{f.service}] {Style.BRIGHT}{f.title}{Style.RESET_ALL}")
            print(f"     Resource:   {f.resource_id} ({f.resource_type})")
            print(f"     Issue:      {f.description}")
            print(f"     Remedy:     {Fore.GREEN}{f.remediation}{Style.RESET_ALL}")
            print(f"     Benchmark:  {f.compliance_benchmark}")

        print("\n" + "=" * 70 + "\n")

    def generate_json_report(self, findings: List[Finding], metadata: Dict[str, Any], output_dir: str) -> str:
        os.makedirs(output_dir, exist_ok=True)
        summary = self.calculate_summary(findings)
        timestamp_str = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        filename = f"cloudsentinel_report_{timestamp_str}.json"
        output_file = os.path.join(output_dir, filename)

        data = {
            "scanner": "CloudSentinel",
            "version": "1.0.0",
            "metadata": metadata,
            "summary": summary,
            "findings": [f.to_dict() for f in findings]
        }

        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

        return os.path.abspath(output_file)

    def generate_html_report(self, findings: List[Finding], metadata: Dict[str, Any], output_dir: str) -> str:
        os.makedirs(output_dir, exist_ok=True)
        summary = self.calculate_summary(findings)
        timestamp_str = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        filename = f"cloudsentinel_report_{timestamp_str}.html"
        output_file = os.path.join(output_dir, filename)

        template = self.jinja_env.get_template("report_template.html")
        rendered_html = template.render(
            findings=[f.to_dict() for f in findings],
            summary=summary,
            metadata=metadata
        )

        with open(output_file, "w", encoding="utf-8") as f:
            f.write(rendered_html)

        return os.path.abspath(output_file)
