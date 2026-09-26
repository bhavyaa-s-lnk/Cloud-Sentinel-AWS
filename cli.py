from datetime import datetime, timezone
import logging
import os
import sys
import click
from colorama import init, Fore, Style

# Ensure project root is in sys.path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from reporting.reporter import Reporter
from scanners.s3_scanner import S3Scanner
from scanners.iam_scanner import IAMScanner
from scanners.ec2_scanner import EC2Scanner
from scanners.rds_scanner import RDSScanner

# Initialize colorama
init(autoreset=True)

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("CloudSentinel")

AVAILABLE_SCANNERS = {
    "s3": S3Scanner,
    "iam": IAMScanner,
    "ec2": EC2Scanner,
    "rds": RDSScanner,
}


@click.group()
@click.version_option(version="1.0.0", prog_name="CloudSentinel")
def cli():
    """CloudSentinel: Automated AWS Cloud Security & Compliance Scanner"""
    pass


@cli.command()
@click.option("--profile", default="default", help="AWS CLI profile name to use.")
@click.option("--region", default="us-east-1", help="Target AWS region to audit.")
@click.option(
    "--services",
    default="all",
    help="Comma-separated services to scan (s3, iam, ec2, rds) or 'all'.",
)
@click.option(
    "--output-dir",
    default="reports",
    help="Directory to save generated audit reports.",
)
@click.option(
    "--format",
    "report_format",
    type=click.Choice(["all", "html", "json", "terminal"], case_sensitive=False),
    default="all",
    help="Desired report output format.",
)
@click.option(
    "--demo",
    is_flag=True,
    default=False,
    help="Run simulated scan with realistic misconfigurations (no active AWS credentials required).",
)
def scan(profile, region, services, output_dir, report_format, demo):
    """Run an automated security misconfiguration scan on AWS services."""
    banner = rf"""
{Fore.CYAN}{Style.BRIGHT}=======================================================
   ____ _                 _____             _   _            _ 
  / ___| | ___  _   _  __| / ___|  ___ _ __ | |_(_)_ __   ___| |
 | |   | |/ _ \| | | |/ _` \___ \ / _ \ '_ \| __| | '_ \ / _ \ |
 | |___| | (_) | |_| | (_| |___) |  __/ | | | |_| | | | |  __/ |
  \____|_|\___/ \__,_|\__,_|____/ \___|_| |_|\__|_|_| |_|\___|_|
                     AWS SECURITY AUDIT ENGINE v1.0.0
======================================================={Style.RESET_ALL}"""
    click.echo(banner)

    mode_label = "DEMO / SIMULATION (No credentials needed)" if demo else f"LIVE AWS ({profile})"
    click.echo(f"  Execution Mode: {Fore.YELLOW}{mode_label}{Style.RESET_ALL}")
    click.echo(f"  Target Region:  {Fore.GREEN}{region}{Style.RESET_ALL}")

    if services.strip().lower() == "all":
        services_to_scan = list(AVAILABLE_SCANNERS.keys())
    else:
        services_to_scan = [s.strip().lower() for s in services.split(",") if s.strip()]

    click.echo(f"  Target Services: {Fore.CYAN}{', '.join(services_to_scan).upper()}{Style.RESET_ALL}\n")

    all_findings = []

    for svc in services_to_scan:
        scanner_class = AVAILABLE_SCANNERS.get(svc)
        if not scanner_class:
            click.echo(Fore.RED + f"[-] Unknown service '{svc}'. Skipping.")
            continue

        click.echo(Fore.CYAN + f"[*] Launching {svc.upper()} Security Scanner...")
        scanner = scanner_class(profile_name=profile, region_name=region, demo_mode=demo)
        service_findings = scanner.scan()
        all_findings.extend(service_findings)
        click.echo(Fore.GREEN + f"[+] {svc.upper()} Scanner complete: {len(service_findings)} findings identified.")

    click.echo("\n" + Fore.CYAN + "[*] Processing and generating audit reports...")
    reporter = Reporter()

    scan_metadata = {
        "profile": profile,
        "region": region,
        "services": ", ".join(services_to_scan).upper(),
        "mode": "DEMO" if demo else "LIVE",
        "scan_date": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    }

    # Terminal output
    if report_format in ["all", "terminal"]:
        reporter.print_terminal_summary(all_findings, scan_metadata)

    # JSON export
    if report_format in ["all", "json"]:
        json_path = reporter.generate_json_report(all_findings, scan_metadata, output_dir)
        click.echo(Fore.GREEN + f"[+] JSON Report generated: {json_path}")

    # HTML export
    if report_format in ["all", "html"]:
        html_path = reporter.generate_html_report(all_findings, scan_metadata, output_dir)
        click.echo(Fore.GREEN + f"[+] HTML Audit Report generated: {html_path}")

    click.echo(Fore.CYAN + Style.BRIGHT + "[OK] Security audit scan completed successfully!\n")


if __name__ == "__main__":
    cli()
