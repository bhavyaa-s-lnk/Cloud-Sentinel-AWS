import json
import os
import pytest

from models.finding import Finding, Severity
from scanners.s3_scanner import S3Scanner
from scanners.iam_scanner import IAMScanner
from scanners.ec2_scanner import EC2Scanner
from scanners.rds_scanner import RDSScanner
from reporting.reporter import Reporter


def test_finding_model():
    finding = Finding(
        service="S3",
        resource_id="test-bucket",
        severity=Severity.HIGH.value,
        title="Test Bucket Issue",
        description="Detailed description",
        remediation="Run remediation command"
    )
    assert finding.service == "S3"
    assert finding.severity == "HIGH"
    assert finding.resource_type == "AWS::S3::Resource"
    assert finding.finding_id.startswith("CS-")
    assert finding.timestamp is not None
    data = finding.to_dict()
    assert data["resource_id"] == "test-bucket"


def test_s3_scanner_demo():
    scanner = S3Scanner(demo_mode=True)
    findings = scanner.scan()
    assert len(findings) > 0
    services = {f.service for f in findings}
    assert services == {"S3"}
    titles = [f.title for f in findings]
    assert any("Public Access" in t for t in titles)
    assert any("Encryption" in t for t in titles)


def test_iam_scanner_demo():
    scanner = IAMScanner(demo_mode=True)
    findings = scanner.scan()
    assert len(findings) > 0
    services = {f.service for f in findings}
    assert services == {"IAM"}
    titles = [f.title for f in findings]
    assert any("Root Account" in t for t in titles)
    assert any("MFA" in t for t in titles)


def test_ec2_scanner_demo():
    scanner = EC2Scanner(demo_mode=True)
    findings = scanner.scan()
    assert len(findings) > 0
    services = {f.service for f in findings}
    assert services == {"EC2"}
    titles = [f.title for f in findings]
    assert any("SSH" in t for t in titles)
    assert any("EBS Volume" in t for t in titles)


def test_rds_scanner_demo():
    scanner = RDSScanner(demo_mode=True)
    findings = scanner.scan()
    assert len(findings) > 0
    services = {f.service for f in findings}
    assert services == {"RDS"}
    titles = [f.title for f in findings]
    # Verify all 5 check categories are represented in demo findings
    assert any("Publicly Accessible" in t for t in titles), "Missing public accessibility finding"
    assert any("Encrypted" in t or "Encryption" in t for t in titles), "Missing encryption finding"
    assert any("Backup" in t for t in titles), "Missing backup retention finding"
    assert any("Master Username" in t for t in titles), "Missing default username finding"
    assert any("Multi-AZ" in t for t in titles), "Missing multi-AZ finding"


def test_rds_scanner_demo_severity_distribution():
    scanner = RDSScanner(demo_mode=True)
    findings = scanner.scan()
    severities = {f.severity for f in findings}
    # Demo should cover at minimum CRITICAL, HIGH, MEDIUM, LOW
    assert Severity.CRITICAL.value in severities, "No CRITICAL severity finding in RDS demo"
    assert Severity.HIGH.value in severities, "No HIGH severity finding in RDS demo"
    assert Severity.MEDIUM.value in severities, "No MEDIUM severity finding in RDS demo"
    assert Severity.LOW.value in severities, "No LOW severity finding in RDS demo"


def test_rds_scanner_demo_resource_types():
    scanner = RDSScanner(demo_mode=True)
    findings = scanner.scan()
    for finding in findings:
        assert finding.resource_type == "AWS::RDS::DBInstance", \
            f"Unexpected resource_type '{finding.resource_type}' in finding '{finding.title}'"
        assert finding.finding_id.startswith("CS-"), "Finding ID should start with 'CS-'"
        assert finding.compliance_benchmark, "Compliance benchmark should not be empty"


def test_reporter_summary_calculation():
    reporter = Reporter()
    sample_findings = [
        Finding(service="S3", resource_id="b1", severity=Severity.CRITICAL.value, title="T1", description="D1", remediation="R1"),
        Finding(service="IAM", resource_id="u1", severity=Severity.HIGH.value, title="T2", description="D2", remediation="R2"),
        Finding(service="EC2", resource_id="i1", severity=Severity.MEDIUM.value, title="T3", description="D3", remediation="R3"),
    ]
    summary = reporter.calculate_summary(sample_findings)
    assert summary["total_findings"] == 3
    assert summary["critical_count"] == 1
    assert summary["high_count"] == 1
    assert summary["medium_count"] == 1
    assert summary["low_count"] == 0
    assert summary["service_breakdown"] == {"S3": 1, "IAM": 1, "EC2": 1}
    assert summary["security_score"] == 100 - (20 + 10 + 4)  # 66


def test_reporter_json_and_html_generation(tmp_path):
    reporter = Reporter()
    sample_findings = [
        Finding(service="S3", resource_id="b1", severity=Severity.CRITICAL.value, title="Public S3", description="Public access open", remediation="Block access")
    ]
    meta = {
        "profile": "test",
        "region": "us-east-1",
        "services": "S3",
        "mode": "DEMO",
        "scan_date": "2026-09-25 12:00:00 UTC"
    }
    output_dir = str(tmp_path / "reports")

    # JSON report
    json_path = reporter.generate_json_report(sample_findings, meta, output_dir)
    assert os.path.exists(json_path)
    with open(json_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    assert data["scanner"] == "CloudSentinel"
    assert len(data["findings"]) == 1

    # HTML report
    html_path = reporter.generate_html_report(sample_findings, meta, output_dir)
    assert os.path.exists(html_path)
    with open(html_path, "r", encoding="utf-8") as f:
        html_content = f.read()
    assert "CloudSentinel" in html_content
    assert "Public S3" in html_content
    assert "CRITICAL" in html_content

