# CloudSentinel 🛡️

**CloudSentinel** is an automated AWS cloud security misconfiguration scanner built in Python. It audits your AWS environment against CIS AWS Foundations Benchmarks and the AWS Well-Architected Security Pillar, then generates rich, audit-ready reports in terminal, JSON, and interactive HTML formats.

> ✅ **Zero credentials required** — run a full simulated scan instantly with `--demo` mode.

---

## Features

| Scanner | Security Checks |
|---|---|
| **S3** | Public Access Block, Server-Side Encryption, Versioning, Access Logging, Bucket Policy exposure |
| **IAM** | Root MFA, Root access keys, User MFA, Stale access keys (>90 days), Wildcard admin policies |
| **EC2** | Open security groups (SSH/RDP/DB ports), Unencrypted EBS volumes, Public IP instances |
| **RDS** | Public accessibility, Storage encryption, Backup retention, Default master username, Multi-AZ |

### Report Formats
- 🖥️ **Terminal** — Color-coded severity output with a security posture score
- 📄 **JSON** — Structured machine-readable export for CI/CD pipelines
- 🌐 **HTML** — Dark-mode glassmorphism dashboard with interactive filters and expandable findings

---

## Quickstart

### 1. Install dependencies

```bash
python -m venv .venv
# Windows
.venv\Scripts\pip install -r requirements.txt
# macOS/Linux
.venv/bin/pip install -r requirements.txt
```

### 2. Run a demo scan (no AWS credentials needed)

```bash
# Windows
.venv\Scripts\python cli.py scan --demo --services all --format all

# macOS/Linux
.venv/bin/python cli.py scan --demo --services all --format all
```

### 3. Run a live scan against your AWS account

```bash
# Scan all services using your default AWS profile
python cli.py scan --profile default --region us-east-1 --services all --format all

# Scan only S3 and RDS, output JSON only
python cli.py scan --profile prod --region eu-west-1 --services s3,rds --format json
```

---

## CLI Reference

```
Usage: cli.py scan [OPTIONS]

Options:
  --profile TEXT         AWS CLI profile name to use.         [default: default]
  --region TEXT          Target AWS region to audit.          [default: us-east-1]
  --services TEXT        Comma-separated services (s3, iam, ec2, rds) or 'all'.
  --output-dir TEXT      Directory for generated reports.     [default: reports]
  --format [all|html|json|terminal]  Report output format.   [default: all]
  --demo                 Simulated scan — no credentials required.
  --version              Show version and exit.
  --help                 Show this message and exit.
```

---

## Project Structure

```
CloudSentinel/
├── cli.py                          # CLI entry point (Click)
├── requirements.txt                # Python dependencies
├── conftest.py                     # Pytest configuration
├── models/
│   └── finding.py                  # Finding dataclass + Severity enum
├── scanners/
│   ├── base_scanner.py             # Abstract base with boto3 session management
│   ├── s3_scanner.py               # S3 security checks
│   ├── iam_scanner.py              # IAM security checks
│   ├── ec2_scanner.py              # EC2 / VPC security checks
│   └── rds_scanner.py              # RDS security checks
├── reporting/
│   ├── reporter.py                 # Terminal, JSON, and HTML report generation
│   └── templates/
│       └── report_template.html    # Jinja2 dark-mode HTML report template
├── tests/
│   └── test_scanners.py            # Pytest unit tests (9 tests)
└── reports/                        # Generated reports output directory
```

---

## Running Tests

```bash
# Windows
.venv\Scripts\pytest tests -v

# macOS/Linux
.venv/bin/pytest tests -v
```

Expected output: **9 passed** ✅

---

## Compliance Benchmarks Covered

- **CIS AWS Foundations Benchmark v1.4.0**
- **AWS Well-Architected Framework — Security Pillar**
- **AWS Well-Architected Framework — Reliability Pillar**

---

## Requirements

- Python 3.10+
- boto3, click, Jinja2, colorama, pytest

---

## License

MIT License — free to use, modify, and distribute.
