import json
import logging
from typing import List
from botocore.exceptions import ClientError

from models.finding import Finding, Severity
from scanners.base_scanner import BaseScanner

logger = logging.getLogger("CloudSentinel.S3Scanner")


class S3Scanner(BaseScanner):
    """Scanner for detecting security misconfigurations in AWS S3 buckets."""

    def run_scan(self) -> List[Finding]:
        findings = []
        client = self.get_client("s3")
        if not client:
            return findings

        try:
            response = client.list_buckets()
            buckets = response.get("Buckets", [])
        except ClientError as e:
            logger.error(f"Failed to list S3 buckets: {e}")
            return findings

        for bucket in buckets:
            bucket_name = bucket["Name"]
            logger.info(f"Scanning S3 Bucket: {bucket_name}")
            findings.extend(self._check_public_access_block(client, bucket_name))
            findings.extend(self._check_encryption(client, bucket_name))
            findings.extend(self._check_versioning(client, bucket_name))
            findings.extend(self._check_logging(client, bucket_name))
            findings.extend(self._check_bucket_policy(client, bucket_name))

        return findings

    def _check_public_access_block(self, client, bucket_name: str) -> List[Finding]:
        findings = []
        try:
            res = client.get_public_access_block(Bucket=bucket_name)
            pab = res.get("PublicAccessBlockConfiguration", {})
            required_flags = ["BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets"]
            missing_flags = [flag for flag in required_flags if not pab.get(flag, False)]

            if missing_flags:
                findings.append(Finding(
                    service="S3",
                    resource_id=bucket_name,
                    resource_type="AWS::S3::Bucket",
                    severity=Severity.HIGH.value,
                    title="S3 Bucket Public Access Block Configuration Incomplete",
                    description=f"Bucket '{bucket_name}' has Public Access Block enabled, but the following protections are disabled: {', '.join(missing_flags)}.",
                    remediation=f"Execute: aws s3api put-public-access-block --bucket {bucket_name} --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true",
                    compliance_benchmark="CIS AWS Foundations v1.4.0 (2.1.5)",
                    region=self.region_name
                ))
        except ClientError as e:
            code = e.response.get("Error", {}).get("Code")
            if code in ["NoSuchPublicAccessBlockConfiguration", "404"]:
                findings.append(Finding(
                    service="S3",
                    resource_id=bucket_name,
                    resource_type="AWS::S3::Bucket",
                    severity=Severity.CRITICAL.value,
                    title="S3 Bucket Missing Public Access Block Protection",
                    description=f"Bucket '{bucket_name}' does not have S3 Block Public Access configured, leaving it vulnerable to accidental public exposure.",
                    remediation=f"Execute: aws s3api put-public-access-block --bucket {bucket_name} --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true",
                    compliance_benchmark="CIS AWS Foundations v1.4.0 (2.1.5)",
                    region=self.region_name
                ))
            else:
                logger.warning(f"Error checking Public Access Block for {bucket_name}: {e}")
        return findings

    def _check_encryption(self, client, bucket_name: str) -> List[Finding]:
        findings = []
        try:
            res = client.get_bucket_encryption(Bucket=bucket_name)
            rules = res.get("ServerSideEncryptionConfiguration", {}).get("Rules", [])
            if not rules:
                findings.append(Finding(
                    service="S3",
                    resource_id=bucket_name,
                    resource_type="AWS::S3::Bucket",
                    severity=Severity.HIGH.value,
                    title="S3 Bucket Server-Side Encryption Not Enabled",
                    description=f"Bucket '{bucket_name}' is not configured with default server-side encryption.",
                    remediation=f"Execute: aws s3api put-bucket-encryption --bucket {bucket_name} --server-side-encryption-configuration '{{\"Rules\": [{{\"ApplyServerSideEncryptionByDefault\": {{\"SSEAlgorithm\": \"AES256\"}}}}]}}'",
                    compliance_benchmark="CIS AWS Foundations v1.4.0 (2.1.1)",
                    region=self.region_name
                ))
        except ClientError as e:
            code = e.response.get("Error", {}).get("Code")
            if code == "ServerSideEncryptionConfigurationNotFoundError":
                findings.append(Finding(
                    service="S3",
                    resource_id=bucket_name,
                    resource_type="AWS::S3::Bucket",
                    severity=Severity.HIGH.value,
                    title="S3 Bucket Server-Side Encryption Not Configured",
                    description=f"Bucket '{bucket_name}' has no server-side encryption configuration found.",
                    remediation=f"Execute: aws s3api put-bucket-encryption --bucket {bucket_name} --server-side-encryption-configuration '{{\"Rules\": [{{\"ApplyServerSideEncryptionByDefault\": {{\"SSEAlgorithm\": \"AES256\"}}}}]}}'",
                    compliance_benchmark="CIS AWS Foundations v1.4.0 (2.1.1)",
                    region=self.region_name
                ))
            else:
                logger.warning(f"Error checking encryption for {bucket_name}: {e}")
        return findings

    def _check_versioning(self, client, bucket_name: str) -> List[Finding]:
        findings = []
        try:
            res = client.get_bucket_versioning(Bucket=bucket_name)
            status = res.get("Status")
            if status != "Enabled":
                findings.append(Finding(
                    service="S3",
                    resource_id=bucket_name,
                    resource_type="AWS::S3::Bucket",
                    severity=Severity.MEDIUM.value,
                    title="S3 Bucket Versioning Disabled",
                    description=f"Bucket '{bucket_name}' does not have object versioning enabled, exposing data to ransomware and accidental deletion.",
                    remediation=f"Execute: aws s3api put-bucket-versioning --bucket {bucket_name} --versioning-configuration Status=Enabled",
                    compliance_benchmark="AWS Well-Architected Security Pillar (SEC-09)",
                    region=self.region_name
                ))
        except ClientError as e:
            logger.warning(f"Error checking versioning for {bucket_name}: {e}")
        return findings

    def _check_logging(self, client, bucket_name: str) -> List[Finding]:
        findings = []
        try:
            res = client.get_bucket_logging(Bucket=bucket_name)
            if "LoggingEnabled" not in res:
                findings.append(Finding(
                    service="S3",
                    resource_id=bucket_name,
                    resource_type="AWS::S3::Bucket",
                    severity=Severity.LOW.value,
                    title="S3 Bucket Server Access Logging Disabled",
                    description=f"Bucket '{bucket_name}' does not record access logs for object-level requests.",
                    remediation=f"Enable server access logging in the S3 console or using: aws s3api put-bucket-logging --bucket {bucket_name} --bucket-logging-status file://logging.json",
                    compliance_benchmark="CIS AWS Foundations v1.4.0 (2.1.3)",
                    region=self.region_name
                ))
        except ClientError as e:
            logger.warning(f"Error checking logging for {bucket_name}: {e}")
        return findings

    def _check_bucket_policy(self, client, bucket_name: str) -> List[Finding]:
        findings = []
        try:
            res = client.get_bucket_policy(Bucket=bucket_name)
            policy = json.loads(res.get("Policy", "{}"))
            statements = policy.get("Statement", [])
            if isinstance(statements, dict):
                statements = [statements]

            for stmt in statements:
                effect = stmt.get("Effect")
                principal = stmt.get("Principal")
                condition = stmt.get("Condition")

                is_public_principal = (
                    principal == "*" or
                    (isinstance(principal, dict) and principal.get("AWS") == "*")
                )

                if effect == "Allow" and is_public_principal and not condition:
                    findings.append(Finding(
                        service="S3",
                        resource_id=bucket_name,
                        resource_type="AWS::S3::Bucket",
                        severity=Severity.CRITICAL.value,
                        title="S3 Bucket Policy Permits Unrestricted Public Access",
                        description=f"Bucket '{bucket_name}' has an access policy granting 'Allow' to principal '*' without restrictions.",
                        remediation=f"Review and restrict bucket policy statement to authorized principals or delete public statement: aws s3api delete-bucket-policy --bucket {bucket_name}",
                        compliance_benchmark="CIS AWS Foundations v1.4.0 (2.1.2)",
                        region=self.region_name
                    ))
                    break
        except ClientError as e:
            code = e.response.get("Error", {}).get("Code")
            if code not in ["NoSuchBucketPolicy", "404"]:
                logger.warning(f"Error checking bucket policy for {bucket_name}: {e}")
        return findings

    def run_demo_scan(self) -> List[Finding]:
        return [
            Finding(
                service="S3",
                resource_id="corp-finance-records-2026",
                resource_type="AWS::S3::Bucket",
                severity=Severity.CRITICAL.value,
                title="S3 Bucket Policy Permits Unrestricted Public Access",
                description="Bucket 'corp-finance-records-2026' policy grants 'Allow' on 's3:GetObject' to principal '*' without IP or VPC endpoint conditions.",
                remediation="Remove public statement or attach condition: aws s3api delete-bucket-policy --bucket corp-finance-records-2026",
                compliance_benchmark="CIS AWS Foundations v1.4.0 (2.1.2)",
                region=self.region_name
            ),
            Finding(
                service="S3",
                resource_id="app-dev-asset-storage",
                resource_type="AWS::S3::Bucket",
                severity=Severity.HIGH.value,
                title="S3 Bucket Server-Side Encryption Not Enabled",
                description="Bucket 'app-dev-asset-storage' stores objects unencrypted at rest without KMS or SSE-S3 configuration.",
                remediation="Execute: aws s3api put-bucket-encryption --bucket app-dev-asset-storage --server-side-encryption-configuration '{\"Rules\": [{\"ApplyServerSideEncryptionByDefault\": {\"SSEAlgorithm\": \"AES256\"}}]}'",
                compliance_benchmark="CIS AWS Foundations v1.4.0 (2.1.1)",
                region=self.region_name
            ),
            Finding(
                service="S3",
                resource_id="app-dev-asset-storage",
                resource_type="AWS::S3::Bucket",
                severity=Severity.MEDIUM.value,
                title="S3 Bucket Versioning Disabled",
                description="Bucket 'app-dev-asset-storage' does not have object versioning enabled, making file overwrites irreversible.",
                remediation="Execute: aws s3api put-bucket-versioning --bucket app-dev-asset-storage --versioning-configuration Status=Enabled",
                compliance_benchmark="AWS Well-Architected Security Pillar (SEC-09)",
                region=self.region_name
            ),
            Finding(
                service="S3",
                resource_id="analytics-raw-events",
                resource_type="AWS::S3::Bucket",
                severity=Severity.LOW.value,
                title="S3 Bucket Server Access Logging Disabled",
                description="Bucket 'analytics-raw-events' does not have server access logging enabled to capture incoming request telemetry.",
                remediation="Enable S3 access logging target bucket in AWS Management Console or CLI.",
                compliance_benchmark="CIS AWS Foundations v1.4.0 (2.1.3)",
                region=self.region_name
            )
        ]