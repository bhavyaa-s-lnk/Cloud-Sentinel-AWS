from datetime import datetime, timezone
import json
import logging
from typing import List
from botocore.exceptions import ClientError

from models.finding import Finding, Severity
from scanners.base_scanner import BaseScanner

logger = logging.getLogger("CloudSentinel.IAMScanner")


class IAMScanner(BaseScanner):
    """Scanner for detecting identity and access management (IAM) security risks."""

    def run_scan(self) -> List[Finding]:
        findings = []
        client = self.get_client("iam")
        if not client:
            return findings

        findings.extend(self._check_root_account(client))

        try:
            paginator = client.get_paginator("list_users")
            for page in paginator.paginate():
                for user in page.get("Users", []):
                    user_name = user["UserName"]
                    logger.info(f"Scanning IAM User: {user_name}")
                    findings.extend(self._check_user_mfa(client, user_name))
                    findings.extend(self._check_access_keys(client, user_name))
                    findings.extend(self._check_user_policies(client, user_name))
        except ClientError as e:
            logger.error(f"Error enumerating IAM users: {e}")

        return findings

    def _check_root_account(self, client) -> List[Finding]:
        findings = []
        try:
            summary = client.get_account_summary().get("SummaryMap", {})
            if summary.get("AccountMFAEnabled", 0) == 0:
                findings.append(Finding(
                    service="IAM",
                    resource_id="root",
                    resource_type="AWS::IAM::RootAccount",
                    severity=Severity.CRITICAL.value,
                    title="AWS Root Account Missing Multi-Factor Authentication (MFA)",
                    description="The root user account does not have MFA enabled. Root account compromise leads to full AWS account takeover.",
                    remediation="Log in as the root user immediately and activate a hardware or virtual MFA device via IAM console.",
                    compliance_benchmark="CIS AWS Foundations v1.4.0 (1.5)",
                    region="global"
                ))

            if summary.get("AccountAccessKeysPresent", 0) > 0:
                findings.append(Finding(
                    service="IAM",
                    resource_id="root",
                    resource_type="AWS::IAM::RootAccount",
                    severity=Severity.CRITICAL.value,
                    title="Active Access Keys Present on AWS Root Account",
                    description="Active programmatic API access keys exist on the AWS root user account. Root keys bypass least-privilege boundaries.",
                    remediation="Delete all root user access keys immediately and utilize IAM roles or individual admin users with MFA.",
                    compliance_benchmark="CIS AWS Foundations v1.4.0 (1.4)",
                    region="global"
                ))
        except ClientError as e:
            logger.warning(f"Unable to inspect account summary for root checks: {e}")
        return findings

    def _check_user_mfa(self, client, user_name: str) -> List[Finding]:
        findings = []
        has_login_profile = False
        try:
            client.get_login_profile(UserName=user_name)
            has_login_profile = True
        except ClientError as e:
            if e.response.get("Error", {}).get("Code") != "NoSuchEntity":
                logger.warning(f"Error checking login profile for {user_name}: {e}")

        if has_login_profile:
            try:
                mfa_devices = client.list_mfa_devices(UserName=user_name).get("MFADevices", [])
                if not mfa_devices:
                    findings.append(Finding(
                        service="IAM",
                        resource_id=user_name,
                        resource_type="AWS::IAM::User",
                        severity=Severity.HIGH.value,
                        title="IAM Console User Missing MFA Protection",
                        description=f"User '{user_name}' has password console access enabled without any registered MFA devices.",
                        remediation=f"Enforce MFA for user '{user_name}' using IAM MFA policies or register a virtual MFA authenticator.",
                        compliance_benchmark="CIS AWS Foundations v1.4.0 (1.6)",
                        region="global"
                    ))
            except ClientError as e:
                logger.warning(f"Error checking MFA devices for {user_name}: {e}")
        return findings

    def _check_access_keys(self, client, user_name: str) -> List[Finding]:
        findings = []
        now = datetime.now(timezone.utc)
        try:
            keys = client.list_access_keys(UserName=user_name).get("AccessKeyMetadata", [])
            for key in keys:
                if key.get("Status") == "Active":
                    create_date = key.get("CreateDate")
                    if create_date:
                        age_days = (now - create_date).days
                        if age_days > 90:
                            findings.append(Finding(
                                service="IAM",
                                resource_id=f"{user_name}:{key.get('AccessKeyId')}",
                                resource_type="AWS::IAM::AccessKey",
                                severity=Severity.MEDIUM.value,
                                title=f"IAM Access Key Unrotated for {age_days} Days (>90 Days)",
                                description=f"Access key '{key.get('AccessKeyId')}' for user '{user_name}' has not been rotated in {age_days} days.",
                                remediation=f"Create a new access key, update consuming applications, and delete key '{key.get('AccessKeyId')}'.",
                                compliance_benchmark="CIS AWS Foundations v1.4.0 (1.14)",
                                region="global"
                            ))
        except ClientError as e:
            logger.warning(f"Error checking access keys for {user_name}: {e}")
        return findings

    def _check_user_policies(self, client, user_name: str) -> List[Finding]:
        findings = []
        try:
            # Inline policies
            inline_policy_names = client.list_user_policies(UserName=user_name).get("PolicyNames", [])
            for pol_name in inline_policy_names:
                pol_doc = client.get_user_policy(UserName=user_name, PolicyName=pol_name).get("PolicyDocument", {})
                if isinstance(pol_doc, str):
                    pol_doc = json.loads(pol_doc)
                if self._has_admin_privileges(pol_doc):
                    findings.append(Finding(
                        service="IAM",
                        resource_id=f"{user_name}:{pol_name}",
                        resource_type="AWS::IAM::UserPolicy",
                        severity=Severity.HIGH.value,
                        title="IAM User Directly Granted Wildcard Administrative Privileges (*:*)",
                        description=f"User '{user_name}' has inline policy '{pol_name}' granting full admin rights (Action: *, Resource: *).",
                        remediation=f"Apply least privilege by attaching scoped managed policies to IAM groups rather than inline wildcard policies.",
                        compliance_benchmark="CIS AWS Foundations v1.4.0 (1.16)",
                        region="global"
                    ))
        except ClientError as e:
            logger.warning(f"Error checking policies for {user_name}: {e}")
        return findings

    def _has_admin_privileges(self, policy_doc: dict) -> bool:
        statements = policy_doc.get("Statement", [])
        if isinstance(statements, dict):
            statements = [statements]
        for stmt in statements:
            if stmt.get("Effect") == "Allow":
                actions = stmt.get("Action", [])
                resources = stmt.get("Resource", [])
                if actions == "*" and resources == "*":
                    return True
                if isinstance(actions, list) and "*" in actions and isinstance(resources, list) and "*" in resources:
                    return True
        return False

    def run_demo_scan(self) -> List[Finding]:
        return [
            Finding(
                service="IAM",
                resource_id="root",
                resource_type="AWS::IAM::RootAccount",
                severity=Severity.CRITICAL.value,
                title="AWS Root Account Missing Multi-Factor Authentication (MFA)",
                description="The AWS root account does not have virtual or hardware MFA activated.",
                remediation="Enable hardware or virtual MFA on the root account via the IAM console immediately.",
                compliance_benchmark="CIS AWS Foundations v1.4.0 (1.5)",
                region="global"
            ),
            Finding(
                service="IAM",
                resource_id="root",
                resource_type="AWS::IAM::RootAccount",
                severity=Severity.CRITICAL.value,
                title="Active Access Keys Present on AWS Root Account",
                description="Active API access key 'AKIAIOSFODNN7EXAMPLE' detected on the root account.",
                remediation="Delete root access keys and use IAM roles with least privilege instead.",
                compliance_benchmark="CIS AWS Foundations v1.4.0 (1.4)",
                region="global"
            ),
            Finding(
                service="IAM",
                resource_id="bhavya-dev",
                resource_type="AWS::IAM::User",
                severity=Severity.HIGH.value,
                title="IAM Console User Missing MFA Protection",
                description="User 'bhavya-dev' has console password access enabled without a configured MFA device.",
                remediation="Enforce MFA policy requiring authenticator app registration upon login.",
                compliance_benchmark="CIS AWS Foundations v1.4.0 (1.6)",
                region="global"
            ),
            Finding(
                service="IAM",
                resource_id="ci-deployer-svc:AKIA2LMNOPQRSTUVWXY",
                resource_type="AWS::IAM::AccessKey",
                severity=Severity.MEDIUM.value,
                title="IAM Access Key Unrotated for 184 Days (>90 Days)",
                description="Access key 'AKIA2LMNOPQRSTUVWXY' used by 'ci-deployer-svc' has exceeded the 90-day rotation compliance cycle.",
                remediation="Rotate access key by issuing a replacement key, verifying deployment pipelines, and deactivating the old key.",
                compliance_benchmark="CIS AWS Foundations v1.4.0 (1.14)",
                region="global"
            )
        ]
