import logging
from typing import List
from botocore.exceptions import ClientError

from models.finding import Finding, Severity
from scanners.base_scanner import BaseScanner

logger = logging.getLogger("CloudSentinel.RDSScanner")

# Common default master usernames that signal poor credential hygiene
DEFAULT_MASTER_USERNAMES = {"admin", "administrator", "root", "postgres", "mysql", "oracle", "dbadmin", "dbuser", "sa", "master"}

# Minimum backup retention days considered compliant
MIN_BACKUP_RETENTION_DAYS = 7


class RDSScanner(BaseScanner):
    """Scanner for detecting security misconfigurations in AWS RDS DB instances and clusters."""

    def run_scan(self) -> List[Finding]:
        findings = []
        client = self.get_client("rds")
        if not client:
            return findings

        try:
            paginator = client.get_paginator("describe_db_instances")
            for page in paginator.paginate():
                for db in page.get("DBInstances", []):
                    db_id = db.get("DBInstanceIdentifier", "unknown")
                    logger.info(f"Scanning RDS Instance: {db_id}")
                    findings.extend(self._check_encryption_at_rest(db))
                    findings.extend(self._check_public_accessibility(db))
                    findings.extend(self._check_backup_retention(db))
                    findings.extend(self._check_default_master_username(db))
                    findings.extend(self._check_multi_az(db))
        except ClientError as e:
            logger.error(f"Failed to describe RDS DB instances: {e}")

        return findings

    def _check_encryption_at_rest(self, db: dict) -> List[Finding]:
        findings = []
        db_id = db.get("DBInstanceIdentifier")
        db_engine = db.get("Engine", "unknown")
        db_class = db.get("DBInstanceClass", "unknown")
        storage_encrypted = db.get("StorageEncrypted", False)

        if not storage_encrypted:
            findings.append(Finding(
                service="RDS",
                resource_id=db_id,
                resource_type="AWS::RDS::DBInstance",
                severity=Severity.HIGH.value,
                title=f"RDS Instance '{db_id}' Storage Is Not Encrypted at Rest",
                description=(
                    f"RDS DB instance '{db_id}' (Engine: {db_engine}, Class: {db_class}) does not have storage "
                    f"encryption enabled. Unencrypted storage exposes sensitive database records if the underlying "
                    f"EBS storage or snapshots are compromised."
                ),
                remediation=(
                    f"RDS encryption can only be enabled at creation time. To encrypt: snapshot the instance, "
                    f"copy the snapshot with encryption enabled (KMS key), then restore a new instance from the "
                    f"encrypted snapshot and update your connection strings. "
                    f"CLI: aws rds copy-db-snapshot --source-db-snapshot-identifier <snapshot-id> "
                    f"--target-db-snapshot-identifier {db_id}-encrypted-snap --kms-key-id alias/aws/rds"
                ),
                compliance_benchmark="CIS AWS Foundations v1.4.0 (2.3.1)",
                region=self.region_name
            ))
        return findings

    def _check_public_accessibility(self, db: dict) -> List[Finding]:
        findings = []
        db_id = db.get("DBInstanceIdentifier")
        db_engine = db.get("Engine", "unknown")
        publicly_accessible = db.get("PubliclyAccessible", False)
        endpoint = db.get("Endpoint", {}).get("Address", "N/A")

        if publicly_accessible:
            findings.append(Finding(
                service="RDS",
                resource_id=db_id,
                resource_type="AWS::RDS::DBInstance",
                severity=Severity.CRITICAL.value,
                title=f"RDS Instance '{db_id}' Is Publicly Accessible from the Internet",
                description=(
                    f"RDS DB instance '{db_id}' (Engine: {db_engine}) has 'PubliclyAccessible' set to true "
                    f"with endpoint '{endpoint}'. The database is reachable from any IP address on the internet, "
                    f"dramatically increasing the attack surface for credential stuffing, SQLi, and zero-days."
                ),
                remediation=(
                    f"Disable public accessibility: aws rds modify-db-instance "
                    f"--db-instance-identifier {db_id} --no-publicly-accessible --apply-immediately. "
                    f"Place the instance inside a private VPC subnet and use a bastion host, "
                    f"AWS Systems Manager Session Manager, or RDS Proxy for application access."
                ),
                compliance_benchmark="CIS AWS Foundations v1.4.0 (2.3.2)",
                region=self.region_name
            ))
        return findings

    def _check_backup_retention(self, db: dict) -> List[Finding]:
        findings = []
        db_id = db.get("DBInstanceIdentifier")
        db_engine = db.get("Engine", "unknown")
        retention_days = db.get("BackupRetentionPeriod", 0)

        if retention_days == 0:
            findings.append(Finding(
                service="RDS",
                resource_id=db_id,
                resource_type="AWS::RDS::DBInstance",
                severity=Severity.HIGH.value,
                title=f"RDS Instance '{db_id}' Has Automated Backups Completely Disabled",
                description=(
                    f"RDS DB instance '{db_id}' (Engine: {db_engine}) has automated backups disabled "
                    f"(BackupRetentionPeriod = 0). With no automated backups, point-in-time recovery is "
                    f"impossible and data loss in the event of accidental deletion or corruption is permanent."
                ),
                remediation=(
                    f"Enable automated backups with a minimum 7-day retention: "
                    f"aws rds modify-db-instance --db-instance-identifier {db_id} "
                    f"--backup-retention-period 7 --preferred-backup-window 03:00-04:00 --apply-immediately"
                ),
                compliance_benchmark="AWS Well-Architected Security Pillar (REL-09)",
                region=self.region_name
            ))
        elif retention_days < MIN_BACKUP_RETENTION_DAYS:
            findings.append(Finding(
                service="RDS",
                resource_id=db_id,
                resource_type="AWS::RDS::DBInstance",
                severity=Severity.MEDIUM.value,
                title=f"RDS Instance '{db_id}' Has Insufficient Backup Retention ({retention_days} days < 7)",
                description=(
                    f"RDS DB instance '{db_id}' (Engine: {db_engine}) has automated backups configured with "
                    f"only {retention_days} day(s) of retention. Best practices recommend at least 7 days "
                    f"to enable adequate point-in-time recovery and meet most compliance mandates."
                ),
                remediation=(
                    f"Increase backup retention to at least 7 days: "
                    f"aws rds modify-db-instance --db-instance-identifier {db_id} "
                    f"--backup-retention-period 7 --apply-immediately"
                ),
                compliance_benchmark="CIS AWS Foundations v1.4.0 (2.3.3)",
                region=self.region_name
            ))
        return findings

    def _check_default_master_username(self, db: dict) -> List[Finding]:
        findings = []
        db_id = db.get("DBInstanceIdentifier")
        db_engine = db.get("Engine", "unknown")
        master_username = db.get("MasterUsername", "")

        if master_username.lower() in DEFAULT_MASTER_USERNAMES:
            findings.append(Finding(
                service="RDS",
                resource_id=db_id,
                resource_type="AWS::RDS::DBInstance",
                severity=Severity.MEDIUM.value,
                title=f"RDS Instance '{db_id}' Uses Default Master Username '{master_username}'",
                description=(
                    f"RDS DB instance '{db_id}' (Engine: {db_engine}) is configured with the predictable "
                    f"master username '{master_username}'. Default usernames are the first guess in brute-force "
                    f"and credential stuffing attacks, reducing the effective difficulty of unauthorized access."
                ),
                remediation=(
                    f"Create a new database user with a strong, unique name and full privileges, "
                    f"then remove or restrict the '{master_username}' superuser account where the DB engine allows. "
                    f"For new instances, specify a non-default master username at creation time via: "
                    f"aws rds create-db-instance --master-username <unique-name> ..."
                ),
                compliance_benchmark="AWS Well-Architected Security Pillar (SEC-02)",
                region=self.region_name
            ))
        return findings

    def _check_multi_az(self, db: dict) -> List[Finding]:
        findings = []
        db_id = db.get("DBInstanceIdentifier")
        db_engine = db.get("Engine", "unknown")
        db_class = db.get("DBInstanceClass", "")
        multi_az = db.get("MultiAZ", False)
        db_status = db.get("DBInstanceStatus", "")

        # Only flag running, non-aurora instances (Aurora clusters handle HA separately)
        is_aurora = db_engine.startswith("aurora")
        is_running = db_status == "available"

        if not is_aurora and is_running and not multi_az:
            findings.append(Finding(
                service="RDS",
                resource_id=db_id,
                resource_type="AWS::RDS::DBInstance",
                severity=Severity.LOW.value,
                title=f"RDS Instance '{db_id}' Is Not Configured for Multi-AZ High Availability",
                description=(
                    f"RDS DB instance '{db_id}' (Engine: {db_engine}, Class: {db_class}) does not have "
                    f"Multi-AZ deployment enabled. Single-AZ instances are vulnerable to availability zone "
                    f"outages, hardware failures, and maintenance-window downtime with no automatic failover."
                ),
                remediation=(
                    f"Enable Multi-AZ for automatic failover: "
                    f"aws rds modify-db-instance --db-instance-identifier {db_id} "
                    f"--multi-az --apply-immediately. "
                    f"Note: this triggers a brief failover on next maintenance window."
                ),
                compliance_benchmark="AWS Well-Architected Reliability Pillar (REL-06)",
                region=self.region_name
            ))
        return findings

    def run_demo_scan(self) -> List[Finding]:
        return [
            Finding(
                service="RDS",
                resource_id="prod-mysql-primary",
                resource_type="AWS::RDS::DBInstance",
                severity=Severity.CRITICAL.value,
                title="RDS Instance 'prod-mysql-primary' Is Publicly Accessible from the Internet",
                description=(
                    "RDS DB instance 'prod-mysql-primary' (Engine: mysql 8.0, Class: db.r6g.large) has "
                    "'PubliclyAccessible' set to true with endpoint 'prod-mysql-primary.abc123.us-east-1.rds.amazonaws.com'. "
                    "The database is reachable from any IP on the internet, exposing customer PII to brute-force attacks."
                ),
                remediation=(
                    "Disable public accessibility: aws rds modify-db-instance "
                    "--db-instance-identifier prod-mysql-primary --no-publicly-accessible --apply-immediately. "
                    "Place the instance in a private subnet group and use RDS Proxy for application connectivity."
                ),
                compliance_benchmark="CIS AWS Foundations v1.4.0 (2.3.2)",
                region=self.region_name
            ),
            Finding(
                service="RDS",
                resource_id="analytics-postgres-replica",
                resource_type="AWS::RDS::DBInstance",
                severity=Severity.HIGH.value,
                title="RDS Instance 'analytics-postgres-replica' Storage Is Not Encrypted at Rest",
                description=(
                    "RDS DB instance 'analytics-postgres-replica' (Engine: postgres 15.3, Class: db.t3.medium) "
                    "does not have storage encryption enabled. The analytics database contains sensitive business "
                    "intelligence data that is vulnerable to exposure through snapshot exfiltration."
                ),
                remediation=(
                    "Snapshot the instance, copy the snapshot with --kms-key-id alias/aws/rds to create an "
                    "encrypted copy, then restore a new instance. Update application connection strings accordingly."
                ),
                compliance_benchmark="CIS AWS Foundations v1.4.0 (2.3.1)",
                region=self.region_name
            ),
            Finding(
                service="RDS",
                resource_id="dev-mysql-scratch",
                resource_type="AWS::RDS::DBInstance",
                severity=Severity.HIGH.value,
                title="RDS Instance 'dev-mysql-scratch' Has Automated Backups Completely Disabled",
                description=(
                    "RDS DB instance 'dev-mysql-scratch' (Engine: mysql 8.0) has automated backups disabled "
                    "(BackupRetentionPeriod = 0). Without backups, any data loss event — accidental deletion, "
                    "corruption, or ransomware — is permanent and unrecoverable."
                ),
                remediation=(
                    "Enable automated backups: aws rds modify-db-instance "
                    "--db-instance-identifier dev-mysql-scratch "
                    "--backup-retention-period 7 --preferred-backup-window 03:00-04:00 --apply-immediately"
                ),
                compliance_benchmark="AWS Well-Architected Security Pillar (REL-09)",
                region=self.region_name
            ),
            Finding(
                service="RDS",
                resource_id="staging-postgres-db",
                resource_type="AWS::RDS::DBInstance",
                severity=Severity.MEDIUM.value,
                title="RDS Instance 'staging-postgres-db' Uses Default Master Username 'admin'",
                description=(
                    "RDS DB instance 'staging-postgres-db' (Engine: postgres 15.3) is using the default master "
                    "username 'admin'. Predictable usernames reduce the complexity of credential-based attacks "
                    "and violate the principle of least-obvious identity."
                ),
                remediation=(
                    "Create a dedicated application database user with scoped privileges. "
                    "Avoid reusing default usernames for any new RDS instances."
                ),
                compliance_benchmark="AWS Well-Architected Security Pillar (SEC-02)",
                region=self.region_name
            ),
            Finding(
                service="RDS",
                resource_id="reporting-sqlserver-01",
                resource_type="AWS::RDS::DBInstance",
                severity=Severity.LOW.value,
                title="RDS Instance 'reporting-sqlserver-01' Is Not Configured for Multi-AZ High Availability",
                description=(
                    "RDS DB instance 'reporting-sqlserver-01' (Engine: sqlserver-se 15.00, Class: db.m5.xlarge) "
                    "has Multi-AZ disabled. A single-AZ failure or hardware fault will cause unplanned downtime "
                    "with no automatic failover for this business-critical reporting database."
                ),
                remediation=(
                    "Enable Multi-AZ: aws rds modify-db-instance "
                    "--db-instance-identifier reporting-sqlserver-01 --multi-az --apply-immediately"
                ),
                compliance_benchmark="AWS Well-Architected Reliability Pillar (REL-06)",
                region=self.region_name
            )
        ]
