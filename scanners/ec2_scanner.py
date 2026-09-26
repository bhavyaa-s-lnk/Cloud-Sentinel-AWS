import logging
from typing import List
from botocore.exceptions import ClientError

from models.finding import Finding, Severity
from scanners.base_scanner import BaseScanner

logger = logging.getLogger("CloudSentinel.EC2Scanner")

SENSITIVE_PORTS = {
    22: ("SSH", Severity.CRITICAL.value, "CIS AWS Foundations v1.4.0 (5.2)"),
    3389: ("RDP", Severity.CRITICAL.value, "CIS AWS Foundations v1.4.0 (5.3)"),
    3306: ("MySQL Database", Severity.HIGH.value, "AWS Well-Architected Security Pillar"),
    5432: ("PostgreSQL Database", Severity.HIGH.value, "AWS Well-Architected Security Pillar"),
    27017: ("MongoDB Database", Severity.HIGH.value, "AWS Well-Architected Security Pillar"),
    6379: ("Redis Cache", Severity.HIGH.value, "AWS Well-Architected Security Pillar"),
    1433: ("MSSQL Database", Severity.HIGH.value, "AWS Well-Architected Security Pillar"),
}


class EC2Scanner(BaseScanner):
    """Scanner for detecting compute and network misconfigurations in AWS EC2 and VPC."""

    def run_scan(self) -> List[Finding]:
        findings = []
        client = self.get_client("ec2")
        if not client:
            return findings

        findings.extend(self._check_security_groups(client))
        findings.extend(self._check_ebs_encryption(client))
        findings.extend(self._check_public_instances(client))
        return findings

    def _check_security_groups(self, client) -> List[Finding]:
        findings = []
        try:
            paginator = client.get_paginator("describe_security_groups")
            for page in paginator.paginate():
                for sg in page.get("SecurityGroups", []):
                    sg_id = sg.get("GroupId")
                    sg_name = sg.get("GroupName")
                    logger.info(f"Scanning Security Group: {sg_name} ({sg_id})")

                    for perm in sg.get("IpPermissions", []):
                        from_port = perm.get("FromPort")
                        to_port = perm.get("ToPort")
                        ip_proto = perm.get("IpProtocol")

                        ip_ranges = [r.get("CidrIp") for r in perm.get("IpRanges", [])]
                        ipv6_ranges = [r.get("CidrIpv6") for r in perm.get("Ipv6Ranges", [])]
                        all_cidrs = ip_ranges + ipv6_ranges

                        is_open_to_world = "0.0.0.0/0" in all_cidrs or "::/0" in all_cidrs
                        if not is_open_to_world:
                            continue

                        # Check for all traffic open
                        if ip_proto == "-1" or (from_port == 0 and to_port == 65535):
                            findings.append(Finding(
                                service="EC2",
                                resource_id=sg_id,
                                resource_type="AWS::EC2::SecurityGroup",
                                severity=Severity.CRITICAL.value,
                                title=f"Security Group '{sg_name}' Allows ALL Inbound Traffic from Anywhere",
                                description=f"Security Group '{sg_name}' ({sg_id}) allows unrestricted inbound traffic across all protocols from 0.0.0.0/0 or ::/0.",
                                remediation=f"Revoke full open ingress rule: aws ec2 revoke-security-group-ingress --group-id {sg_id} --protocol all --cidr 0.0.0.0/0",
                                compliance_benchmark="AWS Well-Architected Security Pillar (SEC-05)",
                                region=self.region_name
                            ))
                            continue

                        # Check sensitive ports
                        for port, (name, severity, benchmark) in SENSITIVE_PORTS.items():
                            if from_port is not None and to_port is not None:
                                if from_port <= port <= to_port:
                                    findings.append(Finding(
                                        service="EC2",
                                        resource_id=sg_id,
                                        resource_type="AWS::EC2::SecurityGroup",
                                        severity=severity,
                                        title=f"Security Group '{sg_name}' Exposes {name} (Port {port}) to the Internet",
                                        description=f"Security group '{sg_name}' ({sg_id}) has ingress rule allowing 0.0.0.0/0 or ::/0 on port {port} ({name}).",
                                        remediation=f"Restrict inbound access for port {port} to a specific corporate VPN CIDR or bastion host IP range: aws ec2 revoke-security-group-ingress --group-id {sg_id} --protocol tcp --port {port} --cidr 0.0.0.0/0",
                                        compliance_benchmark=benchmark,
                                        region=self.region_name
                                    ))
        except ClientError as e:
            logger.error(f"Error checking security groups: {e}")
        return findings

    def _check_ebs_encryption(self, client) -> List[Finding]:
        findings = []
        try:
            paginator = client.get_paginator("describe_volumes")
            for page in paginator.paginate():
                for vol in page.get("Volumes", []):
                    vol_id = vol.get("VolumeId")
                    encrypted = vol.get("Encrypted", False)
                    size = vol.get("Size")
                    vol_type = vol.get("VolumeType")

                    if not encrypted:
                        findings.append(Finding(
                            service="EC2",
                            resource_id=vol_id,
                            resource_type="AWS::EC2::Volume",
                            severity=Severity.HIGH.value,
                            title=f"EBS Volume '{vol_id}' is Not Encrypted at Rest",
                            description=f"Volume '{vol_id}' ({size} GB {vol_type}) does not have EBS encryption enabled. Data is vulnerable if physical media or snapshots are compromised.",
                            remediation="Enable default EBS encryption on the AWS account/region and migrate unencrypted volumes using snapshot copy with encryption.",
                            compliance_benchmark="CIS AWS Foundations v1.4.0 (2.2.1)",
                            region=self.region_name
                        ))
        except ClientError as e:
            logger.error(f"Error checking EBS volumes: {e}")
        return findings

    def _check_public_instances(self, client) -> List[Finding]:
        findings = []
        try:
            paginator = client.get_paginator("describe_instances")
            for page in paginator.paginate():
                for res in page.get("Reservations", []):
                    for inst in res.get("Instances", []):
                        if inst.get("State", {}).get("Name") != "running":
                            continue
                        inst_id = inst.get("InstanceId")
                        public_ip = inst.get("PublicIpAddress")
                        if public_ip:
                            findings.append(Finding(
                                service="EC2",
                                resource_id=inst_id,
                                resource_type="AWS::EC2::Instance",
                                severity=Severity.MEDIUM.value,
                                title=f"EC2 Instance '{inst_id}' Has Direct Public IP Address ({public_ip})",
                                description=f"Instance '{inst_id}' is running with a publicly routable IP address ({public_ip}). Applications should preferably sit behind an Application Load Balancer inside private subnets.",
                                remediation="Place instance in private subnet and route egress via NAT Gateway or ingress via AWS Application Load Balancer.",
                                compliance_benchmark="AWS Well-Architected Framework Reliability Pillar",
                                region=self.region_name
                            ))
        except ClientError as e:
            logger.error(f"Error checking EC2 instances: {e}")
        return findings

    def run_demo_scan(self) -> List[Finding]:
        return [
            Finding(
                service="EC2",
                resource_id="sg-04a1b2c3d4e5f6078",
                resource_type="AWS::EC2::SecurityGroup",
                severity=Severity.CRITICAL.value,
                title="Security Group 'bastion-sg' Exposes SSH (Port 22) to the Internet",
                description="Security group 'bastion-sg' (sg-04a1b2c3d4e5f6078) allows inbound SSH (TCP/22) from 0.0.0.0/0, permitting brute-force and zero-day exposure.",
                remediation="Execute: aws ec2 revoke-security-group-ingress --group-id sg-04a1b2c3d4e5f6078 --protocol tcp --port 22 --cidr 0.0.0.0/0",
                compliance_benchmark="CIS AWS Foundations v1.4.0 (5.2)",
                region=self.region_name
            ),
            Finding(
                service="EC2",
                resource_id="sg-098f6bcd4621d373c",
                resource_type="AWS::EC2::SecurityGroup",
                severity=Severity.HIGH.value,
                title="Security Group 'db-replica-sg' Exposes PostgreSQL Database (Port 5432) to the Internet",
                description="Security group 'db-replica-sg' (sg-098f6bcd4621d373c) allows ingress on TCP/5432 from 0.0.0.0/0, exposing backend database directly.",
                remediation="Restrict PostgreSQL port 5432 ingress to backend app security group ID: sg-app-tier.",
                compliance_benchmark="AWS Well-Architected Security Pillar (SEC-05)",
                region=self.region_name
            ),
            Finding(
                service="EC2",
                resource_id="vol-0e318991b1a9e8d42",
                resource_type="AWS::EC2::Volume",
                severity=Severity.HIGH.value,
                title="EBS Volume 'vol-0e318991b1a9e8d42' is Not Encrypted at Rest",
                description="Attached root volume 'vol-0e318991b1a9e8d42' (80 GB gp3) does not have EBS encryption enabled.",
                remediation="Snapshot volume, create encrypted copy with KMS key, and replace root volume.",
                compliance_benchmark="CIS AWS Foundations v1.4.0 (2.2.1)",
                region=self.region_name
            ),
            Finding(
                service="EC2",
                resource_id="i-0589a19c67e810f22",
                resource_type="AWS::EC2::Instance",
                severity=Severity.MEDIUM.value,
                title="EC2 Instance 'i-0589a19c67e810f22' Has Direct Public IP Address (54.210.12.89)",
                description="EC2 instance is directly reachable via public IP 54.210.12.89 without WAF or API Gateway perimeter shielding.",
                remediation="Relocate instance to a private subnet behind an Application Load Balancer with AWS WAF enabled.",
                compliance_benchmark="AWS Well-Architected Framework Reliability Pillar",
                region=self.region_name
            )
        ]
