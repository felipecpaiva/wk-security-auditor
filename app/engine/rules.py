"""Security rules engine for infrastructure configuration auditing."""

from dataclasses import dataclass


@dataclass
class RuleFinding:
    rule_id: str
    severity: str  # Critical, High, Medium, Low
    weight: int
    resource_type: str
    resource_name: str
    description: str
    remediation: str


# --- Terraform Rules ---

def check_s3_public_acl(resources: dict) -> list[RuleFinding]:
    """S3-001: S3 bucket with public ACL."""
    findings = []
    for name, config in resources.get("aws_s3_bucket", {}).items():
        acl = config.get("acl", "")
        if acl in ("public-read", "public-read-write", "authenticated-read"):
            findings.append(RuleFinding(
                rule_id="S3-001",
                severity="Critical",
                weight=10,
                resource_type="aws_s3_bucket",
                resource_name=name,
                description=f"S3 bucket '{name}' has public ACL '{acl}'. This exposes data to the internet.",
                remediation=f'Set acl = "private" on resource "{name}" or use aws_s3_bucket_acl with private access.',
            ))
    return findings


def check_s3_no_encryption(resources: dict) -> list[RuleFinding]:
    """S3-002: S3 bucket without server-side encryption."""
    findings = []
    for name, config in resources.get("aws_s3_bucket", {}).items():
        sse = config.get("server_side_encryption_configuration")
        if not sse:
            findings.append(RuleFinding(
                rule_id="S3-002",
                severity="High",
                weight=7,
                resource_type="aws_s3_bucket",
                resource_name=name,
                description=f"S3 bucket '{name}' has no server-side encryption configured.",
                remediation=f'Add server_side_encryption_configuration block with AES256 or aws:kms to "{name}".',
            ))
    return findings


def check_sg_ssh_open(resources: dict) -> list[RuleFinding]:
    """SG-001: Security group with SSH (port 22) open to 0.0.0.0/0."""
    findings = []
    for name, config in resources.get("aws_security_group", {}).items():
        ingress_rules = config.get("ingress", [])
        if isinstance(ingress_rules, dict):
            ingress_rules = [ingress_rules]
        for rule in ingress_rules:
            cidr = rule.get("cidr_blocks", [])
            if isinstance(cidr, str):
                cidr = [cidr]
            from_port = rule.get("from_port", 0)
            to_port = rule.get("to_port", 0)
            if "0.0.0.0/0" in cidr and _port_in_range(22, from_port, to_port):
                findings.append(RuleFinding(
                    rule_id="SG-001",
                    severity="Critical",
                    weight=10,
                    resource_type="aws_security_group",
                    resource_name=name,
                    description=f"Security group '{name}' allows SSH (port 22) from 0.0.0.0/0.",
                    remediation=f'Restrict SSH access in "{name}" to specific CIDR ranges (e.g., your office IP).',
                ))
    return findings


def check_sg_wide_open(resources: dict) -> list[RuleFinding]:
    """SG-002: Security group with any port open to 0.0.0.0/0."""
    findings = []
    for name, config in resources.get("aws_security_group", {}).items():
        ingress_rules = config.get("ingress", [])
        if isinstance(ingress_rules, dict):
            ingress_rules = [ingress_rules]
        for rule in ingress_rules:
            cidr = rule.get("cidr_blocks", [])
            if isinstance(cidr, str):
                cidr = [cidr]
            from_port = rule.get("from_port", 0)
            to_port = rule.get("to_port", 65535)
            if "0.0.0.0/0" in cidr and not (from_port == 22 and to_port == 22):
                findings.append(RuleFinding(
                    rule_id="SG-002",
                    severity="High",
                    weight=7,
                    resource_type="aws_security_group",
                    resource_name=name,
                    description=f"Security group '{name}' allows traffic on ports {from_port}-{to_port} from 0.0.0.0/0.",
                    remediation=f'Restrict ingress in "{name}" to specific CIDR blocks and required ports only.',
                ))
    return findings


def check_ec2_imdsv2(resources: dict) -> list[RuleFinding]:
    """EC2-001: EC2 instance without IMDSv2 enforced."""
    findings = []
    for name, config in resources.get("aws_instance", {}).items():
        metadata_options = config.get("metadata_options", {})
        http_tokens = metadata_options.get("http_tokens", "optional")
        if http_tokens != "required":
            findings.append(RuleFinding(
                rule_id="EC2-001",
                severity="Medium",
                weight=4,
                resource_type="aws_instance",
                resource_name=name,
                description=f"EC2 instance '{name}' does not enforce IMDSv2 (http_tokens != required).",
                remediation=f'Add metadata_options {{ http_tokens = "required" }} to instance "{name}".',
            ))
    return findings


def check_iam_wildcard(resources: dict) -> list[RuleFinding]:
    """IAM-001: IAM policy with wildcard actions."""
    findings = []
    for name, config in resources.get("aws_iam_policy", {}).items():
        policy_doc = config.get("policy", "")
        if isinstance(policy_doc, str) and '"Action": "*"' in policy_doc:
            findings.append(RuleFinding(
                rule_id="IAM-001",
                severity="Critical",
                weight=10,
                resource_type="aws_iam_policy",
                resource_name=name,
                description=f"IAM policy '{name}' grants wildcard Action '*'. This violates least privilege.",
                remediation=f'Scope down actions in policy "{name}" to only required permissions.',
            ))
        elif isinstance(policy_doc, dict):
            statements = policy_doc.get("Statement", [])
            for stmt in statements:
                action = stmt.get("Action", "")
                if action == "*" or (isinstance(action, list) and "*" in action):
                    findings.append(RuleFinding(
                        rule_id="IAM-001",
                        severity="Critical",
                        weight=10,
                        resource_type="aws_iam_policy",
                        resource_name=name,
                        description=f"IAM policy '{name}' grants wildcard Action '*'. This violates least privilege.",
                        remediation=f'Scope down actions in policy "{name}" to only required permissions.',
                    ))
                    break
    return findings


def check_rds_public(resources: dict) -> list[RuleFinding]:
    """RDS-001: RDS instance publicly accessible."""
    findings = []
    for name, config in resources.get("aws_db_instance", {}).items():
        if config.get("publicly_accessible", False) is True:
            findings.append(RuleFinding(
                rule_id="RDS-001",
                severity="Critical",
                weight=10,
                resource_type="aws_db_instance",
                resource_name=name,
                description=f"RDS instance '{name}' is publicly accessible.",
                remediation=f'Set publicly_accessible = false on RDS instance "{name}".',
            ))
    return findings


def check_rds_no_encryption(resources: dict) -> list[RuleFinding]:
    """RDS-002: RDS instance without encryption at rest."""
    findings = []
    for name, config in resources.get("aws_db_instance", {}).items():
        if config.get("storage_encrypted", False) is not True:
            findings.append(RuleFinding(
                rule_id="RDS-002",
                severity="High",
                weight=7,
                resource_type="aws_db_instance",
                resource_name=name,
                description=f"RDS instance '{name}' does not have encryption at rest enabled.",
                remediation=f'Set storage_encrypted = true on RDS instance "{name}".',
            ))
    return findings


def check_cloudtrail_disabled(resources: dict) -> list[RuleFinding]:
    """LOG-001: CloudTrail not enabled (no aws_cloudtrail resource found)."""
    findings = []
    if "aws_cloudtrail" not in resources or len(resources.get("aws_cloudtrail", {})) == 0:
        aws_resource_types = [k for k in resources if k.startswith("aws_")]
        if aws_resource_types:
            findings.append(RuleFinding(
                rule_id="LOG-001",
                severity="High",
                weight=7,
                resource_type="aws_cloudtrail",
                resource_name="(missing)",
                description="No CloudTrail resource found. AWS API activity is not being logged.",
                remediation="Add an aws_cloudtrail resource to enable API activity logging.",
            ))
    return findings


def check_ebs_no_encryption(resources: dict) -> list[RuleFinding]:
    """EBS-001: EBS volume without encryption."""
    findings = []
    for name, config in resources.get("aws_ebs_volume", {}).items():
        if config.get("encrypted", False) is not True:
            findings.append(RuleFinding(
                rule_id="EBS-001",
                severity="Medium",
                weight=4,
                resource_type="aws_ebs_volume",
                resource_name=name,
                description=f"EBS volume '{name}' is not encrypted.",
                remediation=f'Set encrypted = true on EBS volume "{name}".',
            ))
    return findings


# --- CloudFormation Rules ---

def check_cf_s3_public(resources: dict) -> list[RuleFinding]:
    """S3-001 (CF): S3 bucket with public access."""
    findings = []
    for name, resource in resources.items():
        if resource.get("Type") != "AWS::S3::Bucket":
            continue
        props = resource.get("Properties", {})
        access_control = props.get("AccessControl", "")
        if access_control in ("PublicRead", "PublicReadWrite", "AuthenticatedRead"):
            findings.append(RuleFinding(
                rule_id="S3-001",
                severity="Critical",
                weight=10,
                resource_type="AWS::S3::Bucket",
                resource_name=name,
                description=f"S3 bucket '{name}' has public AccessControl '{access_control}'.",
                remediation=f'Remove AccessControl or set to "Private" on bucket "{name}".',
            ))
    return findings


def check_cf_s3_no_encryption(resources: dict) -> list[RuleFinding]:
    """S3-002 (CF): S3 bucket without encryption."""
    findings = []
    for name, resource in resources.items():
        if resource.get("Type") != "AWS::S3::Bucket":
            continue
        props = resource.get("Properties", {})
        encryption = props.get("BucketEncryption")
        if not encryption:
            findings.append(RuleFinding(
                rule_id="S3-002",
                severity="High",
                weight=7,
                resource_type="AWS::S3::Bucket",
                resource_name=name,
                description=f"S3 bucket '{name}' has no encryption configured.",
                remediation=f'Add BucketEncryption with SSEAlgorithm "aws:kms" or "AES256" to "{name}".',
            ))
    return findings


def check_cf_sg_ssh_open(resources: dict) -> list[RuleFinding]:
    """SG-001 (CF): Security group with SSH open to 0.0.0.0/0."""
    findings = []
    for name, resource in resources.items():
        if resource.get("Type") != "AWS::EC2::SecurityGroup":
            continue
        props = resource.get("Properties", {})
        for rule in props.get("SecurityGroupIngress", []):
            cidr = rule.get("CidrIp", "")
            from_port = rule.get("FromPort", 0)
            to_port = rule.get("ToPort", 0)
            if cidr == "0.0.0.0/0" and _port_in_range(22, from_port, to_port):
                findings.append(RuleFinding(
                    rule_id="SG-001",
                    severity="Critical",
                    weight=10,
                    resource_type="AWS::EC2::SecurityGroup",
                    resource_name=name,
                    description=f"Security group '{name}' allows SSH (port 22) from 0.0.0.0/0.",
                    remediation=f'Restrict SSH CIDR in "{name}" to trusted IP ranges.',
                ))
    return findings


def check_cf_sg_wide_open(resources: dict) -> list[RuleFinding]:
    """SG-002 (CF): Security group with any port open to 0.0.0.0/0."""
    findings = []
    for name, resource in resources.items():
        if resource.get("Type") != "AWS::EC2::SecurityGroup":
            continue
        props = resource.get("Properties", {})
        for rule in props.get("SecurityGroupIngress", []):
            cidr = rule.get("CidrIp", "")
            from_port = rule.get("FromPort", 0)
            to_port = rule.get("ToPort", 65535)
            if cidr == "0.0.0.0/0" and not (from_port == 22 and to_port == 22):
                findings.append(RuleFinding(
                    rule_id="SG-002",
                    severity="High",
                    weight=7,
                    resource_type="AWS::EC2::SecurityGroup",
                    resource_name=name,
                    description=f"Security group '{name}' allows ports {from_port}-{to_port} from 0.0.0.0/0.",
                    remediation=f'Restrict ingress in "{name}" to required ports and trusted CIDRs.',
                ))
    return findings


def check_cf_rds_public(resources: dict) -> list[RuleFinding]:
    """RDS-001 (CF): RDS publicly accessible."""
    findings = []
    for name, resource in resources.items():
        if resource.get("Type") != "AWS::RDS::DBInstance":
            continue
        props = resource.get("Properties", {})
        if props.get("PubliclyAccessible", False) is True:
            findings.append(RuleFinding(
                rule_id="RDS-001",
                severity="Critical",
                weight=10,
                resource_type="AWS::RDS::DBInstance",
                resource_name=name,
                description=f"RDS instance '{name}' is publicly accessible.",
                remediation=f'Set PubliclyAccessible to false on "{name}".',
            ))
    return findings


def check_cf_rds_no_encryption(resources: dict) -> list[RuleFinding]:
    """RDS-002 (CF): RDS without encryption."""
    findings = []
    for name, resource in resources.items():
        if resource.get("Type") != "AWS::RDS::DBInstance":
            continue
        props = resource.get("Properties", {})
        if props.get("StorageEncrypted", False) is not True:
            findings.append(RuleFinding(
                rule_id="RDS-002",
                severity="High",
                weight=7,
                resource_type="AWS::RDS::DBInstance",
                resource_name=name,
                description=f"RDS instance '{name}' does not have encryption at rest.",
                remediation=f'Set StorageEncrypted to true on "{name}".',
            ))
    return findings


def check_cf_iam_wildcard(resources: dict) -> list[RuleFinding]:
    """IAM-001 (CF): IAM policy with wildcard actions."""
    findings = []
    for name, resource in resources.items():
        if resource.get("Type") not in ("AWS::IAM::Policy", "AWS::IAM::ManagedPolicy", "AWS::IAM::Role"):
            continue
        props = resource.get("Properties", {})
        policies = props.get("Policies", [props]) if "PolicyDocument" not in props else [props]
        for policy in policies:
            doc = policy.get("PolicyDocument", {})
            for stmt in doc.get("Statement", []):
                action = stmt.get("Action", "")
                if action == "*" or (isinstance(action, list) and "*" in action):
                    findings.append(RuleFinding(
                        rule_id="IAM-001",
                        severity="Critical",
                        weight=10,
                        resource_type=resource.get("Type", "AWS::IAM::Policy"),
                        resource_name=name,
                        description=f"IAM resource '{name}' grants wildcard Action '*'.",
                        remediation=f'Scope down actions in "{name}" to least privilege.',
                    ))
                    break
    return findings


# --- Helpers ---

def _port_in_range(port: int, from_port, to_port) -> bool:
    """Check if a port falls within a range."""
    try:
        return int(from_port) <= port <= int(to_port)
    except (ValueError, TypeError):
        return False


# --- Rule Registry ---

TERRAFORM_RULES = [
    check_s3_public_acl,
    check_s3_no_encryption,
    check_sg_ssh_open,
    check_sg_wide_open,
    check_ec2_imdsv2,
    check_iam_wildcard,
    check_rds_public,
    check_rds_no_encryption,
    check_cloudtrail_disabled,
    check_ebs_no_encryption,
]

CLOUDFORMATION_RULES = [
    check_cf_s3_public,
    check_cf_s3_no_encryption,
    check_cf_sg_ssh_open,
    check_cf_sg_wide_open,
    check_cf_rds_public,
    check_cf_rds_no_encryption,
    check_cf_iam_wildcard,
]
