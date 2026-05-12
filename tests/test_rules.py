"""Tests for the security rules engine.

Covers all 10 Terraform rules + 7 CloudFormation rules + _port_in_range helper.
Each rule tested for: fires when misconfigured, does NOT fire when correct, edge case.
~60 tests total.
"""

from app.engine.rules import (
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
    check_cf_s3_public,
    check_cf_s3_no_encryption,
    check_cf_sg_ssh_open,
    check_cf_sg_wide_open,
    check_cf_rds_public,
    check_cf_rds_no_encryption,
    check_cf_iam_wildcard,
    _port_in_range,
)


# ══════════════════════════════════════════════
# Helper: _port_in_range
# ══════════════════════════════════════════════

class TestPortInRange:
    def test_port_exact_match(self):
        assert _port_in_range(22, 22, 22) is True

    def test_port_within_range(self):
        assert _port_in_range(22, 0, 65535) is True

    def test_port_outside_range(self):
        assert _port_in_range(22, 80, 443) is False

    def test_port_invalid_values(self):
        """Non-numeric ports → False (no crash)."""
        assert _port_in_range(22, "abc", "def") is False


# ══════════════════════════════════════════════
# Terraform Rules
# ══════════════════════════════════════════════

# --- S3-001: Public ACL ---

class TestS3PublicAcl:
    def test_fires_on_public_read(self):
        resources = {"aws_s3_bucket": {"bad": {"acl": "public-read"}}}
        findings = check_s3_public_acl(resources)
        assert len(findings) == 1
        assert findings[0].rule_id == "S3-001"
        assert findings[0].severity == "Critical"
        assert findings[0].weight == 10

    def test_fires_on_public_read_write(self):
        resources = {"aws_s3_bucket": {"bad": {"acl": "public-read-write"}}}
        assert len(check_s3_public_acl(resources)) == 1

    def test_fires_on_authenticated_read(self):
        resources = {"aws_s3_bucket": {"bad": {"acl": "authenticated-read"}}}
        assert len(check_s3_public_acl(resources)) == 1

    def test_silent_on_private(self):
        resources = {"aws_s3_bucket": {"good": {"acl": "private"}}}
        assert len(check_s3_public_acl(resources)) == 0

    def test_silent_on_no_buckets(self):
        assert len(check_s3_public_acl({})) == 0

    def test_multiple_buckets_2_public_1_private(self):
        """3 S3 buckets (2 public + 1 private) → exactly 2 findings."""
        resources = {"aws_s3_bucket": {
            "bad1": {"acl": "public-read"},
            "bad2": {"acl": "public-read-write"},
            "good": {"acl": "private"},
        }}
        findings = check_s3_public_acl(resources)
        assert len(findings) == 2


# --- S3-002: No Encryption ---

class TestS3NoEncryption:
    def test_fires_when_no_encryption(self):
        resources = {"aws_s3_bucket": {"unenc": {"acl": "private"}}}
        findings = check_s3_no_encryption(resources)
        assert len(findings) == 1
        assert findings[0].rule_id == "S3-002"
        assert findings[0].severity == "High"

    def test_silent_when_encrypted(self):
        resources = {"aws_s3_bucket": {"enc": {
            "server_side_encryption_configuration": {"rule": {}}
        }}}
        assert len(check_s3_no_encryption(resources)) == 0

    def test_fires_when_no_acl_key_at_all(self):
        """Bucket with no acl and no encryption → still flagged for encryption."""
        resources = {"aws_s3_bucket": {"minimal": {}}}
        assert len(check_s3_no_encryption(resources)) == 1


# --- SG-001: SSH Open ---

class TestSgSshOpen:
    def test_fires_on_ssh_to_world(self):
        resources = {"aws_security_group": {"sg": {
            "ingress": {"from_port": 22, "to_port": 22, "cidr_blocks": ["0.0.0.0/0"]}
        }}}
        findings = check_sg_ssh_open(resources)
        assert len(findings) == 1
        assert findings[0].rule_id == "SG-001"
        assert findings[0].severity == "Critical"

    def test_silent_on_restricted_cidr(self):
        resources = {"aws_security_group": {"sg": {
            "ingress": {"from_port": 22, "to_port": 22, "cidr_blocks": ["10.0.0.0/8"]}
        }}}
        assert len(check_sg_ssh_open(resources)) == 0

    def test_silent_on_non_ssh_port(self):
        resources = {"aws_security_group": {"sg": {
            "ingress": {"from_port": 443, "to_port": 443, "cidr_blocks": ["0.0.0.0/0"]}
        }}}
        assert len(check_sg_ssh_open(resources)) == 0

    def test_fires_when_ssh_in_wide_range(self):
        """Port 22 within 0-65535 range open to world → fires."""
        resources = {"aws_security_group": {"sg": {
            "ingress": {"from_port": 0, "to_port": 65535, "cidr_blocks": ["0.0.0.0/0"]}
        }}}
        assert len(check_sg_ssh_open(resources)) == 1

    def test_handles_cidr_as_string(self):
        """Some Terraform configs have cidr_blocks as a string, not a list."""
        resources = {"aws_security_group": {"sg": {
            "ingress": {"from_port": 22, "to_port": 22, "cidr_blocks": "0.0.0.0/0"}
        }}}
        assert len(check_sg_ssh_open(resources)) == 1

    def test_handles_ingress_as_list(self):
        """Multiple ingress rules as a list."""
        resources = {"aws_security_group": {"sg": {
            "ingress": [
                {"from_port": 443, "to_port": 443, "cidr_blocks": ["0.0.0.0/0"]},
                {"from_port": 22, "to_port": 22, "cidr_blocks": ["0.0.0.0/0"]},
            ]
        }}}
        assert len(check_sg_ssh_open(resources)) == 1


# --- SG-002: Wide Open ---

class TestSgWideOpen:
    def test_fires_on_all_ports_open(self):
        resources = {"aws_security_group": {"sg": {
            "ingress": {"from_port": 0, "to_port": 65535, "cidr_blocks": ["0.0.0.0/0"]}
        }}}
        findings = check_sg_wide_open(resources)
        assert len(findings) == 1
        assert findings[0].rule_id == "SG-002"
        assert findings[0].severity == "High"

    def test_skips_ssh_only_port(self):
        """Port 22 to 22 is handled by SG-001, SG-002 should skip it."""
        resources = {"aws_security_group": {"sg": {
            "ingress": {"from_port": 22, "to_port": 22, "cidr_blocks": ["0.0.0.0/0"]}
        }}}
        assert len(check_sg_wide_open(resources)) == 0

    def test_fires_on_http_open(self):
        resources = {"aws_security_group": {"sg": {
            "ingress": {"from_port": 80, "to_port": 80, "cidr_blocks": ["0.0.0.0/0"]}
        }}}
        assert len(check_sg_wide_open(resources)) == 1

    def test_fires_on_rdp_open(self):
        resources = {"aws_security_group": {"sg": {
            "ingress": {"from_port": 3389, "to_port": 3389, "cidr_blocks": ["0.0.0.0/0"]}
        }}}
        assert len(check_sg_wide_open(resources)) == 1

    def test_silent_on_restricted_cidr(self):
        resources = {"aws_security_group": {"sg": {
            "ingress": {"from_port": 80, "to_port": 80, "cidr_blocks": ["10.0.0.0/8"]}
        }}}
        assert len(check_sg_wide_open(resources)) == 0


# --- EC2-001: IMDSv2 ---

class TestEc2Imdsv2:
    def test_fires_when_no_metadata_options(self):
        resources = {"aws_instance": {"srv": {"ami": "ami-123"}}}
        findings = check_ec2_imdsv2(resources)
        assert len(findings) == 1
        assert findings[0].rule_id == "EC2-001"
        assert findings[0].severity == "Medium"

    def test_fires_when_tokens_optional(self):
        resources = {"aws_instance": {"srv": {
            "metadata_options": {"http_tokens": "optional"}
        }}}
        assert len(check_ec2_imdsv2(resources)) == 1

    def test_silent_when_tokens_required(self):
        resources = {"aws_instance": {"srv": {
            "metadata_options": {"http_tokens": "required"}
        }}}
        assert len(check_ec2_imdsv2(resources)) == 0

    def test_fires_when_metadata_empty(self):
        """metadata_options present but empty → defaults to optional → fires."""
        resources = {"aws_instance": {"srv": {
            "metadata_options": {}
        }}}
        assert len(check_ec2_imdsv2(resources)) == 1


# --- IAM-001: Wildcard Actions ---

class TestIamWildcard:
    def test_fires_on_wildcard_in_json_string(self):
        """Policy as a JSON string containing Action: * → fires."""
        resources = {"aws_iam_policy": {"pol": {
            "policy": '{"Statement": [{"Action": "*"}]}'
        }}}
        findings = check_iam_wildcard(resources)
        assert len(findings) == 1
        assert findings[0].rule_id == "IAM-001"
        assert findings[0].severity == "Critical"

    def test_fires_on_wildcard_in_dict(self):
        """Policy as a dict with Action: * → fires."""
        resources = {"aws_iam_policy": {"pol": {
            "policy": {"Statement": [{"Action": "*"}]}
        }}}
        assert len(check_iam_wildcard(resources)) == 1

    def test_fires_on_wildcard_in_list(self):
        """Action is a list containing * → fires."""
        resources = {"aws_iam_policy": {"pol": {
            "policy": {"Statement": [{"Action": ["s3:*", "*"]}]}
        }}}
        assert len(check_iam_wildcard(resources)) == 1

    def test_silent_on_scoped_action(self):
        resources = {"aws_iam_policy": {"pol": {
            "policy": {"Statement": [{"Action": "s3:GetObject"}]}
        }}}
        assert len(check_iam_wildcard(resources)) == 0

    def test_silent_on_no_policies(self):
        assert len(check_iam_wildcard({})) == 0


# --- RDS-001: Public ---

class TestRdsPublic:
    def test_fires_when_publicly_accessible(self):
        resources = {"aws_db_instance": {"db": {"publicly_accessible": True}}}
        findings = check_rds_public(resources)
        assert len(findings) == 1
        assert findings[0].rule_id == "RDS-001"
        assert findings[0].severity == "Critical"

    def test_silent_when_private(self):
        resources = {"aws_db_instance": {"db": {"publicly_accessible": False}}}
        assert len(check_rds_public(resources)) == 0

    def test_silent_when_key_missing(self):
        """No publicly_accessible key → defaults to False → clean."""
        resources = {"aws_db_instance": {"db": {"engine": "postgres"}}}
        assert len(check_rds_public(resources)) == 0


# --- RDS-002: No Encryption ---

class TestRdsNoEncryption:
    def test_fires_when_not_encrypted(self):
        resources = {"aws_db_instance": {"db": {"storage_encrypted": False}}}
        findings = check_rds_no_encryption(resources)
        assert len(findings) == 1
        assert findings[0].rule_id == "RDS-002"
        assert findings[0].severity == "High"

    def test_silent_when_encrypted(self):
        resources = {"aws_db_instance": {"db": {"storage_encrypted": True}}}
        assert len(check_rds_no_encryption(resources)) == 0

    def test_fires_when_key_missing(self):
        """No storage_encrypted key → defaults to False → fires."""
        resources = {"aws_db_instance": {"db": {"engine": "postgres"}}}
        assert len(check_rds_no_encryption(resources)) == 1


# --- LOG-001: CloudTrail ---

class TestCloudtrailDisabled:
    def test_fires_when_no_cloudtrail_but_aws_resources(self):
        resources = {"aws_s3_bucket": {"b": {}}}
        findings = check_cloudtrail_disabled(resources)
        assert len(findings) == 1
        assert findings[0].rule_id == "LOG-001"
        assert findings[0].severity == "High"

    def test_silent_when_cloudtrail_present(self):
        resources = {"aws_s3_bucket": {"b": {}}, "aws_cloudtrail": {"trail": {}}}
        assert len(check_cloudtrail_disabled(resources)) == 0

    def test_silent_when_no_aws_resources(self):
        """No AWS resources at all → nothing to protect → clean."""
        assert len(check_cloudtrail_disabled({})) == 0


# --- EBS-001: No Encryption ---

class TestEbsNoEncryption:
    def test_fires_when_not_encrypted(self):
        resources = {"aws_ebs_volume": {"vol": {"encrypted": False}}}
        findings = check_ebs_no_encryption(resources)
        assert len(findings) == 1
        assert findings[0].rule_id == "EBS-001"
        assert findings[0].severity == "Medium"

    def test_silent_when_encrypted(self):
        resources = {"aws_ebs_volume": {"vol": {"encrypted": True}}}
        assert len(check_ebs_no_encryption(resources)) == 0

    def test_fires_when_key_missing(self):
        """No encrypted key → defaults to False → fires."""
        resources = {"aws_ebs_volume": {"vol": {"size": 100}}}
        assert len(check_ebs_no_encryption(resources)) == 1


# ══════════════════════════════════════════════
# CloudFormation Rules
# ══════════════════════════════════════════════

# --- CF S3-001: Public ---

class TestCfS3Public:
    def test_fires_on_public_read(self):
        resources = {"Bucket": {"Type": "AWS::S3::Bucket", "Properties": {"AccessControl": "PublicRead"}}}
        findings = check_cf_s3_public(resources)
        assert len(findings) == 1
        assert findings[0].severity == "Critical"

    def test_fires_on_public_read_write(self):
        resources = {"Bucket": {"Type": "AWS::S3::Bucket", "Properties": {"AccessControl": "PublicReadWrite"}}}
        assert len(check_cf_s3_public(resources)) == 1

    def test_silent_on_private(self):
        resources = {"Bucket": {"Type": "AWS::S3::Bucket", "Properties": {"AccessControl": "Private"}}}
        assert len(check_cf_s3_public(resources)) == 0

    def test_skips_non_s3_resources(self):
        resources = {"SG": {"Type": "AWS::EC2::SecurityGroup", "Properties": {}}}
        assert len(check_cf_s3_public(resources)) == 0


# --- CF S3-002: No Encryption ---

class TestCfS3NoEncryption:
    def test_fires_when_no_encryption(self):
        resources = {"Bucket": {"Type": "AWS::S3::Bucket", "Properties": {}}}
        findings = check_cf_s3_no_encryption(resources)
        assert len(findings) == 1
        assert findings[0].rule_id == "S3-002"

    def test_silent_when_encrypted(self):
        resources = {"Bucket": {"Type": "AWS::S3::Bucket", "Properties": {"BucketEncryption": {"Rules": []}}}}
        assert len(check_cf_s3_no_encryption(resources)) == 0

    def test_fires_on_missing_properties(self):
        """Bucket with empty Properties → no encryption → fires."""
        resources = {"Bucket": {"Type": "AWS::S3::Bucket", "Properties": {"BucketName": "test"}}}
        assert len(check_cf_s3_no_encryption(resources)) == 1


# --- CF SG-001: SSH Open ---

class TestCfSgSshOpen:
    def test_fires_on_ssh_to_world(self):
        resources = {"SG": {"Type": "AWS::EC2::SecurityGroup", "Properties": {
            "SecurityGroupIngress": [{"CidrIp": "0.0.0.0/0", "FromPort": 22, "ToPort": 22}]
        }}}
        findings = check_cf_sg_ssh_open(resources)
        assert len(findings) == 1
        assert findings[0].rule_id == "SG-001"

    def test_silent_on_restricted(self):
        resources = {"SG": {"Type": "AWS::EC2::SecurityGroup", "Properties": {
            "SecurityGroupIngress": [{"CidrIp": "10.0.0.0/8", "FromPort": 22, "ToPort": 22}]
        }}}
        assert len(check_cf_sg_ssh_open(resources)) == 0

    def test_fires_when_ssh_in_range(self):
        """Port range 0-65535 includes SSH → fires."""
        resources = {"SG": {"Type": "AWS::EC2::SecurityGroup", "Properties": {
            "SecurityGroupIngress": [{"CidrIp": "0.0.0.0/0", "FromPort": 0, "ToPort": 65535}]
        }}}
        assert len(check_cf_sg_ssh_open(resources)) == 1


# --- CF SG-002: Wide Open ---

class TestCfSgWideOpen:
    def test_fires_on_non_ssh_port(self):
        resources = {"SG": {"Type": "AWS::EC2::SecurityGroup", "Properties": {
            "SecurityGroupIngress": [{"CidrIp": "0.0.0.0/0", "FromPort": 80, "ToPort": 80}]
        }}}
        findings = check_cf_sg_wide_open(resources)
        assert len(findings) == 1
        assert findings[0].rule_id == "SG-002"

    def test_skips_ssh_only(self):
        """Port 22 to 22 → handled by SG-001, SG-002 skips."""
        resources = {"SG": {"Type": "AWS::EC2::SecurityGroup", "Properties": {
            "SecurityGroupIngress": [{"CidrIp": "0.0.0.0/0", "FromPort": 22, "ToPort": 22}]
        }}}
        assert len(check_cf_sg_wide_open(resources)) == 0

    def test_fires_on_all_ports(self):
        resources = {"SG": {"Type": "AWS::EC2::SecurityGroup", "Properties": {
            "SecurityGroupIngress": [{"CidrIp": "0.0.0.0/0", "FromPort": 0, "ToPort": 65535}]
        }}}
        assert len(check_cf_sg_wide_open(resources)) == 1


# --- CF RDS-001: Public ---

class TestCfRdsPublic:
    def test_fires_when_publicly_accessible(self):
        resources = {"DB": {"Type": "AWS::RDS::DBInstance", "Properties": {"PubliclyAccessible": True}}}
        findings = check_cf_rds_public(resources)
        assert len(findings) == 1
        assert findings[0].rule_id == "RDS-001"

    def test_silent_when_private(self):
        resources = {"DB": {"Type": "AWS::RDS::DBInstance", "Properties": {"PubliclyAccessible": False}}}
        assert len(check_cf_rds_public(resources)) == 0

    def test_silent_when_key_missing(self):
        resources = {"DB": {"Type": "AWS::RDS::DBInstance", "Properties": {"Engine": "postgres"}}}
        assert len(check_cf_rds_public(resources)) == 0


# --- CF RDS-002: No Encryption ---

class TestCfRdsNoEncryption:
    def test_fires_when_not_encrypted(self):
        resources = {"DB": {"Type": "AWS::RDS::DBInstance", "Properties": {"StorageEncrypted": False}}}
        findings = check_cf_rds_no_encryption(resources)
        assert len(findings) == 1
        assert findings[0].rule_id == "RDS-002"

    def test_silent_when_encrypted(self):
        resources = {"DB": {"Type": "AWS::RDS::DBInstance", "Properties": {"StorageEncrypted": True}}}
        assert len(check_cf_rds_no_encryption(resources)) == 0

    def test_fires_when_key_missing(self):
        """No StorageEncrypted key → defaults to False → fires."""
        resources = {"DB": {"Type": "AWS::RDS::DBInstance", "Properties": {"Engine": "mysql"}}}
        assert len(check_cf_rds_no_encryption(resources)) == 1


# --- CF IAM-001: Wildcard ---

class TestCfIamWildcard:
    def test_fires_on_wildcard_action(self):
        resources = {"Role": {"Type": "AWS::IAM::Role", "Properties": {
            "Policies": [{"PolicyDocument": {"Statement": [{"Action": "*"}]}}]
        }}}
        findings = check_cf_iam_wildcard(resources)
        assert len(findings) == 1
        assert findings[0].rule_id == "IAM-001"

    def test_silent_on_scoped_action(self):
        resources = {"Role": {"Type": "AWS::IAM::Role", "Properties": {
            "Policies": [{"PolicyDocument": {"Statement": [{"Action": "s3:GetObject"}]}}]
        }}}
        assert len(check_cf_iam_wildcard(resources)) == 0

    def test_fires_on_wildcard_in_action_list(self):
        resources = {"Policy": {"Type": "AWS::IAM::Policy", "Properties": {
            "PolicyDocument": {"Statement": [{"Action": ["s3:*", "*"]}]}
        }}}
        assert len(check_cf_iam_wildcard(resources)) == 1

    def test_fires_on_managed_policy_type(self):
        resources = {"MP": {"Type": "AWS::IAM::ManagedPolicy", "Properties": {
            "PolicyDocument": {"Statement": [{"Action": "*"}]}
        }}}
        assert len(check_cf_iam_wildcard(resources)) == 1
