"""Tests for the security rules engine."""

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
)


# --- S3 Rules (Terraform) ---

class TestS3PublicAcl:
    def test_public_read_flagged(self):
        resources = {"aws_s3_bucket": {"bad": {"acl": "public-read"}}}
        findings = check_s3_public_acl(resources)
        assert len(findings) == 1
        assert findings[0].rule_id == "S3-001"
        assert findings[0].severity == "Critical"

    def test_public_read_write_flagged(self):
        resources = {"aws_s3_bucket": {"bad": {"acl": "public-read-write"}}}
        findings = check_s3_public_acl(resources)
        assert len(findings) == 1

    def test_authenticated_read_flagged(self):
        resources = {"aws_s3_bucket": {"bad": {"acl": "authenticated-read"}}}
        assert len(check_s3_public_acl(resources)) == 1

    def test_private_acl_clean(self):
        resources = {"aws_s3_bucket": {"good": {"acl": "private"}}}
        assert len(check_s3_public_acl(resources)) == 0

    def test_no_s3_buckets(self):
        assert len(check_s3_public_acl({})) == 0

    def test_multiple_buckets(self):
        resources = {"aws_s3_bucket": {
            "bad1": {"acl": "public-read"},
            "bad2": {"acl": "public-read-write"},
            "good": {"acl": "private"},
        }}
        findings = check_s3_public_acl(resources)
        assert len(findings) == 2


class TestS3NoEncryption:
    def test_missing_encryption_flagged(self):
        resources = {"aws_s3_bucket": {"unenc": {"acl": "private"}}}
        findings = check_s3_no_encryption(resources)
        assert len(findings) == 1
        assert findings[0].rule_id == "S3-002"
        assert findings[0].severity == "High"

    def test_with_encryption_clean(self):
        resources = {"aws_s3_bucket": {"enc": {
            "server_side_encryption_configuration": {"rule": {}}
        }}}
        assert len(check_s3_no_encryption(resources)) == 0


# --- Security Group Rules (Terraform) ---

class TestSgSshOpen:
    def test_ssh_open_to_world(self):
        resources = {"aws_security_group": {"sg": {
            "ingress": {"from_port": 22, "to_port": 22, "cidr_blocks": ["0.0.0.0/0"]}
        }}}
        findings = check_sg_ssh_open(resources)
        assert len(findings) == 1
        assert findings[0].rule_id == "SG-001"
        assert findings[0].severity == "Critical"

    def test_ssh_restricted_clean(self):
        resources = {"aws_security_group": {"sg": {
            "ingress": {"from_port": 22, "to_port": 22, "cidr_blocks": ["10.0.0.0/8"]}
        }}}
        assert len(check_sg_ssh_open(resources)) == 0

    def test_non_ssh_port_not_flagged(self):
        resources = {"aws_security_group": {"sg": {
            "ingress": {"from_port": 443, "to_port": 443, "cidr_blocks": ["0.0.0.0/0"]}
        }}}
        assert len(check_sg_ssh_open(resources)) == 0

    def test_ssh_in_range(self):
        resources = {"aws_security_group": {"sg": {
            "ingress": {"from_port": 0, "to_port": 65535, "cidr_blocks": ["0.0.0.0/0"]}
        }}}
        findings = check_sg_ssh_open(resources)
        assert len(findings) == 1

    def test_cidr_as_string(self):
        resources = {"aws_security_group": {"sg": {
            "ingress": {"from_port": 22, "to_port": 22, "cidr_blocks": "0.0.0.0/0"}
        }}}
        findings = check_sg_ssh_open(resources)
        assert len(findings) == 1


class TestSgWideOpen:
    def test_all_ports_open(self):
        resources = {"aws_security_group": {"sg": {
            "ingress": {"from_port": 0, "to_port": 65535, "cidr_blocks": ["0.0.0.0/0"]}
        }}}
        findings = check_sg_wide_open(resources)
        assert len(findings) == 1
        assert findings[0].rule_id == "SG-002"

    def test_skips_ssh_only(self):
        resources = {"aws_security_group": {"sg": {
            "ingress": {"from_port": 22, "to_port": 22, "cidr_blocks": ["0.0.0.0/0"]}
        }}}
        assert len(check_sg_wide_open(resources)) == 0

    def test_http_open_flagged(self):
        resources = {"aws_security_group": {"sg": {
            "ingress": {"from_port": 80, "to_port": 80, "cidr_blocks": ["0.0.0.0/0"]}
        }}}
        findings = check_sg_wide_open(resources)
        assert len(findings) == 1

    def test_restricted_cidr_clean(self):
        resources = {"aws_security_group": {"sg": {
            "ingress": {"from_port": 80, "to_port": 80, "cidr_blocks": ["10.0.0.0/8"]}
        }}}
        assert len(check_sg_wide_open(resources)) == 0


# --- EC2 Rules ---

class TestEc2Imdsv2:
    def test_no_metadata_options(self):
        resources = {"aws_instance": {"srv": {"ami": "ami-123"}}}
        findings = check_ec2_imdsv2(resources)
        assert len(findings) == 1
        assert findings[0].rule_id == "EC2-001"
        assert findings[0].severity == "Medium"

    def test_optional_tokens(self):
        resources = {"aws_instance": {"srv": {
            "metadata_options": {"http_tokens": "optional"}
        }}}
        assert len(check_ec2_imdsv2(resources)) == 1

    def test_required_tokens_clean(self):
        resources = {"aws_instance": {"srv": {
            "metadata_options": {"http_tokens": "required"}
        }}}
        assert len(check_ec2_imdsv2(resources)) == 0


# --- IAM Rules ---

class TestIamWildcard:
    def test_wildcard_in_json_string(self):
        resources = {"aws_iam_policy": {"pol": {
            "policy": '{"Statement": [{"Action": "*"}]}'
        }}}
        findings = check_iam_wildcard(resources)
        assert len(findings) == 1
        assert findings[0].rule_id == "IAM-001"
        assert findings[0].severity == "Critical"

    def test_wildcard_in_dict(self):
        resources = {"aws_iam_policy": {"pol": {
            "policy": {"Statement": [{"Action": "*"}]}
        }}}
        assert len(check_iam_wildcard(resources)) == 1

    def test_wildcard_in_list(self):
        resources = {"aws_iam_policy": {"pol": {
            "policy": {"Statement": [{"Action": ["s3:*", "*"]}]}
        }}}
        assert len(check_iam_wildcard(resources)) == 1

    def test_scoped_action_clean(self):
        resources = {"aws_iam_policy": {"pol": {
            "policy": {"Statement": [{"Action": "s3:GetObject"}]}
        }}}
        assert len(check_iam_wildcard(resources)) == 0

    def test_no_iam_policies(self):
        assert len(check_iam_wildcard({})) == 0


# --- RDS Rules ---

class TestRdsPublic:
    def test_publicly_accessible(self):
        resources = {"aws_db_instance": {"db": {"publicly_accessible": True}}}
        findings = check_rds_public(resources)
        assert len(findings) == 1
        assert findings[0].rule_id == "RDS-001"
        assert findings[0].severity == "Critical"

    def test_private_clean(self):
        resources = {"aws_db_instance": {"db": {"publicly_accessible": False}}}
        assert len(check_rds_public(resources)) == 0


class TestRdsNoEncryption:
    def test_no_encryption(self):
        resources = {"aws_db_instance": {"db": {"storage_encrypted": False}}}
        findings = check_rds_no_encryption(resources)
        assert len(findings) == 1
        assert findings[0].rule_id == "RDS-002"

    def test_encrypted_clean(self):
        resources = {"aws_db_instance": {"db": {"storage_encrypted": True}}}
        assert len(check_rds_no_encryption(resources)) == 0


# --- Logging Rules ---

class TestCloudtrailDisabled:
    def test_no_cloudtrail_with_aws_resources(self):
        resources = {"aws_s3_bucket": {"b": {}}}
        findings = check_cloudtrail_disabled(resources)
        assert len(findings) == 1
        assert findings[0].rule_id == "LOG-001"

    def test_with_cloudtrail_clean(self):
        resources = {"aws_s3_bucket": {"b": {}}, "aws_cloudtrail": {"trail": {}}}
        assert len(check_cloudtrail_disabled(resources)) == 0

    def test_no_aws_resources_clean(self):
        assert len(check_cloudtrail_disabled({})) == 0


# --- EBS Rules ---

class TestEbsNoEncryption:
    def test_unencrypted_volume(self):
        resources = {"aws_ebs_volume": {"vol": {"encrypted": False}}}
        findings = check_ebs_no_encryption(resources)
        assert len(findings) == 1
        assert findings[0].rule_id == "EBS-001"

    def test_encrypted_clean(self):
        resources = {"aws_ebs_volume": {"vol": {"encrypted": True}}}
        assert len(check_ebs_no_encryption(resources)) == 0


# --- CloudFormation Rules ---

class TestCfS3Public:
    def test_public_read(self):
        resources = {"Bucket": {"Type": "AWS::S3::Bucket", "Properties": {"AccessControl": "PublicRead"}}}
        findings = check_cf_s3_public(resources)
        assert len(findings) == 1
        assert findings[0].severity == "Critical"

    def test_private_clean(self):
        resources = {"Bucket": {"Type": "AWS::S3::Bucket", "Properties": {"AccessControl": "Private"}}}
        assert len(check_cf_s3_public(resources)) == 0


class TestCfS3NoEncryption:
    def test_no_encryption(self):
        resources = {"Bucket": {"Type": "AWS::S3::Bucket", "Properties": {}}}
        findings = check_cf_s3_no_encryption(resources)
        assert len(findings) == 1
        assert findings[0].rule_id == "S3-002"

    def test_with_encryption_clean(self):
        resources = {"Bucket": {"Type": "AWS::S3::Bucket", "Properties": {"BucketEncryption": {"Rules": []}}}}
        assert len(check_cf_s3_no_encryption(resources)) == 0


class TestCfSgSshOpen:
    def test_ssh_open(self):
        resources = {"SG": {"Type": "AWS::EC2::SecurityGroup", "Properties": {
            "SecurityGroupIngress": [{"CidrIp": "0.0.0.0/0", "FromPort": 22, "ToPort": 22}]
        }}}
        findings = check_cf_sg_ssh_open(resources)
        assert len(findings) == 1

    def test_restricted_clean(self):
        resources = {"SG": {"Type": "AWS::EC2::SecurityGroup", "Properties": {
            "SecurityGroupIngress": [{"CidrIp": "10.0.0.0/8", "FromPort": 22, "ToPort": 22}]
        }}}
        assert len(check_cf_sg_ssh_open(resources)) == 0


class TestCfSgWideOpen:
    def test_wide_open(self):
        resources = {"SG": {"Type": "AWS::EC2::SecurityGroup", "Properties": {
            "SecurityGroupIngress": [{"CidrIp": "0.0.0.0/0", "FromPort": 80, "ToPort": 80}]
        }}}
        findings = check_cf_sg_wide_open(resources)
        assert len(findings) == 1

    def test_ssh_only_skipped(self):
        resources = {"SG": {"Type": "AWS::EC2::SecurityGroup", "Properties": {
            "SecurityGroupIngress": [{"CidrIp": "0.0.0.0/0", "FromPort": 22, "ToPort": 22}]
        }}}
        assert len(check_cf_sg_wide_open(resources)) == 0


class TestCfRdsPublic:
    def test_publicly_accessible(self):
        resources = {"DB": {"Type": "AWS::RDS::DBInstance", "Properties": {"PubliclyAccessible": True}}}
        findings = check_cf_rds_public(resources)
        assert len(findings) == 1

    def test_private_clean(self):
        resources = {"DB": {"Type": "AWS::RDS::DBInstance", "Properties": {"PubliclyAccessible": False}}}
        assert len(check_cf_rds_public(resources)) == 0


class TestCfRdsNoEncryption:
    def test_no_encryption(self):
        resources = {"DB": {"Type": "AWS::RDS::DBInstance", "Properties": {"StorageEncrypted": False}}}
        findings = check_cf_rds_no_encryption(resources)
        assert len(findings) == 1

    def test_encrypted_clean(self):
        resources = {"DB": {"Type": "AWS::RDS::DBInstance", "Properties": {"StorageEncrypted": True}}}
        assert len(check_cf_rds_no_encryption(resources)) == 0


class TestCfIamWildcard:
    def test_wildcard_action(self):
        resources = {"Role": {"Type": "AWS::IAM::Role", "Properties": {
            "Policies": [{"PolicyDocument": {"Statement": [{"Action": "*"}]}}]
        }}}
        findings = check_cf_iam_wildcard(resources)
        assert len(findings) == 1

    def test_scoped_action_clean(self):
        resources = {"Role": {"Type": "AWS::IAM::Role", "Properties": {
            "Policies": [{"PolicyDocument": {"Statement": [{"Action": "s3:GetObject"}]}}]
        }}}
        assert len(check_cf_iam_wildcard(resources)) == 0

    def test_wildcard_in_list(self):
        resources = {"Policy": {"Type": "AWS::IAM::Policy", "Properties": {
            "PolicyDocument": {"Statement": [{"Action": ["s3:*", "*"]}]}
        }}}
        findings = check_cf_iam_wildcard(resources)
        assert len(findings) == 1
