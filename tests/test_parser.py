"""Tests for the config parser module."""

from app.engine.parser import parse_terraform, parse_cloudformation, detect_format


class TestDetectFormat:
    def test_tf_extension(self):
        assert detect_format("main.tf", "") == "terraform"

    def test_tf_json_extension(self):
        assert detect_format("main.tf.json", "{}") == "terraform"

    def test_cfn_json_extension(self):
        assert detect_format("stack.cfn.json", "{}") == "cloudformation"

    def test_cfn_yaml_extension(self):
        assert detect_format("stack.cfn.yaml", "") == "cloudformation"

    def test_template_extension(self):
        assert detect_format("stack.template", "{}") == "cloudformation"

    def test_json_with_aws_template_version(self):
        content = '{"AWSTemplateFormatVersion": "2010-09-09", "Resources": {}}'
        assert detect_format("infra.json", content) == "cloudformation"

    def test_json_with_resources_key(self):
        content = '{"Resources": {"MyBucket": {"Type": "AWS::S3::Bucket"}}}'
        assert detect_format("infra.json", content) == "cloudformation"

    def test_yaml_with_aws_template_version(self):
        content = "AWSTemplateFormatVersion: '2010-09-09'\nResources: {}"
        assert detect_format("infra.yaml", content) == "cloudformation"

    def test_unknown_defaults_to_terraform(self):
        assert detect_format("unknown.txt", "resource {") == "terraform"


class TestParseTerraform:
    def test_parses_hcl_s3_bucket(self, clean_tf):
        resources = parse_terraform(clean_tf)
        assert "aws_s3_bucket" in resources
        assert "secure_bucket" in resources["aws_s3_bucket"]

    def test_parses_security_group(self, terrible_tf):
        resources = parse_terraform(terrible_tf)
        assert "aws_security_group" in resources
        assert "yolo_sg" in resources["aws_security_group"]

    def test_parses_ec2_instance(self, terrible_tf):
        resources = parse_terraform(terrible_tf)
        assert "aws_instance" in resources

    def test_parses_rds_instance(self, terrible_tf):
        resources = parse_terraform(terrible_tf)
        assert "aws_db_instance" in resources

    def test_parses_iam_policy(self, terrible_tf):
        resources = parse_terraform(terrible_tf)
        assert "aws_iam_policy" in resources

    def test_parses_cloudtrail(self, clean_tf):
        resources = parse_terraform(clean_tf)
        assert "aws_cloudtrail" in resources

    def test_parses_ebs_volume(self, terrible_tf):
        resources = parse_terraform(terrible_tf)
        assert "aws_ebs_volume" in resources

    def test_returns_empty_for_garbage(self):
        resources = parse_terraform("this is not valid terraform at all")
        assert resources == {}

    def test_json_terraform_format(self):
        content = '{"resource": {"aws_s3_bucket": {"test": {"acl": "private"}}}}'
        resources = parse_terraform(content)
        assert "aws_s3_bucket" in resources
        assert "test" in resources["aws_s3_bucket"]


class TestParseCloudFormation:
    def test_parses_yaml_resources(self, bad_cf_yaml):
        resources = parse_cloudformation(bad_cf_yaml)
        assert "PublicBucket" in resources
        assert resources["PublicBucket"]["Type"] == "AWS::S3::Bucket"

    def test_parses_security_groups(self, bad_cf_yaml):
        resources = parse_cloudformation(bad_cf_yaml)
        assert "OpenSSHGroup" in resources
        assert resources["OpenSSHGroup"]["Type"] == "AWS::EC2::SecurityGroup"

    def test_parses_rds(self, bad_cf_yaml):
        resources = parse_cloudformation(bad_cf_yaml)
        assert "PublicDatabase" in resources

    def test_parses_iam_role(self, bad_cf_yaml):
        resources = parse_cloudformation(bad_cf_yaml)
        assert "AdminRole" in resources

    def test_parses_json_cloudformation(self):
        content = '{"AWSTemplateFormatVersion": "2010-09-09", "Resources": {"Bucket": {"Type": "AWS::S3::Bucket", "Properties": {}}}}'
        resources = parse_cloudformation(content)
        assert "Bucket" in resources

    def test_returns_empty_for_garbage(self):
        resources = parse_cloudformation("not valid yaml or json }{")
        assert resources == {}

    def test_returns_empty_for_non_dict(self):
        resources = parse_cloudformation('"just a string"')
        assert resources == {}
