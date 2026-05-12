"""Tests for the config parser module.

Covers: parse_terraform, parse_cloudformation, detect_format.
14 tests defining expected parsing behavior.
"""

from app.engine.parser import parse_terraform, parse_cloudformation, detect_format


# --- detect_format ---

class TestDetectFormat:
    def test_detect_format_tf_extension(self):
        """A .tf file is always Terraform."""
        assert detect_format("main.tf", "") == "terraform"

    def test_detect_format_tf_json(self):
        """.tf.json is Terraform JSON format."""
        assert detect_format("main.tf.json", "{}") == "terraform"

    def test_detect_format_cf_extension(self):
        """.cfn.yaml is CloudFormation."""
        assert detect_format("stack.cfn.yaml", "") == "cloudformation"

    def test_detect_format_cf_by_content(self):
        """JSON with AWSTemplateFormatVersion → CloudFormation regardless of extension."""
        content = '{"AWSTemplateFormatVersion": "2010-09-09", "Resources": {}}'
        assert detect_format("infra.json", content) == "cloudformation"

    def test_detect_format_cf_by_resources_key(self):
        """JSON with Resources containing AWS types → CloudFormation."""
        content = '{"Resources": {"MyBucket": {"Type": "AWS::S3::Bucket"}}}'
        assert detect_format("infra.json", content) == "cloudformation"

    def test_detect_format_cf_yaml_by_content(self):
        """YAML with AWSTemplateFormatVersion → CloudFormation."""
        content = "AWSTemplateFormatVersion: '2010-09-09'\nResources: {}"
        assert detect_format("infra.yaml", content) == "cloudformation"

    def test_detect_format_fallback(self):
        """Unknown extension with 'resource' keyword → defaults to Terraform."""
        assert detect_format("unknown.txt", "resource {") == "terraform"


# --- parse_terraform ---

class TestParseTerraform:
    def test_parse_terraform_single_resource(self):
        """Minimal HCL with one S3 bucket parses to correct resource dict."""
        hcl = '''
resource "aws_s3_bucket" "test" {
  bucket = "my-bucket"
  acl    = "private"
}
'''
        resources = parse_terraform(hcl)
        assert "aws_s3_bucket" in resources
        assert "test" in resources["aws_s3_bucket"]
        assert resources["aws_s3_bucket"]["test"]["acl"] == "private"

    def test_parse_terraform_multiple_types(self):
        """HCL with S3 + SG → both resource types in dict."""
        hcl = '''
resource "aws_s3_bucket" "bucket" {
  bucket = "test"
  acl    = "private"
}

resource "aws_security_group" "sg" {
  name = "test-sg"
}
'''
        resources = parse_terraform(hcl)
        assert "aws_s3_bucket" in resources
        assert "aws_security_group" in resources
        assert "bucket" in resources["aws_s3_bucket"]
        assert "sg" in resources["aws_security_group"]

    def test_parse_terraform_json_format(self):
        """.tf.json content normalizes the same as HCL."""
        content = '{"resource": {"aws_s3_bucket": {"test": {"acl": "private"}}}}'
        resources = parse_terraform(content)
        assert "aws_s3_bucket" in resources
        assert resources["aws_s3_bucket"]["test"]["acl"] == "private"

    def test_parse_terraform_empty_string(self):
        """Empty string → empty dict (no crash)."""
        assert parse_terraform("") == {}

    def test_parse_terraform_malformed(self):
        """Invalid/garbage content → empty dict (graceful failure)."""
        assert parse_terraform("this is not valid terraform at all!!!") == {}

    def test_parse_terraform_full_file(self, terrible_tf):
        """Full sample file parses all resource types."""
        resources = parse_terraform(terrible_tf)
        assert "aws_s3_bucket" in resources
        assert "aws_security_group" in resources
        assert "aws_instance" in resources
        assert "aws_iam_policy" in resources
        assert "aws_db_instance" in resources
        assert "aws_ebs_volume" in resources


# --- parse_cloudformation ---

class TestParseCloudFormation:
    def test_parse_cloudformation_yaml(self, bad_cf_yaml):
        """Valid CF YAML → resources dict with correct types."""
        resources = parse_cloudformation(bad_cf_yaml)
        assert "PublicBucket" in resources
        assert resources["PublicBucket"]["Type"] == "AWS::S3::Bucket"
        assert "OpenSSHGroup" in resources
        assert "AdminRole" in resources

    def test_parse_cloudformation_json(self):
        """Valid CF JSON → resources dict."""
        content = '{"AWSTemplateFormatVersion": "2010-09-09", "Resources": {"Bucket": {"Type": "AWS::S3::Bucket", "Properties": {}}}}'
        resources = parse_cloudformation(content)
        assert "Bucket" in resources
        assert resources["Bucket"]["Type"] == "AWS::S3::Bucket"

    def test_parse_cloudformation_empty(self):
        """Empty string → empty dict (no crash)."""
        assert parse_cloudformation("") == {}

    def test_parse_cloudformation_malformed(self):
        """Garbage content → empty dict (graceful failure)."""
        assert parse_cloudformation("not valid yaml or json }{") == {}

    def test_parse_cloudformation_non_dict(self):
        """Non-dict YAML/JSON → empty dict."""
        assert parse_cloudformation('"just a string"') == {}
