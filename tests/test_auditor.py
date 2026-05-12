"""Tests for the audit orchestrator — end-to-end integration.

Verifies that run_audit() correctly chains parser → rules → scorer
and returns the expected structure and values for each sample config.
"""

from app.engine.auditor import run_audit


class TestRunAudit:
    def test_audit_clean_tf(self, clean_tf):
        """Clean Terraform → score 0.0, level Low, 0 findings."""
        result = run_audit("clean.tf", clean_tf)
        assert result["file_type"] == "terraform"
        assert result["risk_score"] == 0.0
        assert result["risk_level"] == "Low"
        assert result["total_findings"] == 0

    def test_audit_moderate_tf(self, moderate_tf):
        """Moderate risk Terraform → 5 findings, level Medium."""
        result = run_audit("moderate.tf", moderate_tf)
        assert result["file_type"] == "terraform"
        assert result["total_findings"] == 5
        assert result["risk_level"] == "Medium"
        assert 26 <= result["risk_score"] <= 50

    def test_audit_terrible_tf(self, terrible_tf):
        """Terrible Terraform → score 100.0, level Critical, 13 findings."""
        result = run_audit("terrible.tf", terrible_tf)
        assert result["file_type"] == "terraform"
        assert result["risk_score"] == 100.0
        assert result["risk_level"] == "Critical"
        assert result["total_findings"] == 13
        assert result["critical_count"] == 5
        assert result["high_count"] == 6
        assert result["medium_count"] == 2

    def test_audit_bad_cloudformation(self, bad_cf_yaml):
        """Bad CloudFormation → level Critical, 10 findings, file_type cloudformation."""
        result = run_audit("stack.cfn.yaml", bad_cf_yaml)
        assert result["file_type"] == "cloudformation"
        assert result["risk_level"] == "Critical"
        assert result["total_findings"] == 10
        assert result["risk_score"] == 100.0

    def test_audit_empty_file(self):
        """Empty file → 0 findings, score 0.0."""
        result = run_audit("empty.tf", "")
        assert result["total_findings"] == 0
        assert result["risk_score"] == 0.0
        assert result["risk_level"] == "Low"

    def test_audit_returns_all_required_keys(self, clean_tf):
        """Result dict contains all expected keys."""
        result = run_audit("clean.tf", clean_tf)
        expected_keys = {
            "file_type", "risk_score", "risk_level",
            "total_findings", "critical_count", "high_count",
            "medium_count", "low_count", "findings",
        }
        assert set(result.keys()) == expected_keys

    def test_audit_counts_match_findings(self, terrible_tf):
        """Severity counts in result match actual finding objects."""
        result = run_audit("terrible.tf", terrible_tf)
        critical = sum(1 for f in result["findings"] if f.severity == "Critical")
        high = sum(1 for f in result["findings"] if f.severity == "High")
        medium = sum(1 for f in result["findings"] if f.severity == "Medium")
        low = sum(1 for f in result["findings"] if f.severity == "Low")
        assert result["critical_count"] == critical
        assert result["high_count"] == high
        assert result["medium_count"] == medium
        assert result["low_count"] == low
