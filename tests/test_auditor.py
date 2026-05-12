"""Tests for the audit orchestrator."""

from app.engine.auditor import run_audit


class TestRunAudit:
    def test_clean_terraform_no_findings(self, clean_tf):
        result = run_audit("clean.tf", clean_tf)
        assert result["file_type"] == "terraform"
        assert result["risk_score"] == 0.0
        assert result["risk_level"] == "Low"
        assert result["total_findings"] == 0

    def test_terrible_terraform_high_score(self, terrible_tf):
        result = run_audit("terrible.tf", terrible_tf)
        assert result["file_type"] == "terraform"
        assert result["risk_score"] > 75
        assert result["risk_level"] == "Critical"
        assert result["total_findings"] > 5
        assert result["critical_count"] >= 4

    def test_moderate_terraform_medium_score(self, moderate_tf):
        result = run_audit("moderate.tf", moderate_tf)
        assert result["file_type"] == "terraform"
        assert 0 < result["risk_score"] < 75
        assert result["total_findings"] > 0

    def test_bad_cloudformation(self, bad_cf_yaml):
        result = run_audit("stack.cfn.yaml", bad_cf_yaml)
        assert result["file_type"] == "cloudformation"
        assert result["risk_score"] > 50
        assert result["total_findings"] > 5

    def test_result_has_findings_list(self, terrible_tf):
        result = run_audit("terrible.tf", terrible_tf)
        assert isinstance(result["findings"], list)
        assert len(result["findings"]) == result["total_findings"]

    def test_result_has_all_keys(self, clean_tf):
        result = run_audit("clean.tf", clean_tf)
        expected_keys = {
            "file_type", "risk_score", "risk_level",
            "total_findings", "critical_count", "high_count",
            "medium_count", "low_count", "findings",
        }
        assert set(result.keys()) == expected_keys

    def test_counts_match_findings(self, terrible_tf):
        result = run_audit("terrible.tf", terrible_tf)
        critical = sum(1 for f in result["findings"] if f.severity == "Critical")
        high = sum(1 for f in result["findings"] if f.severity == "High")
        medium = sum(1 for f in result["findings"] if f.severity == "Medium")
        low = sum(1 for f in result["findings"] if f.severity == "Low")
        assert result["critical_count"] == critical
        assert result["high_count"] == high
        assert result["medium_count"] == medium
        assert result["low_count"] == low
