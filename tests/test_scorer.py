"""Tests for the risk scoring engine."""

from app.engine.scorer import calculate_risk_score, severity_counts


class TestCalculateRiskScore:
    def test_no_findings_is_zero(self):
        score, level = calculate_risk_score([])
        assert score == 0.0
        assert level == "Low"

    def test_single_critical_finding(self, make_finding):
        findings = [make_finding(severity="Critical", weight=10)]
        score, level = calculate_risk_score(findings)
        assert score > 0
        assert score <= 100

    def test_low_threshold(self, make_finding):
        findings = [make_finding(weight=4)]
        score, _ = calculate_risk_score(findings)
        assert score <= 25

    def test_medium_threshold(self, make_finding):
        findings = [
            make_finding(weight=7),
            make_finding(weight=7),
            make_finding(weight=7),
        ]
        score, level = calculate_risk_score(findings)
        assert 26 <= score <= 50
        assert level == "Medium"

    def test_high_threshold(self, make_finding):
        findings = [
            make_finding(weight=10),
            make_finding(weight=10),
            make_finding(weight=10),
            make_finding(weight=10),
        ]
        score, level = calculate_risk_score(findings)
        assert 51 <= score <= 75
        assert level == "High"

    def test_critical_threshold(self, make_finding):
        findings = [make_finding(weight=10) for _ in range(8)]
        score, level = calculate_risk_score(findings)
        assert score >= 76
        assert level == "Critical"

    def test_capped_at_100(self, make_finding):
        findings = [make_finding(weight=10) for _ in range(20)]
        score, _ = calculate_risk_score(findings)
        assert score == 100.0

    def test_score_is_rounded(self, make_finding):
        findings = [make_finding(weight=3)]
        score, _ = calculate_risk_score(findings)
        assert score == round(score, 1)


class TestSeverityCounts:
    def test_empty_findings(self):
        counts = severity_counts([])
        assert counts == {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}

    def test_mixed_severities(self, make_finding):
        findings = [
            make_finding(severity="Critical"),
            make_finding(severity="Critical"),
            make_finding(severity="High"),
            make_finding(severity="Medium"),
            make_finding(severity="Low"),
            make_finding(severity="Low"),
        ]
        counts = severity_counts(findings)
        assert counts["Critical"] == 2
        assert counts["High"] == 1
        assert counts["Medium"] == 1
        assert counts["Low"] == 2
