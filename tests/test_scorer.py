"""Tests for the risk scoring engine.

Covers: calculate_risk_score, severity_counts.
Tests boundary conditions at each threshold (25/50/75) and edge cases.
~12 tests using make_finding() fixture from conftest.
"""

from app.engine.scorer import calculate_risk_score, severity_counts, MAX_WEIGHT


class TestCalculateRiskScore:
    def test_no_findings_returns_zero(self):
        """Zero findings → score 0.0, level Low."""
        score, level = calculate_risk_score([])
        assert score == 0.0
        assert level == "Low"

    def test_single_low_weight(self, make_finding):
        """Single weight-4 finding → score ~5.3, level Low."""
        findings = [make_finding(weight=4)]
        score, level = calculate_risk_score(findings)
        assert 0 < score <= 25
        assert level == "Low"

    def test_low_medium_boundary(self, make_finding):
        """Weight just under 26% of MAX → still Low."""
        # 25% of 76 = 19. weight=19 → score = 25.0
        findings = [make_finding(weight=19)]
        score, level = calculate_risk_score(findings)
        assert score == 25.0
        assert level == "Low"

    def test_medium_threshold(self, make_finding):
        """Weights totaling 26-50% of MAX → Medium."""
        # 3 × 7 = 21 → 21/76 × 100 = 27.6
        findings = [
            make_finding(weight=7),
            make_finding(weight=7),
            make_finding(weight=7),
        ]
        score, level = calculate_risk_score(findings)
        assert 26 <= score <= 50
        assert level == "Medium"

    def test_high_threshold(self, make_finding):
        """Weights totaling 51-75% of MAX → High."""
        # 4 × 10 = 40 → 40/76 × 100 = 52.6
        findings = [make_finding(weight=10) for _ in range(4)]
        score, level = calculate_risk_score(findings)
        assert 51 <= score <= 75
        assert level == "High"

    def test_critical_threshold(self, make_finding):
        """Weights totaling 76%+ of MAX → Critical."""
        # 8 × 10 = 80 → 80/76 × 100 = 105.3 → capped at 100
        findings = [make_finding(weight=10) for _ in range(8)]
        score, level = calculate_risk_score(findings)
        assert score >= 76
        assert level == "Critical"

    def test_score_capped_at_100(self, make_finding):
        """Excessive weight → score caps at exactly 100.0."""
        findings = [make_finding(weight=10) for _ in range(20)]
        score, _ = calculate_risk_score(findings)
        assert score == 100.0

    def test_score_is_rounded_to_one_decimal(self, make_finding):
        """Score always has at most one decimal place."""
        findings = [make_finding(weight=3)]
        score, _ = calculate_risk_score(findings)
        assert score == round(score, 1)

    def test_max_weight_constant(self):
        """MAX_WEIGHT = 76 (sum of all rule weights)."""
        assert MAX_WEIGHT == 76


class TestSeverityCounts:
    def test_empty_list(self):
        """No findings → all zeros."""
        counts = severity_counts([])
        assert counts == {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}

    def test_mixed_severities(self, make_finding):
        """Mixed findings counted correctly by severity."""
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

    def test_single_severity(self, make_finding):
        """All findings same severity → only that count non-zero."""
        findings = [make_finding(severity="High") for _ in range(5)]
        counts = severity_counts(findings)
        assert counts["High"] == 5
        assert counts["Critical"] == 0
        assert counts["Medium"] == 0
        assert counts["Low"] == 0
