"""Risk scoring engine."""

from app.engine.rules import RuleFinding

MAX_WEIGHT = 76  # Sum of all rule weights (10+7+10+7+4+10+10+7+7+4)


def calculate_risk_score(findings: list[RuleFinding]) -> tuple[float, str]:
    """Calculate a risk score from 0-100 based on findings.

    Returns (score, level) where level is Low/Medium/High/Critical.
    """
    if not findings:
        return 0.0, "Low"

    total_weight = sum(f.weight for f in findings)
    score = min((total_weight / MAX_WEIGHT) * 100, 100.0)
    score = round(score, 1)

    if score >= 76:
        level = "Critical"
    elif score >= 51:
        level = "High"
    elif score >= 26:
        level = "Medium"
    else:
        level = "Low"

    return score, level


def severity_counts(findings: list[RuleFinding]) -> dict[str, int]:
    """Count findings by severity."""
    counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    return counts
