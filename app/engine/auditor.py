"""Main audit orchestrator — ties parser, rules, and scorer together."""

from app.engine.parser import parse_terraform, parse_cloudformation, detect_format
from app.engine.rules import TERRAFORM_RULES, CLOUDFORMATION_RULES, RuleFinding
from app.engine.scorer import calculate_risk_score, severity_counts


def run_audit(filename: str, content: str) -> dict:
    """Run a full security audit on an infrastructure config file.

    Returns a dict with file_type, risk_score, risk_level, counts, and findings.
    """
    file_type = detect_format(filename, content)

    if file_type == "terraform":
        resources = parse_terraform(content)
        rules = TERRAFORM_RULES
    else:
        resources = parse_cloudformation(content)
        rules = CLOUDFORMATION_RULES

    all_findings: list[RuleFinding] = []
    for rule_fn in rules:
        all_findings.extend(rule_fn(resources))

    risk_score, risk_level = calculate_risk_score(all_findings)
    counts = severity_counts(all_findings)

    return {
        "file_type": file_type,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "total_findings": len(all_findings),
        "critical_count": counts["Critical"],
        "high_count": counts["High"],
        "medium_count": counts["Medium"],
        "low_count": counts["Low"],
        "findings": all_findings,
    }
