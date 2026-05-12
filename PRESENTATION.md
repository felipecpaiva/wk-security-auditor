# Enterprise Security Guardrail Auditor

**Wolters Kluwer — Global Business Services**
Architecture & Engineering Services

---

## The Problem

Infrastructure-as-Code (IaC) has become the standard for provisioning cloud resources. Teams define AWS infrastructure in Terraform and CloudFormation templates, then deploy through CI/CD pipelines.

**But misconfigurations in these templates are the #1 cause of cloud security breaches:**

- **Public S3 buckets** exposing sensitive data to the internet
- **Open security groups** allowing SSH from anywhere (0.0.0.0/0)
- **Unencrypted databases** violating compliance requirements
- **Wildcard IAM policies** granting unrestricted access
- **Missing audit trails** leaving no record of API activity

Manual code review doesn't scale. Security teams can't inspect every Terraform plan before it reaches production.

**Organizations need automated guardrails that catch dangerous patterns before deployment.**

---

## The Solution

An **API-first security auditor** that parses infrastructure configuration files, evaluates them against a rule-based security baseline, and produces actionable results:

- **17 security rules** covering S3, Security Groups, EC2, IAM, RDS, CloudTrail, and EBS
- **Dual-format support** — Terraform (.tf, .tf.json) and CloudFormation (.json, .yaml)
- **Risk scoring** — weighted 0-100 scale with severity levels (Low / Medium / High / Critical)
- **REST API** with auto-generated OpenAPI documentation
- **Interactive dashboard** with Chart.js visualizations and Wolters Kluwer branding

---

## Architecture

```
                          ┌──────────────────────┐
                          │      Client           │
                          │  (Browser / curl)     │
                          └──────────┬────────────┘
                                     │
                          ┌──────────▼────────────┐
                          │      FastAPI App       │
                          │                        │
                          │  GET  /dashboard       │
                          │  POST /api/scan        │
                          │  GET  /api/reports     │
                          │  GET  /api/reports/:id │
                          └──────────┬────────────┘
                                     │
                 ┌───────────────────▼───────────────────┐
                 │            Audit Engine               │
                 │                                       │
                 │  ┌─────────┐   ┌─────────┐           │
                 │  │ Parser  │──▶│  Rules  │           │
                 │  │ (HCL2/  │   │ (17     │           │
                 │  │  YAML/  │   │  checks)│           │
                 │  │  JSON)  │   └────┬────┘           │
                 │  └─────────┘        │                │
                 │              ┌──────▼──────┐         │
                 │              │   Scorer    │         │
                 │              │ (weighted   │         │
                 │              │  0-100)     │         │
                 │              └──────┬──────┘         │
                 │                     │                │
                 │              ┌──────▼──────┐         │
                 │              │  Auditor    │         │
                 │              │ (orchestr.) │         │
                 │              └─────────────┘         │
                 └───────────────────┬───────────────────┘
                                     │
                          ┌──────────▼────────────┐
                          │   SQLite Database      │
                          │   (auditor.db)         │
                          │                        │
                          │   scans    findings    │
                          └────────────────────────┘
```

---

## Tech Stack

| Component | Technology | Why |
|-----------|-----------|-----|
| Runtime | Python 3.11+ | Enterprise standard, rich security ecosystem |
| Web Framework | FastAPI | Async-ready, auto-generated OpenAPI docs, type-safe |
| Database | SQLite | Zero-config, free, single-file — perfect for auditor MVP |
| ORM | SQLAlchemy 2.0 | Industry standard, migration-ready for Postgres scale-up |
| Terraform Parser | python-hcl2 | Parses HCL2 syntax into Python dicts |
| CloudFormation Parser | PyYAML + json | Native YAML/JSON parsing for CF templates |
| Dashboard | Jinja2 + Chart.js | Server-rendered HTML with interactive charts |
| Typography | Fira Sans + Fira Code | Google Fonts — matches WK corporate feel |
| Testing | pytest + httpx | FastAPI-native test client, fixture-based design |

---

## Security Rules

| Rule ID | Severity | Weight | What It Checks |
|---------|----------|--------|----------------|
| S3-001 | Critical | 10 | S3 bucket with public ACL / AccessControl |
| S3-002 | High | 7 | S3 bucket missing server-side encryption |
| SG-001 | Critical | 10 | Security group allows SSH (port 22) from 0.0.0.0/0 |
| SG-002 | High | 7 | Security group allows any port from 0.0.0.0/0 |
| EC2-001 | Medium | 4 | EC2 instance without IMDSv2 enforcement |
| IAM-001 | Critical | 10 | IAM policy with wildcard `Action: "*"` |
| RDS-001 | Critical | 10 | RDS instance publicly accessible |
| RDS-002 | High | 7 | RDS instance without encryption at rest |
| LOG-001 | High | 7 | No CloudTrail resource found |
| EBS-001 | Medium | 4 | EBS volume without encryption |

**10 Terraform rules + 7 CloudFormation rules = 17 total checks**

CloudFormation rules cover: S3-001, S3-002, SG-001, SG-002, RDS-001, RDS-002, IAM-001

---

## Risk Scoring

**Formula:**

```
risk_score = min((sum_of_triggered_weights / MAX_WEIGHT) × 100, 100)
```

Where `MAX_WEIGHT = 76` (sum of all rule weights assuming each fires once).

**Threshold Levels:**

| Score Range | Risk Level | Color |
|-------------|------------|-------|
| 0 – 25 | Low | Green (#6db33f) |
| 26 – 50 | Medium | Yellow (#f5c623) |
| 51 – 75 | High | Orange (#f5a623) |
| 76 – 100 | Critical | Red (#e31937) |

---

## Development Methodology

### Test-Driven Development (TDD)

I specified behavior as executable tests first, then directed the AI to implement code that passes those specifications. The test suite served as a contract — 119 automated tests defining exactly what the system should do before any implementation existed.

This approach ensures:
- Every feature has verification before it's built
- Edge cases are considered upfront (empty files, malformed input, missing keys)
- Refactoring is safe — any regression is caught immediately

### Design System Specification

I analyzed the Wolters Kluwer brand identity — extracting colors from the corporate globe logo (blues, greens, red accent), selecting typography (Fira Sans), and defining component specs. I directed the AI to create a formal DESIGN.md following the google-labs-code/design.md specification format with these brand values.

Later, the AI read this same spec and generated a pixel-consistent branded dashboard — demonstrating that a well-defined design contract enables reproducible UI output from AI agents.

The DESIGN.md includes:
- YAML front matter with all design tokens (colors, typography, spacing, radii, components)
- Component specifications (header, stat-card, severity-badge, upload-zone, data-table)
- Do's and Don'ts section enforcing brand consistency

### Vibe Coding

All code was generated through AI prompting — zero manual edits. The DESIGN.md and test suite served as contracts that the AI had to satisfy. Every prompt is logged in `prompts.md` as an audit trail of the complete build process.

---

## Test Coverage

**119 automated tests across 6 modules — all passing**

| Module | Tests | What It Verifies |
|--------|-------|-----------------|
| test_parser.py | 18 | Format detection, Terraform HCL/JSON parsing, CloudFormation YAML/JSON parsing, edge cases (empty, malformed) |
| test_rules.py | 68 | All 17 security rules: fires when misconfigured, silent when correct, edge cases (missing keys, string CIDRs, port ranges) |
| test_scorer.py | 12 | Risk score boundaries at 25/50/75, cap at 100, rounding, severity counting |
| test_auditor.py | 7 | End-to-end: clean config (score 0), moderate (5 findings), terrible (13 findings, score 100), CloudFormation (10 findings) |
| test_api_scan.py | 8 | File upload, response schema, database persistence, severity breakdown, filename preservation |
| test_api_reports.py | 6 | Report listing, detail retrieval, 404 handling, findings inclusion, date ordering |

```
========================= 119 passed in 0.20s =========================
```

---

## Demo Results

Scans of four sample configurations:

| File | Type | Findings | Score | Level |
|------|------|----------|-------|-------|
| clean.tf | Terraform | 0 | 0.0 | Low |
| moderate_risk.tf | Terraform | 5 | 38.2 | Medium |
| terrible.tf | Terraform | 13 | 100.0 | Critical |
| bad_cloudformation.yaml | CloudFormation | 10 | 100.0 | Critical |

**terrible.tf breakdown:** 5 Critical (2× public S3, SSH open, wildcard IAM, public RDS) + 6 High (2× unencrypted S3, wide-open SG, RDP open, unencrypted RDS, no CloudTrail) + 2 Medium (no IMDSv2, unencrypted EBS)

---

## Future Enhancements

| Enhancement | Value |
|-------------|-------|
| **CI/CD Integration** | GitHub Actions / GitLab CI pipeline step — block merges with Critical findings |
| **Custom Rules YAML** | User-defined rules via YAML config — extensible without code changes |
| **Multi-Cloud** | Azure ARM templates, GCP Deployment Manager support |
| **SARIF Output** | Static Analysis Results Interchange Format — integrates with GitHub Code Scanning |
| **Auto-Remediation** | Generate fixed config files alongside findings |
| **Policy-as-Code** | OPA/Rego integration for complex policy expressions |
| **Historical Trending** | Track security posture over time across teams and projects |

---

## Summary

- **Problem:** IaC misconfigurations are the #1 cause of cloud security breaches
- **Solution:** API-first Python scanner with 17 rules, dual-format support, risk scoring
- **Quality:** 119 automated tests, TDD methodology, formal design system specification
- **Approach:** 100% AI-generated code via vibe coding — zero manual edits
- **Stack:** FastAPI + SQLite + python-hcl2 + Chart.js — all free, all open source

**Repository:** github.com/felipecpaiva/wk-security-auditor
