# Architecture — Enterprise Security Guardrail Auditor

## Problem Statement

Infrastructure-as-Code (IaC) has become the standard for provisioning cloud resources. Teams define their AWS infrastructure in Terraform (.tf) and CloudFormation (.json/.yaml) templates, then apply them through CI/CD pipelines. But misconfigurations in these templates — public S3 buckets, open security groups, unencrypted databases, wildcard IAM policies — are the #1 cause of cloud security breaches.

Manual code review doesn't scale. Security teams can't inspect every Terraform plan before it reaches production. Organizations need automated guardrails that catch dangerous patterns before deployment.

## Solution

A **Python-based security auditor** that parses Terraform and CloudFormation configuration files, evaluates them against a rule-based security baseline, and produces:

- A **risk score** (0-100) with severity level (Low / Medium / High / Critical)
- **Itemized findings** with rule IDs, descriptions, and remediation guidance
- A **dashboard** for visual analysis of scan history and severity trends

The tool is API-first — the REST API is the primary interface, with the dashboard consuming it.

## Architecture Diagram

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

## Tech Stack

| Component | Technology | Rationale |
|-----------|-----------|-----------|
| Runtime | Python 3.11+ | Enterprise standard, rich security ecosystem |
| Web Framework | FastAPI | Async-ready, auto-generated OpenAPI docs, type-safe |
| Database | SQLite | Zero-config, free, single-file — perfect for auditor MVP |
| ORM | SQLAlchemy 2.0 | Industry standard, migration-ready if we scale to Postgres |
| Terraform Parser | python-hcl2 | Parses HCL2 syntax into Python dicts |
| CloudFormation Parser | PyYAML + json | Native YAML/JSON parsing for CF templates |
| Dashboard | Jinja2 + Chart.js | Server-rendered HTML with interactive charts |
| Typography | Fira Sans + Fira Code | Google Fonts — matches Wolters Kluwer corporate feel |
| Testing | pytest + httpx | FastAPI-native test client, fixture-based test design |

## Security Rules

10 rules for Terraform, 7 for CloudFormation (17 total):

| Rule ID | Severity | Weight | What It Checks |
|---------|----------|--------|----------------|
| S3-001 | Critical | 10 | S3 bucket with public ACL (TF) or public AccessControl (CF) |
| S3-002 | High | 7 | S3 bucket missing server-side encryption |
| SG-001 | Critical | 10 | Security group allows SSH (port 22) from 0.0.0.0/0 |
| SG-002 | High | 7 | Security group allows any port from 0.0.0.0/0 |
| EC2-001 | Medium | 4 | EC2 instance without IMDSv2 enforcement (TF only) |
| IAM-001 | Critical | 10 | IAM policy with wildcard `Action: "*"` |
| RDS-001 | Critical | 10 | RDS instance with `publicly_accessible = true` |
| RDS-002 | High | 7 | RDS instance without encryption at rest |
| LOG-001 | High | 7 | No CloudTrail resource found (TF only) |
| EBS-001 | Medium | 4 | EBS volume without encryption (TF only) |

**MAX_WEIGHT** = 76 (sum of all rule weights assuming each fires once).

## Risk Score Formula

```
risk_score = min((sum_of_triggered_weights / MAX_WEIGHT) * 100, 100)
```

| Score Range | Risk Level |
|-------------|------------|
| 0 – 25 | Low |
| 26 – 50 | Medium |
| 51 – 75 | High |
| 76 – 100 | Critical |

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/` | Health check — returns app info and links |
| `GET` | `/dashboard` | Server-rendered HTML dashboard |
| `POST` | `/api/scan` | Upload a file for security audit (multipart form) |
| `GET` | `/api/reports` | List all scan reports (newest first) |
| `GET` | `/api/reports/{scan_id}` | Get a specific report with findings |

## Database Schema

### `scans` table

| Column | Type | Description |
|--------|------|-------------|
| id | INTEGER PK | Auto-increment scan ID |
| filename | TEXT | Uploaded filename |
| file_type | TEXT | "terraform" or "cloudformation" |
| risk_score | REAL | 0.0 – 100.0 |
| risk_level | TEXT | Low / Medium / High / Critical |
| total_findings | INTEGER | Count of all findings |
| critical_count | INTEGER | Count of Critical findings |
| high_count | INTEGER | Count of High findings |
| medium_count | INTEGER | Count of Medium findings |
| low_count | INTEGER | Count of Low findings |
| scanned_at | DATETIME | UTC timestamp |

### `findings` table

| Column | Type | Description |
|--------|------|-------------|
| id | INTEGER PK | Auto-increment finding ID |
| scan_id | INTEGER FK | References scans.id |
| rule_id | TEXT | e.g., "S3-001" |
| severity | TEXT | Critical / High / Medium / Low |
| resource_type | TEXT | e.g., "aws_s3_bucket" |
| resource_name | TEXT | e.g., "public_dump" |
| description | TEXT | What's wrong |
| remediation | TEXT | How to fix it |

## Directory Structure

```
wk-security-auditor/
├── app/
│   ├── __init__.py
│   ├── main.py              # FastAPI app, dashboard route
│   ├── db.py                # SQLAlchemy engine, session, Base
│   ├── models.py            # Scan + Finding ORM models
│   ├── api/
│   │   ├── __init__.py
│   │   ├── scan.py          # POST /api/scan
│   │   └── reports.py       # GET /api/reports, /api/reports/:id
│   └── engine/
│       ├── __init__.py
│       ├── parser.py         # Terraform HCL + CloudFormation parsers
│       ├── rules.py          # 17 security check functions
│       ├── scorer.py         # Risk score calculator
│       └── auditor.py        # Orchestrator: parse → check → score
├── tests/
│   ├── __init__.py
│   ├── conftest.py           # Shared fixtures (in-memory DB, sample configs)
│   ├── test_parser.py
│   ├── test_rules.py
│   ├── test_scorer.py
│   ├── test_auditor.py
│   ├── test_api_scan.py
│   └── test_api_reports.py
├── sample_configs/
│   ├── clean.tf              # Passes all checks (score 0)
│   ├── moderate_risk.tf      # Some findings (score ~30-50)
│   ├── terrible.tf           # Fails most checks (score ~90)
│   └── bad_cloudformation.yaml
├── templates/
│   └── dashboard.html        # Jinja2 template with Chart.js
├── static/                   # Static assets (CSS/JS if extracted)
├── DESIGN.md                 # Design system specification
├── ARCHITECTURE.md           # This file
├── requirements.txt
├── pytest.ini
├── prompts.md                # AI prompt audit log
└── .gitignore
```
