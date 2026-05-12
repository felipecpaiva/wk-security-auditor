# Enterprise Security Guardrail Auditor

A Python-based, API-first tool for auditing Terraform and CloudFormation infrastructure configurations against security baselines. Built with FastAPI, SQLite, and a Wolters Kluwer-branded dashboard.

## Features

- **17 security rules** covering S3, Security Groups, EC2, IAM, RDS, CloudTrail, and EBS
- **Risk scoring** (0-100) with severity levels: Low, Medium, High, Critical
- **REST API** with OpenAPI docs at `/docs`
- **Interactive dashboard** with Chart.js visualizations
- **Supports** Terraform (.tf, .tf.json) and CloudFormation (.json, .yaml, .yml)

## Quick Start

```bash
# Clone
git clone https://github.com/felipecpaiva/wk-security-auditor.git
cd wk-security-auditor

# Set up virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Run the server
uvicorn app.main:app --reload --port 8000

# Open dashboard
open http://localhost:8000/dashboard
```

## Usage

### Scan a file via API

```bash
curl -X POST http://localhost:8000/api/scan \
  -F "file=@sample_configs/terrible.tf"
```

### View reports

```bash
# List all scans
curl http://localhost:8000/api/reports

# Get specific report with findings
curl http://localhost:8000/api/reports/1
```

### Run tests

```bash
pytest
```

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/` | Health check |
| `GET` | `/dashboard` | Interactive dashboard |
| `POST` | `/api/scan` | Upload file for audit |
| `GET` | `/api/reports` | List all scan reports |
| `GET` | `/api/reports/{id}` | Get report with findings |

## Tech Stack

- **Python 3.11+** / FastAPI / Uvicorn
- **SQLite** via SQLAlchemy 2.0
- **python-hcl2** for Terraform parsing
- **PyYAML** for CloudFormation parsing
- **Jinja2 + Chart.js** for the dashboard
- **pytest + httpx** for testing

## Security Rules

| ID | Severity | Description |
|----|----------|-------------|
| S3-001 | Critical | Public S3 bucket ACL |
| S3-002 | High | S3 without encryption |
| SG-001 | Critical | SSH open to 0.0.0.0/0 |
| SG-002 | High | Wide-open security group |
| EC2-001 | Medium | No IMDSv2 enforcement |
| IAM-001 | Critical | Wildcard IAM actions |
| RDS-001 | Critical | Public RDS instance |
| RDS-002 | High | RDS without encryption |
| LOG-001 | High | Missing CloudTrail |
| EBS-001 | Medium | Unencrypted EBS volume |
