# 🛡️ CSPM Platform

**Cloud Security Posture Management** — Industrial-grade multi-cloud security scanner built for placement/portfolio showcase.

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.111-green.svg)](https://fastapi.tiangolo.com)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

---

## 🏗️ Architecture

```
cspm-platform/
├── backend/               # FastAPI + Celery Python monorepo
│   ├── app/
│   │   ├── api/v1/       # REST API routes (auth, scans, findings, reports...)
│   │   ├── core/         # Config, DB, Redis, Security, Logging
│   │   ├── models/       # SQLAlchemy async ORM models
│   │   ├── schemas/      # Pydantic v2 request/response schemas
│   │   ├── scanners/     # Multi-cloud scanner modules
│   │   │   ├── aws/      # IAM, S3, EC2, RDS, VPC, CloudTrail
│   │   │   ├── gcp/      # IAM, Storage, Compute
│   │   │   └── azure/    # Storage, IAM, Network
│   │   ├── rules/        # CIS Benchmark rules + compliance mapping
│   │   ├── workers/      # Celery async task workers
│   │   ├── ai/           # Groq AI integration (risk explainer, remediation)
│   │   └── reporting/    # PDF + HTML report generation
│   └── tests/            # pytest suite with moto mocks
├── frontend/              # React + TypeScript dashboard (see frontend/)
├── infra/                 # Terraform + Kubernetes manifests
├── scripts/              # Dev utilities
└── docker-compose.yml    # Full local stack
```

---

## 🚀 Quick Start

### Prerequisites
- Docker & Docker Compose
- Python 3.11+
- AWS account with a read-only IAM role (for real scanning)

### 1. Clone and setup
```bash
git clone <repo>
cd cspm-platform
bash scripts/setup_dev.sh
```

### 2. Configure credentials
```bash
cp backend/.env.example backend/.env
# Edit .env with your cloud credentials and Groq API key
```

### 3. Start everything
```bash
make up          # Start full Docker stack
make dev         # OR run API locally (after starting postgres+redis)
make worker-scans  # Start Celery scan worker
```

### 4. Access
| Service      | URL                          | Credentials              |
|--------------|------------------------------|--------------------------|
| API Docs     | http://localhost:8000/docs   | —                        |
| pgAdmin      | http://localhost:5050        | admin@cspm.local / admin |
| Flower       | http://localhost:5555        | —                        |

---

## 🔍 What It Scans

### AWS (60+ CIS Checks)
| Service     | Rules                                                          |
|-------------|----------------------------------------------------------------|
| IAM         | Root usage, MFA, key rotation, inactive users, password policy |
| S3          | Public access blocks, encryption, versioning, ACLs, logging    |
| EC2         | Open security groups, EBS encryption, IMDSv2, public AMIs      |
| RDS         | Public access, encryption, backups, deletion protection        |
| VPC         | Flow logs, NACL rules, peering, VPN gateways                  |
| CloudTrail  | Multi-region, log validation, CW integration, alarms          |

### GCP (25+ CIS Checks)
| Service  | Rules                                                     |
|----------|-----------------------------------------------------------|
| IAM      | Primitive roles, SA key rotation, admin separation        |
| Storage  | Public access, uniform bucket access, logging, versioning |
| Compute  | OS Login, serial port, public IPs, firewall rules, Shielded VM |

### Azure (20+ CIS Checks)
| Service  | Rules                                                     |
|----------|-----------------------------------------------------------|
| Storage  | Public blob access, HTTPS enforcement, TLS version, soft delete |
| IAM      | Subscription owners, custom role wildcards, guest accounts |
| Network  | NSG unrestricted SSH/RDP, Network Watcher                 |

---

## 📊 API Reference

### Auth
```bash
POST /api/v1/auth/register    # Create account
POST /api/v1/auth/login       # Get JWT tokens
GET  /api/v1/auth/me          # Current user
POST /api/v1/auth/api-key     # Generate API key
```

### Cloud Accounts
```bash
GET    /api/v1/accounts           # List accounts
POST   /api/v1/accounts           # Register cloud account
POST   /api/v1/accounts/{id}/validate  # Validate credentials
```

### Scans
```bash
POST /api/v1/scans              # Start scan
GET  /api/v1/scans              # List scans
GET  /api/v1/scans/{id}         # Scan details
GET  /api/v1/scans/{id}/status  # Live scan status
POST /api/v1/scans/{id}/cancel  # Cancel running scan
```

### Findings
```bash
POST /api/v1/findings/search           # Search/filter findings
GET  /api/v1/findings/{id}             # Finding details
PUT  /api/v1/findings/{id}/suppress    # Suppress finding
PUT  /api/v1/findings/{id}/status      # Update status
```

### Dashboard
```bash
GET /api/v1/dashboard/summary      # Overall posture summary
GET /api/v1/dashboard/risk-trend   # Risk score over time
GET /api/v1/dashboard/top-risks    # Top recurring rules
GET /api/v1/dashboard/compliance   # Compliance framework posture
```

### Compliance
```bash
GET /api/v1/compliance/frameworks          # List frameworks
GET /api/v1/compliance/posture             # All frameworks posture
GET /api/v1/compliance/posture/{framework} # Framework breakdown
```

### Remediation
```bash
GET  /api/v1/remediation/supported-rules        # Auto-remediable rules
POST /api/v1/remediation/execute                # Trigger remediation
GET  /api/v1/remediation/finding/{id}/steps     # Get remediation steps
POST /api/v1/remediation/finding/{id}/ai-remediation  # AI guidance
```

### Reports
```bash
POST /api/v1/reports                # Generate PDF/HTML report
GET  /api/v1/reports                # List reports
GET  /api/v1/reports/{id}/download  # Download report
```

---

## 🧪 Testing

```bash
make test              # All tests
make test-scanners     # Scanner unit tests (moto mocks)
make test-api          # API integration tests
make test-coverage     # Coverage report
```

---

## 🛠️ Tech Stack

| Layer        | Technology                                      |
|--------------|-------------------------------------------------|
| API          | FastAPI 0.111 + uvicorn                        |
| Database     | PostgreSQL 16 + SQLAlchemy async + Alembic      |
| Queue        | Celery 5 + Redis 7                              |
| Auth         | JWT (python-jose) + bcrypt + API keys           |
| AWS Scan     | boto3 + aiobotocore + moto (tests)              |
| GCP Scan     | google-cloud-* SDK                              |
| Azure Scan   | azure-mgmt-* SDK                                |
| AI           | Groq API (llama3-70b) + tenacity retry          |
| Reports      | ReportLab (PDF) + Jinja2 (HTML)                 |
| Compliance   | CIS Benchmarks + MITRE ATT&CK + CVSS v3.1       |
| Infra        | Docker + Docker Compose + Terraform             |
| CI/CD        | GitHub Actions + bandit + trivy                 |

---

## 🔒 Security Design

- **JWT + API Key dual auth** with role-based access (admin/analyst/viewer)
- **Row-level ownership** — users can only see their own cloud accounts and scans
- **Credential isolation** — cloud credentials never stored in DB, referenced via IAM role ARNs
- **Auto-remediation safety** — dry_run=True by default, requires explicit confirmation
- **Scan sandboxing** — read-only IAM role (SecurityAudit policy) for scanners
- **Secrets** — no credentials in code, all via env vars / Secrets Manager

---

## 📈 Compliance Frameworks

| Framework   | Controls Covered                              |
|-------------|-----------------------------------------------|
| CIS AWS     | 60+ checks across IAM, Storage, Compute, Logs |
| CIS GCP     | 25+ checks across IAM, Storage, Compute       |
| CIS Azure   | 20+ checks across Storage, IAM, Network       |
| SOC 2       | CC6, CC7, CC8 control families               |
| HIPAA       | 164.312 access control, audit, encryption     |

---

## 👤 Author

Built as an industrial-grade placement project demonstrating:
- Production-grade Python API design (FastAPI + async SQLAlchemy)
- Multi-cloud security knowledge (AWS CIS Benchmarks, GCP, Azure)
- Distributed systems (Celery + Redis task queue)
- AI integration (Groq LLM for security analysis)
- DevSecOps practices (CI/CD, SAST, container scanning)
