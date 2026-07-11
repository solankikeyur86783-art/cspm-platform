# CSPM Real-World Testing Guide
## 10 Scenarios — Full Implementation

---

## Prerequisites

```bash
# AWS free tier account at aws.amazon.com
# Python 3.11+, Docker, AWS CLI configured
aws configure   # enter your Access Key ID + Secret

pip install boto3 httpx --break-system-packages
```

---

## Step 1 — Start Your CSPM Platform

```bash
cd cspm-platform
docker compose up --build -d
docker compose exec api python scripts/seed_rules.py
# API → http://localhost:8000/docs
```

---

## Step 2 — Create the Lab (10 Misconfigs in AWS)

```bash
cd cspm-testing/lab_setup

# Preview what will be created (no AWS calls)
python setup_lab.py --dry-run

# Create all 10 misconfigured resources
python setup_lab.py --region us-east-1
```

Expected output:
```
[Scenario 1]  Public S3 Bucket          ✅ created
[Scenario 2]  Open SSH Security Group   ✅ created
[Scenario 3]  Open RDP Security Group   ✅ created
[Scenario 4]  IAM Admin User            ✅ created
[Scenario 5]  Root MFA check            ⚠️  check manually
[Scenario 6]  CloudTrail disabled       ✅ created + stopped
[Scenario 7]  Unencrypted EBS           ✅ created
[Scenario 8]  Public RDS               ✅ creating (5 min)
[Scenario 9]  Secret no rotation        ✅ created
[Scenario 10] S3 no encryption          ✅ created
```

---

## Step 3 — Add SecretsManager Scanner (Scenario 9)

```bash
# Copy the new scanner into your backend
cp cspm-testing/lab_setup/secrets_manager_scanner.py \
   cspm-platform/backend/app/scanners/aws/secrets_manager.py

# Add to cspm-platform/backend/app/scanners/aws/__init__.py:
from app.scanners.aws.secrets_manager import AWSSecretsManagerScanner

AWS_SCANNERS = [
    AWSIAMScanner,
    AWSS3Scanner,
    AWSEC2Scanner,
    AWSRDSScanner,
    AWSVPCScanner,
    AWSCloudTrailScanner,
    AWSSecretsManagerScanner,   # ← ADD THIS
]

# Rebuild and restart
docker compose up --build -d api worker_scans
```

---

## Step 4 — Register Your AWS Account in CSPM

```bash
# In Swagger UI (http://localhost:8000/docs):

# 1. Login
POST /api/v1/auth/login
{"email":"admin@cspm.local","password":"Admin@CSPM123"}

# 2. Register your AWS account
POST /api/v1/accounts
{
  "name": "CSPM Lab AWS",
  "provider": "aws",
  "aws_account_id": "YOUR_ACCOUNT_ID",
  "aws_role_arn": "arn:aws:iam::YOUR_ACCOUNT_ID:role/CSPMScannerRole",
  "aws_regions": ["us-east-1"]
}

# 3. Validate credentials
POST /api/v1/accounts/{id}/validate
```

### Create the scanner IAM role (one-time)
```bash
# In AWS Console → IAM → Roles → Create Role
# Trust entity: Your IAM user (or EC2 instance)
# Attach policy: SecurityAudit (AWS managed, read-only)
# Name: CSPMScannerRole
```

---

## Step 5 — Trigger a Scan

```bash
# Via Swagger or curl:
curl -X POST http://localhost:8000/api/v1/scans \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"cloud_account_id":"YOUR_ACCOUNT_UUID"}'

# Watch progress in Flower: http://localhost:5555
# Scan takes 2-5 minutes
```

---

## Step 6 — Run Automated Test Validation

```bash
cd cspm-testing/test_runner

# Validate against an existing completed scan
python test_runner.py \
  --api http://localhost:8000 \
  --scan-id YOUR_SCAN_UUID

# OR trigger + validate in one command
python test_runner.py \
  --api http://localhost:8000 \
  --account-id YOUR_ACCOUNT_UUID
```

### Expected output:
```
SCENARIO 1 — Public S3 Bucket
  ✅ PASS [HIGH]   Public S3 bucket detected (CIS-S3-2.1.1)
  ✅ PASS          Finding has Resource ID
  ✅ PASS          Finding has Evidence
  ✅ PASS          Finding has CIS mapping
  ✅ PASS          Finding has remediation steps

SCENARIO 2 — Open SSH Security Group
  ✅ PASS [HIGH]   Open SSH (port 22) detected (CIS-EC2-5.2)

SCENARIO 3 — Open RDP Security Group
  ✅ PASS [CRITICAL] Open RDP (port 3389) detected as CRITICAL

...

RESULTS SUMMARY
  Scenarios passed : 18/19
  Total findings   : 34
  ├─ Critical : 5
  ├─ High     : 8
  └─ Medium   : 12
  Overall: ✅ ALL SCENARIOS PASSING
```

---

## Step 7 — Set Up Alerts

### Discord (free)
```bash
# 1. Create a Discord server → channel → Edit channel → Integrations → Webhooks
# 2. Add to backend/.env:
DISCORD_WEBHOOK_URL=https://discord.com/api/webhooks/YOUR/WEBHOOK

# 3. Copy alerts.py to backend/app/
cp cspm-testing/alerts/alerts.py cspm-platform/backend/app/core/alerts.py

# 4. Add to end of _execute_scan() in backend/app/workers/scan_tasks.py:
from app.core.alerts import send_scan_alerts
await send_scan_alerts(scan, enriched_findings)
```

### Email (Gmail SMTP)
```bash
# Add to backend/.env:
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=yourmail@gmail.com
SMTP_PASSWORD=your-app-password   # Gmail → App Passwords
ALERT_EMAIL=alerts@yourcompany.com
```

---

## Step 8 — Schedule Automatic Scans (every 30 min)

```bash
# Add celery_beat service to docker-compose.yml (see scheduled_scans.py)
docker compose up celery_beat -d

# Verify beat is running
docker compose logs celery_beat -f
# Should see: "Scheduler: Sending due task auto-scan-all-accounts"
```

---

## Step 9 — Verify Before/After

```bash
# Fix one finding — block S3 public access
aws s3api put-public-access-block \
  --bucket cspm-lab-public-bucket-XXXX \
  --public-access-block-configuration \
  BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true

# Trigger a new scan and compare:
# Before: Finding CIS-S3-2.1.1 OPEN
# After:  Finding CIS-S3-2.1.1 RESOLVED
# This is your placement demo money shot ↑
```

---

## Step 10 — Cleanup Lab Resources

```bash
python cspm-testing/lab_setup/cleanup.py
# Reads lab_manifest.json and deletes all 10 resources
# ⚠️ RDS deletion takes ~5 min in background
```

---

## Expected Finding Coverage

| # | Scenario | Rule ID | Severity | Our Scanner |
|---|----------|---------|----------|-------------|
| 1 | Public S3 bucket | CIS-S3-2.1.1 | HIGH | ✅ AWSS3Scanner |
| 2 | SSH open SG | CIS-EC2-5.2 | HIGH | ✅ AWSEC2Scanner |
| 3 | RDP open SG | CIS-EC2-5.3 | CRITICAL | ✅ AWSEC2Scanner |
| 4 | IAM admin user | CIS-IAM-1.16 | HIGH | ✅ AWSIAMScanner |
| 5 | Root no MFA | CIS-IAM-1.5 | CRITICAL | ✅ AWSIAMScanner |
| 6 | CloudTrail off | CIS-CT-2.1 | CRITICAL | ✅ AWSCloudTrailScanner |
| 7 | Unencrypted EBS | EC2-EBS-001 | MEDIUM | ✅ AWSEC2Scanner |
| 8 | Public RDS | CIS-RDS-2.3.2 | HIGH | ✅ AWSRDSScanner |
| 9 | No SM rotation | SM-ROTATION-001 | MEDIUM | ✅ AWSSecretsManagerScanner (add) |
| 10 | S3 no encryption | CIS-S3-2.1.2 | MEDIUM | ✅ AWSS3Scanner |

---

## Deliverables Checklist (per your guide)

- [x] FastAPI backend — `cspm-platform/backend/`
- [x] PostgreSQL — Docker service `cspm_postgres`
- [x] Docker — `docker-compose.yml` with full stack
- [x] PDF/JSON reports — `/api/v1/reports`
- [x] Discord/Email alerts — `cspm-platform/backend/app/core/alerts.py`
- [x] Scheduled scans — Celery Beat every 30 min
- [x] On-demand scans — `POST /api/v1/scans`
- [x] Resource ID + Severity + Evidence + CIS + MITRE + Remediation — all in Finding model
- [ ] React dashboard — build separately (see `cspm-platform/frontend/`)
- [ ] GitHub README with screenshots — add after running scans
