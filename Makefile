.PHONY: dev test migrate seed lint build up down logs clean

# ── Dev ──────────────────────────────────────────────────────────
dev:
	cd backend && uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload

dev-docker:
	docker compose up api worker_scans worker_reports --build

# ── Docker ───────────────────────────────────────────────────────
up:
	docker compose up -d

down:
	docker compose down

build:
	docker compose build

logs:
	docker compose logs -f

# ── Database ─────────────────────────────────────────────────────
migrate:
	cd backend && alembic upgrade head

migrate-create:
	cd backend && alembic revision --autogenerate -m "$(name)"

migrate-down:
	cd backend && alembic downgrade -1

seed:
	cd backend && python scripts/seed_rules.py

# ── Testing ──────────────────────────────────────────────────────
test:
	cd backend && pytest tests/ -v --tb=short

test-scanners:
	cd backend && pytest tests/test_scanners/ -v

test-api:
	cd backend && pytest tests/test_api/ -v

test-coverage:
	cd backend && pytest tests/ --cov=app --cov-report=html --cov-report=term

# ── Code Quality ─────────────────────────────────────────────────
lint:
	cd backend && flake8 app/ --max-line-length=120
	cd backend && black app/ --check
	cd backend && isort app/ --check-only

format:
	cd backend && black app/
	cd backend && isort app/

security-scan:
	cd backend && bandit -r app/ -ll

# ── Celery ───────────────────────────────────────────────────────
worker-scans:
	cd backend && celery -A app.workers.celery_app worker --loglevel=info -Q scans -c 3

worker-reports:
	cd backend && celery -A app.workers.celery_app worker --loglevel=info -Q reports,remediation -c 2

flower:
	cd backend && celery -A app.workers.celery_app flower --port=5555

# ── Cleanup ───────────────────────────────────────────────────────
clean:
	docker compose down -v
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -name "*.pyc" -delete 2>/dev/null || true
	find . -type d -name ".pytest_cache" -exec rm -rf {} + 2>/dev/null || true

# ── Real-world Lab Testing ────────────────────────────────────────
lab-setup:
	cd testing && python setup_lab.py --region us-east-1

lab-setup-dry:
	cd testing && python setup_lab.py --dry-run

lab-cleanup:
	cd testing && python cleanup.py

lab-test:
	@echo "Usage: make lab-test SCAN_ID=<uuid>"
	cd testing && python test_runner.py --scan-id $(SCAN_ID)

lab-full-test:
	@echo "Usage: make lab-full-test ACCOUNT_ID=<uuid>"
	cd testing && python test_runner.py --account-id $(ACCOUNT_ID)

# ── Celery Beat ───────────────────────────────────────────────────
beat:
	cd backend && celery -A app.workers.celery_app beat --loglevel=info

beat-docker:
	docker compose up celery_beat -d

# ── Alert test ────────────────────────────────────────────────────
test-discord:
	cd backend && python -c "
import asyncio, sys; sys.path.insert(0,'.')
from app.core.alerts import _send_discord
asyncio.run(_send_discord({'account_name':'Test Account','provider':'aws','risk_score':85,'resources_scanned':42,'duration_seconds':120,'scan_id':'test-123','critical_findings':3,'high_findings':5,'medium_findings':8,'low_findings':4}, []))
print('Discord test sent')
"
