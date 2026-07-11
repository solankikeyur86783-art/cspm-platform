from celery import Celery
from celery.schedules import crontab
from app.core.config import settings

celery_app = Celery(
    "cspm",
    broker=settings.CELERY_BROKER_URL,
    backend=settings.CELERY_RESULT_BACKEND,
    include=[
        "app.workers.scan_tasks",
        "app.workers.report_tasks",
        "app.workers.remediation_tasks",
    ],
)

celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    task_acks_late=True,
    worker_prefetch_multiplier=1,
    task_routes={
        "app.workers.scan_tasks.*":        {"queue": "scans"},
        "app.workers.report_tasks.*":      {"queue": "reports"},
        "app.workers.remediation_tasks.*": {"queue": "remediation"},
    },
    task_soft_time_limit=settings.SCAN_TIMEOUT_SECONDS,
    task_time_limit=settings.SCAN_TIMEOUT_SECONDS + 60,

    # ── Celery Beat schedule — automatic scans ────────────────────────
    beat_schedule={
        # Scan ALL active accounts every 30 minutes
        "auto-scan-all-accounts": {
            "task": "app.workers.scan_tasks.scan_all_active_accounts",
            "schedule": crontab(minute="*/30"),
        },
        # Daily compliance PDF report at 8 AM UTC
        "daily-compliance-report": {
            "task": "app.workers.report_tasks.generate_daily_reports",
            "schedule": crontab(hour=8, minute=0),
        },
        # Weekly full scan every Sunday at 2 AM UTC
        "weekly-full-scan": {
            "task": "app.workers.scan_tasks.scan_all_active_accounts",
            "schedule": crontab(hour=2, minute=0, day_of_week="sunday"),
            "kwargs": {"config": {"scan_type": "full"}},
        },
    },
    beat_scheduler="celery.beat.PersistentScheduler",
)
