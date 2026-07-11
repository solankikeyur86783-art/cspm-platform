from functools import lru_cache
from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import AnyHttpUrl, field_validator
from typing import List


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # ── App ──────────────────────────────────────────
    APP_NAME: str = "CSPM Platform"
    APP_ENV: str = "development"
    DEBUG: bool = False
    SECRET_KEY: str = "change-me-in-production"
    API_V1_PREFIX: str = "/api/v1"
    ALLOWED_ORIGINS: str = "http://localhost:3000,http://localhost:5173"

    @property
    def cors_origins(self) -> List[str]:
        return [o.strip() for o in self.ALLOWED_ORIGINS.split(",")]

    # ── Database ─────────────────────────────────────
    DATABASE_URL: str = "postgresql+asyncpg://cspm:cspm_pass@localhost:5432/cspm_db"
    SYNC_DATABASE_URL: str = "postgresql+psycopg2://cspm:cspm_pass@localhost:5432/cspm_db"
    DB_POOL_SIZE: int = 10
    DB_MAX_OVERFLOW: int = 20

    # ── Redis / Celery ───────────────────────────────
    REDIS_URL: str = "redis://localhost:6379/0"
    CELERY_BROKER_URL: str = "redis://localhost:6379/1"
    CELERY_RESULT_BACKEND: str = "redis://localhost:6379/2"

    # ── JWT ──────────────────────────────────────────
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7

    # ── AWS ──────────────────────────────────────────
    AWS_SCANNER_ROLE_ARN: str = ""
    AWS_REGION: str = "us-east-1"

    # ── GCP ──────────────────────────────────────────
    GCP_PROJECT_ID: str = ""
    GOOGLE_APPLICATION_CREDENTIALS: str = ""

    # ── Azure ────────────────────────────────────────
    AZURE_TENANT_ID: str = ""
    AZURE_CLIENT_ID: str = ""
    AZURE_CLIENT_SECRET: str = ""
    AZURE_SUBSCRIPTION_ID: str = ""

    # ── AI ───────────────────────────────────────────
    GROQ_API_KEY: str = ""
    GROQ_MODEL: str = "llama3-70b-8192"
    GROQ_MAX_TOKENS: int = 2048
    GROQ_TEMPERATURE: float = 0.2

    # ── Storage ──────────────────────────────────────
    S3_BUCKET_REPORTS: str = "cspm-reports-bucket"
    S3_REGION: str = "us-east-1"

    # ── Monitoring ───────────────────────────────────
    SENTRY_DSN: str = ""
    ENABLE_METRICS: bool = True

    # ── Alerts ───────────────────────────────────────
    DISCORD_WEBHOOK_URL: str = ""
    ALERT_EMAIL: str = ""
    ALERT_MIN_SEVERITY: str = "high"
    SMTP_HOST: str = ""
    SMTP_PORT: int = 587
    SMTP_USER: str = ""
    SMTP_PASSWORD: str = ""
    FRONTEND_URL: str = "http://localhost:3000"

    # ── Scanner defaults ─────────────────────────────
    SCAN_TIMEOUT_SECONDS: int = 300
    MAX_CONCURRENT_SCANS: int = 5


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
