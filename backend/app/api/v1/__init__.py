from fastapi import APIRouter

from app.api.v1 import (
    auth, accounts, scans, findings, dashboard,
    reports, compliance, remediation, sse, admin,
)

api_router = APIRouter()

api_router.include_router(auth.router)
api_router.include_router(accounts.router)
api_router.include_router(scans.router)
api_router.include_router(findings.router)
api_router.include_router(dashboard.router)
api_router.include_router(reports.router)
api_router.include_router(compliance.router)
api_router.include_router(remediation.router)
api_router.include_router(sse.router)
api_router.include_router(admin.router)
