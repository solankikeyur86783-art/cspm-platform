"""
Custom FastAPI middleware stack.
"""
import time
import uuid
from typing import Callable

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware

from app.core.logging import logger


class RequestLoggingMiddleware(BaseHTTPMiddleware):
    """Log every request with method, path, status, and duration."""

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        request_id = str(uuid.uuid4())[:8]
        request.state.request_id = request_id

        start = time.perf_counter()
        response = await call_next(request)
        duration_ms = (time.perf_counter() - start) * 1000

        # Skip health checks to reduce noise
        if request.url.path not in ("/health", "/health/deep"):
            logger.info(
                f"[{request_id}] {request.method} {request.url.path} "
                f"→ {response.status_code} ({duration_ms:.1f}ms)"
            )

        response.headers["X-Request-ID"] = request_id
        response.headers["X-Response-Time"] = f"{duration_ms:.1f}ms"
        return response


class RateLimitMiddleware(BaseHTTPMiddleware):
    """
    Simple in-memory rate limiter for auth endpoints.
    Production: use Redis sliding window instead.
    """
    RATE_LIMIT_PATHS = {"/api/v1/auth/login": 10, "/api/v1/auth/register": 5}
    WINDOW_SECONDS = 60

    def __init__(self, app, enabled: bool = True):
        super().__init__(app)
        self._counters: dict = {}
        self.enabled = enabled

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        if not self.enabled:
            return await call_next(request)

        path = request.url.path
        limit = self.RATE_LIMIT_PATHS.get(path)
        if not limit:
            return await call_next(request)

        client_ip = request.client.host if request.client else "unknown"
        key = f"{client_ip}:{path}"
        now = time.time()

        if key not in self._counters:
            self._counters[key] = []

        # Sliding window cleanup
        self._counters[key] = [t for t in self._counters[key] if now - t < self.WINDOW_SECONDS]

        if len(self._counters[key]) >= limit:
            from fastapi.responses import JSONResponse
            from fastapi import status
            logger.warning(f"Rate limit hit: {client_ip} on {path}")
            return JSONResponse(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                content={
                    "code": "RATE_LIMITED",
                    "message": f"Too many requests. Limit: {limit} per {self.WINDOW_SECONDS}s.",
                },
                headers={"Retry-After": str(self.WINDOW_SECONDS)},
            )

        self._counters[key].append(now)
        return await call_next(request)


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Inject security headers on every response."""

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        return response
