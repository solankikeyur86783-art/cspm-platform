"""
Real-time scan progress via Server-Sent Events (SSE).
Clients can subscribe to scan progress without polling.
"""
import asyncio
import json
import uuid
from datetime import datetime, timezone

from fastapi import APIRouter
from fastapi.responses import StreamingResponse
from sqlalchemy import select

from app.api.deps import CurrentUser, DB
from app.core.redis_client import get_redis
from app.models.scan import Scan
from app.models.cloud_account import CloudAccount

router = APIRouter(prefix="/sse", tags=["Real-time"])


@router.get("/scans/{scan_id}/progress")
async def scan_progress_sse(
    scan_id: uuid.UUID,
    current_user: CurrentUser,
    db: DB,
):
    """
    SSE stream for real-time scan progress.
    Connect with: EventSource('/api/v1/sse/scans/{id}/progress')
    """
    # Verify ownership
    result = await db.execute(
        select(Scan)
        .join(CloudAccount, Scan.cloud_account_id == CloudAccount.id)
        .where(Scan.id == scan_id, CloudAccount.owner_id == current_user.id)
    )
    scan = result.scalar_one_or_none()
    if not scan:
        from fastapi import HTTPException, status
        raise HTTPException(status_code=404, detail="Scan not found")

    async def event_generator():
        r = await get_redis()
        pubsub = r.pubsub()
        await pubsub.subscribe(f"scan:{scan_id}")

        # Send current state immediately
        from app.core.redis_client import cache
        current = await cache.get_scan_status(str(scan_id)) or {
            "status": scan.status,
            "progress": scan.progress,
        }
        yield f"data: {json.dumps(current)}\n\n"

        # Terminal statuses — no need to stream
        if scan.status in ("completed", "failed", "cancelled"):
            await pubsub.unsubscribe(f"scan:{scan_id}")
            return

        timeout = 600  # 10 min max stream
        elapsed = 0
        interval = 2

        try:
            while elapsed < timeout:
                message = await pubsub.get_message(ignore_subscribe_messages=True, timeout=interval)
                if message and message.get("type") == "message":
                    data = message.get("data", "{}")
                    yield f"data: {data}\n\n"

                    parsed = json.loads(data) if isinstance(data, str) else data
                    if parsed.get("status") in ("completed", "failed", "cancelled"):
                        break
                else:
                    # Send heartbeat to keep connection alive
                    yield f": heartbeat {datetime.now(timezone.utc).isoformat()}\n\n"

                elapsed += interval
                await asyncio.sleep(0)

        finally:
            await pubsub.unsubscribe(f"scan:{scan_id}")
            await pubsub.aclose()

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
            "Connection": "keep-alive",
        },
    )
