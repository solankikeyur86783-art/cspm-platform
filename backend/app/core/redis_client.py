from typing import Optional, Any
import json
import redis.asyncio as aioredis
from app.core.config import settings
from app.core.logging import logger


_redis: Optional[aioredis.Redis] = None


async def get_redis() -> aioredis.Redis:
    global _redis
    if _redis is None:
        _redis = await aioredis.from_url(
            settings.REDIS_URL,
            encoding="utf-8",
            decode_responses=True,
            max_connections=20,
        )
    return _redis


async def close_redis() -> None:
    global _redis
    if _redis:
        await _redis.aclose()
        _redis = None
        logger.info("Redis connection closed")


class CacheService:
    def __init__(self, prefix: str = "cspm", default_ttl: int = 300):
        self.prefix = prefix
        self.default_ttl = default_ttl

    def _key(self, key: str) -> str:
        return f"{self.prefix}:{key}"

    async def get(self, key: str) -> Any | None:
        r = await get_redis()
        val = await r.get(self._key(key))
        if val:
            try:
                return json.loads(val)
            except json.JSONDecodeError:
                return val
        return None

    async def set(self, key: str, value: Any, ttl: int | None = None) -> None:
        r = await get_redis()
        ttl = ttl or self.default_ttl
        serialized = json.dumps(value) if not isinstance(value, str) else value
        await r.setex(self._key(key), ttl, serialized)

    async def delete(self, key: str) -> None:
        r = await get_redis()
        await r.delete(self._key(key))

    async def exists(self, key: str) -> bool:
        r = await get_redis()
        return bool(await r.exists(self._key(key)))

    async def increment(self, key: str, amount: int = 1) -> int:
        r = await get_redis()
        return await r.incrby(self._key(key), amount)

    async def set_scan_status(self, scan_id: str, status: dict) -> None:
        await self.set(f"scan:status:{scan_id}", status, ttl=3600)

    async def get_scan_status(self, scan_id: str) -> dict | None:
        return await self.get(f"scan:status:{scan_id}")

    async def publish_scan_event(self, scan_id: str, event: dict) -> None:
        r = await get_redis()
        await r.publish(f"scan:{scan_id}", json.dumps(event))


cache = CacheService()
