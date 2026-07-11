"""
seed_rules.py — Seeds initial data:
  - Default admin user
  - CIS benchmark rule metadata (for reference/UI display)

Run: python scripts/seed_rules.py
"""
import asyncio
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app.core.database import AsyncSessionLocal, init_db
from app.core.security import hash_password
from app.models.user import User, UserRole
from app.core.logging import setup_logging, logger

ADMIN_EMAIL = "admin@cspm.local"
ADMIN_PASSWORD = "Admin@CSPM123"


async def seed_admin_user(db) -> None:
    from sqlalchemy import select
    result = await db.execute(select(User).where(User.email == ADMIN_EMAIL))
    existing = result.scalar_one_or_none()

    if existing:
        logger.info(f"Admin user already exists: {ADMIN_EMAIL}")
        return

    admin = User(
        email=ADMIN_EMAIL,
        full_name="CSPM Admin",
        hashed_password=hash_password(ADMIN_PASSWORD),
        role=UserRole.ADMIN,
        is_active=True,
        is_verified=True,
    )
    db.add(admin)
    await db.flush()
    logger.info(f"✅ Created admin user: {ADMIN_EMAIL} / {ADMIN_PASSWORD}")
    logger.warning("⚠️  Change this password immediately after first login!")


async def main() -> None:
    setup_logging()
    logger.info("Starting database seed...")

    await init_db()

    async with AsyncSessionLocal() as db:
        await seed_admin_user(db)
        await db.commit()

    logger.info("✅ Seed complete!")
    logger.info("")
    logger.info("Default credentials:")
    logger.info(f"  Email:    {ADMIN_EMAIL}")
    logger.info(f"  Password: {ADMIN_PASSWORD}")
    logger.info("")
    logger.info("API Docs: http://localhost:8000/docs")


if __name__ == "__main__":
    asyncio.run(main())
