import sys
import logging
from loguru import logger
from app.core.config import settings


class InterceptHandler(logging.Handler):
    """Redirect standard logging to loguru."""

    def emit(self, record: logging.LogRecord) -> None:
        try:
            level = logger.level(record.levelname).name
        except ValueError:
            level = record.levelno

        frame, depth = logging.currentframe(), 2
        while frame.f_code.co_filename == logging.__file__:
            frame = frame.f_back
            depth += 1

        logger.opt(depth=depth, exception=record.exc_info).log(
            level, record.getMessage()
        )


def setup_logging() -> None:
    logger.remove()

    if settings.APP_ENV == "production":
        logger.add(
            sys.stdout,
            format=(
                '{{"time":"{time:YYYY-MM-DDTHH:mm:ss.SSSZ}",'
                '"level":"{level}",'
                '"message":"{message}",'
                '"module":"{module}",'
                '"function":"{function}",'
                '"line":{line}}}'
            ),
            level="INFO",
            serialize=False,
        )
    else:
        logger.add(
            sys.stdout,
            format=(
                "<green>{time:YYYY-MM-DD HH:mm:ss}</green> | "
                "<level>{level: <8}</level> | "
                "<cyan>{name}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan> - "
                "<level>{message}</level>"
            ),
            level="DEBUG",
            colorize=True,
        )

    logger.add(
        "logs/cspm.log",
        rotation="100 MB",
        retention="30 days",
        compression="gz",
        level="INFO",
    )

    logging.basicConfig(handlers=[InterceptHandler()], level=0, force=True)
    for name in ("uvicorn", "uvicorn.error", "uvicorn.access", "fastapi"):
        logging.getLogger(name).handlers = [InterceptHandler()]

    logger.info(f"Logging initialized | env={settings.APP_ENV}")


__all__ = ["logger", "setup_logging"]
