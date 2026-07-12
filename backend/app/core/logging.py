"""
Logging configuration module using Loguru.

Provides centralized logging configuration for the entire IDS application
with support for file and console output, log rotation, and structured logging.
"""

import sys
from pathlib import Path
from loguru import logger

from app.core.config import settings


def setup_logging() -> None:
    """
    Configure Loguru logger for the application.

    Sets up:
    - Console logging with colored output
    - File logging with rotation
    - Custom format for IDS-specific information
    """
    # Remove default logger
    logger.remove()

    # Define log format
    log_format = (
        "<green>{time:YYYY-MM-DD HH:mm:ss.SSS}</green> | "
        "<level>{level: <8}</level> | "
        "<cyan>{name}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan> | "
        "<level>{message}</level>"
    )

    # Add console handler
    logger.add(
        sys.stdout,
        format=log_format,
        level=settings.LOG_LEVEL,
        colorize=True,
        backtrace=True,
        diagnose=settings.DEBUG,
    )

    # Ensure log directory exists
    log_file = Path(settings.LOG_FILE)
    log_file.parent.mkdir(parents=True, exist_ok=True)

    # Add file handler with rotation
    logger.add(
        str(log_file),
        format=log_format,
        level=settings.LOG_LEVEL,
        rotation="10 MB",  # Rotate when file reaches 10MB
        retention="7 days",  # Keep logs for 7 days
        compression="zip",  # Compress rotated logs
        backtrace=True,
        diagnose=settings.DEBUG,
    )

    logger.info(f"Logging initialized - Level: {settings.LOG_LEVEL}")


def get_logger(name: str = "ids"):
    """
    Get a logger instance with the specified name.

    Args:
        name: Logger name for identification in logs

    Returns:
        Logger instance bound with the specified name
    """
    return logger.bind(name=name)


# Initialize logging on module import
setup_logging()

# Export configured logger
ids_logger = get_logger("ids")
