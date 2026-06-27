"""
Configuration module for the IDS backend.

This module manages all application settings using Pydantic BaseSettings,
allowing configuration via environment variables or .env file.
"""

from pathlib import Path
from typing import List
from pydantic_settings import BaseSettings
from functools import lru_cache


class Settings(BaseSettings):
    """
    Application settings loaded from environment variables.

    Attributes:
        APP_NAME: Name of the application
        DEBUG: Debug mode flag
        DATABASE_URL: SQLite database connection string
        NETWORK_INTERFACE: Network interface to capture packets from
        CAPTURE_FILTER: BPF filter for packet capture
        SIGNATURES_DIR: Directory containing signature JSON files
        LOG_LEVEL: Logging level (DEBUG, INFO, WARNING, ERROR)
        LOG_FILE: Path to log file
        ALERT_RETENTION_DAYS: Number of days to retain alerts
        MAX_PACKET_BUFFER: Maximum packets to buffer before processing
        CAPTURE_TIMEOUT: Timeout in seconds for packet capture batches
    """

    # Application settings
    APP_NAME: str = "IDS Backend"
    APP_VERSION: str = "1.0.0"
    DEBUG: bool = False

    # Database settings
    DATABASE_URL: str = "sqlite:///./data/ids.db"

    # Network capture settings
    NETWORK_INTERFACE: str = "eth0"
    CAPTURE_FILTER: str = "ip"  # BPF filter - capture all IP packets
    CAPTURE_TIMEOUT: int = 10  # seconds
    MAX_PACKET_BUFFER: int = 1000

    # Signature settings
    SIGNATURES_DIR: Path = Path("app/signatures")

    # Logging settings
    LOG_LEVEL: str = "INFO"
    LOG_FILE: Path = Path("data/ids.log")

    # Alert settings
    ALERT_RETENTION_DAYS: int = 30

    # API settings
    API_PREFIX: str = "/api/v1"
    ALLOWED_HOSTS: List[str] = ["*"]

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        case_sensitive = True


@lru_cache()
def get_settings() -> Settings:
    """
    Returns cached settings instance.

    Using lru_cache ensures settings are loaded only once
    and reused across the application.

    Returns:
        Settings: Application settings instance
    """
    return Settings()


# Global settings instance for easy access
settings = get_settings()
