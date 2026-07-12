"""
Time utility functions.

Provides helper functions for timestamp handling, formatting,
and time-based filtering in the IDS.
"""

from datetime import datetime, timedelta, timezone
from typing import Optional


def utc_now() -> datetime:
    """
    Get current UTC datetime.

    Returns:
        datetime: Current UTC time
    """
    return datetime.now(timezone.utc)


def timestamp_to_datetime(timestamp: float) -> datetime:
    """
    Convert Unix timestamp to datetime.

    Args:
        timestamp: Unix timestamp (seconds since epoch)

    Returns:
        datetime: Converted datetime object

    Example:
        >>> timestamp_to_datetime(1609459200)
        datetime(2021, 1, 1, 0, 0, tzinfo=timezone.utc)
    """
    return datetime.fromtimestamp(timestamp, tz=timezone.utc)


def datetime_to_timestamp(dt: datetime) -> float:
    """
    Convert datetime to Unix timestamp.

    Args:
        dt: Datetime object

    Returns:
        float: Unix timestamp
    """
    return dt.timestamp()


def format_timestamp(dt: datetime, format_str: str = "%Y-%m-%d %H:%M:%S") -> str:
    """
    Format datetime as string.

    Args:
        dt: Datetime object to format
        format_str: strftime format string

    Returns:
        str: Formatted timestamp string

    Example:
        >>> format_timestamp(datetime.now())
        '2024-01-15 14:30:45'
    """
    return dt.strftime(format_str)


def parse_timestamp(
    timestamp_str: str, format_str: str = "%Y-%m-%d %H:%M:%S"
) -> Optional[datetime]:
    """
    Parse timestamp string to datetime.

    Args:
        timestamp_str: Timestamp string to parse
        format_str: Expected format

    Returns:
        datetime: Parsed datetime or None if invalid
    """
    try:
        return datetime.strptime(timestamp_str, format_str)
    except ValueError:
        return None


def get_time_ago(minutes: int = 0, hours: int = 0, days: int = 0) -> datetime:
    """
    Get datetime from a specified time ago.

    Args:
        minutes: Minutes ago
        hours: Hours ago
        days: Days ago

    Returns:
        datetime: Datetime representing the time ago

    Example:
        >>> get_time_ago(hours=24)  # 24 hours ago
        datetime(...)
    """
    delta = timedelta(minutes=minutes, hours=hours, days=days)
    return utc_now() - delta


def is_within_time_window(timestamp: datetime, window_minutes: int = 60) -> bool:
    """
    Check if a timestamp is within a time window from now.

    Args:
        timestamp: Timestamp to check
        window_minutes: Size of time window in minutes

    Returns:
        bool: True if timestamp is within the window

    Example:
        >>> is_within_time_window(some_timestamp, window_minutes=5)
        True  # If timestamp is within last 5 minutes
    """
    window_start = get_time_ago(minutes=window_minutes)
    return timestamp >= window_start


def get_time_range(
    start: Optional[datetime] = None,
    end: Optional[datetime] = None,
    default_hours: int = 24,
) -> tuple:
    """
    Get a time range with sensible defaults.

    Args:
        start: Start of range (default: default_hours ago)
        end: End of range (default: now)
        default_hours: Default range size if start not specified

    Returns:
        tuple: (start_datetime, end_datetime)
    """
    if end is None:
        end = utc_now()

    if start is None:
        start = get_time_ago(hours=default_hours)

    return (start, end)


def format_duration(seconds: float) -> str:
    """
    Format a duration in seconds to human-readable string.

    Args:
        seconds: Duration in seconds

    Returns:
        str: Human-readable duration

    Example:
        >>> format_duration(3665)
        '1h 1m 5s'
    """
    if seconds < 60:
        return f"{seconds:.1f}s"
    elif seconds < 3600:
        minutes = int(seconds // 60)
        secs = int(seconds % 60)
        return f"{minutes}m {secs}s"
    else:
        hours = int(seconds // 3600)
        minutes = int((seconds % 3600) // 60)
        secs = int(seconds % 60)
        return f"{hours}h {minutes}m {secs}s"


def get_date_boundaries(date: datetime) -> tuple:
    """
    Get start and end of day for a given date.

    Args:
        date: Date to get boundaries for

    Returns:
        tuple: (start_of_day, end_of_day)
    """
    start_of_day = date.replace(hour=0, minute=0, second=0, microsecond=0)
    end_of_day = date.replace(hour=23, minute=59, second=59, microsecond=999999)
    return (start_of_day, end_of_day)
