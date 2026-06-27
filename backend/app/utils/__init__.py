"""
Utilities package initialization.

Exports utility functions for use throughout the application.
"""

from app.utils.ip_utils import (
    is_valid_ip,
    is_valid_cidr,
    ip_in_network,
    ip_matches_pattern,
    get_ip_version,
    is_private_ip,
    normalize_ip,
)

from app.utils.regex_utils import (
    compile_pattern,
    is_valid_regex,
    match_pattern,
    pattern_matches,
    extract_all_matches,
    sanitize_for_regex,
    build_keyword_pattern,
)

from app.utils.time_utils import (
    utc_now,
    timestamp_to_datetime,
    datetime_to_timestamp,
    format_timestamp,
    parse_timestamp,
    get_time_ago,
    is_within_time_window,
    get_time_range,
    format_duration,
    get_date_boundaries,
)

__all__ = [
    # IP utilities
    "is_valid_ip",
    "is_valid_cidr",
    "ip_in_network",
    "ip_matches_pattern",
    "get_ip_version",
    "is_private_ip",
    "normalize_ip",
    # Regex utilities
    "compile_pattern",
    "is_valid_regex",
    "match_pattern",
    "pattern_matches",
    "extract_all_matches",
    "sanitize_for_regex",
    "build_keyword_pattern",
    # Time utilities
    "utc_now",
    "timestamp_to_datetime",
    "datetime_to_timestamp",
    "format_timestamp",
    "parse_timestamp",
    "get_time_ago",
    "is_within_time_window",
    "get_time_range",
    "format_duration",
    "get_date_boundaries",
]
