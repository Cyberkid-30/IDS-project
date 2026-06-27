"""
Regex utility functions.

Provides helper functions for regex pattern compilation,
matching, and validation used in payload inspection.
"""

import re
from typing import Optional, Pattern, Match
from functools import lru_cache

from app.core.logging import ids_logger


@lru_cache(maxsize=256)
def compile_pattern(pattern: str, flags: int = 0) -> Optional[Pattern]:
    """
    Compile a regex pattern with caching for performance.

    Compiled patterns are cached to avoid recompilation overhead
    during packet inspection.

    Args:
        pattern: Regex pattern string
        flags: Regex flags (re.IGNORECASE, etc.)

    Returns:
        Pattern: Compiled regex pattern or None if invalid

    Example:
        >>> pat = compile_pattern(r"password=\w+", re.IGNORECASE)
        >>> pat.search("Password=secret")
        <re.Match object>
    """
    try:
        return re.compile(pattern, flags)
    except re.error as e:
        ids_logger.warning(f"Invalid regex pattern '{pattern}': {e}")
        return None


def is_valid_regex(pattern: str) -> bool:
    """
    Check if a string is a valid regex pattern.

    Args:
        pattern: Regex pattern to validate

    Returns:
        bool: True if pattern is valid regex

    Example:
        >>> is_valid_regex(r"\d+")
        True
        >>> is_valid_regex(r"[invalid")
        False
    """
    try:
        re.compile(pattern)
        return True
    except re.error:
        return False


def match_pattern(
    pattern: str, text: str, case_sensitive: bool = False
) -> Optional[Match]:
    """
    Match a regex pattern against text.

    Args:
        pattern: Regex pattern to match
        text: Text to search in
        case_sensitive: Whether matching is case-sensitive

    Returns:
        Match: Match object if found, None otherwise

    Example:
        >>> match = match_pattern(r"error:\s*(.+)", "Error: Connection refused")
        >>> match.group(1)
        'Connection refused'
    """
    flags = 0 if case_sensitive else re.IGNORECASE
    compiled = compile_pattern(pattern, flags)

    if compiled is None:
        return None

    return compiled.search(text)


def pattern_matches(
    pattern: Optional[str], text: Optional[str], case_sensitive: bool = False
) -> bool:
    """
    Check if a pattern matches text (handles None values safely).

    Args:
        pattern: Regex pattern (None = always match)
        text: Text to search (None = no match unless pattern is None)
        case_sensitive: Whether matching is case-sensitive

    Returns:
        bool: True if pattern matches text

    Example:
        >>> pattern_matches(r"admin", "User: admin@example.com")
        True
        >>> pattern_matches(None, "any text")
        True
    """
    # No pattern means match everything
    if pattern is None:
        return True

    # Pattern but no text means no match
    if text is None:
        return False

    match = match_pattern(pattern, text, case_sensitive)
    return match is not None


def extract_all_matches(pattern: str, text: str, case_sensitive: bool = False) -> list:
    """
    Extract all matches of a pattern from text.

    Args:
        pattern: Regex pattern with optional groups
        text: Text to search
        case_sensitive: Whether matching is case-sensitive

    Returns:
        list: List of all matches (strings or tuples for groups)

    Example:
        >>> extract_all_matches(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", text)
        ['192.168.1.1', '10.0.0.1']
    """
    flags = 0 if case_sensitive else re.IGNORECASE
    compiled = compile_pattern(pattern, flags)

    if compiled is None:
        return []

    return compiled.findall(text)


def sanitize_for_regex(text: str) -> str:
    """
    Escape special regex characters in text for literal matching.

    Args:
        text: Text to escape

    Returns:
        str: Escaped text safe for regex literal matching

    Example:
        >>> sanitize_for_regex("test.txt")
        'test\\.txt'
    """
    return re.escape(text)


def build_keyword_pattern(keywords: list, word_boundary: bool = True) -> str:
    """
    Build a regex pattern to match any of the given keywords.

    Args:
        keywords: List of keywords to match
        word_boundary: Whether to match whole words only

    Returns:
        str: Regex pattern matching any keyword

    Example:
        >>> build_keyword_pattern(["error", "warning", "fatal"])
        '\\b(error|warning|fatal)\\b'
    """
    if not keywords:
        return ""

    # Escape each keyword for safety
    escaped = [re.escape(kw) for kw in keywords]
    pattern = "(" + "|".join(escaped) + ")"

    if word_boundary:
        pattern = r"\b" + pattern + r"\b"

    return pattern
