"""
IP address utility functions.

Provides helper functions for IP address validation, parsing,
and CIDR matching used in signature matching.
"""

import ipaddress
from typing import Optional


def is_valid_ip(ip_string: str) -> bool:
    """
    Check if a string is a valid IPv4 or IPv6 address.

    Args:
        ip_string: IP address string to validate

    Returns:
        bool: True if valid IP address, False otherwise

    Example:
        >>> is_valid_ip("192.168.1.1")
        True
        >>> is_valid_ip("invalid")
        False
    """
    try:
        ipaddress.ip_address(ip_string)
        return True
    except ValueError:
        return False


def is_valid_cidr(cidr_string: str) -> bool:
    """
    Check if a string is a valid CIDR notation.

    Args:
        cidr_string: CIDR notation string (e.g., "192.168.1.0/24")

    Returns:
        bool: True if valid CIDR notation

    Example:
        >>> is_valid_cidr("192.168.1.0/24")
        True
        >>> is_valid_cidr("192.168.1.1")
        False
    """
    try:
        ipaddress.ip_network(cidr_string, strict=False)
        return "/" in cidr_string
    except ValueError:
        return False


def ip_in_network(ip: str, network: str) -> bool:
    """
    Check if an IP address is within a network range.

    Supports both individual IP addresses and CIDR notation for network.

    Args:
        ip: IP address to check
        network: Network in CIDR notation or single IP

    Returns:
        bool: True if IP is in the network range

    Example:
        >>> ip_in_network("192.168.1.50", "192.168.1.0/24")
        True
        >>> ip_in_network("10.0.0.1", "192.168.1.0/24")
        False
    """
    try:
        ip_obj = ipaddress.ip_address(ip)

        # If network is a single IP, do exact match
        if "/" not in network:
            return ip == network

        # Otherwise, check if IP is in network range
        network_obj = ipaddress.ip_network(network, strict=False)
        return ip_obj in network_obj
    except ValueError:
        return False


def ip_matches_pattern(ip: str, pattern: Optional[str]) -> bool:
    """
    Check if an IP matches a pattern (single IP, CIDR, or 'any').

    Args:
        ip: IP address to check
        pattern: Pattern to match against (IP, CIDR, 'any', or None)

    Returns:
        bool: True if IP matches the pattern

    Example:
        >>> ip_matches_pattern("192.168.1.1", "any")
        True
        >>> ip_matches_pattern("192.168.1.1", "192.168.1.0/24")
        True
        >>> ip_matches_pattern("192.168.1.1", None)
        True
    """
    # None or 'any' pattern matches everything
    if pattern is None or pattern.lower() == "any":
        return True

    # Check for CIDR or exact match
    return ip_in_network(ip, pattern)


def get_ip_version(ip: str) -> Optional[int]:
    """
    Get the IP version (4 or 6) for an IP address.

    Args:
        ip: IP address string

    Returns:
        int: 4 for IPv4, 6 for IPv6, None if invalid
    """
    try:
        ip_obj = ipaddress.ip_address(ip)
        return ip_obj.version
    except ValueError:
        return None


def is_private_ip(ip: str) -> bool:
    """
    Check if an IP address is in a private range.

    Private ranges:
    - 10.0.0.0/8
    - 172.16.0.0/12
    - 192.168.0.0/16

    Args:
        ip: IP address to check

    Returns:
        bool: True if IP is private
    """
    try:
        ip_obj = ipaddress.ip_address(ip)
        return ip_obj.is_private
    except ValueError:
        return False


def normalize_ip(ip: str) -> Optional[str]:
    """
    Normalize an IP address to standard format.

    Args:
        ip: IP address string

    Returns:
        str: Normalized IP string or None if invalid
    """
    try:
        return str(ipaddress.ip_address(ip))
    except ValueError:
        return None
