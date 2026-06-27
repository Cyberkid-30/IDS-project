"""
Permissions and security utilities module.

Handles permission checks required for packet capture operations
and provides security-related helper functions.
"""

import os
import sys
from typing import Tuple

from app.core.logging import ids_logger


def check_root_privileges() -> bool:
    """
    Check if the application has root/administrator privileges.

    Root privileges are required for raw packet capture using Scapy.

    Returns:
        bool: True if running with elevated privileges, False otherwise
    """
    # On Unix-like systems, check for root (UID 0)
    if sys.platform != "win32":
        return os.geteuid() == 0
    else:
        # On Windows, check for administrator privileges
        try:
            import ctypes

            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            return False


def verify_capture_permissions() -> Tuple[bool, str]:
    """
    Verify that the application has necessary permissions for packet capture.

    Returns:
        Tuple[bool, str]: (success, message) indicating if capture is possible
    """
    if check_root_privileges():
        ids_logger.info("Root privileges verified - packet capture enabled")
        return True, "Packet capture permissions verified"

    # Check for CAP_NET_RAW capability on Linux
    if sys.platform.startswith("linux"):
        try:
            # Try to check capabilities
            import subprocess

            result = subprocess.run(
                ["getcap", sys.executable], capture_output=True, text=True
            )
            if "cap_net_raw" in result.stdout.lower():
                ids_logger.info("CAP_NET_RAW capability detected")
                return True, "CAP_NET_RAW capability available"
        except Exception as e:
            ids_logger.warning(f"Could not check capabilities: {e}")

    warning_msg = (
        "Insufficient privileges for packet capture. "
        "Run with sudo or set CAP_NET_RAW capability."
    )
    ids_logger.warning(warning_msg)
    return False, warning_msg


def get_available_interfaces() -> list:
    """
    Get list of available network interfaces.

    Returns:
        list: List of interface names available for capture
    """
    try:
        from scapy.all import get_if_list

        interfaces = get_if_list()
        ids_logger.debug(f"Available interfaces: {interfaces}")
        return interfaces
    except Exception as e:
        ids_logger.error(f"Failed to get network interfaces: {e}")
        return []


def validate_interface(interface: str) -> bool:
    """
    Validate that a network interface exists and is available.

    Args:
        interface: Name of the network interface to validate

    Returns:
        bool: True if interface is valid and available
    """
    available = get_available_interfaces()
    is_valid = interface in available

    if not is_valid:
        ids_logger.warning(f"Interface '{interface}' not found. Available: {available}")

    return is_valid
