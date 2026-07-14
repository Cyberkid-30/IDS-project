import subprocess
from typing import Optional

from app.models.blocked_ip import BlockedIP
from app.core.logging import ids_logger


def _run_ufw(*args: str) -> tuple[bool, str]:
    """
    Run a ufw command and return (success, output_or_error).

    Args:
        *args: Arguments to pass to ufw (e.g. "deny", "from", "1.2.3.4")
    """
    try:
        result = subprocess.run(
            ["ufw", *args],
            capture_output=True,
            text=True,
            check=False,
        )
        output = result.stdout.strip() or result.stderr.strip()
        success = result.returncode == 0
        if not success:
            ids_logger.warning(f"ufw {' '.join(args)} failed: {output}")
        return success, output
    except FileNotFoundError:
        ids_logger.error("ufw command not found – is ufw installed?")
        return False, "ufw command not found"
    except Exception as e:
        ids_logger.error(f"ufw error: {e}")
        return False, str(e)


def block_ip(ip: str) -> bool:
    """
    Block an IP address via ufw.

    Returns True if the ufw deny rule was added successfully.
    """
    success, output = _run_ufw("deny", "from", ip)
    if success:
        ids_logger.info(f"UFW: blocked {ip}")
    return success


def unblock_ip(ip: str) -> bool:
    """
    Remove a ufw deny rule for an IP address.

    Returns True if the ufw delete command succeeded.
    """
    success, output = _run_ufw("delete", "deny", "from", ip)
    if success:
        ids_logger.info(f"UFW: unblocked {ip}")
    return success


def list_blocked_ips() -> list[str]:
    """
    Parse ufw status output to extract deny rules with explicit IPs.

    Returns a list of IP strings currently denied by ufw.
    """
    success, output = _run_ufw("status")
    if not success:
        ids_logger.warning("Could not retrieve ufw status")
        return []

    blocked = []
    for line in output.splitlines():
        line = line.strip()
        if "DENY" in line.upper():
            parts = line.split()
            for candidate in parts:
                if "/" not in candidate and candidate.count(".") == 3:
                    blocked.append(candidate)
    return blocked


def is_ip_blocked(ip: str) -> bool:
    """
    Check if an IP is currently blocked by ufw.

    Returns True if a deny rule for the IP exists.
    """
    return ip in list_blocked_ips()