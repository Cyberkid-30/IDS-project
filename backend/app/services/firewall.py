import subprocess
import ipaddress

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

    Returns True if the ufw deny rule was added or already present.
    """
    success, output = _run_ufw("deny", "from", ip)
    if success:
        ids_logger.info(f"UFW: blocked {ip}")
        return True
    # Tolerate the "rule already exists" case so that block semantics are
    # idempotent — the DB row is the source of truth for our side, but ufw
    # may already hold a matching rule (e.g. added manually at the shell).
    lowered = output.lower()
    if "already" in lowered or "exist" in lowered:
        ids_logger.info(f"UFW: rule for {ip} already present, treating as success")
        return True
    return False


def unblock_ip(ip: str) -> bool:
    """
    Remove a ufw deny rule for an IP address.

    Returns True if the rule was removed or already absent.
    """
    success, output = _run_ufw("delete", "deny", "from", ip)
    if success:
        ids_logger.info(f"UFW: unblocked {ip}")
        return True
    # "Rule not found" is the idempotent-success case for unblock: the
    # caller's intent (no deny rule for this IP) is already satisfied.
    lowered = output.lower()
    if "not found" in lowered or "could not" in lowered or "does not exist" in lowered:
        ids_logger.info(f"UFW: no rule for {ip}, treating as success")
        return True
    return False


def _is_ip_token(token: str) -> bool:
    """Return True if token looks like a valid IPv4/IPv6 address or CIDR."""
    try:
        # Try as a plain address first (covers both v4 and v6).
        ipaddress.ip_address(token)
        return True
    except ValueError:
        pass
    try:
        # Fall back to network/CIDR form, e.g. "10.0.0.0/24" or "fe80::/64".
        ipaddress.ip_network(token, strict=False)
        return True
    except ValueError:
        return False


def list_blocked_ips() -> list[str]:
    """
    Parse ufw status output to extract deny rules with explicit IPs.

    Returns a list of IP/CIDR strings currently denied by ufw. Supports
    both IPv4 and IPv6 addresses as well as CIDR notation.
    """
    success, output = _run_ufw("status")
    if not success:
        ids_logger.warning("Could not retrieve ufw status")
        return []

    blocked = []
    for line in output.splitlines():
        line = line.strip()
        if "DENY" not in line.upper():
            continue
        for candidate in line.split():
            if _is_ip_token(candidate):
                blocked.append(candidate)
    return blocked


def is_ip_blocked(ip: str) -> bool:
    """
    Check if an IP is currently blocked by ufw.

    Returns True if a deny rule for the IP exists.
    """
    return ip in list_blocked_ips()
