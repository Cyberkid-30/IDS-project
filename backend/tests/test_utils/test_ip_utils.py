from app.utils.ip_utils import (
    is_valid_ip,
    is_valid_cidr,
    ip_in_network,
    ip_matches_pattern,
    get_ip_version,
    is_private_ip,
    normalize_ip,
)


class TestIsValidIP:
    def test_valid_ipv4(self):
        assert is_valid_ip("192.168.1.1") is True

    def test_valid_ipv6(self):
        assert is_valid_ip("::1") is True
        assert is_valid_ip("fe80::1") is True

    def test_invalid_ip(self):
        assert is_valid_ip("not.an.ip") is False
        assert is_valid_ip("999.999.999.999") is False
        assert is_valid_ip("") is False

    def test_cidr_not_valid_ip(self):
        assert is_valid_ip("192.168.1.0/24") is False


class TestIsValidCIDR:
    def test_valid_cidr(self):
        assert is_valid_cidr("192.168.1.0/24") is True
        assert is_valid_cidr("10.0.0.0/8") is True

    def test_single_ip_not_cidr(self):
        assert is_valid_cidr("192.168.1.1") is False

    def test_invalid_cidr(self):
        assert is_valid_cidr("not-a-cidr") is False
        assert is_valid_cidr("") is False


class TestIpInNetwork:
    def test_ip_in_cidr(self):
        assert ip_in_network("192.168.1.50", "192.168.1.0/24") is True

    def test_ip_outside_cidr(self):
        assert ip_in_network("10.0.0.1", "192.168.1.0/24") is False

    def test_exact_ip_match(self):
        assert ip_in_network("192.168.1.1", "192.168.1.1") is True

    def test_exact_ip_mismatch(self):
        assert ip_in_network("192.168.1.2", "192.168.1.1") is False

    def test_invalid_ip_returns_false(self):
        assert ip_in_network("bad", "192.168.1.0/24") is False

    def test_invalid_network_returns_false(self):
        assert ip_in_network("192.168.1.1", "bad") is False


class TestIpMatchesPattern:
    def test_none_pattern_matches_any(self):
        assert ip_matches_pattern("10.0.0.1", None) is True

    def test_any_pattern_matches_any(self):
        assert ip_matches_pattern("10.0.0.1", "any") is True
        assert ip_matches_pattern("10.0.0.1", "ANY") is True

    def test_exact_ip_match(self):
        assert ip_matches_pattern("192.168.1.1", "192.168.1.1") is True

    def test_cidr_match(self):
        assert ip_matches_pattern("192.168.1.100", "192.168.1.0/24") is True

    def test_no_match(self):
        assert ip_matches_pattern("10.0.0.1", "192.168.1.1") is False


class TestGetIpVersion:
    def test_ipv4(self):
        assert get_ip_version("192.168.1.1") == 4

    def test_ipv6(self):
        assert get_ip_version("::1") == 6

    def test_invalid(self):
        assert get_ip_version("bad") is None


class TestIsPrivateIp:
    def test_private_10(self):
        assert is_private_ip("10.0.0.1") is True

    def test_private_192_168(self):
        assert is_private_ip("192.168.1.1") is True

    def test_public_ip(self):
        assert is_private_ip("8.8.8.8") is False

    def test_invalid(self):
        assert is_private_ip("bad") is False


class TestNormalizeIp:
    def test_normalize_valid(self):
        assert normalize_ip("192.168.1.1") == "192.168.1.1"

    def test_normalize_invalid(self):
        assert normalize_ip("bad") is None
