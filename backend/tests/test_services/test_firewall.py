from unittest.mock import patch

import pytest

from app.services import firewall as fw


class TestBlockIP:
    @patch("app.services.firewall._run_ufw")
    def test_block_ip_success(self, mock_run):
        mock_run.return_value = (True, "Rule added")
        result = fw.block_ip("10.0.0.1")
        assert result is True
        mock_run.assert_called_once_with("deny", "from", "10.0.0.1")

    @patch("app.services.firewall._run_ufw")
    def test_block_ip_failure(self, mock_run):
        mock_run.return_value = (False, "ERROR: wrong args")
        result = fw.block_ip("10.0.0.1")
        assert result is False

    @patch("app.services.firewall._run_ufw")
    def test_block_ip_already_exists_is_idempotent(self, mock_run):
        # ufw returns failure with "already exists" wording -> treat as success
        mock_run.return_value = (False, "ERROR: rule already exists")
        result = fw.block_ip("10.0.0.1")
        assert result is True


class TestUnblockIP:
    @patch("app.services.firewall._run_ufw")
    def test_unblock_ip_success(self, mock_run):
        mock_run.return_value = (True, "Rule deleted")
        result = fw.unblock_ip("10.0.0.1")
        assert result is True
        mock_run.assert_called_once_with("delete", "deny", "from", "10.0.0.1")

    @patch("app.services.firewall._run_ufw")
    def test_unblock_ip_failure(self, mock_run):
        mock_run.return_value = (False, "ERROR: internal ufw error")
        result = fw.unblock_ip("10.0.0.1")
        assert result is False

    @patch("app.services.firewall._run_ufw")
    def test_unblock_ip_not_found_is_idempotent(self, mock_run):
        mock_run.return_value = (False, "ERROR: Rule not found")
        result = fw.unblock_ip("10.0.0.1")
        assert result is True


class TestListBlockedIPs:
    @patch("app.services.firewall._run_ufw")
    def test_list_blocked_mixed_ipv4_ipv6_cidr(self, mock_run):
        mock_run.return_value = (True, (
            "Status: active\n"
            "    10.0.0.1              DENY        Anywhere\n"
            "    10.0.0.2              DENY        Anywhere (v6)\n"
            "    2001:db8::1           DENY        Anywhere (v6)\n"
            "    10.0.0.0/24           DENY        Anywhere\n"
            "   Anywhere_%20           DENY        Anywhere\n"
        ))
        result = fw.list_blocked_ips()
        assert "10.0.0.1" in result
        assert "10.0.0.2" in result
        assert "2001:db8::1" in result
        assert "10.0.0.0/24" in result
        # Garbage tokens must not slip through.
        assert "Anywhere_%20" not in result

    @patch("app.services.firewall._run_ufw")
    def test_list_blocked_empty(self, mock_run):
        mock_run.return_value = (True, "Status: active\n")
        result = fw.list_blocked_ips()
        assert result == []

    @patch("app.services.firewall._run_ufw")
    def test_list_blocked_ufw_unavailable(self, mock_run):
        mock_run.return_value = (False, "ufw command not found")
        result = fw.list_blocked_ips()
        assert result == []


class TestIsIPBlocked:
    @patch("app.services.firewall.list_blocked_ips")
    def test_ip_is_blocked(self, mock_list):
        mock_list.return_value = ["10.0.0.1", "10.0.0.2"]
        assert fw.is_ip_blocked("10.0.0.1") is True

    @patch("app.services.firewall.list_blocked_ips")
    def test_ip_not_blocked(self, mock_list):
        mock_list.return_value = ["10.0.0.1"]
        assert fw.is_ip_blocked("10.0.0.99") is False


class TestIsIpToken:
    """Direct unit tests for the IP/CIDR token validator helper."""

    def test_ipv4_token(self):
        assert fw._is_ip_token("10.0.0.1") is True

    def test_ipv6_token(self):
        assert fw._is_ip_token("2001:db8::1") is True

    def test_cidr_token(self):
        assert fw._is_ip_token("10.0.0.0/24") is True
        assert fw._is_ip_token("fe80::/64") is True

    def test_garbage_token(self):
        assert fw._is_ip_token("Anywhere") is False
        assert fw._is_ip_token("(v6)") is False
        assert fw._is_ip_token("") is False

    def test_garbage_subnet_token(self):
        assert fw._is_ip_token("10.0.0.0/40") is False
