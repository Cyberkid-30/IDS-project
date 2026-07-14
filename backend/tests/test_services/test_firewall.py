from unittest.mock import patch, MagicMock

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


class TestUnblockIP:
    @patch("app.services.firewall._run_ufw")
    def test_unblock_ip_success(self, mock_run):
        mock_run.return_value = (True, "Rule deleted")
        result = fw.unblock_ip("10.0.0.1")
        assert result is True
        mock_run.assert_called_once_with("delete", "deny", "from", "10.0.0.1")

    @patch("app.services.firewall._run_ufw")
    def test_unblock_ip_failure(self, mock_run):
        mock_run.return_value = (False, "Rule not found")
        result = fw.unblock_ip("10.0.0.1")
        assert result is False


class TestListBlockedIPs:
    @patch("app.services.firewall._run_ufw")
    def test_list_blocked(self, mock_run):
        mock_run.return_value = (True, (
            "Status: active\n"
            "    10.0.0.1              DENY        Anywhere\n"
            "    10.0.0.2              DENY        Anywhere (v6)\n"
        ))
        result = fw.list_blocked_ips()
        assert result == ["10.0.0.1", "10.0.0.2"]

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
