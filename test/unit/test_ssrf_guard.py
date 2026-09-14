"""SSRF guard tests. DNS resolution is fully mocked — no real network/DNS lookups."""
import socket
from unittest.mock import patch

from bashsim.ssrf_guard import resolve_and_check


def _fake_addrinfo(ip: str):
    return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, 0))]


def test_public_ip_allowed():
    # 1.2.3.4 is a widely-used generic placeholder for "some ordinary public address" in
    # networking docs/tests; unlike RFC 5737 TEST-NET ranges it is NOT flagged non-global
    # by Python's ipaddress module, so it actually exercises the "allowed" code path.
    with patch("socket.getaddrinfo", return_value=_fake_addrinfo("1.2.3.4")):
        result = resolve_and_check("example-payload-host.test")
    assert result.blocked is False
    assert result.resolved_ips == ["1.2.3.4"]


def test_private_ip_blocked():
    with patch("socket.getaddrinfo", return_value=_fake_addrinfo("10.0.0.5")):
        result = resolve_and_check("internal.test")
    assert result.blocked is True
    assert "blocked_private_target" in result.reason


def test_link_local_private_ip_blocked():
    with patch("socket.getaddrinfo", return_value=_fake_addrinfo("192.168.1.1")):
        result = resolve_and_check("internal.test")
    assert result.blocked is True


def test_loopback_blocked():
    with patch("socket.getaddrinfo", return_value=_fake_addrinfo("127.0.0.1")):
        result = resolve_and_check("localhost.test")
    assert result.blocked is True


def test_cloud_metadata_ip_explicitly_blocked():
    with patch("socket.getaddrinfo", return_value=_fake_addrinfo("169.254.169.254")):
        result = resolve_and_check("metadata.test")
    assert result.blocked is True
    assert "169.254.169.254" in result.reason


def test_dns_failure_is_unresolvable_not_blocked():
    with patch("socket.getaddrinfo", side_effect=socket.gaierror("Name or service not known")):
        result = resolve_and_check("nonexistent.test")
    assert result.blocked is False
    assert result.reason.startswith("dns_resolution_failed")
