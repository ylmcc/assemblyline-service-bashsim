"""fetcher.fetch_url tests. HTTP is fully mocked via requests_mock; DNS resolution is
fully mocked via unittest.mock.patch("socket.getaddrinfo") — no real network/DNS ever
touched. All hostnames/IPs are synthetic (.test TLD / RFC 5737 ranges), never real
infrastructure.
"""
import hashlib
import os
import socket

import pytest
import requests
import requests_mock as rm_module
from unittest.mock import patch

from bashsim.fetcher import fetch_url

# 1.2.3.4/5.6.7.8 are generic "ordinary public address" placeholders (not flagged non-global
# by Python's ipaddress module, unlike RFC 5737 TEST-NET ranges) so the "should succeed" fetch
# tests actually exercise the success path; internal-target.test is deliberately a real
# private-range address to exercise the SSRF block.
_HOST_IPS = {
    "payload.test": "1.2.3.4",
    "payload-redirect.test": "5.6.7.8",
    "internal-target.test": "10.0.0.5",
}


def _fake_getaddrinfo(host, *args, **kwargs):
    ip = _HOST_IPS.get(host)
    if ip is None:
        raise socket.gaierror(f"no mapping for {host}")
    return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, 0))]


@pytest.fixture(autouse=True)
def _mock_dns():
    with patch("socket.getaddrinfo", side_effect=_fake_getaddrinfo):
        yield


@pytest.fixture
def requests_mocker():
    with rm_module.Mocker() as m:
        yield m


def test_successful_fetch(tmp_path, requests_mocker):
    content = b"fake payload bytes"
    requests_mocker.get("http://payload.test/x", content=content, headers={"Content-Type": "application/octet-stream"})

    result = fetch_url("http://payload.test/x", str(tmp_path), timeout=5, max_size=1024,
                        max_redirects=3, user_agent="test-agent")

    assert result.ok is True
    assert result.size == len(content)
    assert result.sha256 == hashlib.sha256(content).hexdigest()
    assert os.path.exists(result.body_path)
    with open(result.body_path, "rb") as f:
        assert f.read() == content


def test_oversize_response_aborted_mid_stream(tmp_path, requests_mocker):
    content = b"x" * 1000
    requests_mocker.get("http://payload.test/big", content=content)

    result = fetch_url("http://payload.test/big", str(tmp_path), timeout=5, max_size=10,
                        max_redirects=3, user_agent="test-agent")

    assert result.ok is False
    assert result.error == "too_large"
    assert result.body_path is None


def test_timeout(tmp_path, requests_mocker):
    requests_mocker.get("http://payload.test/slow", exc=requests.exceptions.Timeout)

    result = fetch_url("http://payload.test/slow", str(tmp_path), timeout=5, max_size=1024,
                        max_redirects=3, user_agent="test-agent")

    assert result.ok is False
    assert result.error == "timeout"


def test_connection_error(tmp_path, requests_mocker):
    requests_mocker.get("http://payload.test/down", exc=requests.exceptions.ConnectionError("refused"))

    result = fetch_url("http://payload.test/down", str(tmp_path), timeout=5, max_size=1024,
                        max_redirects=3, user_agent="test-agent")

    assert result.ok is False
    assert result.error.startswith("connection_error")


def test_redirect_chain_within_cap(tmp_path, requests_mocker):
    content = b"final content"
    requests_mocker.get("http://payload.test/start", status_code=302,
                         headers={"Location": "http://payload-redirect.test/final"})
    requests_mocker.get("http://payload-redirect.test/final", content=content)

    result = fetch_url("http://payload.test/start", str(tmp_path), timeout=5, max_size=1024,
                        max_redirects=3, user_agent="test-agent")

    assert result.ok is True
    assert result.final_url == "http://payload-redirect.test/final"
    assert result.sha256 == hashlib.sha256(content).hexdigest()


def test_redirect_chain_exceeds_cap(tmp_path, requests_mocker):
    requests_mocker.get("http://payload.test/hop0", status_code=302,
                         headers={"Location": "http://payload.test/hop1"})
    requests_mocker.get("http://payload.test/hop1", status_code=302,
                         headers={"Location": "http://payload.test/hop2"})
    requests_mocker.get("http://payload.test/hop2", content=b"unreachable within cap")

    result = fetch_url("http://payload.test/hop0", str(tmp_path), timeout=5, max_size=1024,
                        max_redirects=1, user_agent="test-agent")

    assert result.ok is False
    assert result.error == "too_many_redirects"


def test_sequential_fetches_in_same_dest_dir_do_not_collide(tmp_path, requests_mocker):
    # Regression test: a single execute() call fetching multiple URLs (e.g. a script
    # with several wget/curl lines) calls fetch_url() more than once against the same
    # dest_dir (self.working_directory). Each call's internal hop counter starts at 0,
    # so a hop-index-only filename would collide across calls and silently overwrite an
    # earlier fetch's body before AL4 reads/hashes it -- this must never happen.
    content_a = b"payload A content"
    content_b = b"payload B content"
    requests_mocker.get("http://payload.test/a", content=content_a)
    requests_mocker.get("http://payload.test/b", content=content_b)

    result_a = fetch_url("http://payload.test/a", str(tmp_path), timeout=5, max_size=1024,
                          max_redirects=3, user_agent="test-agent")
    result_b = fetch_url("http://payload.test/b", str(tmp_path), timeout=5, max_size=1024,
                          max_redirects=3, user_agent="test-agent")

    assert result_a.ok is True and result_b.ok is True
    assert result_a.body_path != result_b.body_path
    with open(result_a.body_path, "rb") as f:
        assert f.read() == content_a
    with open(result_b.body_path, "rb") as f:
        assert f.read() == content_b


def test_redirect_to_private_ip_is_blocked_mid_chain(tmp_path, requests_mocker):
    requests_mocker.get("http://payload.test/start", status_code=302,
                         headers={"Location": "http://internal-target.test/steal"})
    # Registered but must never actually be reached if the SSRF guard works correctly.
    requests_mocker.get("http://internal-target.test/steal", content=b"should never be fetched")

    result = fetch_url("http://payload.test/start", str(tmp_path), timeout=5, max_size=1024,
                        max_redirects=3, user_agent="test-agent")

    assert result.ok is False
    assert result.error.startswith("ssrf_blocked")
    # Only the first hop should have actually been requested.
    requested_urls = [h.url for h in requests_mocker.request_history]
    assert "http://internal-target.test/steal" not in requested_urls
