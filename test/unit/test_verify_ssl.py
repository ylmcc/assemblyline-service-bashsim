"""Tests for the `verify_ssl` option of fetcher.fetch_url and the BashSim service.

No real host is ever contacted and no real DNS is used:
  * HTTP is mocked with requests_mock, or (for the TLS tests) served by a throwaway
    self-signed HTTPS server bound to 127.0.0.1 on an ephemeral port inside the test
    process.
  * DNS is mocked (`socket.getaddrinfo`).
  * Hostnames are `.test`; every literal IP is from an RFC 5737 documentation range
    (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24), apart from 127.0.0.1 which is the
    local stub server itself.

Python's ipaddress module treats RFC 5737 ranges as non-global, so the real SSRF guard
blocks them. Tests that need a fetch to be *allowed* therefore patch the guard for the one
allowed hostname only (`_allow_hosts`) and delegate everything else to the real guard.
"""
import datetime
import http.server
import socket
import ssl
import threading
import warnings
from unittest.mock import MagicMock, patch

import pytest
import requests
import requests_mock as rm_module
from urllib3.exceptions import InsecureRequestWarning

from bashsim import fetcher
from bashsim.fetcher import fetch_url
from bashsim.ssrf_guard import SSRFCheckResult, resolve_and_check

_REAL_RESOLVE_AND_CHECK = resolve_and_check

_HOST_IPS = {
    "ok.test": "198.51.100.10",
    "ok-redirect.test": "198.51.100.11",
    "internal-a.test": "192.0.2.10",
    "internal-b.test": "203.0.113.20",
}


def _fake_getaddrinfo(host, *args, **kwargs):
    ip = _HOST_IPS.get(host)
    if ip is None:
        raise socket.gaierror(f"no mapping for {host}")
    return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, 0))]


def _allow_hosts(*allowed):
    """A stand-in for resolve_and_check that lets only `allowed` hostnames through and
    runs the real guard (and real DNS mock) for every other host."""

    def _check(host):
        if host in allowed:
            return SSRFCheckResult([_HOST_IPS.get(host, "198.51.100.10")], False, "")
        return _REAL_RESOLVE_AND_CHECK(host)

    return _check


@pytest.fixture(autouse=True)
def _mock_dns():
    with patch("socket.getaddrinfo", side_effect=_fake_getaddrinfo):
        yield


@pytest.fixture
def requests_mocker():
    with rm_module.Mocker() as m:
        yield m


def _fetch(tmp_path, url, **kwargs):
    kwargs.setdefault("timeout", 5)
    kwargs.setdefault("max_size", 1024)
    kwargs.setdefault("max_redirects", 3)
    return fetch_url(url, str(tmp_path), user_agent="test-agent", **kwargs)


# --- verify flag is passed through to requests -----------------------------------------


@pytest.mark.parametrize("verify_ssl", [True, False])
def test_verify_flag_is_passed_to_requests(tmp_path, requests_mocker, verify_ssl):
    requests_mocker.get("https://ok.test/x", content=b"body")

    with patch("bashsim.fetcher.resolve_and_check", _allow_hosts("ok.test")):
        result = _fetch(tmp_path, "https://ok.test/x", verify_ssl=verify_ssl)

    assert result.ok is True
    assert [h.verify for h in requests_mocker.request_history] == [verify_ssl]


def test_verify_defaults_to_false(tmp_path, requests_mocker):
    requests_mocker.get("https://ok.test/x", content=b"body")

    with patch("bashsim.fetcher.resolve_and_check", _allow_hosts("ok.test")):
        result = _fetch(tmp_path, "https://ok.test/x")

    assert result.ok is True
    assert requests_mocker.request_history[0].verify is False


@pytest.mark.parametrize("verify_ssl", [True, False])
def test_verify_flag_applies_to_every_redirect_hop(tmp_path, requests_mocker, verify_ssl):
    requests_mocker.get("https://ok.test/a", status_code=302, headers={"Location": "https://ok-redirect.test/b"})
    requests_mocker.get("https://ok-redirect.test/b", status_code=302, headers={"Location": "https://ok.test/c"})
    requests_mocker.get("https://ok.test/c", content=b"final")

    with patch("bashsim.fetcher.resolve_and_check", _allow_hosts("ok.test", "ok-redirect.test")):
        result = _fetch(tmp_path, "https://ok.test/a", verify_ssl=verify_ssl)

    assert result.ok is True
    assert [h.url for h in requests_mocker.request_history] == [
        "https://ok.test/a", "https://ok-redirect.test/b", "https://ok.test/c",
    ]
    assert [h.verify for h in requests_mocker.request_history] == [verify_ssl] * 3


# --- InsecureRequestWarning suppression ------------------------------------------------


def _warning_emitting_get(*args, **kwargs):
    # Stand-in for what urllib3 does on every HTTPS connection made with verify=False.
    warnings.warn("Unverified HTTPS request is being made", InsecureRequestWarning)
    resp = MagicMock()
    resp.is_redirect = False
    resp.status_code = 200
    resp.headers = {"Content-Type": "text/plain"}
    resp.iter_content.return_value = [b"body"]
    return resp


def _insecure_warnings(recorded):
    return [w for w in recorded if issubclass(w.category, InsecureRequestWarning)]


def test_insecure_request_warning_suppressed_when_verify_off(tmp_path):
    with patch("bashsim.fetcher.resolve_and_check", _allow_hosts("ok.test")), \
            patch.object(fetcher.requests, "get", side_effect=_warning_emitting_get), \
            warnings.catch_warnings(record=True) as recorded:
        warnings.simplefilter("always")
        result = _fetch(tmp_path, "https://ok.test/x", verify_ssl=False)

    assert result.ok is True
    assert _insecure_warnings(recorded) == []


def test_insecure_request_warning_not_suppressed_when_verify_on(tmp_path):
    with patch("bashsim.fetcher.resolve_and_check", _allow_hosts("ok.test")), \
            patch.object(fetcher.requests, "get", side_effect=_warning_emitting_get), \
            warnings.catch_warnings(record=True) as recorded:
        warnings.simplefilter("always")
        result = _fetch(tmp_path, "https://ok.test/x", verify_ssl=True)

    assert result.ok is True
    assert len(_insecure_warnings(recorded)) == 1


def test_warning_suppression_is_scoped_not_process_wide(tmp_path):
    # Fetching with verification off must not leave a global "ignore" filter behind that
    # would hide the warning for unrelated code.
    with patch("bashsim.fetcher.resolve_and_check", _allow_hosts("ok.test")), \
            patch.object(fetcher.requests, "get", side_effect=_warning_emitting_get), \
            warnings.catch_warnings(record=True) as recorded:
        warnings.simplefilter("always")
        _fetch(tmp_path, "https://ok.test/x", verify_ssl=False)
        warnings.warn("unrelated", InsecureRequestWarning)

    assert len(_insecure_warnings(recorded)) == 1


# --- safeguards are unchanged with verify off ------------------------------------------


def test_ssrf_check_still_enforced_on_initial_url_with_verify_off(tmp_path, requests_mocker):
    requests_mocker.get("https://internal-a.test/x", content=b"must never be fetched")

    result = _fetch(tmp_path, "https://internal-a.test/x", verify_ssl=False)  # 192.0.2.10

    assert result.ok is False
    assert result.error.startswith("ssrf_blocked:blocked_private_target:192.0.2.10")
    assert requests_mocker.request_history == []


def test_ssrf_check_still_enforced_on_redirect_hop_with_verify_off(tmp_path, requests_mocker):
    requests_mocker.get("https://ok.test/start", status_code=302, headers={"Location": "https://internal-b.test/steal"})
    requests_mocker.get("https://internal-b.test/steal", content=b"must never be fetched")

    with patch("bashsim.fetcher.resolve_and_check", _allow_hosts("ok.test")):
        result = _fetch(tmp_path, "https://ok.test/start", verify_ssl=False)  # hop 2 -> 203.0.113.20

    assert result.ok is False
    assert result.error.startswith("ssrf_blocked:blocked_private_target:203.0.113.20")
    assert [h.url for h in requests_mocker.request_history] == ["https://ok.test/start"]


def test_size_cap_and_redirect_cap_still_enforced_with_verify_off(tmp_path, requests_mocker):
    requests_mocker.get("https://ok.test/big", content=b"x" * 1000)
    requests_mocker.get("https://ok.test/loop", status_code=302, headers={"Location": "https://ok.test/loop"})

    with patch("bashsim.fetcher.resolve_and_check", _allow_hosts("ok.test")):
        big = _fetch(tmp_path, "https://ok.test/big", max_size=10, verify_ssl=False)
        loop = _fetch(tmp_path, "https://ok.test/loop", max_redirects=2, verify_ssl=False)

    assert big.ok is False and big.error == "too_large" and big.body_path is None
    assert loop.ok is False and loop.error == "too_many_redirects"


def test_timeout_still_passed_and_reported_with_verify_off(tmp_path, requests_mocker):
    requests_mocker.get("https://ok.test/slow", exc=requests.exceptions.Timeout)

    with patch("bashsim.fetcher.resolve_and_check", _allow_hosts("ok.test")):
        result = _fetch(tmp_path, "https://ok.test/slow", timeout=7, verify_ssl=False)

    assert result.error == "timeout"
    assert requests_mocker.request_history[0].timeout == 7


# --- SSL failure reporting -------------------------------------------------------------


def test_ssl_error_reported_distinctly_when_verify_on(tmp_path, requests_mocker):
    requests_mocker.get(
        "https://ok.test/x",
        exc=requests.exceptions.SSLError("certificate verify failed: self-signed certificate"),
    )

    with patch("bashsim.fetcher.resolve_and_check", _allow_hosts("ok.test")):
        result = _fetch(tmp_path, "https://ok.test/x", verify_ssl=True)

    assert result.ok is False
    assert result.error.startswith("ssl_error:")  # not "connection_error", though SSLError subclasses it
    assert "certificate verify failed" in result.error
    assert "verify_ssl=false" in result.error


def test_ssl_error_with_verify_off_has_no_misleading_hint(tmp_path, requests_mocker):
    # e.g. a protocol/handshake failure that has nothing to do with the certificate.
    requests_mocker.get("https://ok.test/x", exc=requests.exceptions.SSLError("handshake failure"))

    with patch("bashsim.fetcher.resolve_and_check", _allow_hosts("ok.test")):
        result = _fetch(tmp_path, "https://ok.test/x", verify_ssl=False)

    assert result.error.startswith("ssl_error:")
    assert "verify_ssl=false" not in result.error


def test_plain_connection_refused_is_still_connection_error(tmp_path, requests_mocker):
    requests_mocker.get("http://ok.test:4444/x", exc=requests.exceptions.ConnectionError("Connection refused"))

    with patch("bashsim.fetcher.resolve_and_check", _allow_hosts("ok.test")):
        result = _fetch(tmp_path, "http://ok.test:4444/x", verify_ssl=False)

    assert result.error.startswith("connection_error:")


# --- real TLS handshake against a local self-signed stub -------------------------------


@pytest.fixture
def selfsigned_https_server(tmp_path):
    x509 = pytest.importorskip("cryptography.x509")
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "selfsigned.test")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name).issuer_name(name).public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    cert_path, key_path = tmp_path / "cert.pem", tmp_path / "key.pem"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            body = b"stub payload bytes"
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(str(cert_path), str(key_path))
    server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
    server.socket = ctx.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server.server_address[1]
    finally:
        server.shutdown()
        server.server_close()


def _resolve_selfsigned_to_loopback(host, port=None, *args, **kwargs):
    if host == "selfsigned.test":
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", port or 0))]
    return _fake_getaddrinfo(host)


def test_self_signed_cert_real_handshake(tmp_path, selfsigned_https_server):
    url = f"https://selfsigned.test:{selfsigned_https_server}/x"

    with patch("socket.getaddrinfo", side_effect=_resolve_selfsigned_to_loopback), \
            patch("bashsim.fetcher.resolve_and_check", _allow_hosts("selfsigned.test")):
        strict = _fetch(tmp_path, url, verify_ssl=True)
        with warnings.catch_warnings(record=True) as recorded:
            warnings.simplefilter("always")
            lenient = _fetch(tmp_path, url, verify_ssl=False)

    assert strict.ok is False
    assert strict.error.startswith("ssl_error:")
    assert "CERTIFICATE_VERIFY_FAILED" in strict.error or "certificate verify failed" in strict.error

    assert lenient.ok is True
    assert lenient.http_status == 200
    with open(lenient.body_path, "rb") as f:
        assert f.read() == b"stub payload bytes"
    assert _insecure_warnings(recorded) == []


# --- service level: param wiring, manifest, result visibility --------------------------


def _manifest_param(name):
    from pathlib import Path

    import yaml

    manifest = yaml.safe_load((Path(__file__).parent.parent.parent / "service_manifest.yml").read_text())
    return next(p for p in manifest["submission_params"] if p["name"] == name)


def test_manifest_verify_ssl_param_defaults_false():
    param = _manifest_param("verify_ssl")
    assert param["type"] == "bool"
    assert param["default"] is False
    assert param["value"] is False


def _run_service(tmp_path, verify_ssl, simulate_downloads_only=False):
    """Drive BashSim.execute() with a fake request; fetch_url is stubbed so we can see
    exactly what the service hands it."""
    from bashsim.bashsim import BashSim
    from bashsim.fetcher import FetchResult

    params = {
        "max_loop_iterations": 200, "max_recursion_depth": 25, "max_urls": 10,
        "fetch_timeout_seconds": 5, "max_download_size_mb": 1, "max_redirects": 3,
        "user_agent": "test-agent", "verify_ssl": verify_ssl,
        "simulate_downloads_only": simulate_downloads_only,
    }
    request = MagicMock()
    request.file_contents = b"wget https://ok.test/payload.bin\n"
    request.get_param.side_effect = params.__getitem__

    svc = BashSim.__new__(BashSim)
    svc.identify = MagicMock()
    svc.identify.fileinfo.return_value = {"type": "unknown"}
    error = "ssl_error: certificate verify failed [certificate verification is ON]" if verify_ssl else "timeout"
    fake = FetchResult(False, "https://ok.test/payload.bin", None, None, None, 0, None, error)

    with patch("bashsim.bashsim.fetch_url", return_value=fake) as mock_fetch, \
            patch.object(BashSim, "working_directory", new=str(tmp_path), create=True):
        svc.execute(request)
    return mock_fetch, request.result


def _flatten(section):
    yield section
    for sub in section.subsections:
        yield from _flatten(sub)


@pytest.mark.parametrize("verify_ssl", [True, False])
def test_service_passes_param_to_fetch_and_reports_it(tmp_path, verify_ssl):
    mock_fetch, result = _run_service(tmp_path, verify_ssl)

    assert mock_fetch.call_args.kwargs["verify_ssl"] is verify_ssl

    sections = [s for top in result.sections for s in _flatten(top)]
    note = next(s for s in sections if s.title_text == "TLS certificate verification")
    body = note.body if isinstance(note.body, str) else str(note.body)
    assert ("was ON" in body) if verify_ssl else ("was OFF" in body)

    table = next(s for s in sections if s.title_text == "Real fetches performed")
    assert note in table.subsections
    row_text = str(table.body)
    if verify_ssl:
        assert "ssl_error" in row_text  # clear reason surfaces in the results table


def test_simulate_downloads_only_prevents_any_fetch_regardless_of_verify_ssl(tmp_path):
    """The safety switch that stops BashSim from ever fetching must not be bypassable by
    verify_ssl -- neither value of verify_ssl should cause a fetch when it is true."""
    from bashsim.bashsim import BashSim

    for verify_ssl in (True, False):
        params = {
            "max_loop_iterations": 200, "max_recursion_depth": 25, "max_urls": 10,
            "fetch_timeout_seconds": 5, "max_download_size_mb": 1, "max_redirects": 3,
            "user_agent": "test-agent", "verify_ssl": verify_ssl,
            "simulate_downloads_only": True,
        }
        request = MagicMock()
        request.file_contents = b"wget https://ok.test/payload.bin\n"
        request.get_param.side_effect = params.__getitem__

        svc = BashSim.__new__(BashSim)
        svc.identify = MagicMock()

        with patch("bashsim.bashsim.fetch_url") as mock_fetch, \
                patch.object(BashSim, "working_directory", new=str(tmp_path), create=True):
            svc.execute(request)

        mock_fetch.assert_not_called()
        sections = [s for top in request.result.sections for s in _flatten(top)]
        assert not any(s.title_text == "Real fetches performed" for s in sections)
        assert not any(s.title_text == "TLS certificate verification" for s in sections)
