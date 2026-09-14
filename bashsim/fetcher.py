# Vendored verbatim from ~/assemblyline-service-payloadfetcher/payload_fetcher/fetcher.py
# Keep in sync manually if the original changes.
"""Fetch a URL and stream its response to disk, with a per-hop SSRF check and a hard
size cap.

Never executes or interprets the fetched content — it is only streamed to disk, hashed,
and handed back for the caller to classify by real bytes.
"""
from __future__ import annotations

import hashlib
import os
import tempfile
from dataclasses import dataclass
from urllib.parse import urljoin, urlparse

import requests

from .ssrf_guard import resolve_and_check

_CHUNK_SIZE = 65536


@dataclass
class FetchResult:
    ok: bool
    final_url: str
    http_status: int | None
    content_type_header: str | None
    body_path: str | None
    size: int
    sha256: str | None
    error: str


def fetch_url(
    url: str,
    dest_dir: str,
    timeout: int,
    max_size: int,
    max_redirects: int,
    user_agent: str,
) -> FetchResult:
    current_url = url

    for hop in range(max_redirects + 1):
        host = urlparse(current_url).hostname
        if not host:
            return FetchResult(False, current_url, None, None, None, 0, None, "invalid_url")

        check = resolve_and_check(host)
        if check.blocked:
            return FetchResult(False, current_url, None, None, None, 0, None, f"ssrf_blocked:{check.reason}")
        if check.reason.startswith("dns_resolution_failed"):
            return FetchResult(False, current_url, None, None, None, 0, None, check.reason)

        try:
            resp = requests.get(
                current_url,
                headers={"User-Agent": user_agent},
                timeout=timeout,
                stream=True,
                allow_redirects=False,
            )
        except requests.exceptions.Timeout:
            return FetchResult(False, current_url, None, None, None, 0, None, "timeout")
        except requests.exceptions.ConnectionError as e:
            return FetchResult(False, current_url, None, None, None, 0, None, f"connection_error: {e}")
        except requests.exceptions.RequestException as e:
            return FetchResult(False, current_url, None, None, None, 0, None, f"request_error: {e}")

        if resp.is_redirect and resp.headers.get("Location"):
            current_url = urljoin(current_url, resp.headers["Location"])
            resp.close()
            continue

        # A fresh, guaranteed-unique filename per call: dest_dir (self.working_directory)
        # is shared across every fetch_url() call within one execute() invocation, and
        # a hop-index-only name (e.g. "fetch_0.bin") collides across separate calls that
        # each start their own hop counter at 0 -- silently overwriting an earlier fetch's
        # body before AL4 reads/hashes it, which surfaces later as a confusing
        # "uploaded file does not match expected hash" error on an unrelated file.
        fd, body_path = tempfile.mkstemp(dir=dest_dir, prefix="fetch_", suffix=f"_hop{hop}.bin")
        os.close(fd)
        size = 0
        digest = hashlib.sha256()
        try:
            with open(body_path, "wb") as f:
                for chunk in resp.iter_content(chunk_size=_CHUNK_SIZE):
                    if not chunk:
                        continue
                    size += len(chunk)
                    if size > max_size:
                        resp.close()
                        try:
                            os.remove(body_path)
                        except OSError:
                            pass
                        return FetchResult(
                            False, current_url, resp.status_code,
                            resp.headers.get("Content-Type"), None, size, None, "too_large",
                        )
                    f.write(chunk)
                    digest.update(chunk)
        finally:
            resp.close()

        return FetchResult(
            True, current_url, resp.status_code, resp.headers.get("Content-Type"),
            body_path, size, digest.hexdigest(), "",
        )

    return FetchResult(False, current_url, None, None, None, 0, None, "too_many_redirects")
