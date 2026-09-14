# Vendored verbatim from ~/assemblyline-service-payloadfetcher/payload_fetcher/ssrf_guard.py
# Keep in sync manually if the original changes.
"""SSRF protection: resolve a hostname and reject private/internal targets.

Isolated from fetcher.py so the only network-adjacent call (DNS resolution) is easy to
mock in tests without touching the HTTP layer.
"""
from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass

_METADATA_IP = "169.254.169.254"


@dataclass
class SSRFCheckResult:
    resolved_ips: list[str]
    blocked: bool
    reason: str  # "" | "dns_resolution_failed: ..." | f"blocked_private_target:{ip}"


def _is_blocked(ip_str: str) -> bool:
    if ip_str == _METADATA_IP:
        return True
    ip = ipaddress.ip_address(ip_str)
    return (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    )


def resolve_and_check(hostname: str) -> SSRFCheckResult:
    try:
        infos = socket.getaddrinfo(hostname, None)
    except socket.gaierror as e:
        return SSRFCheckResult([], False, f"dns_resolution_failed: {e}")

    ips = sorted({info[4][0] for info in infos})
    for ip_str in ips:
        if _is_blocked(ip_str):
            return SSRFCheckResult(ips, True, f"blocked_private_target:{ip_str}")
    return SSRFCheckResult(ips, False, "")
