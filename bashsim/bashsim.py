"""BashSim: symbolically emulates a bash script's grammar (loops, variable
substitution, safe base64/text-transform decoding) WITHOUT ever executing it, to
reveal dynamically-built commands/URLs a flat regex would miss. Any resolved
network-fetch command is optionally given a real, SSRF-guarded fetch (reusing the
same logic as the sibling PayloadFetcher service). Everything else recognized
(persistence/system-mutation commands, direct execution of fetched/decoded content)
is only ever logged, never performed.

No subprocess, no eval/exec of script text, no real bash/sh invocation anywhere in
this service.
"""
from __future__ import annotations

import json
import os
from urllib.parse import urlparse

from assemblyline.common.identify import Identify
from assemblyline_v4_service.common.base import ServiceBase
from assemblyline_v4_service.common.request import ServiceRequest
from assemblyline_v4_service.common.result import (
    Heuristic,
    Result,
    ResultSection,
    ResultTableSection,
    TableRow,
)
from assemblyline_v4_service.common.task import PARENT_RELATION

from bashsim.fetcher import fetch_url
from bashsim.interpreter import BashSimInterpreter, has_multi_arch_pattern

_MISMATCH_PRONE_EXTENSIONS = {".php", ".html", ".htm", ".txt", ".asp", ".aspx", ".jsp"}
_RISKY_SIGNATURES = {"executable", "script"}


def _classify_signature(sniffed_type: str) -> str:
    if sniffed_type.startswith("executable"):
        return "executable"
    if sniffed_type.startswith(("code/shell", "code/python", "code/perl", "code/batch", "code/ps1")):
        return "script"
    if sniffed_type.startswith(("code/php", "code/html", "text/")):
        return "webshell_or_html"
    return "other"


class BashSim(ServiceBase):
    def __init__(self, config=None) -> None:
        super().__init__(config)
        self.identify = None

    def start(self) -> None:
        self.identify = Identify(use_cache=False)

    def execute(self, request: ServiceRequest) -> None:
        text = request.file_contents.decode("utf-8", errors="ignore")

        interp = BashSimInterpreter(
            max_loop_iterations=request.get_param("max_loop_iterations"),
            max_recursion_depth=request.get_param("max_recursion_depth"),
        )
        ir = interp.run(text)

        result = Result()
        audit_log = {
            "parse_errors": ir.parse_errors,
            "truncated": ir.truncated,
            "actions": [
                {
                    "kind": a.kind, "command": a.command, "args": a.args,
                    "resolved": a.resolved, "conditional": a.conditional, "detail": a.detail,
                }
                for a in ir.actions
            ],
        }

        if ir.parse_errors:
            parse_section = ResultSection(
                "Parse was incomplete",
                body=f"bashlex could not fully parse this script: {ir.parse_errors}. "
                     "Results below reflect only what was successfully parsed.",
            )
            parse_section.set_heuristic(7, signature="parse_incomplete")
            result.add_section(parse_section)

        fetches = [a for a in ir.actions if a.kind == "network_fetch" and a.resolved and a.detail.get("url")]

        if has_multi_arch_pattern(fetches):
            multi_arch = ResultSection(
                "Multi-architecture loader pattern detected",
                body="Four or more architecture-specific payload URLs were resolved on a "
                     "single host, matching the shape of a Mirai/Gafgyt-style multi-arch loader.",
            )
            multi_arch.set_heuristic(2, signature="multi_arch_loader")
            result.add_section(multi_arch)

        exfils = [a for a in ir.actions if a.kind == "exfil_upload"]
        if exfils:
            exfil_section = ResultSection(
                "Exfiltration pattern recognized",
                body="The script sends local data to a remote host (e.g. curl -F/--data), "
                     "recognized but never actually sent:\n"
                     + "\n".join(f"{a.command} -> {a.detail.get('url')}" for a in exfils),
            )
            exfil_section.set_heuristic(3, signature="exfil_upload")
            result.add_section(exfil_section)

        mutations = [a for a in ir.actions if a.kind == "system_mutation"]
        if mutations:
            mutation_section = ResultSection(
                "Persistence/system-mutation commands recognized (not performed)",
                body="\n".join(f"{a.command} {' '.join(a.args)}" for a in mutations),
            )
            mutation_section.set_heuristic(4, signature="system_mutation")
            result.add_section(mutation_section)

        direct_execs = [a for a in ir.actions if a.kind == "direct_execution"]
        if direct_execs:
            lines = []
            for a in direct_execs:
                line = f"{a.command} {a.detail.get('target', '')}"
                if a.detail.get("cross_reference"):
                    line += f" ({a.detail['cross_reference']})"
                lines.append(line)
            direct_exec_section = ResultSection(
                "Direct execution of fetched/decoded content recognized (not performed)",
                body="\n".join(lines),
            )
            direct_exec_section.set_heuristic(5, signature="direct_execution")
            result.add_section(direct_exec_section)

        if fetches and not request.get_param("simulate_downloads_only"):
            fetch_table = ResultTableSection("Real fetches performed")
            heur_fetch = None
            ssrf_blocked_urls = []
            for a in fetches:
                url = a.detail["url"]
                fr = fetch_url(
                    url, self.working_directory,
                    request.get_param("fetch_timeout_seconds"),
                    request.get_param("max_download_size_mb") * 1024 * 1024,
                    request.get_param("max_redirects"),
                    request.get_param("user_agent"),
                )
                if not fr.ok:
                    fetch_table.add_row(TableRow(url=url, outcome="failed", reason=fr.error))
                    if fr.error.startswith("ssrf_blocked"):
                        ssrf_blocked_urls.append(url)
                    continue

                file_info = self.identify.fileinfo(fr.body_path, skip_fuzzy_hashes=True, calculate_entropy=False)
                sniffed_type = file_info["type"]
                url_ext = os.path.splitext(urlparse(url).path)[1].lower()
                display_name = f"{fr.sha256}{url_ext}" if url_ext else fr.sha256
                request.add_extracted(
                    fr.body_path, display_name,
                    f"Payload resolved and fetched via {a.command} ({url})",
                    parent_relation=PARENT_RELATION.DOWNLOADED,
                )
                fetch_table.add_row(TableRow(
                    url=url, outcome="fetched", http_status=fr.http_status,
                    content_type_header=fr.content_type_header or "",
                    sniffed_type=sniffed_type, size=fr.size, sha256=fr.sha256,
                ))
                heur_fetch = heur_fetch or Heuristic(1)
                heur_fetch.add_signature_id(_classify_signature(sniffed_type))

            result.add_section(fetch_table)
            if heur_fetch:
                fetch_table.set_heuristic(heur_fetch)

            if ssrf_blocked_urls:
                ssrf_section = ResultSection(
                    "SSRF-risk targets blocked",
                    body="The following resolved URL(s) (or a redirect target) resolved to a "
                         "private/loopback/link-local/metadata address and were not fetched:\n"
                         + "\n".join(ssrf_blocked_urls),
                )
                ssrf_section.set_heuristic(6, signature="ssrf_blocked")
                result.add_section(ssrf_section)

        log_path = os.path.join(self.working_directory, "bashsim_actions_log.json")
        with open(log_path, "w") as f:
            json.dump(audit_log, f, indent=2)
        request.add_supplementary(log_path, "bashsim_actions_log.json", "Full symbolic-interpretation action log")

        request.result = result
