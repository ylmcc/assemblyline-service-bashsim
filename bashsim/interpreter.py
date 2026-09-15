"""Pure-Python symbolic emulator for bash scripts.

Parses a script with `bashlex` (a grammar parser with no execution/subprocess/network
capability whatsoever) and walks the resulting AST, resolving variable substitution,
literal `for` loops, and a small safe allowlist of pure-text-transform command
substitutions (echo/printf/base64/tr/rev/xxd -r) symbolically. Every external command
the script would have invoked is only ever recorded as an `Action` -- never executed.

No subprocess, no `eval`/`exec` of script text, no real bash/sh invocation, anywhere in
this module. This module also makes no network calls of its own -- it only *identifies*
network-fetch-shaped commands and reports the resolved URL/output path for the caller
(bashsim.py) to decide whether to perform a real, SSRF-guarded fetch.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

import bashlex

from . import text_transforms
from .text_transforms import SAFE_TRANSFORM_COMMANDS, TransformError

_NETWORK_FETCH_CMDS = {"wget", "curl", "tftp", "nc", "ncat", "scp"}
_EXFIL_FLAGS = ("-F", "--data", "--data-binary", "--data-raw", "--data-urlencode", "-T")
_SYSTEM_MUTATION_CMDS = {
    "chmod", "chown", "rm", "mv", "cp", "mkdir", "touch", "crontab", "useradd", "userdel",
    "passwd", "mysql", "systemctl", "service", "iptables", "chattr", "kill", "pkill",
}
_DIRECT_EXEC_KEYWORDS = {"source", "eval", "."}
_DIRECT_EXEC_SHELLS = {"bash", "sh"}


@dataclass
class SymValue:
    concrete: Optional[str]
    resolved: bool
    source_note: str  # "literal" | "resolved via ..." | "unresolved: <why>"


@dataclass
class Action:
    kind: str  # "network_fetch" | "exfil_upload" | "system_mutation" | "direct_execution" | "other_command"
    command: str
    args: list[str]
    resolved: bool
    conditional: bool
    raw_node_text: str
    detail: dict = field(default_factory=dict)


@dataclass
class InterpretResult:
    actions: list[Action]
    parse_errors: list[str]
    truncated: bool


class BashSimInterpreter:
    def __init__(self, max_loop_iterations: int = 200, max_recursion_depth: int = 25):
        self.max_loop_iterations = max_loop_iterations
        self.max_recursion_depth = max_recursion_depth
        self.script_text = ""
        self._parse_errors: list[str] = []
        self._truncated = False
        self._functions: dict[str, "object"] = {}
        self._function_called_directly: set[str] = set()

    def run(self, script_text: str) -> InterpretResult:
        self.script_text = script_text
        self._parse_errors = []
        self._truncated = False
        actions: list[Action] = []

        if not self._strip_comments_and_blanks(script_text).strip():
            # A script with nothing but comments/shebang/blank lines has no real
            # content to analyze -- and bashlex's own AST-visitor crashes on this
            # degenerate input (AttributeError: 'str' object has no attribute 'kind',
            # an internal bashlex bug, not ours). Skip parsing entirely: there is
            # genuinely nothing to resolve, so an empty, non-error result is correct.
            return InterpretResult([], [], False)

        try:
            trees = bashlex.parse(script_text)
        except NotImplementedError as e:
            if "arithmetic expansion" in str(e):
                # bashlex's grammar doesn't support $((...)); neutralize each such
                # span with an inert placeholder word (bashlex parses fine) so one
                # unsupported construct doesn't discard analysis of an otherwise
                # ordinary script. The placeholders are not evaluated -- reported so
                # results are understood as best-effort around them.
                neutralized, count = self._neutralize_arithmetic_expansions(script_text)
                try:
                    trees = bashlex.parse(neutralized)
                    self.script_text = neutralized
                    self._parse_errors.append(
                        f"{count} arithmetic expansion(s) (e.g. $((...))) replaced with inert "
                        "placeholders -- bashlex cannot parse them, so they were not resolved"
                    )
                except Exception as e2:
                    return InterpretResult([], [f"parse failed: {e2}"], False)
            else:
                return InterpretResult([], [f"parse failed: {e}"], False)
        except Exception as e:  # bashlex can raise various errors on malformed/adversarial input
            return InterpretResult([], [f"parse failed: {e}"], False)

        # First pass: register every user-defined function by name, and note which
        # ones are ever invoked by a direct literal command name anywhere in the
        # script. This lets _walk_command re-walk a function's body per call site
        # with $1/$2/... bound to that call's actual arguments (see below), instead
        # of the old behaviour of walking every function body exactly once, blind,
        # at its definition point -- which could never resolve positional
        # parameters to anything concrete. Functions never called by a direct
        # literal name (indirect/dynamic dispatch, or genuinely dead code) fall
        # back to that original blind-walk-at-definition behaviour, so nothing is
        # silently dropped.
        self._functions = {}
        self._function_called_directly = set()
        for tree in trees:
            self._collect_functions_and_calls(tree)

        env: dict[str, SymValue] = {}
        for tree in trees:
            try:
                self._walk(tree, env, actions, conditional=False, depth=0)
            except Exception as e:  # never let a single malformed construct crash the whole run
                self._parse_errors.append(f"error while walking script: {e}")

        self._cross_reference_direct_execution(actions)
        return InterpretResult(actions, self._parse_errors, self._truncated)

    def _collect_functions_and_calls(self, node):
        """Pre-pass: populate self._functions (name -> function node) and
        self._function_called_directly (names ever invoked as a plain literal
        command word anywhere in the script). No resolution/env needed -- this
        only looks at static structure."""
        kind = node.kind
        if kind == "function":
            name_node = getattr(node, "name", None)
            if name_node is not None and getattr(name_node, "word", None):
                self._functions[name_node.word] = node
            body = getattr(node, "body", None)
            if body is not None:
                self._collect_functions_and_calls(body)
            return
        if kind == "command":
            words = [p for p in (getattr(node, "parts", None) or []) if p.kind == "word"]
            if words and not (getattr(words[0], "parts", None)):
                self._function_called_directly.add(words[0].word)
            return
        for child in (getattr(node, "parts", None) or getattr(node, "list", None) or []):
            self._collect_functions_and_calls(child)

    # ---- AST walking ----------------------------------------------------

    def _walk(self, node, env, actions, conditional, depth):
        if depth > self.max_recursion_depth:
            self._truncated = True
            return
        kind = node.kind
        if kind == "compound":
            for child in getattr(node, "list", None) or []:
                self._walk(child, env, actions, conditional, depth + 1)
        elif kind == "list":
            for child in getattr(node, "parts", None) or []:
                if child.kind != "operator":
                    self._walk(child, env, actions, conditional, depth + 1)
        elif kind == "pipeline":
            prev_action = None
            for child in getattr(node, "parts", None) or []:
                if child.kind != "command":
                    continue
                before_len = len(actions)
                self._walk(child, env, actions, conditional, depth + 1)
                if len(actions) > before_len:
                    new_action = actions[-1]
                    if (
                        new_action.kind == "direct_execution"
                        and new_action.detail.get("target") == "<stdin>"
                        and prev_action is not None
                    ):
                        if prev_action.kind == "network_fetch" and prev_action.detail.get("url"):
                            new_action.detail["cross_reference"] = (
                                f"executes piped output of fetching {prev_action.detail['url']}"
                            )
                        else:
                            new_action.detail["cross_reference"] = (
                                f"executes piped output of '{prev_action.command}'"
                            )
                    prev_action = new_action
        elif kind == "for":
            self._walk_for(node, env, actions, conditional, depth)
        elif kind in ("if", "while", "until"):
            self._walk_all_lists_conditional(node, env, actions, depth)
        elif kind == "command":
            self._walk_command(node, env, actions, conditional, depth)
        elif kind == "function":
            # Only blind-walk here if this function is never invoked by a direct
            # literal command name anywhere in the script (see
            # _collect_functions_and_calls) -- if it is, _walk_command re-walks
            # its body per call site with real argument binding instead, which is
            # strictly more informative than one unconditional blind pass.
            name_node = getattr(node, "name", None)
            name = getattr(name_node, "word", None) if name_node is not None else None
            if name is not None and name in self._function_called_directly:
                return
            body = getattr(node, "body", None)
            if body is not None:
                self._walk(body, dict(env), actions, True, depth + 1)
            else:
                # Unexpected bashlex shape (no .body attribute) -- fall back to the
                # old parts-iteration approach rather than silently dropping the
                # function's contents.
                for child in getattr(node, "parts", None) or []:
                    self._walk(child, dict(env), actions, True, depth + 1)
        # other kinds (operator, reservedword, redirect, ...) have nothing to do standalone

    def _walk_all_lists_conditional(self, node, env, actions, depth):
        """Shared handling for if/while/until: walk every nested part (conditions AND
        bodies -- each may be a bare 'command' node when it's a single statement, or a
        'list' node when there are multiple) unconditionally, but mark every action
        found as conditional=True, since we deliberately do not attempt to evaluate real
        runtime truth values."""
        self._walk_conditional_parts(getattr(node, "parts", None) or [], env, actions, depth)

    def _walk_conditional_parts(self, parts, env, actions, depth):
        for p in parts:
            if p.kind == "reservedword":
                # bashlex quirk: a chain of 2+ elif/else branches gets the *second*
                # and later branches nested as a raw list of further AST nodes
                # inside a reservedword's .word attribute, instead of as normal
                # sibling parts -- confirmed via direct inspection (a 4-elif+else
                # chain nests recursively this way). Recurse into it (arbitrary
                # depth) so branches beyond the first elif aren't silently dropped.
                if isinstance(p.word, list):
                    self._walk_conditional_parts(p.word, env, actions, depth)
                continue
            self._walk(p, dict(env), actions, True, depth + 1)

    def _walk_for(self, node, env, actions, conditional, depth):
        parts = getattr(node, "parts", None) or []
        var_name = None
        items = []
        body_nodes = []
        has_in = False
        in_body = False
        for p in parts:
            if p.kind == "reservedword" and p.word == "do":
                in_body = True
                continue
            if p.kind == "reservedword" and p.word == "done":
                in_body = False
                continue
            if in_body:
                body_nodes.append(p)
                continue
            if p.kind == "reservedword" and p.word == "in":
                has_in = True
            elif p.kind == "word" and var_name is None:
                var_name = p.word
            elif p.kind == "word" and has_in:
                items.append(p)

        if not body_nodes:
            self._parse_errors.append("for-loop body not found")
            return

        def walk_body(child_env, cond):
            for bn in body_nodes:
                self._walk(bn, child_env, actions, cond, depth + 1)

        if var_name and has_in and items:
            resolved_items = [self._resolve_word(w, env) for w in items]
            if all(ri.resolved for ri in resolved_items):
                count = 0
                for ri in resolved_items:
                    if count >= self.max_loop_iterations:
                        self._truncated = True
                        break
                    child_env = dict(env)
                    child_env[var_name] = ri
                    walk_body(child_env, conditional)
                    count += 1
                return

        # Unresolvable item list (or no 'in' clause, e.g. iterating "$@"): walk the body
        # once, with the loop variable marked unresolved, flagged conditional since this
        # single pass isn't guaranteed representative of the real iteration.
        child_env = dict(env)
        if var_name:
            child_env[var_name] = SymValue(None, False, "unresolved: loop list not statically resolvable")
        walk_body(child_env, True)

    def _walk_command(self, node, env, actions, conditional, depth=0):
        words = []
        for p in getattr(node, "parts", None) or []:
            if p.kind == "assignment":
                name = p.word.split("=", 1)[0]
                sv_full = self._resolve_spliced(p, env)
                prefix_len = len(name) + 1
                value = sv_full.concrete[prefix_len:] if sv_full.concrete is not None else None
                env[name] = SymValue(value, sv_full.resolved, sv_full.source_note)
            elif p.kind == "word":
                words.append(p)
            # redirect/heredoc parts are ignored: nothing is ever actually written/read

        if not words:
            return  # pure assignment statement -- nothing to classify as a command

        resolved = [self._resolve_word(w, env) for w in words]
        command_name = resolved[0].concrete if resolved[0].concrete is not None else "<unresolved>"
        # Use concrete text whenever it's available, even if not every part of the
        # word resolved (e.g. "https://217.60.103.56/$1" with $1 unresolved) --
        # _resolve_spliced already spliced literal text around the unresolved
        # fragment, so the static portion (an IP, a path, ...) must not be thrown
        # away and replaced with an opaque "<unresolved>" token. `resolved`
        # (all_resolved below) still correctly reflects that not everything in
        # this action was concretely known.
        args = [r.concrete if r.concrete is not None else "<unresolved>" for r in resolved[1:]]
        all_resolved = all(r.resolved for r in resolved)

        kind, detail = self._classify(command_name, args)
        actions.append(Action(
            kind=kind,
            command=command_name,
            args=args,
            resolved=all_resolved,
            conditional=conditional,
            raw_node_text=self._slice(node),
            detail=detail,
        ))

        func_node = self._functions.get(command_name)
        if func_node is not None:
            body = getattr(func_node, "body", None)
            if body is not None:
                child_env = dict(env)
                arg_values = resolved[1:]
                for i, rv in enumerate(arg_values, start=1):
                    child_env[str(i)] = rv
                if arg_values:
                    joined = " ".join(rv.concrete for rv in arg_values if rv.concrete is not None)
                    all_args_resolved = all(rv.resolved for rv in arg_values)
                    child_env["@"] = SymValue(joined, all_args_resolved, "resolved via call-site arguments")
                    child_env["*"] = child_env["@"]
                child_env["#"] = SymValue(str(len(arg_values)), True, "literal")
                self._walk(body, child_env, actions, conditional, depth + 1)

    def _cross_reference_direct_execution(self, actions):
        fetch_by_path = {
            a.detail.get("output_path"): a
            for a in actions
            if a.kind == "network_fetch" and a.detail.get("output_path")
        }
        for a in actions:
            if a.kind != "direct_execution":
                continue
            target = a.detail.get("target")
            if target in fetch_by_path:
                src = fetch_by_path[target]
                a.detail["cross_reference"] = f"would execute payload fetched from {src.detail.get('url')}"

    # ---- classification ---------------------------------------------------

    def _classify(self, name: str, args: list[str]) -> tuple[str, dict]:
        base_name = name.rsplit("/", 1)[-1]

        if base_name == "curl" and any(
            a in _EXFIL_FLAGS or a.startswith("--data") for a in args
        ):
            return "exfil_upload", {"url": self._extract_url(args)}

        if base_name in _NETWORK_FETCH_CMDS:
            return "network_fetch", {
                "url": self._extract_url(args),
                "output_path": self._extract_output_path(base_name, args),
            }

        if base_name in _SYSTEM_MUTATION_CMDS:
            return "system_mutation", {}

        if base_name in _DIRECT_EXEC_KEYWORDS:
            return "direct_execution", {"target": args[0] if args else None}

        if base_name in _DIRECT_EXEC_SHELLS:
            # A bare `sh`/`bash` with no file argument reads its script from stdin --
            # the classic `curl ... | sh` RCE pattern. Still direct_execution, just
            # with no on-disk target path; the pipeline walker cross-references this
            # to whatever fed its stdin (see the "pipeline" case in _walk).
            return "direct_execution", {"target": args[0] if args else "<stdin>"}

        if name.startswith("./") or name.startswith("../") or (
            name.startswith("/") and base_name not in _DIRECT_EXEC_SHELLS
        ):
            return "direct_execution", {"target": name}

        return "other_command", {}

    @staticmethod
    def _extract_url(args: list[str]) -> Optional[str]:
        for a in args:
            if "://" in a:
                return a
        for a in args:
            if a != "<unresolved>" and not a.startswith("-"):
                return a
        return None

    @staticmethod
    def _extract_output_path(command: str, args: list[str]) -> Optional[str]:
        flags = {"-O", "-o", "--output-document"}
        for i, a in enumerate(args):
            if a in flags and i + 1 < len(args):
                return args[i + 1]
        return None

    # ---- word / substitution resolution ------------------------------------

    def _resolve_word(self, word_node, env) -> SymValue:
        return self._resolve_spliced(word_node, env)

    def _resolve_spliced(self, node, env) -> SymValue:
        """Reconstruct a word/assignment node's concrete text by splicing resolved
        parameter/command-substitution values into the literal base text, using
        bashlex's absolute character offsets."""
        base = node.word
        parts = getattr(node, "parts", None) or []
        if not parts:
            return SymValue(base, True, "literal")

        start = node.pos[0]
        pieces = []
        cursor = 0
        all_resolved = True
        notes = []
        for part in parts:
            rel_start = part.pos[0] - start
            rel_end = part.pos[1] - start
            pieces.append(base[cursor:rel_start])

            if part.kind == "parameter":
                sv = env.get(part.value)
                if sv is not None and sv.resolved and sv.concrete is not None:
                    pieces.append(sv.concrete)
                else:
                    pieces.append(base[rel_start:rel_end])
                    all_resolved = False
                    notes.append(f"unresolved variable ${part.value}")
            elif part.kind == "commandsubstitution":
                sv = self._eval_command_substitution(part.command, env)
                if sv.resolved and sv.concrete is not None:
                    pieces.append(sv.concrete)
                else:
                    pieces.append("")
                    all_resolved = False
                    notes.append(sv.source_note)
            else:
                pieces.append(base[rel_start:rel_end])
                all_resolved = False
                notes.append(f"unresolved node kind '{part.kind}'")
            cursor = rel_end
        pieces.append(base[cursor:])
        concrete = "".join(pieces)
        note = "resolved via substitution" if all_resolved else "; ".join(notes)
        return SymValue(concrete, all_resolved, note)

    def _eval_command_substitution(self, node, env) -> SymValue:
        commands = self._flatten_pipeline(node)
        if commands is None:
            return SymValue(None, False, "unresolved: complex substitution structure")

        stdin_value: Optional[str] = None
        for cmd_node in commands:
            words = [p for p in (getattr(cmd_node, "parts", None) or []) if p.kind == "word"]
            if not words:
                return SymValue(None, False, "unresolved: empty command in substitution")
            resolved_words = [self._resolve_word(w, env) for w in words]
            if any(not rw.resolved for rw in resolved_words):
                return SymValue(None, False, "unresolved: unresolvable argument inside substitution")
            name = resolved_words[0].concrete
            args = [rw.concrete for rw in resolved_words[1:]]
            if name not in SAFE_TRANSFORM_COMMANDS:
                return SymValue(None, False, f"unresolved: contains non-text-transform command '{name}'")
            try:
                stdin_value = self._apply_transform(name, args, stdin_value)
            except TransformError as e:
                return SymValue(None, False, f"unresolved: {e}")

        return SymValue(stdin_value or "", True, "resolved via text-transform pipeline")

    @staticmethod
    def _flatten_pipeline(node):
        if node.kind == "command":
            return [node]
        if node.kind == "pipeline":
            cmds = [p for p in (getattr(node, "parts", None) or []) if p.kind == "command"]
            return cmds or None
        if node.kind == "list":
            cmds = []
            for p in getattr(node, "parts", None) or []:
                if p.kind == "command":
                    cmds.append(p)
                elif p.kind == "operator":
                    continue
                else:
                    return None
            return cmds or None
        return None

    @staticmethod
    def _apply_transform(name: str, args: list[str], stdin_value: Optional[str]) -> str:
        if name == "echo":
            no_newline = "-n" in args
            interpret = "-e" in args
            real_args = [a for a in args if a not in ("-n", "-e")]
            return text_transforms.echo(real_args, no_newline, interpret)
        if name == "printf":
            if not args:
                raise TransformError("printf needs a format string")
            return text_transforms.printf(args[0], args[1:])
        if name == "base64":
            if stdin_value is None:
                raise TransformError("base64 needs stdin input")
            if not any(a in ("-d", "--decode") for a in args):
                raise TransformError("only 'base64 -d' is supported")
            return text_transforms.base64_decode(stdin_value)
        if name == "tr":
            if stdin_value is None:
                raise TransformError("tr needs stdin input")
            if len(args) < 2:
                raise TransformError("tr needs from/to character sets")
            return text_transforms.tr(stdin_value, args[0], args[1])
        if name == "rev":
            if stdin_value is None:
                raise TransformError("rev needs stdin input")
            return text_transforms.rev(stdin_value)
        if name == "xxd":
            if stdin_value is None:
                raise TransformError("xxd needs stdin input")
            if "-r" not in args:
                raise TransformError("only 'xxd -r' is supported")
            return text_transforms.xxd_r(stdin_value, plain="-p" in args)
        if name == "cat":
            if stdin_value is not None:
                return stdin_value
            raise TransformError("'cat' with file arguments is not supported, only piped stdin")
        raise TransformError(f"unsupported transform '{name}'")

    def _slice(self, node) -> str:
        try:
            return self.script_text[node.pos[0]:node.pos[1]]
        except Exception:
            return ""

    @staticmethod
    def _strip_comments_and_blanks(text: str) -> str:
        lines = []
        for line in text.splitlines():
            stripped = line.strip()
            if stripped and not stripped.startswith("#"):
                lines.append(line)
        return "\n".join(lines)

    @staticmethod
    def _neutralize_arithmetic_expansions(text: str) -> tuple[str, int]:
        """Replace each $((...)) span (tracking nested parens) with an inert,
        bashlex-parseable placeholder word. Returns (new_text, count_replaced)."""
        out = []
        i = 0
        n = len(text)
        count = 0
        while i < n:
            if text.startswith("$((", i):
                depth = 2  # the two '(' already consumed after '$'
                j = i + 3
                while j < n and depth > 0:
                    if text[j] == "(":
                        depth += 1
                    elif text[j] == ")":
                        depth -= 1
                    j += 1
                out.append(f"__bashsim_arith_{count}__")
                count += 1
                i = j
            else:
                out.append(text[i])
                i += 1
        return "".join(out), count


def has_multi_arch_pattern(actions: list[Action], threshold: int = 4) -> bool:
    from collections import defaultdict
    from urllib.parse import urlparse

    groups: dict[str, int] = defaultdict(int)
    for a in actions:
        if a.kind != "network_fetch" or not a.resolved:
            continue
        url = a.detail.get("url")
        if not url:
            continue
        host = urlparse(url).hostname
        if host:
            groups[host.lower()] += 1
    return any(count >= threshold for count in groups.values())
