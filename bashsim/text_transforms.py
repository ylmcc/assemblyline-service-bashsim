"""Pure-Python implementations of a small allowlist of safe, side-effect-free text
transforms (echo/printf/base64/tr/rev/xxd -r). No subprocess, no shell, ever.

Used by interpreter.py to resolve command-substitution chains like
`$(echo -n 'BASE64...' | base64 -d)` symbolically, matching the real corpus's
multi-layer base64-nested payloads, without ever invoking a real shell.
"""
from __future__ import annotations

import base64
import binascii


class TransformError(Exception):
    """Raised when a transform's input can't be safely computed (e.g. malformed base64)."""


def echo(args: list[str], no_newline: bool = False, interpret_escapes: bool = False) -> str:
    text = " ".join(args)
    if interpret_escapes:
        text = text.encode().decode("unicode_escape")
    if not no_newline:
        text += "\n"
    return text


def printf(fmt: str, args: list[str]) -> str:
    # Minimal, safe subset: repeatedly substitute %s with successive args; ignore other
    # format specifiers rather than risk misinterpreting something unexpected.
    out = fmt
    for a in args:
        if "%s" in out:
            out = out.replace("%s", a, 1)
    return out.encode().decode("unicode_escape") if "\\" in out else out


def base64_decode(s: str) -> str:
    try:
        cleaned = "".join(s.split())
        padded = cleaned + "=" * (-len(cleaned) % 4)
        return base64.b64decode(padded, validate=True).decode("utf-8", errors="replace")
    except (binascii.Error, ValueError) as e:
        raise TransformError(f"invalid base64: {e}") from e


def tr(s: str, from_set: str, to_set: str) -> str:
    if len(to_set) < len(from_set):
        to_set = to_set + to_set[-1:] * (len(from_set) - len(to_set)) if to_set else "\0" * len(from_set)
    table = str.maketrans(from_set, to_set[: len(from_set)])
    return s.translate(table)


def rev(s: str) -> str:
    return "\n".join(line[::-1] for line in s.splitlines())


def xxd_r(s: str, plain: bool) -> str:
    try:
        hex_str = "".join(s.split()) if plain else "".join(
            line.split(":", 1)[-1] for line in s.splitlines()
        )
        hex_str = "".join(ch for ch in hex_str if ch in "0123456789abcdefABCDEF")
        return bytes.fromhex(hex_str).decode("utf-8", errors="replace")
    except ValueError as e:
        raise TransformError(f"invalid hex: {e}") from e


# Command names this module can safely compute, mapped for interpreter.py's dispatch.
SAFE_TRANSFORM_COMMANDS = {"echo", "printf", "base64", "tr", "rev", "xxd", "cat"}
