"""Add `case ... esac` support to bashlex (pure parsing -- nothing is executed).

bashlex (0.18, the latest release) has the full `case` grammar in its PLY parser
(`case_command`, `case_clause`, `case_clause_sequence`, `pattern_list`, `pattern`),
but every one of those productions' action functions is a stub that raises
`NotImplementedError('type = {pattern}, token = {...}')`. A single `case` anywhere in
a script therefore makes `bashlex.parse()` reject the *whole* script, which is a
serious gap for malware analysis: `case "$1" in start) ... ;; esac` is the standard
shape of an init.d persistence script, and `case $(uname -m) in ...` is the standard
shape of a multi-arch IoT-botnet loader.

This module supplies real implementations for those five actions and rebinds them
on bashlex's already-built yacc parser (PLY binds each production's callable once,
at `yacc.yacc()` time, so replacing the module-level functions alone has no
effect). It also teaches `bashlex.ast.nodevisitor` the two new node kinds, because
`bashlex.parse()` itself runs a `posshifter` visitor over every top-level statement
after the first, and the stock visitor raises `ValueError` on unknown kinds.

Resulting AST shape (mirrors how bashlex represents `for`/`if`):

    compound(list=[case(parts=[reservedword 'case', word <subject>,
                               reservedword 'in',
                               pattern(parts=[word, (reservedword '|', word)...,
                                              reservedword ')', <body node>?,
                                              reservedword ';;'?]),
                               ...,
                               reservedword 'esac'])])

The patch is applied only while bashlex's own stub is still bound, so a future
bashlex release that implements `case` natively is left untouched.
"""
import bashlex
from bashlex import ast
from bashlex import parser as _bp

_STUB_NAMES = (
    "p_case_command",
    "p_case_clause",
    "p_pattern_list",
    "p_case_clause_sequence",
    "p_pattern",
)


def p_case_command(p):
    parts = _bp._makeparts(p)
    case_node = ast.node(kind="case", parts=parts, pos=_bp._partsspan(parts))
    p[0] = ast.node(kind="compound", redirects=[], list=[case_node], pos=case_node.pos)


def p_case_clause(p):
    # case_clause : pattern_list | case_clause_sequence pattern_list
    if len(p) == 2:
        p[0] = [p[1]]
    else:
        p[0] = p[1] + [p[2]]


def p_pattern_list(p):
    # newline_list [LEFT_PAREN] pattern RIGHT_PAREN (compound_list | newline_list)
    parts = _bp._makeparts(p)
    p[0] = ast.node(kind="pattern", parts=parts, pos=_bp._partsspan(parts))


def p_case_clause_sequence(p):
    # (case_clause_sequence)? pattern_list (SEMI_SEMI | SEMI_AND | SEMI_SEMI_AND)
    if len(p) == 3:
        seq, pat, term_idx = [], p[1], 2
    else:
        seq, pat, term_idx = p[1], p[2], 3
    term = ast.node(kind="reservedword", word=p[term_idx], pos=p.lexspan(term_idx))
    pat.parts.append(term)
    pat.pos = (pat.pos[0], term.pos[1])
    p[0] = seq + [pat]


def p_pattern(p):
    # pattern : WORD | pattern BAR WORD
    if len(p) == 2:
        p[0] = _bp._makeparts(p)
    else:
        bar = ast.node(kind="reservedword", word=p[2], pos=p.lexspan(2))
        p[0] = p[1] + [bar, _bp._expandword(p.context, p.slice[3])]


_IMPLS = {
    "p_case_command": p_case_command,
    "p_case_clause": p_case_clause,
    "p_pattern_list": p_pattern_list,
    "p_case_clause_sequence": p_case_clause_sequence,
    "p_pattern": p_pattern,
}

_original_visit = ast.nodevisitor.visit


def _visit(self, n):
    if n.kind in ("case", "pattern"):
        dochild = self._visitnode(n, n.parts)
        if dochild is None or dochild:
            for child in n.parts:
                self.visit(child)
        self.visitnodeend(n)
        return
    return _original_visit(self, n)


_applied = False


def apply() -> bool:
    """Idempotently install case support. Returns True if support is active."""
    global _applied
    if _applied:
        return True
    stubs = {name: getattr(_bp, name, None) for name in _STUB_NAMES}
    rebound = 0
    for prod in _bp.yaccparser.productions:
        func = getattr(prod, "func", None)
        if func in _IMPLS and stubs.get(func) is not None and prod.callable is stubs[func]:
            prod.callable = _IMPLS[func]
            rebound += 1
    if rebound:
        ast.nodevisitor.visit = _visit
        if not hasattr(ast.nodevisitor, "visitcase"):
            ast.nodevisitor.visitcase = lambda self, n, parts: None
        if not hasattr(ast.nodevisitor, "visitpattern"):
            ast.nodevisitor.visitpattern = lambda self, n, parts: None
    _applied = True
    return rebound > 0


apply()

__all__ = ["apply", "bashlex"]
