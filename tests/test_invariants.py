"""Structural invariants enforced at CI time.

Every test in this file walks the AST of Cortex's source files and
fails if a pattern R5 of the red team called out as "path-level
whack-a-mole" reappears. Regex grep was considered and rejected —
``{"role": "tool"}`` is trivially hidden from grep by spreads,
dict() constructors, or runtime mutation. ``ast.parse`` sees through
all of those.

Escape hatch: per-line comment ``# invariant: allow-<rule-id> because
<reason>`` disables the check for exactly that line. Anything without
an allow-comment fails the test. The allow list is greppable by
reviewers during code review — the goal is *visible* exceptions,
not silent ones.

Running these tests:
  * `python3 tests/test_invariants.py`
  * `python3 -m pytest tests/test_invariants.py`
  * conftest.py session-scope fixture auto-runs them for any `pytest`

Phase policy:
  * Phase 0 (now): xfail(strict=False) — migration in progress.
  * Phase 1 (flip): remove xfail, every invariant violation blocks
    the CI. Done once every source file has been migrated.
"""
from __future__ import annotations

import ast
import io
import pathlib
import re
import sys
import tokenize

_REPO = pathlib.Path(__file__).resolve().parent.parent

# R14/#3: discover every top-level .py file automatically instead of a
# static allow-list. A new module at the repo root (next ingress type,
# new subcommand, future API) inherits the invariants without a test
# edit. Keep the exclusion set explicit — security/ IS the invariant
# definition; tests/ intentionally constructs bare dicts for fixtures.
_EXCLUDE_DIRS = {"security", "tests", "plugins", "venv", ".venv",
                 "__pycache__", ".git", "build", "dist"}
_EXCLUDE_FILES = {"ws_test.py"}  # CLI smoke-test, not agent code


def _discover_targets():
    """Yield (name, text) for every source file the invariants apply to."""
    for path in sorted(_REPO.glob("*.py")):
        if path.name in _EXCLUDE_FILES:
            continue
        yield path.name, path.read_text()
    # Also cover the immediate top-level helper modules if they sit in
    # a single subdir that isn't explicitly excluded. Keep this narrow
    # for now — widen only when a new integration lands.

# Phase flag. Flipped to True after R13 phase-1 migration completed —
# all source files now route through security/* and any regression
# fails CI. A new ingress type / new endpoint that bypasses the
# security/ helpers will fail one of the four tests below.
STRICT = True


def _targets():
    return _discover_targets()


def _comment_strings_on_line(src: str, lineno: int) -> list[str]:
    """Return just the comment tokens on *lineno* (1-indexed).

    R14/#2 hardening: previously we ran the allow-regex on the raw
    source line, which matched if the string literal on that line
    happened to contain "# invariant: allow-X because Y". An attacker
    (or a careless refactor) could bypass an invariant by sneaking the
    magic text into a docstring or string constant. tokenize.generate_
    tokens distinguishes COMMENT tokens from STRING tokens — we only
    accept the former.
    """
    try:
        toks = list(tokenize.generate_tokens(io.StringIO(src).readline))
    except tokenize.TokenizeError:
        return []
    return [t.string for t in toks
            if t.type == tokenize.COMMENT and t.start[0] == lineno]


def _allow_comment(line_or_source: str, rule_id: str, lineno: int | None = None,
                   src: str | None = None) -> bool:
    """Return True iff there is a genuine comment-token on the given line
    matching ``# invariant: allow-<rule_id> because <reason>``.

    Two call shapes for back-compat with existing callers:
      * ``_allow_comment(line, rule_id)`` — legacy string form, kept so
        tests that passed a single raw line still work, but falls back
        to substring match and is therefore weaker.
      * ``_allow_comment(line, rule_id, lineno=N, src=FULL)`` — strict
        tokenised form. Prefer this everywhere.
    """
    pattern = rf"# invariant: allow-{rule_id} because .+"
    if src is not None and lineno is not None:
        for comment in _comment_strings_on_line(src, lineno):
            if re.search(pattern, comment):
                return True
        return False
    return bool(re.search(pattern, line_or_source))


def _line_of(src: str, node: ast.AST) -> str:
    return src.splitlines()[node.lineno - 1] if getattr(node, "lineno", 0) else ""


def _any_line_of_node_has_allow(src: str, node: ast.AST, rule_id: str) -> bool:
    """Allow-comment may live on any line spanned by the offending
    node (dict literals can straddle several lines).

    R14/#2: tokenised check — the allow marker must live in a real
    comment token, not in a string literal that happens to contain
    the magic substring.
    """
    start = getattr(node, "lineno", 0) or 0
    end = getattr(node, "end_lineno", start) or start
    if not start:
        return False
    for lineno in range(start, end + 1):
        if _allow_comment(None, rule_id, lineno=lineno, src=src):
            return True
    return False


# ─── INVARIANT 1: bare role=<anything> dict literals outside security/ ───

def _has_role_key(node: ast.Dict) -> str | None:
    """If this Dict has a string key 'role' with a string value, return
    that value. Else None. Caught forms:

        {"role": "tool", ...}
        {"role": "system", ...}
        dict(role="tool", ...)   — handled separately via ast.Call below
    """
    for k, v in zip(node.keys, node.values):
        if isinstance(k, ast.Constant) and k.value == "role" and isinstance(v, ast.Constant):
            return v.value
    return None


def test_no_bare_role_dict_literals():
    """Invariant #1: conversation-message dicts go through
    security.messages.make_message / make_tool_result / etc.

    R14/#6 adds subscript assignment to the detected patterns:
    ``d["role"] = "tool"`` was a straight bypass of the original
    walker. Any place that writes a literal role-name into a
    subscript assignment is flagged too."""
    offenders: list[str] = []
    for fname, src in _targets():
        try:
            tree = ast.parse(src)
        except SyntaxError as e:
            offenders.append(f"{fname}: SyntaxError {e}")
            continue
        for node in ast.walk(tree):
            role_val = None
            # {"role": "<role>", ...}
            if isinstance(node, ast.Dict):
                role_val = _has_role_key(node)
            # dict(role="<role>", ...)
            elif isinstance(node, ast.Call) and _call_name(node) == "dict":
                for kw in node.keywords:
                    if kw.arg == "role" and isinstance(kw.value, ast.Constant):
                        role_val = kw.value.value
                        break
            # d["role"] = "<role>"   (R14/#6)
            elif isinstance(node, ast.Assign):
                for tgt in node.targets:
                    if (isinstance(tgt, ast.Subscript)
                            and isinstance(tgt.slice, ast.Constant)
                            and tgt.slice.value == "role"
                            and isinstance(node.value, ast.Constant)
                            and isinstance(node.value.value, str)):
                        role_val = node.value.value
                        break
            if role_val is None:
                continue
            line = _line_of(src, node)
            if _any_line_of_node_has_allow(src, node, "raw-message"):
                continue
            offenders.append(f"{fname}:{node.lineno} role={role_val!r}  {line.strip()[:120]}")
    _assert(offenders, "Bare role=<...> dicts found — use security.make_message or make_tool_result")


# ─── INVARIANT 2: every @app.<verb>/websocket has Depends(require_auth) ──

_HTTP_DECORATORS = {"get", "post", "put", "delete", "patch", "websocket"}


def _call_name(node):
    """Return the dotted name of a Call's func, or None."""
    if isinstance(node, ast.Call):
        return _attr_chain(node.func)
    return None


def _attr_chain(node) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        inner = _attr_chain(node.value)
        return f"{inner}.{node.attr}" if inner else node.attr
    return None


def _function_decorator_routes(fn: ast.FunctionDef | ast.AsyncFunctionDef):
    """Yield (verb, raw_path) for each FastAPI route decorator on fn."""
    for d in fn.decorator_list:
        if isinstance(d, ast.Call):
            name = _attr_chain(d.func) or ""
            if "." in name:
                verb = name.rsplit(".", 1)[1]
                if verb in _HTTP_DECORATORS:
                    yield verb, d


def _function_auth_dependencies(fn: ast.FunctionDef | ast.AsyncFunctionDef) -> set[str]:
    """Names referenced in Depends(...) defaults on the function args."""
    seen: set[str] = set()
    for arg in (fn.args.args or []) + (fn.args.kwonlyargs or []):
        pass  # defaults live on fn.args.defaults / kw_defaults
    defaults = list(fn.args.defaults) + list(fn.args.kw_defaults or [])
    for d in defaults:
        if isinstance(d, ast.Call) and _attr_chain(d.func) == "Depends":
            if d.args:
                dep = _attr_chain(d.args[0])
                if dep:
                    seen.add(dep)
    return seen


def test_every_route_has_auth_dependency():
    """Invariant #2: every ``@app.<verb>(...)`` / ``@app.websocket(...)``
    declares ``Depends(require_auth)`` or ``Depends(public_endpoint)``.
    Forgetting the dependency means the route ships open to the world.

    The dependency reference is matched by *suffix* — any identifier
    ending in ``require_auth`` / ``require_auth_dep`` / ``public_endpoint``
    counts. This lets wiring code rename the bound callable without
    rewriting the test (e.g. ``_require_auth_dep`` in web.py points at
    the configured instance of ``security.auth.require_auth``).
    """
    offenders: list[str] = []
    # R14/M4: drop bare "require_auth" from the suffix allow-list. The
    # old inline web.py._require_auth function was the drift vector —
    # allowing both names let a future endpoint bind to the dead
    # function and skip the master-token throttle. Only the Depends-
    # wired variants (`_require_auth_dep` from build_require_auth, or
    # anything whose name ends exactly in "public_endpoint") pass.
    allowed_suffixes = ("require_auth_dep", "public_endpoint")
    for fname, src in _targets():
        try:
            tree = ast.parse(src)
        except SyntaxError:
            continue
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                routes = list(_function_decorator_routes(node))
                if not routes:
                    continue
                deps = _function_auth_dependencies(node)
                if any(d.endswith(suf) for d in deps for suf in allowed_suffixes):
                    continue
                line = _line_of(src, node)
                if _allow_comment(line, "unauth-endpoint"):
                    continue
                verbs = ", ".join(v for v, _ in routes)
                offenders.append(
                    f"{fname}:{node.lineno} def {node.name}({verbs}) — "
                    f"missing Depends(require_auth) / Depends(public_endpoint)"
                )
    _assert(offenders, "Routes without explicit auth dependency")


# ─── INVARIANT 3: no direct request.client.host access outside security/ ─

def test_no_direct_client_host_access():
    """Invariant #3: client IPs come from ClientIdentity.from_request,
    not from reading request.client.host inline. Prevents the drift
    R11/M2 + R12/#1 each fixed in one call site."""
    offenders: list[str] = []
    for fname, src in _targets():
        try:
            tree = ast.parse(src)
        except SyntaxError:
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.Attribute) and node.attr == "host":
                inner = _attr_chain(node.value)
                if inner and inner.endswith(".client"):
                    line = _line_of(src, node)
                    if _allow_comment(line, "direct-client-ip"):
                        continue
                    offenders.append(f"{fname}:{node.lineno} {line.strip()[:120]}")
    _assert(offenders, "Direct .client.host access — use ClientIdentity.from_request")


# ─── INVARIANT 4: Anthropic fallback requires FallbackPolicy ─────────────

def test_fallback_goes_through_policy():
    """Invariant #4: no ``fallback_fn = call_anthropic if ANTHROPIC_KEY``
    style wiring. R13/C2 was exactly that pattern; R14/H1 found that
    the original regex test missed ``_agent.call_anthropic`` because of
    the attribute prefix. Switched to AST: any assignment / kwarg whose
    value or RHS references ``call_anthropic`` (qualified or not) AND
    gates on ``ANTHROPIC_KEY`` in the conditional expression fails the
    test. Only going through ``FallbackPolicy.from_env(...).
    as_recovery_callable()`` satisfies the invariant."""
    offenders: list[str] = []

    def _references(node, target_name):
        """True if *node* textually mentions *target_name* as a Name or
        as the attribute of an Attribute (any depth)."""
        for sub in ast.walk(node):
            if isinstance(sub, ast.Name) and sub.id == target_name:
                return True
            if isinstance(sub, ast.Attribute) and sub.attr == target_name:
                return True
        return False

    def _fallback_suspects_from_ifexp(ifexp: ast.IfExp, fname, lineno, src):
        """Given `X if ANTHROPIC_KEY else None`-shaped expression,
        decide if it's the bare pattern and append to offenders.

        Bare pattern: body references `call_anthropic`, test references
        `ANTHROPIC_KEY`, orelse is None / false-ish."""
        body_has_anthropic = _references(ifexp.body, "call_anthropic")
        test_has_key = _references(ifexp.test, "ANTHROPIC_KEY")
        if body_has_anthropic and test_has_key:
            if _allow_comment(None, "bare-fallback", lineno=lineno, src=src):
                return
            offenders.append(
                f"{fname}:{lineno} bare fallback IfExp — use FallbackPolicy.from_env"
            )

    for fname, src in _targets():
        try:
            tree = ast.parse(src)
        except SyntaxError:
            continue
        for node in ast.walk(tree):
            # Match any place the "X if ANTHROPIC_KEY else None" expression
            # flows into something named fallback_fn — assignment target
            # or keyword argument.
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if _attr_chain(target) and _attr_chain(target).endswith("fallback_fn"):
                        if isinstance(node.value, ast.IfExp):
                            _fallback_suspects_from_ifexp(node.value, fname, node.lineno, src)
            if isinstance(node, ast.keyword) and node.arg == "fallback_fn":
                if isinstance(node.value, ast.IfExp):
                    _fallback_suspects_from_ifexp(node.value, fname, getattr(node, "lineno", 0), src)

    _assert(offenders, "Bare fallback_fn wiring — use FallbackPolicy.from_env")


# ─── Phase-0 xfail wrapper ───────────────────────────────────────────────

def _assert(offenders: list[str], title: str) -> None:
    if not offenders:
        return
    msg = title + ":\n  " + "\n  ".join(offenders)
    if STRICT:
        raise AssertionError(msg)
    # Phase-0: surface the report but don't fail the suite. Reviewers
    # can still see the violations in the test log; CI stays green so
    # the migration itself can proceed.
    print(f"\n  [invariant WARN] {msg}", file=sys.stderr)


# ─── Standalone runner ───────────────────────────────────────────────────

if __name__ == "__main__":
    import traceback
    tests = [v for k, v in globals().items() if k.startswith("test_")]
    passed = failed = 0
    for fn in tests:
        try:
            fn()
            print(f"  OK   {fn.__name__}")
            passed += 1
        except Exception:
            print(f"  FAIL {fn.__name__}")
            traceback.print_exc()
            failed += 1
    print(f"\n{passed} passed, {failed} failed")
    sys.exit(1 if failed else 0)
