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
import pathlib
import re
import sys

_REPO = pathlib.Path(__file__).resolve().parent.parent

# Files the invariants apply to. security/ is excluded — it IS the
# invariant definition. tests/ is excluded — test fixtures frequently
# construct bare dicts for setup.
_TARGET_FILES = (
    "agent.py",
    "web.py",
    "worker.py",
    "compactor.py",
    "recovery.py",
    "policy.py",
)

# Phase flag. Flipped to True after R13 phase-1 migration completed —
# all source files now route through security/* and any regression
# fails CI. A new ingress type / new endpoint that bypasses the
# security/ helpers will fail one of the four tests below.
STRICT = True


def _targets():
    for name in _TARGET_FILES:
        path = _REPO / name
        if path.exists():
            yield name, path.read_text()


def _allow_comment(line: str, rule_id: str) -> bool:
    return bool(re.search(rf"# invariant: allow-{rule_id} because .+", line))


def _line_of(src: str, node: ast.AST) -> str:
    return src.splitlines()[node.lineno - 1] if getattr(node, "lineno", 0) else ""


def _any_line_of_node_has_allow(src: str, node: ast.AST, rule_id: str) -> bool:
    """Allow-comment may live on any line spanned by the offending
    node (dict literals can straddle several lines)."""
    start = getattr(node, "lineno", 0) or 0
    end = getattr(node, "end_lineno", start) or start
    if not start:
        return False
    lines = src.splitlines()
    for i in range(start - 1, min(end, len(lines))):
        if _allow_comment(lines[i], rule_id):
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
    security.messages.make_message / make_tool_result / etc."""
    offenders: list[str] = []
    for fname, src in _targets():
        try:
            tree = ast.parse(src)
        except SyntaxError as e:
            offenders.append(f"{fname}: SyntaxError {e}")
            continue
        for node in ast.walk(tree):
            role_val = None
            if isinstance(node, ast.Dict):
                role_val = _has_role_key(node)
            elif isinstance(node, ast.Call) and _call_name(node) == "dict":
                for kw in node.keywords:
                    if kw.arg == "role" and isinstance(kw.value, ast.Constant):
                        role_val = kw.value.value
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
    allowed_suffixes = ("require_auth", "require_auth_dep", "public_endpoint")
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
    style wiring. R13/C2 was exactly that pattern — mere key presence
    silently enabled upload-on-connection-error. FallbackPolicy.from_env
    keeps the gate in one place with a WARN log + opt-in flag."""
    pattern = re.compile(r"fallback_fn\s*=\s*call_anthropic\s+if\s+ANTHROPIC_KEY")
    offenders: list[str] = []
    for fname, src in _targets():
        for i, line in enumerate(src.splitlines(), 1):
            if pattern.search(line):
                if _allow_comment(line, "bare-fallback"):
                    continue
                offenders.append(f"{fname}:{i} {line.strip()[:120]}")
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
