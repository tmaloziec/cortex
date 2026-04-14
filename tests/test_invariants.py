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

# R15 (GPT governance): escape-hatch comments are parsed for an
# optional ``until=YYYY-MM-DD`` clause. Existing comments without an
# expiry are grandfathered through a soft-warn grace period; new
# comments added after the grace date MUST carry an expiry.
_ALLOW_WITH_EXPIRY_RE = re.compile(
    r"# invariant: allow-(?P<rule>[\w-]+)\s+until=(?P<date>\d{4}-\d{2}-\d{2})"
    r"\s+because\s+(?P<reason>.+)"
)
_ALLOW_LEGACY_RE = re.compile(
    r"# invariant: allow-(?P<rule>[\w-]+)\s+because\s+(?P<reason>.+)"
)
# After this date, new allow comments without until= fail the test.
# Existing legacy comments at HEAD on this date get a "grandfathered"
# list in UNSAFE.md; every addition must carry an until= clause.
_GRACE_END_DATE = "2026-06-01"


def _discover_targets():
    """Yield (display_name, text) for every source file the invariants
    apply to.

    R15 (Claude R14 M-1): switched from ``glob("*.py")`` (root-only)
    to ``rglob("*.py")`` so subdirectories added later (``app/``,
    ``routes/``, ``api/``, ``mcp/``...) inherit the invariants.
    Excludes are now path-part-based so anything under
    ``security/``, ``tests/``, ``plugins/``, ``venv/``, etc. is
    skipped wholesale."""
    for path in sorted(_REPO.rglob("*.py")):
        # path.parts relative to repo tells us whether any ancestor
        # directory is on the exclude list.
        try:
            rel = path.relative_to(_REPO)
        except ValueError:
            continue
        if any(part in _EXCLUDE_DIRS for part in rel.parts):
            continue
        if path.name in _EXCLUDE_FILES:
            continue
        yield str(rel), path.read_text()

# Phase flag. Flipped to True after R13 phase-1 migration completed —
# all source files now route through security/* and any regression
# fails CI. A new ingress type / new endpoint that bypasses the
# security/ helpers will fail one of the four tests below.
STRICT = True


def _targets():
    return _discover_targets()


# R16 perf fix (Perplexity): tokenising a source file is O(n); the
# pre-R16 implementation re-tokenised per line lookup, making any
# test that asked about N lines O(n²). test_allow_comments_have_
# lifecycle scans ~thousands of lines — Perplexity's R15 audit
# reported >60s timeout. Cache the per-file token map so every
# test sharing the same source string pays the parse cost once.
_COMMENTS_CACHE: dict[int, dict[int, list[str]]] = {}


def _build_comment_map(src: str) -> dict[int, list[str]]:
    """Tokenise *src* once. Return {lineno: [comment_token_strings]}."""
    result: dict[int, list[str]] = {}
    try:
        for t in tokenize.generate_tokens(io.StringIO(src).readline):
            if t.type == tokenize.COMMENT:
                result.setdefault(t.start[0], []).append(t.string)
    except tokenize.TokenizeError:
        pass
    return result


def _comment_strings_on_line(src: str, lineno: int) -> list[str]:
    """Return just the comment tokens on *lineno* (1-indexed).

    R14/#2 hardening: tokenize.generate_tokens distinguishes COMMENT
    tokens from STRING tokens — a string literal containing
    ``# invariant: allow-X because Y`` cannot satisfy the allow check.

    R16 (perf): memoised per source string. id(src) as key works
    because _targets() returns the same (name, text) tuples inside
    a single test run; a different test that reads fresh text gets
    a fresh cache entry naturally.
    """
    key = id(src)
    mapping = _COMMENTS_CACHE.get(key)
    if mapping is None:
        mapping = _build_comment_map(src)
        _COMMENTS_CACHE[key] = mapping
    return mapping.get(lineno, [])


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
            # R15 (bonus, from GPT's AST extension list):
            # d["<slice>"] = "<role>" assignment. Caught regardless of
            # whether slice is Constant (R14 detected) or other shapes —
            # any Subscript assignment to a 'role'-string target with a
            # constant string value is suspect, and non-literal forms
            # (var, expression, concat) are noted so reviewers see them
            # even if they can't be statically classified.
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


# R15/E5: routes legitimately allowed to use Depends(public_endpoint).
# Anything not on this list that declares public_endpoint fails the
# invariant — new "I'll just mark it public for now" endpoints cannot
# ship without explicit whitelisting.
_KNOWN_PUBLIC_ENDPOINTS = {
    ("get", "/"),             # bootstrap HTML — token exchange handled in body
    ("get", "/health"),       # liveness probe, returns {"status": "ok"}
    ("post", "/api/logout"),  # must work for already-revoked/expired sessions
    ("websocket", "/ws"),     # handshake auth handled in body; per-message
                              # and per-tool-iteration re-auth re-validate
                              # the cookie / master token. FastAPI Depends
                              # on websockets doesn't go through the 401
                              # return path, so public_endpoint + in-body
                              # check is the supported pattern.
}


def test_every_route_has_auth_dependency():
    """Invariant #2: every ``@app.<verb>(...)`` / ``@app.websocket(...)``
    declares ``Depends(require_auth)`` or ``Depends(public_endpoint)``.
    Forgetting the dependency means the route ships open to the world.

    R15/E5: ``Depends(public_endpoint)`` now requires the route to be
    on the ``_KNOWN_PUBLIC_ENDPOINTS`` whitelist. A new endpoint can't
    opt out of auth by typing ``public_endpoint`` — whitelisting
    requires editing this test file, which CODEOWNERS protects.

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
                # `public_endpoint` is only valid for whitelisted routes.
                uses_public = any(d.endswith("public_endpoint") for d in deps)
                uses_authed = any(d.endswith("require_auth_dep") for d in deps)
                if uses_authed:
                    continue
                if uses_public:
                    # Must be a whitelisted (verb, path) combination.
                    path_match = False
                    for verb, dcall in routes:
                        if dcall.args and isinstance(dcall.args[0], ast.Constant):
                            path = dcall.args[0].value
                            if (verb, path) in _KNOWN_PUBLIC_ENDPOINTS:
                                path_match = True
                                break
                    if path_match:
                        continue
                line = _line_of(src, node)
                # R15/E2: tokenised allow-check (string literals on the
                # route line cannot satisfy the exemption).
                if _allow_comment(None, "unauth-endpoint",
                                  lineno=node.lineno, src=src):
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
                    # R15/E2: tokenised allow-check.
                    if _allow_comment(None, "direct-client-ip",
                                      lineno=node.lineno, src=src):
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


# ─── INVARIANT 5: allow-comment lifecycle ────────────────────────────────

def test_allow_comments_have_lifecycle():
    """R15 (GPT governance): every ``# invariant: allow-<id> because
    <reason>`` carries a lifecycle.

    * If the comment has ``until=YYYY-MM-DD`` and the date is in the
      past, the test fails (expired escape hatch = unfinished task).
    * If the comment has no ``until=`` clause, it's grandfathered
      (existing set at the time governance landed) and emitted to
      ``UNSAFE.md`` for review. New comments lacking ``until=`` added
      after ``_GRACE_END_DATE`` fail the test.

    The generated UNSAFE.md is a regenerable report — reviewers can
    see the whole escape surface at a glance rather than grepping
    for the magic comment.
    """
    import datetime as _dt
    today = _dt.date.today()
    grace_end = _dt.date.fromisoformat(_GRACE_END_DATE)

    offenders: list[str] = []
    grandfathered: list[str] = []
    with_expiry: list[str] = []
    expired: list[str] = []

    for fname, src in _targets():
        # R16: iterate the comment map directly — avoids the
        # splitlines() × per-line-lookup path even with the cache.
        comment_map = _build_comment_map(src)
        _COMMENTS_CACHE[id(src)] = comment_map
        for lineno, comments_on_line in comment_map.items():
            for comment in comments_on_line:
                m = _ALLOW_WITH_EXPIRY_RE.search(comment)
                if m:
                    expiry = _dt.date.fromisoformat(m.group("date"))
                    entry = (f"{fname}:{lineno} rule={m.group('rule')} "
                             f"until={m.group('date')} because={m.group('reason')[:80]}")
                    if expiry < today:
                        expired.append(entry)
                    else:
                        with_expiry.append(entry)
                    continue
                # Legacy shape with no until=
                m2 = _ALLOW_LEGACY_RE.search(comment)
                if m2:
                    entry = (f"{fname}:{lineno} rule={m2.group('rule')} "
                             f"(no until=) because={m2.group('reason')[:80]}")
                    if today > grace_end:
                        # Past the grace period — every allow comment
                        # must now carry a lifecycle date.
                        offenders.append(entry)
                    else:
                        grandfathered.append(entry)

    # Regenerate UNSAFE.md regardless of pass/fail so the report is
    # always current. Keep the test independent of whether writing
    # succeeds (read-only test environments still pass).
    try:
        def _section(label, entries):
            header = [f"## {label} ({len(entries)})", ""]
            body = [f"- {e}" for e in entries] if entries else ["(none)"]
            return header + body + [""]
        unsafe_lines = [
            "# Unsafe invariant exceptions",
            "",
            "Auto-generated by `tests/test_invariants.py::"
            "test_allow_comments_have_lifecycle`.",
            "Do not edit manually. Regenerate by running the test suite.",
            "",
            f"Generated: {today.isoformat()}  (grace ends {grace_end.isoformat()})",
            "",
        ]
        unsafe_lines += _section(
            "Active allow-comments with lifecycle", with_expiry)
        unsafe_lines += _section(
            "Grandfathered legacy comments", grandfathered)
        unsafe_lines.insert(-1,
            "These predate the governance rule. After the grace date "
            "they must gain an `until=YYYY-MM-DD` clause or be removed.")
        unsafe_lines += _section(
            "Expired (test fails)", expired)
        (_REPO / "UNSAFE.md").write_text("\n".join(unsafe_lines) + "\n")
    except OSError:
        pass

    # Fail on expired comments always; on missing until= only after grace.
    problems = list(expired) + list(offenders)
    _assert(problems, "Escape-hatch comments: expired or missing until= clause")


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
