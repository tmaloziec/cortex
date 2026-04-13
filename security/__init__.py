"""Cortex security helpers — the single source of truth for invariants.

Every module-facing import of security primitives must come from this
package. ``tests/test_invariants.py`` walks the AST of every other
source file and fails the CI if an invariant is bypassed — a bare
``{"role": "tool", ...}`` dict literal, a FastAPI route without an
auth dependency, a ``subprocess.run`` on model-controlled paths that
weren't normalised, a fallback that uploads history to Anthropic
without the explicit opt-in.

Design rules for anything that lives here:
  * NO imports from agent.py / web.py / worker.py / compactor.py /
    recovery.py / policy.py — keep security.* purely stdlib + typing
    so the import graph has no cycles. (Policy's `_normalize_path`
    is lifted into security.paths instead of re-imported.)
  * Helpers are pure or take explicit dependencies as args — they
    never reach into process-global state implicitly.
  * Breaking changes to this package require explicit reviewer
    approval. A CODEOWNERS entry covers security/ + tests/test_
    invariants.py so a PR that relaxes an invariant can't land by
    default.
"""

from security.messages import (
    wrap_untrusted,
    wrap_tool_output,
    make_message,
    make_tool_result,
    make_system_note,
    make_user_note,
    UNTRUSTED_KINDS,
    Role,
    Message,
    ToolMessage,
)
from security.auth import (
    ClientIdentity,
    require_auth,
    build_require_auth,
    public_endpoint,
    SessionManager,
    rate_limit_key,
    note_auth_fail,
    AuthError,
)
from security.paths import normalize_path, path_under
from security.fallback import FallbackPolicy, _FallbackSentinel

__all__ = [
    # messages
    "wrap_untrusted", "wrap_tool_output",
    "make_message", "make_tool_result", "make_system_note", "make_user_note",
    "UNTRUSTED_KINDS", "Role", "Message", "ToolMessage",
    # auth
    "ClientIdentity", "require_auth", "build_require_auth", "public_endpoint",
    "SessionManager", "rate_limit_key", "note_auth_fail", "AuthError",
    # paths
    "normalize_path", "path_under",
    # fallback
    "FallbackPolicy", "_FallbackSentinel",
]
