"""Message constructors — invariant: every message in the agent's
conversation history goes through one of these helpers.

Background
----------
Rounds R6 through R13 each found a variant of the same bug: a module
was building a ``{"role": "...", "content": "..."}`` dict by hand,
and the content wasn't going through the ``<KIND_<nonce> untrusted>``
fence that protects the model from prompt-injection in data it
processes. Each finding closed one call site. Round R5 of the red
team red-marked the pattern itself: **path-level fixes don't hold;
the invariant has to live in the data structure**.

These helpers are the invariant. Bare dict literals
``{"role": "tool", ...}`` are banned outside this module by
``tests/test_invariants.py`` (AST walker). Use ``make_message`` or
one of the ``make_*_note`` wrappers.

Escape hatch
------------
If you genuinely need to construct a message dict by hand (rare —
almost always a smell), add a comment ``# invariant: allow-raw-message
because <one sentence reason>`` on the line. The invariant test
allows exactly the lines so marked.
"""
from __future__ import annotations

import html as _html
import secrets as _secrets
from typing import Any

# The KIND prefixes the runtime may emit for untrusted ingress. Any
# tag with one of these prefixes is DATA, regardless of nonce, role,
# attributes, or nesting. Rule #13 in the system prompt enumerates
# the same list; edits to either must stay in sync.
UNTRUSTED_KINDS = (
    "tool_output",
    "compacted_history",
    "external_briefing",
    "worker_task",
    "plugin_guidance",
    "recovery_note",
)


def wrap_untrusted(kind: str, content: Any, **attrs: Any) -> str:
    """Wrap *content* in an untrusted container tagged with a fresh
    per-call nonce.

    Every untrusted ingress — tool output, compacted history, CS
    briefing, worker task description, plugin guidance, recovery
    notes — goes through this helper. Payload cannot predict the
    nonce, so it cannot synthesise a matching opener or closer and
    cannot spoof an ``untrusted="false"`` attribute override.

    Regenerates the nonce if the payload already contains it
    (astronomical at 48 bits, but defensive).
    """
    if kind not in UNTRUSTED_KINDS:
        # Not an error, but a soft signal — new KINDs must be added
        # to UNTRUSTED_KINDS so rule #13 can enumerate them.
        raise ValueError(
            f"wrap_untrusted: kind={kind!r} not in UNTRUSTED_KINDS. "
            f"Add it to security/messages.py and to rule #13 first."
        )
    if not isinstance(content, str):
        content = str(content)
    for _ in range(8):
        nonce = _secrets.token_urlsafe(6)  # ~48 bits
        tag = f"{kind}_{nonce}"
        if f"<{tag}" not in content and f"</{tag}>" not in content:
            break
    safe = content.replace(f"</{tag}>", f"<_/{tag}>")
    attr_s = ""
    for k, v in attrs.items():
        attr_s += f' {k}="{_html.escape(str(v), quote=True)}"'
    return f'<{tag} untrusted="true"{attr_s}>\n{safe}\n</{tag}>'


def wrap_tool_output(name: str, result: str) -> str:
    """Tool-output ingress — thin alias so existing imports keep
    working. Prefer ``make_tool_result`` for new code."""
    return wrap_untrusted("tool_output", result, tool=name)


def make_message(role: str, content: str, *,
                 authoritative: bool = False,
                 source: str | None = None,
                 **attrs: Any) -> dict:
    """Canonical conversation-message constructor.

    Arguments
    ---------
    role : ``"system" | "user" | "assistant" | "tool"``
    content : raw string content
    authoritative : if True, content is emitted verbatim (system
        prompt, real streamed assistant output, real user chat
        turn). If False (default), content is wrapped in an untrusted
        container keyed by *source*.
    source : KIND for the untrusted wrapper (required when
        ``authoritative=False`` on role ∈ {"tool","user","assistant"}).

    Why ``authoritative`` is explicit
    ---------------------------------
    Red team rounds R6/R9/R10/R13 all found the same bug: a module
    inserted a mechanical / derived message (compactor summary,
    recovery stub, briefing) into the conversation as a trusted role
    (usually ``assistant``), and the model treated it as its own
    prior statement. Making *authoritative* a required keyword forces
    the caller to state "yes, this came from the operator/model
    directly", instead of defaulting to trust.
    """
    if role not in ("system", "user", "assistant", "tool"):
        raise ValueError(f"make_message: unknown role {role!r}")
    if authoritative:
        return {"role": role, "content": content}
    if not source:
        raise ValueError(
            "make_message: source='<kind>' is required when "
            "authoritative=False — pick one of UNTRUSTED_KINDS or add a "
            "new KIND to security/messages.py + rule #13 first."
        )
    return {"role": role, "content": wrap_untrusted(source, content, **attrs)}


def make_tool_result(name: str, content: str, *, source: str = "tool_output") -> dict:
    """Canonical ``role="tool"`` message. See R11/M1.

    ``source`` kept for back-compat with worker.py / web.py call sites
    that distinguish real tool output from policy DENY / ASK /
    invalid-name responses. The wire format is identical — a
    ``<tool_output_<nonce> untrusted="true">`` container — so the
    model applies rule #13 the same way regardless of ``source``.
    """
    return {
        "role": "tool",
        "content": wrap_untrusted("tool_output", content, tool=name, source=source),
        "name": name,
    }


def make_system_note(content: str, *, source: str = "recovery_note") -> dict:
    """Mechanically-injected system-role note (e.g. recovery hint).

    Wrapped, not authoritative — agent rule #13 extended to cover
    ``recovery_note_<nonce>``. Prevents R13/C3 class where a future
    interpolated exception message turned into a system-role prompt
    injection.
    """
    return make_message("system", content, source=source)


def make_user_note(content: str, *, source: str = "compacted_history") -> dict:
    """Mechanically-injected user-role note (compacted history,
    context-overflow placeholder). Always wrapped — authoritative
    user turns come directly from the human, not from this helper."""
    return make_message("user", content, source=source)
