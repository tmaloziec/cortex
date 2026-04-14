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
from typing import Any, Literal, TypedDict

# R15 (GPT bonus): typed message shape. `mypy --strict` can now flag
# a bare dict literal being passed where Message is expected — second
# defensive layer on top of the AST walker. Runtime behaviour
# unchanged; dicts still flow through the system.
Role = Literal["system", "user", "assistant", "tool"]


class Message(TypedDict, total=False):
    role: Role
    content: str


class ToolMessage(TypedDict):
    role: Literal["tool"]
    content: str
    name: str

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


# R15/E4 (red team round 7), honest scoping after R17 review:
# ------------------------------------------------------------
# These helpers bind their security dependencies as default args so
# the simple attribute-level monkey-patch
#     security.messages.wrap_untrusted = weaker_version
# from a plugin's on_activate does not affect already-defined
# helpers — the default-arg captured at def-time still points at
# the original. This closes the common accidental-regression path
# from a careless plugin author.
#
# This is an *ergonomic* defence, NOT a security boundary:
#
#   * ``wrap_tool_output.__defaults__`` is itself a mutable tuple.
#     ``wrap_tool_output.__defaults__ = (evil,)`` reassigns it.
#   * A plugin running in the same process has full introspection
#     access (``dict.__setattr__``, ``ctypes.pythonapi.PyCell_Set``
#     for closures, etc.).
#
# Real isolation requires OS-level (container / VM) or interpreter-
# level (PEP 684 subinterpreters) separation between plugin and agent.
# Neither is in scope for v1.0.x; plugins are "trusted by design"
# (see SECURITY.md threat model). The default-arg freeze catches
# *careless* monkey-patching; it does not — and cannot — withstand
# a *hostile* in-process plugin.

def wrap_tool_output(name: str, result: str,
                     _wrap=wrap_untrusted) -> str:
    """Tool-output ingress — thin alias so existing imports keep
    working. Prefer ``make_tool_result`` for new code."""
    return _wrap("tool_output", result, tool=name)


def make_message(role: str, content: str, *,
                 authoritative: bool = False,
                 source: str | None = None,
                 _wrap=wrap_untrusted,
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
    return {"role": role, "content": _wrap(source, content, **attrs)}


def make_tool_result(name: str, content: str, *,
                     source: str = "tool_output",
                     _wrap=wrap_untrusted) -> dict:
    """Canonical ``role="tool"`` message. See R11/M1.

    ``source`` kept for back-compat with worker.py / web.py call sites
    that distinguish real tool output from policy DENY / ASK /
    invalid-name responses. The wire format is identical — a
    ``<tool_output_<nonce> untrusted="true">`` container — so the
    model applies rule #13 the same way regardless of ``source``.
    """
    return {
        "role": "tool",
        "content": _wrap("tool_output", content, tool=name, source=source),
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
