"""Anthropic fallback policy — invariant: uploading conversation
history to api.anthropic.com on Ollama ConnectionError is NOT the
default. It requires an explicit env opt-in, it logs every upload at
WARNING with payload size, and it can optionally strip untrusted
containers before the upload leaves the host.

Red team round R13/C2 observed that ``fallback_fn = call_anthropic
if ANTHROPIC_KEY else None`` had an operator mental-model mismatch:
users treated ``ANTHROPIC_API_KEY`` as "opt-in when I want it", but
the code wired it as "run on every transient network blip". A
single ``systemctl restart ollama`` would ship the full
conversation (tool outputs, file contents, CS briefing) silently.

This class centralises the decision so any future call site picks up
the same gates automatically.
"""
from __future__ import annotations

import logging as _logging
import os as _os
import re as _re
from typing import Callable

_log = _logging.getLogger("security.fallback")

# Pattern that matches any of the UNTRUSTED_KINDS containers emitted
# by security.messages.wrap_untrusted. Used when the operator enables
# redaction: file contents and tool output don't leave the host.
_UNTRUSTED_TAG_RE = _re.compile(
    r"<(tool_output|compacted_history|external_briefing|worker_task|plugin_guidance|recovery_note)_[A-Za-z0-9_-]+"
    r"[^>]*>.*?</\1_[A-Za-z0-9_-]+>",
    _re.DOTALL,
)


class _FallbackSentinel:
    """Runtime marker that a callable actually came from
    ``FallbackPolicy.as_recovery_callable()``.

    Red team round 7 showed that AST-based invariant #4 can be
    bypassed by any indirection (``lambda``, ``functools.partial``,
    ``**kwargs`` unpack, factory function, BoolOp, Subscript,
    assignment-through-variable, match-case, ...). Chasing each new
    syntax shape is the same whack-a-mole that regex-based
    enforcement had — just one abstraction level higher.

    The real fix is structural: instead of asking "does this code
    look like a forbidden pattern?", ask "is this value an instance
    of the one type that the policy can emit?". ``RecoveryEngine``
    checks ``isinstance(fallback_fn, _FallbackSentinel)`` at
    runtime. No AST shape defeats that — the ONLY way to get a
    truthy sentinel is to call ``FallbackPolicy.as_recovery_callable()``.
    """

    def __init__(self, fn: Callable):
        # Store the underlying logged/redacted caller; __call__
        # forwards transparently so recovery.py doesn't need to
        # know about the sentinel wrapper.
        self._fn = fn

    def __call__(self, messages, *args, **kwargs):
        return self._fn(messages, *args, **kwargs)


class FallbackPolicy:
    """Policy decision object for whether an Anthropic upload should
    happen and how it should be shaped.

    Instantiate once at startup (``FallbackPolicy.from_env()``), pass
    to ``RecoveryEngine`` and any other consumer. All the decisions
    sit on the instance so nothing is re-checked inline.
    """

    def __init__(self, *, enabled: bool, redact_tool_outputs: bool,
                 call_fn: Callable | None):
        self.enabled = enabled
        self.redact_tool_outputs = redact_tool_outputs
        self._call_fn = call_fn

    @classmethod
    def from_env(cls, *, anthropic_key: str, call_fn: Callable | None) -> "FallbackPolicy":
        """Wire the policy from environment variables.

        Rules:
          * no key → disabled, no matter what.
          * key + CORTEX_FALLBACK_ANTHROPIC=1 → enabled.
          * anything else → disabled, even with key.
        """
        if not anthropic_key or not call_fn:
            return cls(enabled=False, redact_tool_outputs=False, call_fn=None)
        enabled = _os.getenv("CORTEX_FALLBACK_ANTHROPIC") == "1"
        redact = _os.getenv("CORTEX_FALLBACK_REDACT_TOOL_OUTPUTS") == "1"
        return cls(enabled=enabled, redact_tool_outputs=redact, call_fn=call_fn)

    def as_recovery_callable(self) -> _FallbackSentinel | None:
        """Return the sentinel-wrapped callable to pass to
        ``RecoveryEngine(fallback_fn=…)`` or ``None`` if fallback is
        disabled.

        Wrapping in ``_FallbackSentinel`` is what makes invariant #4
        enforcement structural rather than syntactic: only a return
        value from THIS method will survive ``RecoveryEngine``'s
        ``isinstance`` check. No amount of call-site cleverness
        (lambda, partial, getattr, kwargs splat, factory) can
        synthesise one without going through the policy object."""
        if not self.enabled:
            return None
        call_fn = self._call_fn
        redact = self.redact_tool_outputs

        def _logged_fallback(messages: list, *a, **kw):
            payload = messages
            if redact:
                payload = [
                    {**m, "content": _UNTRUSTED_TAG_RE.sub(
                        "[REDACTED untrusted container]",
                        m.get("content", "") or "",
                    )}
                    for m in messages
                ]
            total_chars = sum(len(m.get("content", "") or "") for m in payload)
            _log.warning(
                "fallback: uploading %d messages / %d chars to api.anthropic.com "
                "(CORTEX_FALLBACK_ANTHROPIC=1; redact=%s)",
                len(payload), total_chars, "on" if redact else "off",
            )
            return call_fn(payload, *a, **kw)

        return _FallbackSentinel(_logged_fallback)
