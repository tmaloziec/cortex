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


import weakref as _weakref


# R17 (red team round 8 + Claude R15 audit):
# ------------------------------------------
# R15 used ``isinstance(fallback_fn, _FallbackSentinel)`` as the
# "structural" invariant. Both auditors independently showed it's
# not structural at all — it's a *type-membership* check, and
# Python has at least five paths to satisfy that without going
# through FallbackPolicy:
#
#   1. subclass:   ``class Fake(_FS): pass; Fake()``
#                  isinstance() accepts subclasses.
#   2. __new__:    ``_FS.__new__(_FS); obj._fn = evil``
#                  skips __init__ entirely.
#   3. copy:       ``copy.copy(real); fake._fn = evil``
#                  preserves class, overwrites inner callable.
#   4. metaclass:  ``class M(type): __instancecheck__ = ...``
#                  custom instancecheck returns True for anything.
#   5. direct:     ``_FallbackSentinel(evil_fn)``
#                  public-in-all-but-name constructor.
#
# R17 switches to capability-based enforcement: identity, not type.
#
# Four changes make forgery a type error rather than a runtime
# accident:
#
#   * ``_WITNESS`` — a module-local sentinel object. Only code in
#     this module (i.e. ``FallbackPolicy.as_recovery_callable``)
#     has a reference. Constructing the class without it raises.
#   * ``__init_subclass__`` raises — sealed class.
#   * ``__slots__`` + ``__setattr__`` override — ``_fn`` is
#     assigned exactly once in ``__init__`` and can't be rebound.
#   * ``_REGISTRY`` (``WeakSet``) — the issuing code registers the
#     object on construction; ``RecoveryEngine`` checks membership
#     by identity (``fn in _REGISTRY``), not by type. A forged
#     subclass instance is not in the registry even if
#     ``isinstance`` would accept it. ``copy.copy`` also escapes
#     the registry because it bypasses ``__init__``.
#
# The class is not exported from ``security/__init__.py`` — the
# underscore prefix was previously advisory; now the only public
# surface is ``FallbackPolicy``.
_WITNESS = object()
_REGISTRY: "_weakref.WeakSet[object]" = _weakref.WeakSet()


class _FallbackSentinel:
    """Capability token proving a callable came from
    ``FallbackPolicy.as_recovery_callable()``.

    Do not construct from outside this module — the witness object
    required by ``__init__`` is not exported. ``RecoveryEngine``
    checks registry membership by identity; forged subclasses,
    ``__new__``-skipped instances, and ``copy.copy`` clones are
    NOT in the registry and are refused.
    """

    __slots__ = ("_fn", "__weakref__")

    def __init_subclass__(cls, **kwargs):
        raise TypeError(
            "_FallbackSentinel is sealed; only FallbackPolicy may produce it"
        )

    def __init__(self, fn: Callable, _witness: object | None = None):
        if _witness is not _WITNESS:
            raise TypeError(
                "_FallbackSentinel is not publicly constructible; "
                "go through FallbackPolicy.from_env(...).as_recovery_callable()"
            )
        # __slots__ + our __setattr__ means this is the ONLY assignment
        # to _fn ever permitted on this instance.
        object.__setattr__(self, "_fn", fn)
        _REGISTRY.add(self)

    def __setattr__(self, name, value):
        # Block post-construction mutation. An attacker with
        # ``copy.copy(real)`` skips __init__ and is not in _REGISTRY,
        # but this also stops the simpler ``sentinel._fn = evil``.
        raise AttributeError(
            f"_FallbackSentinel is immutable; cannot set {name!r}"
        )

    def __call__(self, messages, *args, **kwargs):
        # Belt-and-braces: even a correctly-registered sentinel
        # refuses to fire if its identity isn't in the registry at
        # call time (catches theoretical future tampering).
        if self not in _REGISTRY:
            raise RuntimeError("_FallbackSentinel tampered — refusing to call")
        return self._fn(messages, *args, **kwargs)


def _is_registered_sentinel(obj: object) -> bool:
    """Module-level predicate for ``RecoveryEngine`` to use.

    Using membership in the WeakSet (``obj in _REGISTRY``) checks
    by object identity — subclasses, ``__new__``-skipped instances,
    and ``copy.copy`` clones are not in the set even if ``isinstance``
    would accept them. This is the capability check R17 replaced
    the R15 ``isinstance`` shortcut with.
    """
    return obj in _REGISTRY


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

        # Only this call site holds a reference to _WITNESS, so this
        # is the only way to obtain a token registered in _REGISTRY.
        return _FallbackSentinel(_logged_fallback, _witness=_WITNESS)
