"""Path normalisation — invariant: every path the agent receives from
the model is resolved to a canonical absolute form before the policy
check and before the syscall.

Without this, ``/tmp/../etc/shadow`` and symlinks like
``/tmp/safe → /etc/shadow`` bypass policy: the policy evaluates the
raw string (starts with ``/tmp``, looks benign) while the kernel
dereferences to the sensitive target.

This module is the single source of truth. Keep it import-free
(stdlib only) so ``security/`` stays dependency-free.
"""
from __future__ import annotations

import os as _os
from pathlib import Path as _Path


def normalize_path(raw: str) -> str:
    """Resolve path traversal, symlinks, tildes, relative paths to an
    absolute canonical form. Lifted from ``policy._normalize_path``
    so policy and the tool-executor share one function (previously
    duplicated, which drifted).

    ``strict=False`` lets us normalise paths that don't yet exist
    (``write_file`` resolves before the target is created so
    ``/tmp/../etc/x`` is denied before anything is written).
    """
    if not raw:
        return ""
    try:
        expanded = _os.path.expanduser(str(raw))
        return str(_Path(expanded).resolve(strict=False))
    except (OSError, ValueError):
        return str(raw)


def path_under(candidate: str, ancestor: str) -> bool:
    """Return True iff *candidate*, after normalisation, lives under
    *ancestor*. Used by plugin loader and policy checks that need a
    containment test rather than a regex match.
    """
    try:
        c = _Path(normalize_path(candidate))
        a = _Path(normalize_path(ancestor))
        c.relative_to(a)
        return True
    except ValueError:
        return False
