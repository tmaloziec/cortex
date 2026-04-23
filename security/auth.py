"""Auth + session + rate-limit invariants.

Three responsibilities live here, coupled on purpose:

  1. ``ClientIdentity`` — the ONLY way to derive a client IP /
     rate-limit key. Previously ``web.py`` read ``request.client.host``
     in several places with drift between them (R9/R11/R12 each
     added or swapped a header). Centralised here.

  2. ``SessionManager`` — the ONLY way to mint / validate / revoke
     a session cookie. The session dict lives here with its own
     lock + per-sid shard locks (R12/#4). Cookie path auth is a
     method on the manager.

  3. ``require_auth`` — the FastAPI dependency every
     authenticated endpoint uses. Succeeds iff *either* the cookie
     path passes (cookie ∈ live sessions) *or* the master-token
     path passes (constant-time compare). Both paths bucket the
     caller into a rate-limit immediately on success — so R13/C1's
     Bearer / bootstrap bypass is structurally impossible (rate-
     limit is a property of "a successful auth happened", not of
     "which branch we took").

The invariant tests walk every ``@app.get/post/delete/websocket``
and verify it uses ``Depends(require_auth)`` or ``Depends(
public_endpoint)``. A new route without either fails CI.
"""
from __future__ import annotations

import hashlib as _hashlib
import ipaddress as _ipa
import logging as _logging
import secrets as _secrets
import threading as _threading
import time as _time
from typing import Callable

_log = _logging.getLogger("security.auth")


class AuthError(Exception):
    """Internal exception — web adapter converts to 401/429 HTTPException."""
    def __init__(self, status: int, detail: str):
        self.status = status
        self.detail = detail
        super().__init__(detail)


# ─── ClientIdentity ──────────────────────────────────────────────────────

class ClientIdentity:
    """Encapsulates "who is calling" for rate-limit bucketing.

    Proxy-header trust is an explicit flag. When set, True-Client-IP
    → CF-Connecting-IP → X-Real-IP are consulted in that order
    (preference for single-value overwritten headers; X-Forwarded-For
    is never trusted because nginx/caddy APPEND to it and the
    leftmost value is attacker-set, R11/M2). Without the flag, only
    the TCP peer (``request.client.host``) is used.

    IPv6 zone IDs are stripped before parsing (R12/#3). IPv6 addresses
    bucket at /64 because consumer ISPs assign /64s and a Linux box
    can rotate through 2^64 of them trivially (R9/#2).
    """

    _TRUSTED_SINGLE_VALUE_HEADERS = ("true-client-ip", "cf-connecting-ip", "x-real-ip")

    def __init__(self, ip: str):
        self.ip = ip

    @classmethod
    def from_request(cls, request_or_ws, *, trust_proxy: bool) -> "ClientIdentity":
        ip = ""
        try:
            if trust_proxy and hasattr(request_or_ws, "headers"):
                for h in cls._TRUSTED_SINGLE_VALUE_HEADERS:
                    v = request_or_ws.headers.get(h, "").strip()
                    if v:
                        ip = v
                        break
            if not ip:
                client = getattr(request_or_ws, "client", None)
                if client and client.host:
                    ip = client.host
        except Exception:
            pass
        return cls(ip)

    def bucket_key(self) -> str:
        return rate_limit_key(self.ip)


def rate_limit_key(ip: str) -> str:
    """Normalise *ip* into a rate-limit bucket key. Public so tests
    can exercise the collapse rules directly."""
    if not ip:
        return ""
    if "%" in ip:
        ip = ip.split("%", 1)[0]
    if ":" in ip:
        try:
            addr = _ipa.ip_address(ip)
            if isinstance(addr, _ipa.IPv6Address):
                if addr.ipv4_mapped:
                    return f"v4:{addr.ipv4_mapped}"
                net = _ipa.ip_network(f"{ip}/64", strict=False)
                return f"v6/64:{net.network_address}"
        except ValueError:
            pass
    return f"v4:{ip}"


# ─── Auth-failure sliding window (pre-auth rate limit) ───────────────────

_AUTH_FAIL_WINDOW_SEC = 60
_AUTH_FAIL_LIMIT = 10
_AUTH_FAIL_GC_THRESHOLD = 256
_auth_fail_log: dict[str, list[float]] = {}
_auth_fail_lock = _threading.Lock()


def note_auth_fail(ip: str) -> bool:
    """Record an auth failure for *ip*, return True if the caller is
    now over the limit. Used by both cookie-less request paths and
    the WS handshake."""
    key = rate_limit_key(ip)
    if not key:
        return False
    now = _time.monotonic()
    cutoff = now - _AUTH_FAIL_WINDOW_SEC
    with _auth_fail_lock:
        bucket = _auth_fail_log.setdefault(key, [])
        bucket[:] = [t for t in bucket if t > cutoff][-_AUTH_FAIL_LIMIT:]
        bucket.append(now)
        if len(_auth_fail_log) > _AUTH_FAIL_GC_THRESHOLD:
            for k in [k for k, v in _auth_fail_log.items() if not v or v[-1] < cutoff]:
                _auth_fail_log.pop(k, None)
        return len(bucket) >= _AUTH_FAIL_LIMIT


# ─── SessionManager ──────────────────────────────────────────────────────

class SessionManager:
    """In-memory session table with per-session rate limiting.

    Cookie value = session id (random 32 bytes). The master AUTH_TOKEN
    is never written to a cookie. Leaking a cookie leaks one session,
    which can be revoked by popping from the dict (``/api/logout``
    endpoint does exactly this).

    Shards the per-sid hit counter across 8 locks so the authenticated
    rate limit doesn't serialise unrelated sessions (R12/#4). The
    global lock is still held for iteration / eviction.
    """
    SESSION_TTL_SEC = 60 * 60 * 8        # 8h
    SESSION_LIMIT = 64                   # hard cap
    SESSION_RATE_LIMIT = 600
    SESSION_RATE_WINDOW = 60.0
    SHARDS = 8
    COOKIE_NAME = "cortex_session"

    def __init__(self):
        self._sessions: dict[str, dict] = {}
        self._lock = _threading.Lock()
        self._shard_locks = [_threading.Lock() for _ in range(self.SHARDS)]
        # Master-token rate limit buckets (R13/C1). Authenticated
        # master-token path needs the same throttle as cookie path.
        self._mt_hits: dict[str, list[float]] = {}
        self._mt_lock = _threading.Lock()

    def _shard(self, sid: str) -> _threading.Lock:
        return self._shard_locks[hash(sid) % self.SHARDS]

    def mint(self) -> str:
        sid = _secrets.token_urlsafe(32)
        expiry = _time.monotonic() + self.SESSION_TTL_SEC
        with self._lock:
            now = _time.monotonic()
            if len(self._sessions) >= self.SESSION_LIMIT:
                expired = [k for k, v in self._sessions.items()
                           if v.get("expiry", 0) < now]
                for k in expired:
                    self._sessions.pop(k, None)
                if len(self._sessions) >= self.SESSION_LIMIT:
                    oldest = min(self._sessions.items(),
                                 key=lambda kv: kv[1].get("expiry", 0))[0]
                    self._sessions.pop(oldest, None)
            self._sessions[sid] = {"expiry": expiry, "hits": []}
        return sid

    def check(self, sid: str) -> bool:
        if not sid:
            return False
        with self._lock:
            rec = self._sessions.get(sid)
            if rec is None:
                return False
            if rec.get("expiry", 0) < _time.monotonic():
                self._sessions.pop(sid, None)
                return False
        return True

    def revoke(self, sid: str) -> None:
        if not sid:
            return
        with self._lock:
            self._sessions.pop(sid, None)

    def note_hit(self, sid: str) -> bool:
        """Per-session rate-limit hit. Returns True iff over budget."""
        if not sid:
            return False
        now = _time.monotonic()
        with self._shard(sid):
            rec = self._sessions.get(sid)
            if rec is None:
                return False
            hits = rec.setdefault("hits", [])
            cutoff = now - self.SESSION_RATE_WINDOW
            hits[:] = [t for t in hits if t > cutoff][-self.SESSION_RATE_LIMIT:]
            hits.append(now)
            return len(hits) > self.SESSION_RATE_LIMIT

    def note_master_token_hit(self, token: str, ip: str) -> bool:
        """R13/C1: rate-limit the master-token path too. Bucketed on
        hash(token)+ip so two honest clients with the same token
        keep independent budgets."""
        bucket_key = f"mt:{_hashlib.sha256((token + '|' + ip).encode()).hexdigest()[:32]}"
        now = _time.monotonic()
        cutoff = now - self.SESSION_RATE_WINDOW
        with self._mt_lock:
            bucket = self._mt_hits.setdefault(bucket_key, [])
            bucket[:] = [t for t in bucket if t > cutoff][-self.SESSION_RATE_LIMIT:]
            bucket.append(now)
            if len(self._mt_hits) > _AUTH_FAIL_GC_THRESHOLD:
                for k in [k for k, v in self._mt_hits.items() if not v or v[-1] < cutoff]:
                    self._mt_hits.pop(k, None)
            return len(bucket) > self.SESSION_RATE_LIMIT


# ─── FastAPI Depends ─────────────────────────────────────────────────────

def build_require_auth(
    *,
    master_token: str,
    sessions: SessionManager,
    trust_proxy: bool,
    bootstrap_rate_limit: Callable[[ClientIdentity], bool] | None = None,
) -> Callable:
    """Return a FastAPI ``Depends``-compatible callable configured
    with this instance's auth token + session manager.

    The returned callable is ``require_auth``. Every authenticated
    endpoint in web.py declares ``auth: ... = Depends(require_auth)``.
    A new route that forgets this dependency is caught by
    ``tests/test_invariants.py``.
    """
    def require_auth(request) -> ClientIdentity:
        # Imported here to avoid making security.* depend on fastapi.
        from fastapi import HTTPException
        # Pull the inputs directly off the request so the dependency
        # signature stays uniform — endpoints can't forget a header.
        authorization = request.headers.get("authorization", "")
        x_token = request.headers.get("x-token", "")
        query_token = request.query_params.get("token", "")
        cookie_token = request.cookies.get(SessionManager.COOKIE_NAME, "")
        identity = ClientIdentity.from_request(request, trust_proxy=trust_proxy)
        # Cookie path
        if cookie_token and sessions.check(cookie_token):
            if sessions.note_hit(cookie_token):
                raise HTTPException(status_code=429, detail="Session rate limit exceeded")
            return identity
        # Master-token path — constant-time compare.
        token = ""
        if authorization.startswith("Bearer "):
            token = authorization[7:]
        elif x_token:
            token = x_token
        elif query_token:
            token = query_token
        if master_token and token and _secrets.compare_digest(token, master_token):
            # R13/C1: throttle successful master-token calls too.
            if sessions.note_master_token_hit(token, identity.ip):
                raise HTTPException(status_code=429, detail="Token rate limit exceeded")
            return identity
        # Empty token disables auth entirely (dev mode). The opt-in
        # check happens upstream at startup (web.py refuses to run
        # with WEB_TOKEN='' unless WEB_INSECURE=1).
        if not master_token:
            return identity
        # Failure — slide into the auth-failure bucket.
        if note_auth_fail(identity.ip):
            raise HTTPException(status_code=429, detail="Too many auth failures")
        raise HTTPException(status_code=401, detail="Invalid or missing token")

    return require_auth


def public_endpoint() -> None:
    """Explicit no-auth marker for endpoints the operator has decided
    are safe to expose unauthenticated (``/health``, ``/api/logout``).
    Used as ``Depends(public_endpoint)``. The invariant test accepts
    this instead of ``require_auth``; forgetting either dependency
    is what fails CI."""
    return None


def require_auth(*args, **kwargs):
    """Placeholder so tests can import and inspect the name. Real
    binding happens via ``build_require_auth`` at startup. Direct
    invocation without binding is a programming error."""
    raise RuntimeError(
        "require_auth must be built via build_require_auth(master_token=..., "
        "sessions=...) at startup. A bare call means the app wiring skipped "
        "the security initialiser."
    )
