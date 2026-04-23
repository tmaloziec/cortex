# Cortex — Roadmap post-v1.0.8

Three releases land the three things the v1.0.8 audit cycle
deliberately punted on: push-channel delivery, native TLS + per-agent
auth, and plugin isolation. Each one closes a named row in the
`SECURITY.md` "what we don't protect against" table. No feature-only
releases in between — v1.0.x is hotfix-only until v1.1 ships.

---

## v1.1 — CS auth service + TLS + push channel

**Target:** Q3 2026. Covers the "cross-network deployment" and
"cross-agent push" gaps.

### In scope

**CS-issued per-agent tokens.**

- `POST /api/agents/register` returns a JWT bound to `agent_name`
  and a `kid` (key id). Short TTL (1h default), refresh endpoint.
- Cortex stores the token in memory, re-registers on 401.
- CS can revoke a single agent without rotating every other token.
- `CORTEX_AGENT_TOKEN_FILE=/var/lib/cortex/token` — persist across
  restarts without leaking to env vars (which show up in `ps`).

**Native TLS between Cortex and CS.**

- `CS_URL=https://…` required for non-loopback hosts. Plain HTTP
  allowed only for `127.0.0.1` / `::1`.
- `CORTEX_CS_CERT_BUNDLE=/etc/ssl/custom-ca.pem` honoured by the
  `requests` session.
- `validate_cs_url` gains a live check on startup (TLS handshake +
  cert chain verification) before the worker loop begins.
- Optional mTLS: `CORTEX_CS_CLIENT_CERT` + `_KEY`. Off by default.

**Protocol primitives in `security/`:**

```python
class Principal(Protocol):
    id: str
    name: str
    roles: frozenset[str]
    issuer: str
    expires_at: datetime

class TokenVerifier(Protocol):
    def verify(self, token: str) -> Principal: ...
```

`SessionManager` becomes one implementation of `TokenVerifier`
(local session id); `CSTokenVerifier` is the other (JWT from CS).
`build_require_auth` takes a verifier param and is agnostic to
which one you pass. Commercial licensees can write their own
verifier (Auth0, Keycloak, cloud IAM) without touching Cortex.

**Push channel: CS → agent via WebSocket.**

- Cortex-worker opens `wss://cs.example.com/ws/agent` after
  register. CS pushes task-available signals; agent polls the
  `/api/tasks/pending/<name>` endpoint on signal (not on a
  timer). Polling stays as fallback if WS drops.
- Heartbeat becomes bidirectional: WS ping/pong replaces
  `POST /api/agents/<name>/heartbeat` when the socket is up.
- Multi-agent broadcast: CS can push to an **agent class**
  (`role=cortex-coder`) instead of a single name. Dispatcher can
  say "any coder pick this up" instead of binding to one
  instance.

### Out of scope for v1.1 (tracked elsewhere)

- Plugin sandboxing — v1.2.
- Multi-tenant auth / RBAC — deliberate non-goal.
- `web.py` horizontal scale (session table shared across uvicorn
  workers) — deliberate non-goal; single-worker remains the
  supported topology.

### Success criteria

- `CS_URL=http://your-cs-host:3032` **refuses to start** unless
  host is loopback.
- `pip-audit` clean on every new dep (jwt library, maybe
  `cryptography`).
- 5 structural invariants still green; new invariants for
  "every CS request sends `Authorization: Bearer <token>`" +
  "TLS verification is not disabled".
- Integration test: Cortex-A on machine M1, Cortex-B on machine
  M2, CS on machine M3, all three over Tailscale without any
  VPN-level wrap — relies purely on Cortex's own TLS + JWT.

---

## v1.2 — Plugin isolation (PEP 684 subinterpreters)

**Target:** Q1 2027. Covers the "hostile in-process plugin" row in
the SECURITY.md threat-model table.

### In scope

**Each plugin runs in its own subinterpreter.**

- Python 3.12's `interpreters` stdlib module (PEP 684) is the
  mechanism. Each plugin's `on_activate` + `execute_tool` run in
  a fresh interpreter; main agent interpreter never sees the
  plugin's GIL-released state.
- Plugin can't `import ctypes.pythonapi` the agent's memory —
  different interpreter, different PyMemory pool.
- Plugin can't replace `sys.modules["security"]` in the agent —
  each interpreter has its own module table.
- `monkey-patch` of `security.messages.wrap_untrusted.__defaults__`
  from a plugin affects only the plugin's view.

**New IPC contract.**

- Plugin ↔ agent communication goes through a message channel
  (interpreter channel per PEP 554). Values are serialised; no
  shared objects. String-in, string-out: plugin's `execute_tool`
  receives a pickled args dict (safe to unpickle because the
  agent wrote it) and returns a string.
- No shared filesystem handles, no shared threads, no `sys.modules`
  crossover.

**Honest limitations.**

- **CPython sub-interpreters do not isolate against `os`-level
  capabilities.** A plugin can still `os.system("rm -rf /")`
  because the OS sees one process. Real sandboxing (seccomp,
  namespaces, containers) is a further step; v1.3 candidate.
- Plugins that rely on global state across calls (e.g. open
  sockets held in module-level vars) still work within their
  own interpreter — one interpreter per plugin, not per call.
- Startup cost: spawning a subinterpreter per plugin adds
  ~30–100ms per plugin on agent launch. Acceptable; we do it
  once.

### Migration path

- Plugin API backward-compatible (required symbols unchanged).
- Opt-in flag `CORTEX_PLUGIN_ISOLATION=1` in v1.2 beta; default
  in v1.2 final.
- Plugins using `on_activate(config)` to share state with the
  main agent (rare — one exists in the doc examples) get a
  deprecation warning + documented migration to channel IPC.

### Success criteria

- Hostile plugin proof-of-concept (reads `/etc/shadow` via
  `ctypes.pythonapi.PyMemory_RawMalloc` tricks) is blocked by
  subinterpreter isolation in a test fixture.
- No perf regression on tool-call latency outside the ~30ms
  one-time startup cost per plugin.
- `SECURITY.md` table row "Hostile in-process plugin" flips from
  **No** to **Yes (CPython-level; OS-level still needs
  sandboxing)**.

---

## v1.3 — Open slot

Not committing to scope yet. Candidates, ranked:

1. **OS-level sandboxing for plugins.** Takes v1.2 one further
   step — plugin runs in a subprocess with seccomp-bpf filter,
   namespace isolation, read-only FS except a declared
   writable workspace. Closes the "hostile plugin can still
   `os.system`" gap that v1.2 explicitly leaves open.

2. **Multi-user auth / RBAC.** Not for the local-single-user
   case, but commercial licensees running a team instance
   want it. Adds `User` model, per-user session tables, per-tool
   RBAC. Significant scope — would need a dedicated design
   round.

3. **Web UI refresh.** Today's UI is single-file HTML with
   inline JS (CSP `unsafe-inline` required). Split into
   asset-bundled SPA, use nonce-based CSP, add session
   management UI, settings panel, plugin enable/disable
   toggle. Medium scope; no security-boundary change.

4. **Cortex federation.** Cortex-A can delegate a subtask
   directly to Cortex-B without routing through CS. Opens up
   P2P agent cooperation but also re-opens the auth / trust
   surface CS currently mediates. High design risk.

5. **Worker resilience — session checkpoint to CS.** Today if
   a worker process dies mid-loop (OOM, power-loss, kernel
   panic) the in-memory running context is gone; only tasks
   marked DONE survived. Add a periodic checkpoint: every N
   minutes (default 2), worker pushes a compact running-state
   snapshot — current task id, last K tool-calls, recent
   stdout tail — to CS as a `type: observation` note with
   tag `checkpoint` + `session:<uuid>` + `agent:<name>`.
   Dedup by content hash so idle workers don't spam CS.
   On worker restart, `recovery.py` queries CS for the most
   recent checkpoint of its `agent_name`; if the abandoned
   task is still IN_PROGRESS and the checkpoint is fresh
   (< N minutes), resume from that state instead of
   reclaiming from scratch. Closes the gap the supervisor side
   already closed on 2026-04-19 via `~/.claude/bin/
   checkpoint-session.sh` — same pattern, worker-native.
   Low scope; ~80 LOC in worker.py + 30 LOC in recovery.py.
   Does not require v1.1 / v1.2 infrastructure — could
   backport to v1.0.x as a minor feature if a user needs it.

Commercial licensee feedback after v1.1 ships shapes the
v1.3 decision.

---

## What stays stable

Across every release above, these do NOT change:

- **5 structural invariants** enforced by CI. New ones may be
  added; existing ones will not be relaxed without a
  CODEOWNERS-reviewed justification.
- **Dual licensing** (AGPLv3 + commercial) via CLA. The
  commercial terms may be revised; the AGPLv3 branch is
  permanent.
- **Threat model** single-user local agent remains the default.
  Multi-tenant / shared-host is explicitly out of scope —
  anyone deploying there is using Cortex against its design.
- **Plugin API contract** (`PLUGIN_NAME`, `PLUGIN_TOOLS`,
  `execute_tool`). Hooks may be added; the required three
  never change.
- **CS as message-bus role.** Cortex clients talk to CS;
  CS does not execute code. CS being horizontally scalable /
  replicated / multi-region is a CS concern, not a Cortex one.

---

## How to follow along

- GitHub releases: tags `v1.1`, `v1.1-rc1`, etc.
- `docs/ROADMAP.md` — this file, kept current.
- `SECURITY.md` — the per-round log of what each release closed.
  Post-v1.0.8 entries land under a `v1.1` / `v1.2` heading each.
- `UNSAFE.md` — auto-regenerated escape-hatch inventory. If the
  number grows between releases, read the diff before
  upgrading.

No blog. No Discord. Pull requests and GitHub issues are the
whole workflow.
