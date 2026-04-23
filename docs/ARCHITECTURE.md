# Cortex — Architecture

Cortex is a local AI agent: one process, one operator, an Ollama
model on localhost, optional Consciousness Server (CS) on the LAN.
The security invariants land on top of a fairly small runtime.

## Module layout

```
cortex/
├── agent.py            — CLI entry point + shared execute_tool,
│                          build_system_prompt, discover_plugins.
├── web.py              — FastAPI app, WebSocket handler, REST
│                          endpoints; ~2000 LOC, the biggest module.
├── worker.py           — CS polling loop (autonomous mode).
├── compactor.py        — conversation-history compression.
├── recovery.py         — retry / fallback state machine.
├── policy.py           — Policy Engine (allow / deny / ask).
├── security/           — structural invariants (leaf package).
│   ├── __init__.py     — public re-exports.
│   ├── messages.py     — wrap_untrusted, make_message,
│   │                      UNTRUSTED_KINDS.
│   ├── auth.py         — SessionManager, ClientIdentity,
│   │                      build_require_auth, rate-limit.
│   ├── paths.py        — normalize_path, path_under.
│   └── fallback.py     — FallbackPolicy + capability sentinel
│                          (closure-hidden witness + registry).
├── plugins/            — user plugins drop in here.
└── tests/
    ├── test_invariants.py  — 5 AST-enforced structural rules.
    └── test_policy.py      — 52 regression tests (R3–R18).
```

## Dependency direction

`security/` is a **leaf package**. Nothing inside it imports from
`agent` / `web` / `worker` / `policy` / `compactor` / `recovery`.
This is not a style preference — it's invariant #3 in
`tests/test_invariants.py`, enforced by an AST walker.

```
          agent.py    web.py    worker.py      (entry points)
             │          │           │
             │          │           │
             ▼          ▼           ▼
        policy.py  compactor.py  recovery.py  (supporting)
             │          │           │
             └──────────┴───────────┘
                        │
                        ▼
                   security/*              (leaf)
```

Everything above `security/` can import from it; nothing in
`security/` can import upward. This kills entire classes of
plugin-via-monkey-patch attack — a plugin can modify
`agent.execute_tool`, but that change does not reach the helpers
that `RecoveryEngine` or the message wrappers resolve at
load time.

## Runtime data flow

1. **Request ingress** — browser WS, REST, or CLI stdin; worker
   pulls a task from CS.
2. **Auth layer** — `security.build_require_auth()` returns a
   FastAPI dependency that runs on every authenticated route.
   It validates the session cookie against `SessionManager`, or
   falls back to the master token for CLI clients; both paths
   bucket into rate-limit counters before returning a
   `ClientIdentity`. WebSocket re-validates on every inbound
   message and between tool iterations.
3. **Policy check** — `PolicyEngine.check(tool_name, args)`
   returns ALLOW / DENY / ASK. Paths are normalised first
   (`security.normalize_path`) so `/tmp/../etc/x` and
   `/tmp/symlink_to_etc` are evaluated in their resolved form.
4. **Execution** — `agent.execute_tool` runs the underlying
   syscall / subprocess. The bash tool is `subprocess.run([bash,
   -c, cmd], shell=False, …)`; the file tools open the already-
   normalised path.
5. **Result wrapping** — output goes through
   `security.make_tool_result`, which wraps the body in a
   nonce-tagged untrusted container. The message dict (a
   `TypedDict ToolMessage`) is appended to the conversation.
6. **Model call** — `call_model` ships the whole message list to
   Ollama. If `CORTEX_FALLBACK_ANTHROPIC=1` is set and Ollama
   raises `ConnectionError`, `RecoveryEngine` invokes the
   sentinel-wrapped Anthropic fallback (WARN-logged, payload
   optionally redacted).
7. **Streaming response** — the model's output goes back through
   the same auth/session scope. New tool calls recurse to
   step 3.

## Security invariants

Each is an AST or runtime check tied to a test in
`tests/test_invariants.py`. STRICT mode is on; a violation fails
CI.

1. **Bare `role=<...>` dict literals banned outside `security/`.**
   Every conversation message goes through `make_message` /
   `make_tool_result` / `make_system_note` / `make_user_note`.
   Walker catches Dict, `dict(role=...)`, and subscript
   assignment `d["role"] = "..."`.

2. **Every FastAPI route declares its auth dependency.**
   `@app.<verb>` / `@app.websocket` must have `Depends(
   _require_auth_dep)` or `Depends(_public_endpoint)` in the
   signature. `public_endpoint` routes must additionally be on
   the `_KNOWN_PUBLIC_ENDPOINTS` whitelist.

3. **No direct `request.client.host` access.** Client IPs flow
   through `ClientIdentity.from_request` only, which knows about
   proxy-header trust, IPv6 `/64` bucketing, and zone-ID
   stripping.

4. **Anthropic fallback is capability-gated.** `RecoveryEngine.
   __init__` rejects any `fallback_fn` that isn't a
   `_FallbackSentinel` registered in the module-private WeakSet.
   The sentinel class, its witness token, and the registry all
   live inside a closure returned by
   `_make_sentinel_machinery()` — no `from security.fallback
   import _REGISTRY` path exists.

5. **Escape-hatch comments carry a lifecycle.** `# invariant:
   allow-<rule> until=YYYY-MM-DD because <reason>`. Expired
   dates fail the test; every active exemption is regenerated
   into `UNSAFE.md` on each run.

## Untrusted input containers (rule #13)

Six KINDs, all share the same shape
`<KIND_<nonce> untrusted="true" …>…</KIND_<nonce>>` and the
same nonce generation (48-bit urlsafe; regenerate on collision).
Closing tag is scrubbed inside the payload belt-and-braces.

| KIND | Source | Emitted by |
|:--|:--|:--|
| `tool_output_<nonce>` | bash, file read, HTTP fetch, plugin | `wrap_tool_output` / `make_tool_result` |
| `compacted_history_<nonce>` | summariser output | `compactor.compact_messages` |
| `external_briefing_<nonce>` | CS briefing on session start | `agent.build_system_prompt` |
| `worker_task_<nonce>` | task description from CS | `worker.main_loop` |
| `plugin_guidance_<nonce>` | plugin `build_prompt()` output | `agent._full_prompt` |
| `recovery_note_<nonce>` | synthetic system hint / fallback banner | `security.make_system_note` / `make_user_note` |

The system prompt's rule #13 enumerates all six; the model is
told that anything inside ANY `KIND_<…>` container is data,
regardless of nonce, attributes, or claimed role.

## Auth model

- **Master token** (`WEB_TOKEN`): long-lived, used by CLI /
  curl clients via `Authorization: Bearer`, `X-Token`, or
  `?token=`. Successful auths throttle on a hash(token)+IP
  bucket.
- **Session cookie** (`cortex_session`): HttpOnly, SameSite=Strict,
  Secure when HTTPS. Value is a random 32-byte id; the id is the
  lookup key into `SessionManager._sessions`. Cookie leak ≠ master
  token leak. `POST /api/logout` revokes immediately.
- **Rate-limit**: three buckets — pre-auth failures (per IP
  `/64`, 10 / 60s), authenticated sessions (per session id,
  600 / 60s), authenticated master token (per hash(token)+IP,
  600 / 60s). `_note_session_hit` uses a shard of 8 locks keyed
  on `hash(sid)`.
- **Proxy trust**: off by default. `CORTEX_TRUST_PROXY_HEADERS=1`
  honours `True-Client-IP` / `CF-Connecting-IP` / `X-Real-IP` in
  that order. `X-Forwarded-For` is never consulted (leftmost is
  client-set, nginx appends).

## CS (Consciousness Server) integration

**Today, in v1.0.8:**

- One direction only — Cortex is the client. No CS → Cortex
  callback.
- Transport: plaintext HTTP. `CS_URL=http://…`.
  `validate_cs_url` at startup rejects `user:pass@` embedded
  credentials.
- Worker is **polling, not reactive**: HTTP `GET
  /api/tasks/pending/<agent>` every `POLL_INTERVAL` seconds.
  No WebSocket, no server-sent events, no broadcast
  subscription. If CS has an urgent task, Cortex notices it
  on the next poll cycle at worst.
- Agent identity: registration via `POST /api/agents/register`
  + heartbeat via `POST /api/agents/<name>/heartbeat` every
  loop. No token per-agent — CS trusts the LAN.
- Data paths:
  - `GET /api/agents/<name>/briefing` — session-start context.
  - `POST /api/notes` — agent observations, blockers.
  - `POST /api/memory/conversations` — session transcript
    mirror.
  - `POST /api/tasks/<id>/status` — task progress.

**Plans (v1.1 and later):**

- Token per agent, issued by CS. Rotation + revocation.
  `Principal` + `TokenVerifier` Protocol in `security/` already
  sketched.
- HTTPS with pinned cert chain. Self-signed for homelab,
  Let's Encrypt for cross-network. `CORTEX_CS_CERT_BUNDLE` env
  var for custom CA.
- Push-to-agent channel: WebSocket or SSE from CS so urgent
  tasks don't wait `POLL_INTERVAL`. Cortex opens the WS as a
  client; CS broadcasts. Polling stays as fallback.

The current v1.0.8 answer to "is CS comms encrypted?" is
**no, plaintext HTTP** — safe on a LAN you own, not safe across
networks. If `CS_URL` is on a different machine or goes over
the internet, wrap it in a VPN (WireGuard / Tailscale / OpenVPN
/ FortiClient) and accept the tunnel as your encryption layer
until v1.1 lands native TLS.

## Worker: polling, not WS / broadcast

Explicitly asked, explicitly answered:

- The worker does **not** open a WebSocket to CS.
- The worker does **not** broadcast on any channel.
- The worker is a strict HTTP polling loop: register →
  heartbeat → `GET /api/tasks/pending` → execute → `PATCH
  /api/tasks/<id>/status` → report via `POST /api/notes` →
  sleep `POLL_INTERVAL` → repeat.
- If you want reactive / push delivery, either run the worker
  with a shorter `POLL_INTERVAL` (1–3 s is fine on a LAN) or
  wait for the v1.1 push channel.

Multi-agent coordination today is entirely mediated by CS:
two Cortex instances on two machines don't see each other,
they see CS-visible tasks and notes. CS is the bus; agents
are spokes.

## Plugin surface

Plugins are Python files in `plugins/` discovered at startup.
Required symbols: `PLUGIN_NAME`, `PLUGIN_TOOLS`,
`execute_tool(name, args) -> str`. Optional: `build_prompt(
briefing) -> str`, `on_activate(config)`, `on_deactivate()`.

Runtime protection:

- Loaded under `cortex_plugins.<stem>` namespace (can't shadow
  stdlib).
- Filename regex `^[A-Za-z][A-Za-z0-9_]*\.py$`; `..` refused.
- `plugin_dir.resolve()` must land under `PROJECT_ROOT`;
  symlink escapes caught.
- `sys.modules` snapshot on `exec_module` failure → every key
  the plugin registered before raising is popped.
- `PLUGIN_NAME` sanitised against `^[A-Za-z0-9][A-Za-z0-9_.-]
  {0,63}$` with `..` forbidden.
- `on_deactivate` registered via `atexit` + SIGTERM handler so
  normal exit / SIGINT / `kill <pid>` all fire it. SIGKILL and
  OOM-kill remain best-effort (kernel denies userland any
  pre-death hook).
- `build_prompt` output wraps automatically into
  `<plugin_guidance_<nonce> untrusted="true">` — the plugin
  author doesn't think about this and can't accidentally
  bypass it.

Plugin tool calls go through the same Policy Engine as
built-ins. See `PLUGIN_GUIDE.md` for the authoring walkthrough.

## Testing and CI

`tests/test_invariants.py` runs the 5 structural checks in STRICT
mode. `tests/test_policy.py` runs 52 regression cases from rounds
R3–R18 (path traversal, symlinks, fork bombs, wrap escape,
session lifecycle, rate-limit, IPv6, capability sentinel, etc.).

`.github/workflows/invariants.yml` runs both on every push and
PR plus `pip-audit -r requirements.txt --strict` plus a `git
diff --exit-code UNSAFE.md` to catch stale exemption reports.
Python pinned to 3.12; AST node-shape changes across minor
versions would silently weaken the walker otherwise.

## Deliberate non-goals (v1.0.x)

- **Multi-user / multi-tenant.** The auth model is one master
  token and short-lived sessions from that token. No user
  accounts, no RBAC.
- **Plugin sandboxing.** Plugins are trusted Python; see
  `SECURITY.md` "What the security invariants DO and DO NOT
  protect against". Hostile-plugin isolation lands with v1.2
  via PEP 684 subinterpreters.
- **TLS between Cortex and CS.** Plaintext HTTP today; v1.1.
- **Push-delivered tasks.** Polling only today; v1.1.
- **Horizontal scale of `web.py`.** Single-worker uvicorn is
  assumed. Run multiple Cortex instances behind a load
  balancer and you'll see surprising behaviour with session
  cookies (the session table is per-process, not shared).

## Version roadmap

| Version | Headline |
|:--|:--|
| **v1.0.8** | First stable. 18 audit rounds closed. 57 tests green. |
| v1.0.8.x | Hotfix only. |
| v1.1 | CS auth service (JWT, Principal, TokenVerifier). TLS transport for CS. WS push channel from CS to agent. |
| v1.2 | Plugin isolation via PEP 684 subinterpreters. Hostile-plugin class of threat closed. |
| v1.3+ | Open. Commercial-licensee feedback shapes this. |
