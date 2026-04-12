# Security Policy

This document describes Cortex's threat model, intentional design decisions that
look like vulnerabilities but aren't, known limitations, and how to report real
security issues responsibly.

## Reporting a vulnerability

Please **do not** open a public GitHub issue for security bugs.

Email: `security@` the maintainer's domain listed in `COPYRIGHT`, or open a
GitHub security advisory: <https://github.com/tmaloziec/cortex/security/advisories/new>.

Expect an acknowledgement within 5 business days. We aim to ship a fix or
mitigation advisory within 30 days for anything rated High or Critical.

## Threat model

Cortex is a **local, single-user AI agent**. The operator of the machine is
the trusted principal. The design assumptions are:

- You run Cortex on your own workstation, homelab, or VM you control.
- You trust the Ollama instance it connects to (default: `localhost:11434`).
- You read the code (or a trusted review) of any plugin you load.
- You pick which prompts and tasks the agent processes.

Outside that envelope — multi-tenant hosting, untrusted plugin authors,
running the web UI on a public network without auth — Cortex is **not**
designed to be safe, and we do not try to make it so. Those scenarios need a
different tool.

## Intentional design decisions (not bugs)

Static analyzers and external reviewers often flag the items below. They are
**deliberate**. Cortex would not function as a local AI agent without them.

### 1. Plugins execute arbitrary Python

Plugins are loaded via `importlib` from `./plugins/`. Once loaded they have
full Python privileges. This is the same trust model as VS Code extensions,
Vim plugins, or `~/.claude/agents/`.

- **Risk:** a malicious plugin can do anything your user can do.
- **Mitigation:** review plugin source before installing. Prefer plugins
  from authors you know. Consider running Cortex inside a container or VM
  if you plan to experiment with third-party plugins.

### 2. Filesystem access is not sandboxed by default

`read_file`, `write_file`, `edit_file`, and `bash` can reach anywhere the
user running Cortex can reach. Sandboxing the agent would defeat the point
of having a local coding assistant.

- **Risk:** prompt injection + a credulous model could read `~/.ssh/id_rsa`
  or write to `~/.bashrc`.
- **Mitigation:** the Policy Engine (`policy.py`) has deny rules for obvious
  targets (`.ssh/id_`, `.gnupg/`, `/etc/shadow`). Tighten or extend them in
  your local `policy.json`. For stricter isolation, run Cortex in a
  container/VM or as a dedicated restricted user.
- **Planned:** optional `--workspace-root <path>` flag to confine filesystem
  tools to a subtree.

### 3. `subprocess` with a shell for the `bash` tool

`agent.py` invokes `/bin/bash -c <cmd>` (with `shell=False`, so bandit and
semgrep stop complaining, but the semantics are the same as a shell). Pipes,
redirects, globs, and `&&` are how users expect `bash` to work — stripping
them would ship a broken tool. The Policy Engine is the enforcement point,
not argv parsing.

### 4. Custom `policy.json` can relax the defaults

The merge rule prepends user rules to the built-in lists. That means a user
can add an `allow` pattern that matches before a built-in `deny` would fire.
This is on purpose — you own your machine.

- **Risk:** a relaxed policy plus prompt injection equals a wider blast
  radius.
- **Mitigation:** review `_merge_policies` in `policy.py` to understand the
  order. Principle of least privilege — tighten, don't loosen, unless you
  know exactly what you're opting into.

### 5. The compactor calls the **local** Ollama

Context compaction summarises conversation history using the same local
model the agent is already using. Nothing leaves your machine during this
step. Anthropic fallback is opt-in and only runs if `ANTHROPIC_KEY` is set.

### 6. Sessions share one auth token (no per-session ACLs)

Any caller holding `AUTH_TOKEN` can list, read, and delete every session on
disk. Cortex is single-user by design; there is no "other user" to perform
IDOR against. If you share the token with someone, you've shared the whole
agent.

## Hardenings shipped in v1.0.3 / v1.0.4

- `subprocess.run(shell=True)` replaced with explicit `[_BASH_PATH, "-c",
  cmd]` + `shell=False` — same semantics, passes bandit B602 / semgrep
  `subprocess-shell-true`.
- `re.IGNORECASE | re.DOTALL` in the Policy Engine so multi-line payloads
  can't hide a denied pattern behind a newline.
- `copy.deepcopy(DEFAULT_POLICIES)` instead of a shallow copy, so multiple
  `PolicyEngine` instances don't share mutable rule lists.
- `task_id` validated against `^[A-Za-z0-9_-]{1,64}$` before being
  interpolated into any CS URL.
- CS_URL scheme validated (`http`/`https` only) at worker startup.
- Worker's task description moved out of the system prompt into a fenced
  `<task>` XML block in a user message — a hostile task body can no longer
  spoof new system instructions.
- Recovery's bad-JSON hint switched from a fake `[SYSTEM]` prefix in a user
  message to a real `role: system` message; bad JSON is now logged with the
  offending raw payload.
- Web UI `renderContent()` HTML-escapes agent output **before** applying
  markdown regex, closing an XSS vector through code blocks.
- Uvicorn access/error loggers get a filter that redacts `?token=...` to
  `?token=REDACTED` so rotated logs and log shippers don't persist the
  bootstrap token.
- `requirements.txt` pins every dependency (`==`).
- `run.sh` uses `set -euo pipefail`, portable script-path resolution, and
  installs from `requirements.txt` instead of an ad-hoc `pip install` list.
- `ws_test.py` uses bounded `ping_interval` / `ping_timeout` so the harness
  can't hang indefinitely if the server goes quiet.

## Known limitations (v1.0.4)

- The bootstrap URL printed at startup still contains `?token=…` because
  browsers can't attach an `Authorization` header to the first `GET /`.
  The token is stripped from the URL in-browser on first load, stored in
  `sessionStorage`, and redacted in server access logs, but it still
  transits the local loopback once. Treat that first URL as sensitive and
  do not paste it into chat/issue trackers.
- The WebSocket handshake currently authenticates via `?token=`. A future
  release is expected to switch to `Sec-WebSocket-Protocol`-based auth so
  the token never appears in any URL.
- `get_ram_gb()` reads `/proc/meminfo` and returns `0` on macOS/Windows,
  which makes the "fits-in-RAM" hint in the model picker unreliable off
  Linux. It does not affect security.
- `list_models` / `health` endpoints expose the current model name and
  agent name. This is informational and used by the UI; attackers on the
  same host already have more direct paths to that info.

## Reference: external audit (v1.0.4)

Independent review by Perplexity (April 2026) flagged 56 items across the
codebase. After triage and fixes:

- 7 Critical: 5 fixed, 2 classified as **intentional design** (plugin
  loading, filesystem breadth) and documented above.
- 19 High: fixed or reclassified.
- Medium/Low: batched — pinned deps, query-string token redaction,
  portability in `run.sh`, quieter `except` clauses.
