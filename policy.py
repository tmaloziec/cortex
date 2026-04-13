#!/usr/bin/env python3
"""
Policy Engine — reguły bezpieczeństwa dla tool calls.
Wzorowane na Claude Code permission system (Allow/Deny/Ask).
"""

import re
import os
import copy
import json
import shlex
import logging
from pathlib import Path
from typing import Optional

log = logging.getLogger(__name__)

# ─── BASH FILTER — IMPORTANT CAVEAT ──────────────────────────────────────────
# The bash deny-list below is a BEST-EFFORT HEURISTIC, not a hard security
# gate. Bash is Turing-complete; any determined attacker can trivially bypass
# pattern matching using substitution ($(printf 'rm')), escapes (\rm), renamed
# binaries (cp /bin/rm /tmp/x && /tmp/x …), indirect invocation (python -c,
# eval), or by encoding the payload (base64 | sh). The argv-level check below
# adds a second layer that catches the most common "oops, I typed rm -rf /"
# and trivially obfuscated forms, but is not a substitute for deployment
# hygiene: don't run Cortex as root, don't load untrusted plugins, don't
# connect to models you can't trust. See SECURITY.md for the full threat
# model and Policy Engine semantics.

# argv[0] programs that trigger DENY when they appear as the literal first
# token of a parsed command. Regex still runs in addition; this is belt-and-
# suspenders.
_ARGV0_DENY = {
    # Filesystem / hardware destruction
    "mkfs", "dd", "shred", "hdparm", "blkdiscard", "wipefs",
    # System control (keep in sync with the regex above for consistency)
    "shutdown", "reboot", "halt", "poweroff", "init",
    # Scanners — require plugin opt-in
    "nmap", "masscan", "nikto", "sqlmap", "thehoneyharvester", "theharvester",
    "dirb", "gobuster", "hydra", "patator", "medusa",
    # Reverse-shell / egress helpers. `curl` and `wget` intentionally NOT
    # on this list — they have too many legitimate uses; the regex pass
    # handles their dangerous forms (pipe-to-shell).
    "nc", "ncat", "socat",
    # Environment dump helpers — regex also catches these but argv[0]
    # produces a clearer denial reason for the user (audit R4 LOW).
    "env", "printenv",
}

def _argv0_check(cmd: str) -> Optional[str]:
    """Parse *cmd* with shlex and apply argv-level denies.

    Catches common cases regex misses — ``rm -rf -- /``, ``\\rm -rf /``,
    whitespace padding — by looking at the actual program name and flags
    after shell tokenization. Returns a reason string on deny, None otherwise.

    Limitations (intentional, see module header):
    * Does not expand ``$(…)`` or backticks — shlex parses them as one token.
    * Does not recurse into ``bash -c "…"`` / ``python -c "…"``.
    * Silently gives up on unparseable input (regex layer still runs).
    """
    try:
        tokens = shlex.split(cmd, posix=True)
    except ValueError as e:
        # Unbalanced quotes / trailing backslash — fall through to the
        # regex pass but leave a breadcrumb so forensic replays of denied
        # sessions can see the parse was abandoned (audit R4 LOW).
        log.debug("argv0_check: shlex.split failed on %r: %s", cmd[:120], e)
        return None
    if not tokens:
        return None
    prog = os.path.basename(tokens[0]).lower()
    # Normalise obvious obfuscation: strip leading backslash (\rm → rm).
    if prog.startswith("\\"):
        prog = prog[1:]
    if prog in _ARGV0_DENY:
        return f"argv[0]='{prog}' is on the program denylist"
    # Extra rule for rm: regex only catches "rm -rf /" in exact form; argv
    # lets us notice ``rm -rf -- /`` and ``rm -rf /`` padded with flags. We
    # deny rm whenever any positional argument is exactly ``/`` (or a top-
    # level directory like ``/home``, ``/etc``). Regular file deletes are
    # unaffected.
    if prog == "rm":
        args_tail = tokens[1:]
        if "--" in args_tail:
            args_tail = args_tail[args_tail.index("--") + 1:]
        else:
            args_tail = [a for a in args_tail if not a.startswith("-")]
        for a in args_tail:
            if a == "/" or re.fullmatch(r"/(bin|boot|etc|home|lib\w*|opt|root|sbin|srv|usr|var)/?", a):
                return f"rm targets a top-level directory ({a!r})"
    return None

# ─── DEFAULT POLICIES ─────────────────────────────────────────────────────────
# Ładowane jeśli brak policy.json

DEFAULT_POLICIES = {
    # ══════════════════════════════════════════════════════════════════════
    # PHILOSOPHY: DENY protects hardware & critical data. Everything else
    # is ALLOW. No ASK — the agent runs uninterrupted, like Claude Code
    # with --dangerously-skip-permissions.
    # ══════════════════════════════════════════════════════════════════════
    "bash": {
        "deny": [
            # ── HARDWARE DESTRUCTION ──
            r"mkfs\.",                          # format filesystem
            r"dd\s+.*of=/dev/",                 # raw write to device
            r">\s*/dev/sd",                     # redirect to raw device
            r">\s*/dev/nvme",                   # redirect to nvme device
            r"hdparm\s+.*--security-erase",     # disk erase
            r"blkdiscard",                      # discard block device
            r"wipefs",                          # wipe filesystem signatures

            # ── SYSTEM DESTRUCTION ──
            r"rm\s+(-[a-zA-Z]*f|-[a-zA-Z]*r|--force|--recursive)\s+/",  # rm -rf / or /anything
            r"rm\s+-[a-zA-Z]*\s+/",              # rm with any flags targeting /
            # Fork bomb: ``:(){ :|:& };:``. The parentheses and braces are
            # regex metacharacters; the original pattern here was dead code
            # (matched nothing). Escape them and allow optional whitespace.
            r":\s*\(\s*\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:",
            r"shutdown",
            r"reboot",
            r"init\s+[06]",
            r"systemctl\s+(stop|disable|mask)\s+(sshd|NetworkManager|systemd)",

            # ── SECURITY ──
            r"chmod\s+777\s+/",                 # world-writable root
            r"chmod\s+\+s",                     # setuid
            r"chown\s+root",                    # ownership escalation
            r"curl.*\|\s*(bash|sh|zsh)",        # pipe to shell
            r"wget.*\|\s*(bash|sh|zsh)",
            r"\beval\b",                         # eval injection (all forms)

            # ── CREDENTIALS ──
            r"cat.*/etc/shadow",
            r"cat.*\.ssh/id_",
            r"cat.*\.gnupg/",
            # Environment dump leaks ANTHROPIC_API_KEY, WEB_TOKEN, CS_URL, etc.
            # Deny the literal forms; attacker can still `printf "%s" "$FOO"`,
            # so this is heuristic — see the module header and SECURITY.md.
            r"^\s*env(\s|$)",
            r"^\s*printenv(\s|$)",
            # Only deny `export -p` (dumps all env like printenv); plain
            # `export PATH=...` is a legitimate shell operation and blocking
            # it breaks common init snippets (audit R4 LOW).
            r"^\s*export\s+-p\b",
            r"\$\{?ANTHROPIC_API_KEY\}?",
            r"\$\{?WEB_TOKEN\}?",
            # Reverse-shell one-liners commonly used post-injection.
            r"\bnc\b.*\s-e\b",
            r"\bncat\b.*\s-e\b",
            r"/dev/tcp/",                      # bash TCP redirect
            r"bash\s+-i\s+>&\s*/dev/tcp",
            # base64 / xxd piped to shell — classic obfuscated RCE.
            r"base64\s+-d\b.*\|\s*(bash|sh|zsh)",
            r"xxd\s+-r.*\|\s*(bash|sh|zsh)",

            # ── Network scanning tools — require plugin or explicit approval ──
            r"\bnmap\b",
            r"\bnikto\b",
            r"\bsqlmap\b",
            r"\btheHarvester\b",
            r"\bmasscan\b",
            r"\bdirb\b",
            r"\bgobuster\b",
            r"\bhydra\b",
        ],
        "ask": [],  # nothing — DENY or ALLOW, no interruptions
        "allow": [
            r".*",  # everything not denied
        ]
    },
    # Writing to these is a persistent-RCE foothold. Any prompt-injected
    # write_file / edit_file call lands on a file that a later human or
    # system action runs — shell launches, vim/git/python invocations, cron
    # ticks, systemd user units. The list is defined once and reused by
    # write_file and edit_file so the two tools can't drift apart.
    "_PERSISTENCE_DENY": [
        # SSH: config/rc/env add persistence via ProxyCommand or
        # LocalCommand; id_/authorized_keys remain denied too.
        r"\.ssh/",
        r"\.gnupg/",
        # Shell init files (bash, zsh, sh, fish) and their .d/ drop-ins.
        r"\.bashrc$", r"\.bash_profile$", r"\.bash_login$", r"\.bash_logout$",
        r"\.bashrc\.d/",
        r"\.zshrc$", r"\.zshenv$", r"\.zprofile$", r"\.zlogin$",
        r"\.zshrc\.d/",
        r"\.profile$",
        r"\.inputrc$",
        r"\.config/fish/", r"(^|/)fish/config\.fish$",
        # X11 / Wayland / desktop-session init files.
        r"\.xinitrc$", r"\.xsession$", r"\.xsessionrc$", r"\.xprofile$",
        # XDG-style triggers: systemd user units, autostart, env.d, apps.
        r"\.config/systemd/user/",
        r"\.config/autostart/",
        r"\.config/environment\.d/",
        r"\.local/share/applications/.*\.desktop$",
        # Cron.
        r"(^|/)crontab$",
        r"/var/spool/cron/",
        r"/etc/cron",
        # Python site-packages .pth — runs on every python invocation.
        r"site-packages/.*\.pth$",
        # VCS alias/hook persistence. `.git/hooks/` is the obvious one; a
        # crafted `.gitconfig` [alias] runs on the next `git <alias>`.
        r"\.git/hooks/",
        r"\.gitconfig$", r"\.config/git/config$",
        # Editor startup files — vim/neovim run code on first invocation.
        r"\.vimrc$", r"\.gvimrc$",
        r"\.config/nvim/init\.(vim|lua)$",
        # Python / Node / pip global configs — alter what gets imported or
        # fetched next time the user runs pip/npm/python.
        r"\.config/pip/pip\.conf$", r"(^|/)pip\.conf$", r"\.pip/pip\.conf$",
        r"\.npmrc$", r"\.pypirc$",
        # Cortex's own plugin directory: importlib-loaded at startup =
        # persistent RCE on next `python agent.py`.
        r"(^|/)plugins/.*\.py$",
    ],

    # Anything holding a live credential should be off-limits to both read
    # paths (exfil) and write paths (poisoning / overwriting with attacker
    # keys). Kept as one list and applied to read_file / write_file /
    # edit_file / grep_search / list_dir so a single tool can't sneak past
    # the others.
    "_CREDENTIAL_DENY": [
        # Use (/|$) so list_dir on the directory itself is also denied —
        # just enumerating ~/.aws or ~/.ssh leaks profile names.
        r"\.ssh(/|$)",
        r"\.gnupg(/|$)",
        r"(^|/)shadow$",
        r"\.env($|\.)",
        r"\.envrc$",
        r"\.aws(/|$)",
        r"\.azure(/|$)",
        r"\.gcloud(/|$)",
        r"\.kube/config",
        r"\.docker/config\.json",
        r"\.netrc$",
        r"\.git-credentials$",
        r"\.config/.*(token|credentials|secret|apikey|api_key)",
        # R-02 regression (v1.0.6): npmrc/pypirc were only on the write
        # persistence list; their `_authToken` / `password` fields are
        # live credentials and read_file/grep_search must deny them too.
        r"\.npmrc$", r"\.pypirc$",
        # R-01 regression (v1.0.6): Cortex's own session store contains
        # prior tool_output (file contents, bash output) — reading it
        # defeats read_file denies through the back door.
        r"(^|/)\.cortex/sessions(/|$)",
    ],

    # Historical files often contain typed passwords, tokens, or sensitive
    # command lines; read_file blocks them even though writing is generally
    # harmless.
    "_HISTORY_DENY": [
        r"\.bash_history$", r"\.zsh_history$", r"\.python_history$",
        r"\.lesshst$", r"\.mysql_history$", r"\.psql_history$",
        r"\.node_repl_history$",
    ],

    # System paths the user should never overwrite via the agent tool
    # (even as root — we intentionally make this hurt to typo).
    "_SYSTEM_DIRS_DENY": [
        r"^/boot/",
        r"^/usr/",
        r"^/bin/",
        r"^/sbin/",
        r"^/etc/",
    ],

    # _PLACEHOLDERS_: the three underscore-prefixed keys above are merged
    # into the real tool rules below by _expand_shared_lists(); they are
    # not tool names themselves.
    "write_file": {
        "deny": [
            # filled in by _expand_shared_lists() from the three lists above
        ],
        "ask": [],
        "allow": [r".*"],
    },
    "read_file": {
        "deny": [
            # filled in by _expand_shared_lists()
        ],
        "allow": [r".*"],
    },
    "list_dir": {
        "deny": [
            # credential dirs shouldn't be enumerable either — listing
            # ~/.aws tells the attacker "here are the profiles I can try"
        ],
        "allow": [r".*"],
    },
    "cs_note": {"allow": [r".*"]},
    "cs_task": {"allow": [r".*"]},
    "cs_briefing": {"allow": [r".*"]},
    "grep_search": {
        "deny": [
            # filled in by _expand_shared_lists() — otherwise grep_search
            # is an obvious bypass of read_file's credential list.
        ],
        "allow": [r".*"],
    },
    "edit_file": {
        "deny": [
            # filled in by _expand_shared_lists()
        ],
        "allow": [
            r"^" + str(Path.home()) + r"/",
            r"^/tmp/",
        ],
    },
    "glob_find": {
        "deny": [
            # filled in by _expand_shared_lists() — otherwise glob_find is an
            # obvious bypass: `**/id_rsa` or `.ssh/*` would enumerate credential
            # filenames without ever calling read_file/list_dir.
        ],
        "allow": [".*"]
    },
    # Plugin tools inherit ALLOW by default — add custom rules here
    # "my_plugin_tool": { "deny": [...], "ask": [...], "allow": [...] }
}


def _expand_shared_lists(policies: dict) -> dict:
    """Move the underscore-prefixed shared lists into the real tool rules.

    Keeps the source readable (one canonical _PERSISTENCE_DENY /
    _CREDENTIAL_DENY / _HISTORY_DENY / _SYSTEM_DIRS_DENY) and removes the
    copy-paste drift class that tripped up v1.0.5 — where write_file and
    edit_file fell out of sync and one of them missed a cloud-cred deny
    the other had.
    """
    persistence = policies.pop("_PERSISTENCE_DENY", [])
    credential  = policies.pop("_CREDENTIAL_DENY", [])
    history     = policies.pop("_HISTORY_DENY", [])
    system_dirs = policies.pop("_SYSTEM_DIRS_DENY", [])

    # Write paths: persistence + credentials (poisoning) + system dirs.
    for tool in ("write_file", "edit_file"):
        rules = policies.setdefault(tool, {"deny": [], "allow": [r".*"]})
        rules["deny"] = list(system_dirs) + list(persistence) + list(credential) + list(rules.get("deny", []))

    # Read paths: credentials + history. Persistence files are technically
    # readable (they're config, not secrets) but some like crontab can
    # expose scheduled-job secrets — credential list already covers the
    # worst of it.
    policies.setdefault("read_file", {"deny": [], "allow": [r".*"]})["deny"] = (
        list(credential) + list(history) + list(policies["read_file"].get("deny", []))
    )

    # grep_search, list_dir and glob_find must not become a read_file bypass:
    # if read_file denies a credential, an unrestricted search/enumeration
    # across the same path would still let the model discover or read it.
    for tool in ("grep_search", "list_dir", "glob_find"):
        rules = policies.setdefault(tool, {"deny": [], "allow": [r".*"]})
        rules["deny"] = list(credential) + list(history) + list(rules.get("deny", []))

    return policies


# Snapshot the shared lists before expansion — PolicyEngine._merge_policies
# needs them to re-expand when a user adds entries via custom policy.json.
# _expand_shared_lists mutates (pops) these keys, so we grab copies first.
SHARED_DEFAULTS = {
    k: list(DEFAULT_POLICIES.get(k, []))
    for k in ("_CREDENTIAL_DENY", "_PERSISTENCE_DENY",
              "_HISTORY_DENY", "_SYSTEM_DIRS_DENY")
}

DEFAULT_POLICIES = _expand_shared_lists(DEFAULT_POLICIES)


class PolicyDecision:
    ALLOW = "allow"
    DENY = "deny"
    ASK = "ask"


def _normalize_path(raw: str) -> str:
    """Resolve path traversal, symlinks, and relative paths to an absolute
    canonical form **before** policy evaluation.

    Without this, both families of bypass work: ``/tmp/../etc/cron.d/evil``
    starts with ``/tmp`` so ``^/etc/`` never matches, and a symlink
    ``/tmp/safe → /etc/shadow`` lets the policy evaluate the benign
    ``/tmp/safe`` while the OS dereferences to the sensitive target.

    ``strict=False`` lets us normalise paths that don't exist yet (common
    for ``write_file`` — we want to deny ``/tmp/../etc/x`` *before*
    anything is created).
    """
    if not raw:
        return ""
    try:
        expanded = os.path.expanduser(str(raw))
        return str(Path(expanded).resolve(strict=False))
    except (OSError, ValueError):
        # Unresolvable input — return the raw string; downstream deny rules
        # still see something to match against and the tool will likely
        # fail later anyway.
        return str(raw)


def _get_check_value(tool_name: str, args: dict) -> str:
    """Wyciągnij wartość do sprawdzenia z argumentów toola. Path-based tools
    go through _normalize_path so traversal and symlinks can't hide a
    denied target behind a benign-looking prefix."""
    if tool_name == "bash":
        # Strip NUL bytes before pattern matching; some regex backends
        # stop scanning at a NUL and an attacker-crafted payload could
        # hide a denied command after one. NUL isn't meaningful to bash
        # anyway (it terminates argv strings at the syscall boundary).
        return (args.get("command", "") or "").replace("\x00", "")
    elif tool_name in ("read_file", "write_file", "edit_file"):
        return _normalize_path(args.get("path", ""))
    elif tool_name == "list_dir":
        return _normalize_path(args.get("path", ""))
    elif tool_name == "glob_find":
        # Return pattern and path as newline-separated values. The check()
        # loop applies re.search (not fullmatch), so anchored patterns like
        # `\.bash_history$` only hit end-of-line — newline makes the two
        # halves independent line endings. re.DOTALL stays on elsewhere
        # but `$` in MULTILINE-aware search still matches end-of-line;
        # we enable MULTILINE explicitly in check() for this tool.
        return args.get("pattern", "") + "\n" + _normalize_path(args.get("path", ""))
    elif tool_name == "grep_search":
        return _normalize_path(args.get("path", ""))
    return json.dumps(args)


class PolicyEngine:
    def __init__(self, policy_file: Optional[str] = None):
        # deepcopy: DEFAULT_POLICIES contains nested lists; shallow copy would
        # make two PolicyEngine instances share the same underlying lists.
        self.policies = copy.deepcopy(DEFAULT_POLICIES)
        self._shared_defaults = copy.deepcopy(SHARED_DEFAULTS)
        self.user_overrides: dict = {}

        # zaladuj custom policies jesli sa
        if policy_file:
            pf = Path(policy_file)
            if pf.exists():
                try:
                    custom = json.loads(pf.read_text())
                    self._merge_policies(custom)
                except Exception as e:
                    log.warning("Failed to load custom policy %s: %s", pf, e)

    def _merge_policies(self, custom: dict):
        """Merge custom policies z default.

        Shared-list keys (``_CREDENTIAL_DENY``, ``_PERSISTENCE_DENY``,
        ``_HISTORY_DENY``, ``_SYSTEM_DIRS_DENY``) in *custom* must be re-
        expanded across every tool that inherits from them — otherwise a
        user adding ``~/.vault/`` to ``_CREDENTIAL_DENY`` would only see it
        applied if they *also* listed every consumer tool by hand. v1.0.6
        silently dropped these keys on the floor.
        """
        shared_keys = {
            "_CREDENTIAL_DENY", "_PERSISTENCE_DENY",
            "_HISTORY_DENY", "_SYSTEM_DIRS_DENY",
        }
        has_shared = any(k in custom for k in shared_keys)

        for tool, rules in custom.items():
            if tool in shared_keys:
                continue  # handled by re-expansion below
            if tool not in self.policies:
                self.policies[tool] = rules
            else:
                for key in ("deny", "ask", "allow"):
                    if key in rules:
                        existing = self.policies[tool].get(key, [])
                        self.policies[tool][key] = rules[key] + existing

        if has_shared:
            # Re-run the shared-list expansion with the user's additions
            # prepended to the defaults so user rules take precedence.
            merged_shared = {
                k: list(custom.get(k, [])) + list(self._shared_defaults.get(k, []))
                for k in shared_keys
            }
            # _expand_shared_lists consumes the underscore keys via pop(),
            # so feed a combined dict (tool rules + shared lists) and
            # write back the expanded result.
            combined = dict(self.policies)
            combined.update(merged_shared)
            self.policies = _expand_shared_lists(combined)

    def check(self, tool_name: str, args: dict) -> tuple[str, str]:
        """
        Sprawdz czy tool call jest dozwolony.
        Returns: (decision, reason)
        """
        rules = self.policies.get(tool_name)
        if not rules:
            return PolicyDecision.ASK, f"Brak reguł dla tool: {tool_name}"

        value = _get_check_value(tool_name, args)

        # Second bash layer: argv[0] denylist (heuristic, documented as such).
        # Runs before the regex pass so the reason we surface to the user is
        # precise ("argv[0]='rm' …") rather than a regex fragment.
        if tool_name == "bash":
            argv_reason = _argv0_check(value)
            if argv_reason:
                return PolicyDecision.DENY, argv_reason

        # deny first
        for pattern in rules.get("deny", []):
            try:
                if re.search(pattern, value, re.IGNORECASE | re.DOTALL | re.MULTILINE):
                    return PolicyDecision.DENY, f"Zablokowane przez regułę: {pattern}"
            except re.error:
                continue

        # then ask
        for pattern in rules.get("ask", []):
            try:
                if re.search(pattern, value, re.IGNORECASE | re.DOTALL | re.MULTILINE):
                    return PolicyDecision.ASK, f"Wymaga potwierdzenia: {pattern}"
            except re.error:
                continue

        # then allow
        for pattern in rules.get("allow", []):
            try:
                if re.search(pattern, value, re.IGNORECASE | re.DOTALL | re.MULTILINE):
                    return PolicyDecision.ALLOW, "OK"
            except re.error:
                continue

        # domyslnie: ask
        return PolicyDecision.ASK, "Brak pasującej reguły — wymaga potwierdzenia"

    def format_ask_prompt(self, tool_name: str, args: dict, reason: str) -> str:
        """Sformatuj pytanie do usera."""
        value = _get_check_value(tool_name, args)
        preview = value[:80] + ("..." if len(value) > 80 else "")
        return f"[POLICY] {tool_name}: {preview}\n  Powód: {reason}\n  Zezwolić? (t/n/zawsze): "
