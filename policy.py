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
    except ValueError:
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
            r":(){ :\|:& };:",                  # fork bomb
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
    "write_file": {
        "deny": [
            # system directories
            r"^/boot/",
            r"^/usr/",
            r"^/bin/",
            r"^/sbin/",
            r"^/etc/",
            # credentials
            r"\.ssh/id_",
            r"\.ssh/authorized_keys",
            r"\.gnupg/",
            # Shell/session persistence — prompt injection + write_file would
            # otherwise be a one-shot backdoor (reverse shell on next login).
            r"\.bashrc$", r"\.bash_profile$", r"\.bash_login$", r"\.bash_logout$",
            r"\.zshrc$", r"\.zshenv$", r"\.zprofile$", r"\.zlogin$",
            r"\.profile$",
            r"\.inputrc$",
            # Cron and systemd user units — another persistence vector.
            r"(^|/)crontab$",
            r"/var/spool/cron/",
            r"\.config/systemd/user/",
            r"\.config/autostart/",
            # Dropping code into Cortex's own plugin directory = auto-RCE on
            # next startup (plugins/ is importlib-loaded at boot).
            r"(^|/)plugins/.*\.py$",
            # Other persistence-rich dotfiles.
            r"\.git/hooks/",
        ],
        "ask": [],
        "allow": [
            r".*",  # everything not denied
        ]
    },
    "read_file": {
        "deny": [
            # Traditional creds
            r"\.ssh/id_",
            r"\.ssh/authorized_keys",
            r"\.gnupg/",
            r"shadow$",
            # Dotenv / cloud / tool credentials — prompt injection could
            # otherwise silently ship these to an external tool output.
            r"\.env($|\.)",
            r"\.aws/",
            r"\.azure/",
            r"\.gcloud/",
            r"\.kube/config",
            r"\.docker/config\.json",
            r"\.npmrc$", r"\.pypirc$",
            r"\.netrc$",
            r"\.git-credentials$",
            r"\.config/.*(token|credentials|secret|apikey|api_key)",
            # Shell & language history — often contains typed passwords.
            r"\.bash_history$", r"\.zsh_history$", r"\.python_history$",
            r"\.lesshst$", r"\.mysql_history$", r"\.psql_history$",
            # Other users' Cortex sessions.
            r"\.cortex/sessions/",
        ],
        "allow": [".*"]
    },
    "list_dir": {
        "allow": [".*"]
    },
    "cs_note": {
        "allow": [".*"]
    },
    "cs_task": {
        "allow": [".*"]
    },
    "cs_briefing": {
        "allow": [".*"]
    },
    "grep_search": {
        "allow": [".*"]
    },
    "edit_file": {
        "deny": [
            r"^/etc/",
            r"^/boot/",
            r"^/usr/",
            r"^/bin/",
            r"^/sbin/",
            r"\.ssh/",
            r"\.gnupg/",
            r"\.env($|\.)",
            # Persistence hooks — same list as write_file. Keeping both in
            # sync matters; edit_file w/o these denies lets a reverse shell
            # line be appended to an existing ~/.bashrc.
            r"\.bashrc$", r"\.bash_profile$", r"\.bash_login$", r"\.bash_logout$",
            r"\.zshrc$", r"\.zshenv$", r"\.zprofile$", r"\.zlogin$",
            r"\.profile$", r"\.inputrc$",
            r"(^|/)crontab$",
            r"/var/spool/cron/",
            r"\.config/systemd/user/",
            r"\.config/autostart/",
            r"(^|/)plugins/.*\.py$",
            r"\.git/hooks/",
            # Cloud / tool creds
            r"\.aws/", r"\.azure/", r"\.gcloud/",
            r"\.kube/config",
            r"\.docker/config\.json",
            r"\.netrc$", r"\.git-credentials$",
        ],
        "allow": [
            r"^" + str(Path.home()) + r"/",
            r"^/tmp/",
        ]
    },
    "glob_find": {
        "allow": [".*"]
    },
    # Plugin tools inherit ALLOW by default — add custom rules here
    # "my_plugin_tool": { "deny": [...], "ask": [...], "allow": [...] }
}


class PolicyDecision:
    ALLOW = "allow"
    DENY = "deny"
    ASK = "ask"


def _get_check_value(tool_name: str, args: dict) -> str:
    """Wyciągnij wartość do sprawdzenia z argumentów toola."""
    if tool_name == "bash":
        return args.get("command", "")
    elif tool_name in ("read_file", "write_file", "edit_file"):
        return args.get("path", "")
    elif tool_name == "list_dir":
        return args.get("path", "")
    elif tool_name == "glob_find":
        return args.get("pattern", "") + " " + args.get("path", "")
    elif tool_name == "grep_search":
        return args.get("path", "")
    return json.dumps(args)


class PolicyEngine:
    def __init__(self, policy_file: Optional[str] = None):
        # deepcopy: DEFAULT_POLICIES contains nested lists; shallow copy would
        # make two PolicyEngine instances share the same underlying lists.
        self.policies = copy.deepcopy(DEFAULT_POLICIES)
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
        """Merge custom policies z default."""
        for tool, rules in custom.items():
            if tool not in self.policies:
                self.policies[tool] = rules
            else:
                for key in ("deny", "ask", "allow"):
                    if key in rules:
                        existing = self.policies[tool].get(key, [])
                        self.policies[tool][key] = rules[key] + existing

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
                if re.search(pattern, value, re.IGNORECASE | re.DOTALL):
                    return PolicyDecision.DENY, f"Zablokowane przez regułę: {pattern}"
            except re.error:
                continue

        # then ask
        for pattern in rules.get("ask", []):
            try:
                if re.search(pattern, value, re.IGNORECASE | re.DOTALL):
                    return PolicyDecision.ASK, f"Wymaga potwierdzenia: {pattern}"
            except re.error:
                continue

        # then allow
        for pattern in rules.get("allow", []):
            try:
                if re.search(pattern, value, re.IGNORECASE | re.DOTALL):
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
