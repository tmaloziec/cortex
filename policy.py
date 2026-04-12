#!/usr/bin/env python3
"""
Policy Engine — reguły bezpieczeństwa dla tool calls.
Wzorowane na Claude Code permission system (Allow/Deny/Ask).
"""

import re
import json
from pathlib import Path
from typing import Optional

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
            # credentials
            r"\.ssh/id_",
            r"\.gnupg/",
        ],
        "ask": [],
        "allow": [
            r".*",  # everything not denied
        ]
    },
    "read_file": {
        "deny": [
            r"\.ssh/id_",
            r"\.gnupg/",
            r"shadow$",
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
            r"\.ssh/",
            r"\.env$",
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
        self.policies = DEFAULT_POLICIES.copy()
        self.user_overrides: dict = {}

        # zaladuj custom policies jesli sa
        if policy_file:
            pf = Path(policy_file)
            if pf.exists():
                try:
                    custom = json.loads(pf.read_text())
                    self._merge_policies(custom)
                except Exception:
                    pass

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

        # deny first
        for pattern in rules.get("deny", []):
            try:
                if re.search(pattern, value, re.IGNORECASE):
                    return PolicyDecision.DENY, f"Zablokowane przez regułę: {pattern}"
            except re.error:
                continue

        # then ask
        for pattern in rules.get("ask", []):
            try:
                if re.search(pattern, value, re.IGNORECASE):
                    return PolicyDecision.ASK, f"Wymaga potwierdzenia: {pattern}"
            except re.error:
                continue

        # then allow
        for pattern in rules.get("allow", []):
            try:
                if re.search(pattern, value, re.IGNORECASE):
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
