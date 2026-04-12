#!/usr/bin/env python3
# Cortex — Local AI Agent
# Copyright (C) 2026 Tomasz Maloziec
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published
# by the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
#
# Commercial licensing available — see LICENSE-COMMERCIAL.md
"""
Cortex — local AI agent with tool calling, powered by Ollama.

Modules:
  - policy.py    — Policy Engine (Allow/Deny/Ask per tool)
  - compactor.py — Context Compression (auto-summarize)
  - recovery.py  — Recovery Engine (retry, fallback, error handling)
  - plugins/     — Optional plugins (extra tools, modes, prompts)
"""

import os
import sys
import json
import glob as glob_module
import socket
import subprocess
import datetime
import readline
import re
import requests
import logging
import threading
import itertools
import time
import signal
import shutil
import importlib.util
from pathlib import Path
from typing import Optional

# Ignore Ctrl+Z (SIGTSTP) — Unix only; SIGTSTP doesn't exist on Windows
if hasattr(signal, "SIGTSTP"):
    signal.signal(signal.SIGTSTP, signal.SIG_IGN)

# Detect available shell — prefer bash, fall back to system default
_BASH_PATH = shutil.which("bash") or "/bin/sh"

from policy import PolicyEngine, PolicyDecision
from compactor import compact_messages, estimate_tokens, should_compact
from recovery import RecoveryEngine, RecoveryAction

# ─── CONFIG ────────────────────────────────────────────────────────────────────
OLLAMA_URL      = os.getenv("OLLAMA_URL",      "http://localhost:11434")
OLLAMA_MODEL    = os.getenv("OLLAMA_MODEL",     "gemma4:e4b")
CS_URL          = os.getenv("CS_URL",           "")
AGENT_NAME      = os.getenv("AGENT_NAME",       "cortex")
ANTHROPIC_KEY   = os.getenv("ANTHROPIC_API_KEY", "")
USE_ANTHROPIC   = os.getenv("USE_ANTHROPIC",    "false").lower() == "true"
THINK_MODE      = os.getenv("THINK_MODE",       "false").lower() == "true"
MAX_TOOL_LOOPS  = 10
CONTEXT_MAX_TOKENS = int(os.getenv("CONTEXT_MAX_TOKENS", "16000"))
POLICY_FILE     = os.getenv("POLICY_FILE", "")  # optional custom policy.json

logging.basicConfig(level=logging.WARNING, format="%(levelname)s: %(message)s")
log = logging.getLogger("agent")

# ─── COLORS ────────────────────────────────────────────────────────────────────
class C:
    RESET   = "\033[0m"
    BOLD    = "\033[1m"
    DIM     = "\033[2m"
    BLUE    = "\033[38;5;39m"
    CYAN    = "\033[38;5;51m"
    GREEN   = "\033[38;5;82m"
    AMBER   = "\033[38;5;220m"
    RED     = "\033[38;5;196m"
    PURPLE  = "\033[38;5;141m"
    GRAY    = "\033[38;5;245m"
    WHITE   = "\033[38;5;255m"

    @staticmethod
    def rl(code):
        """Wrap ANSI code for readline (marks as zero-width)."""
        return f"\001{code}\002"

# ─── PLUGIN SYSTEM ─────────────────────────────────────────────────────────────
PLUGINS = {}  # name -> plugin module

def discover_plugins(plugin_dir: Path = None) -> dict:
    """
    Load plugins from plugins/ directory.

    Each plugin is a Python file that exposes:
      - PLUGIN_NAME: str           — unique plugin name
      - PLUGIN_TOOLS: list[dict]   — Ollama tool definitions (same format as TOOLS)
      - execute_tool(name, args) -> str  — handler for plugin tools
      - build_prompt(briefing) -> str    — (optional) system prompt for plugin mode
      - on_activate(config)              — (optional) called when plugin mode starts
      - on_deactivate()                  — (optional) called when plugin mode stops

    Returns dict of {name: module}.
    """
    if plugin_dir is None:
        plugin_dir = Path(__file__).parent / "plugins"

    plugins = {}
    if not plugin_dir.is_dir():
        return plugins

    for f in sorted(plugin_dir.glob("*.py")):
        if f.name.startswith("_"):
            continue
        try:
            spec = importlib.util.spec_from_file_location(f.stem, f)
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            name = getattr(mod, "PLUGIN_NAME", f.stem)
            plugins[name] = mod
            log.info(f"Plugin loaded: {name}")
        except Exception as e:
            log.warning(f"Plugin {f.name} failed to load: {e}")

    return plugins


def get_plugin_tools(plugin_name: str) -> list:
    """Get tool definitions from a loaded plugin."""
    mod = PLUGINS.get(plugin_name)
    if mod:
        return getattr(mod, "PLUGIN_TOOLS", [])
    return []


def execute_plugin_tool(plugin_name: str, tool_name: str, args: dict) -> str:
    """Delegate tool execution to a plugin."""
    mod = PLUGINS.get(plugin_name)
    if mod and hasattr(mod, "execute_tool"):
        return mod.execute_tool(tool_name, args)
    return f"Plugin '{plugin_name}' not found or has no execute_tool"

# ─── TOOLS DEFINITION ──────────────────────────────────────────────────────────
TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "bash",
            "description": "Execute a bash command. Returns stdout and stderr.",
            "parameters": {
                "type": "object",
                "properties": {
                    "command": {
                        "type": "string",
                        "description": "Bash command to execute"
                    },
                    "timeout": {
                        "type": "integer",
                        "description": "Timeout in seconds (default 30)",
                        "default": 30
                    }
                },
                "required": ["command"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "read_file",
            "description": "Read file contents with line numbers.",
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Absolute path to file"
                    },
                    "offset": {
                        "type": "integer",
                        "description": "Start line (from 0, default 0)",
                        "default": 0
                    },
                    "limit": {
                        "type": "integer",
                        "description": "Max lines to read (default 200)",
                        "default": 200
                    }
                },
                "required": ["path"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "write_file",
            "description": "Write content to a file (creates directories if needed).",
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Absolute path to file"
                    },
                    "content": {
                        "type": "string",
                        "description": "Content to write"
                    },
                    "append": {
                        "type": "boolean",
                        "description": "Append instead of overwrite",
                        "default": False
                    }
                },
                "required": ["path", "content"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "edit_file",
            "description": "Edit a file — replace old_string with new_string. Safer than write_file.",
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Absolute path to file"
                    },
                    "old_string": {
                        "type": "string",
                        "description": "Text to find (must be unique in file)"
                    },
                    "new_string": {
                        "type": "string",
                        "description": "Replacement text"
                    }
                },
                "required": ["path", "old_string", "new_string"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "grep_search",
            "description": "Search files by regex pattern. Returns matching lines with filenames.",
            "parameters": {
                "type": "object",
                "properties": {
                    "pattern": {
                        "type": "string",
                        "description": "Regex pattern to search for"
                    },
                    "path": {
                        "type": "string",
                        "description": "Directory or file to search",
                        "default": "."
                    },
                    "glob": {
                        "type": "string",
                        "description": "File filter, e.g. '*.py', '*.js'",
                        "default": ""
                    },
                    "max_results": {
                        "type": "integer",
                        "description": "Result limit (default 50)",
                        "default": 50
                    }
                },
                "required": ["pattern"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "glob_find",
            "description": "Find files by glob pattern (e.g. '**/*.py', 'src/**/*.ts').",
            "parameters": {
                "type": "object",
                "properties": {
                    "pattern": {
                        "type": "string",
                        "description": "Glob pattern"
                    },
                    "path": {
                        "type": "string",
                        "description": "Base directory",
                        "default": "."
                    }
                },
                "required": ["pattern"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "list_dir",
            "description": "List directory contents.",
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Path to directory"
                    }
                },
                "required": ["path"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "cs_note",
            "description": "Save a note to Consciousness Server.",
            "parameters": {
                "type": "object",
                "properties": {
                    "content": {
                        "type": "string",
                        "description": "Note content"
                    },
                    "type": {
                        "type": "string",
                        "description": "Type: observation | decision | blocker | idea | handoff",
                        "default": "observation"
                    }
                },
                "required": ["content"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "cs_task",
            "description": "Create a task in Consciousness Server and assign to an agent.",
            "parameters": {
                "type": "object",
                "properties": {
                    "title": {
                        "type": "string",
                        "description": "Task title"
                    },
                    "assigned_to": {
                        "type": "string",
                        "description": "Agent name to assign to"
                    },
                    "priority": {
                        "type": "string",
                        "description": "LOW | MEDIUM | HIGH | CRITICAL",
                        "default": "MEDIUM"
                    },
                    "description": {
                        "type": "string",
                        "description": "Task description"
                    }
                },
                "required": ["title", "assigned_to"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "cs_briefing",
            "description": "Get briefing from Consciousness Server — what happened recently.",
            "parameters": {
                "type": "object",
                "properties": {
                    "hours": {
                        "type": "integer",
                        "description": "Hours to look back (default 24)",
                        "default": 24
                    }
                }
            }
        }
    }
]

# ─── TOOL EXECUTION ──────────────────────────────────────────────────────────
# Map plugin tool names to their plugin for dispatch
_PLUGIN_TOOL_MAP = {}  # tool_name -> plugin_name


def _rebuild_plugin_tool_map():
    """Rebuild the mapping from tool name to plugin name."""
    _PLUGIN_TOOL_MAP.clear()
    for pname, mod in PLUGINS.items():
        for t in getattr(mod, "PLUGIN_TOOLS", []):
            tname = t.get("function", {}).get("name", "")
            if tname:
                _PLUGIN_TOOL_MAP[tname] = pname


def execute_tool(name: str, args: dict) -> str:
    try:
        if name == "bash":
            cmd     = args["command"]
            timeout = args.get("timeout", 30)
            result  = subprocess.run(
                cmd, shell=True, capture_output=True,
                text=True, timeout=timeout,
                executable=_BASH_PATH
            )
            out = result.stdout.strip()
            err = result.stderr.strip()
            if result.returncode != 0:
                return f"[exit {result.returncode}]\nstdout: {out}\nstderr: {err}"
            return out or "(no output)"

        elif name == "read_file":
            path   = Path(args["path"])
            offset = args.get("offset", 0)
            limit  = args.get("limit", 200)
            if not path.exists():
                return f"File not found: {path}"
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
            total = len(lines)
            selected = lines[offset:offset + limit]
            numbered = [f"{i+offset+1}\t{line}" for i, line in enumerate(selected)]
            result = "\n".join(numbered)
            if offset + limit < total:
                result += f"\n... [{total - offset - limit} lines omitted, total: {total}]"
            return result

        elif name == "write_file":
            path    = Path(args["path"])
            content = args["content"]
            append  = args.get("append", False)
            path.parent.mkdir(parents=True, exist_ok=True)
            mode = "a" if append else "w"
            with path.open(mode, encoding="utf-8") as f:
                f.write(content)
            return f"OK — wrote {len(content)} chars to {path}"

        elif name == "edit_file":
            path       = Path(args["path"])
            old_string = args["old_string"]
            new_string = args["new_string"]
            if not path.exists():
                return f"File not found: {path}"
            text = path.read_text(encoding="utf-8", errors="replace")
            count = text.count(old_string)
            if count == 0:
                return f"old_string not found in {path}"
            if count > 1:
                return f"old_string found {count}x — must be unique. Provide more context."
            new_text = text.replace(old_string, new_string, 1)
            path.write_text(new_text, encoding="utf-8")
            return f"OK — edited {path} (replaced 1 occurrence)"

        elif name == "grep_search":
            pattern     = args["pattern"]
            search_path = args.get("path", ".")
            file_glob   = args.get("glob", "")
            max_results = args.get("max_results", 50)

            cmd_parts = ["grep", "-rn", "--color=never"]
            if file_glob:
                cmd_parts.extend(["--include", file_glob])
            cmd_parts.extend([pattern, search_path])

            result = subprocess.run(
                cmd_parts, capture_output=True, text=True, timeout=15
            )
            # grep exit codes: 0 = match found, 1 = no match, >=2 = error
            if result.returncode >= 2:
                return f"grep error: {result.stderr.strip() or 'unknown error'}"
            lines = result.stdout.strip().splitlines()
            if len(lines) > max_results:
                lines = lines[:max_results]
                lines.append(f"... [truncated to {max_results} results]")
            return "\n".join(lines) or "(no results)"

        elif name == "glob_find":
            pattern   = args["pattern"]
            base_path = args.get("path", ".")
            full_pattern = str(Path(base_path) / pattern)
            matches = sorted(glob_module.glob(full_pattern, recursive=True))
            if not matches:
                return "(no results)"
            if len(matches) > 100:
                matches = matches[:100]
                matches.append(f"... [truncated to 100 results]")
            return "\n".join(matches)

        elif name == "list_dir":
            path = Path(args["path"])
            if not path.exists():
                return f"Directory not found: {path}"
            if not path.is_dir():
                return f"Not a directory: {path} (use read_file for files)"
            items = sorted(path.iterdir(), key=lambda p: (p.is_file(), p.name))
            lines = []
            for item in items:
                if item.is_dir():
                    lines.append(f"  d {item.name}/")
                else:
                    size = item.stat().st_size
                    lines.append(f"  f {item.name} ({size:,} B)")
            return "\n".join(lines) or "(empty directory)"

        elif name == "cs_note":
            if not CS_URL:
                return "Consciousness Server not configured (set CS_URL)"
            r = requests.post(f"{CS_URL}/api/notes", json={
                "agent":   AGENT_NAME,
                "content": args["content"],
                "type":    args.get("type", "observation")
            }, timeout=5)
            if r.ok:
                return f"Note saved (id: {r.json().get('id', '?')})"
            return f"CS error: {r.status_code} {r.text[:200]}"

        elif name == "cs_task":
            if not CS_URL:
                return "Consciousness Server not configured (set CS_URL)"
            r = requests.post(f"{CS_URL}/api/tasks", json={
                "title":       args["title"],
                "assigned_to": args["assigned_to"],
                "priority":    args.get("priority", "MEDIUM"),
                "description": args.get("description", ""),
                "created_by":  AGENT_NAME,
                "project":     "cortex"
            }, timeout=5)
            if r.ok:
                return f"Task created (id: {r.json().get('id', '?')})"
            return f"CS error: {r.status_code} {r.text[:200]}"

        elif name == "cs_briefing":
            if not CS_URL:
                return "Consciousness Server not configured (set CS_URL)"
            hours = args.get("hours", 24)
            r = requests.get(
                f"{CS_URL}/api/agents/{AGENT_NAME}/briefing",
                params={"hours": hours}, timeout=5
            )
            if r.ok:
                data = r.json()
                return json.dumps(data, ensure_ascii=False, indent=2)
            return f"CS unavailable: {r.status_code}"

        else:
            # check plugins
            plugin_name = _PLUGIN_TOOL_MAP.get(name)
            if plugin_name:
                return execute_plugin_tool(plugin_name, name, args)
            return f"Unknown tool: {name}"

    except subprocess.TimeoutExpired:
        return f"Timeout — command '{args.get('command', name)}' exceeded {args.get('timeout', 30)}s."
    except requests.exceptions.ConnectionError:
        return f"Consciousness Server unavailable ({CS_URL})"
    except Exception as e:
        return f"Tool error {name}: {e}"

# ─── MODEL CALLS ───────────────────────────────────────────────────────────────
def call_ollama(messages: list, tools: list, stream_cb=None, thinking_cb=None) -> dict:
    """Call model via Ollama API with tool calling."""
    payload = {
        "model":    OLLAMA_MODEL,
        "messages": messages,
        "tools":    tools,
        "stream":   stream_cb is not None,
        "think":    THINK_MODE,
        "options": {
            "temperature": 0.7,
            "num_ctx":     int(os.getenv("NUM_CTX", "32768")),
        }
    }

    r = requests.post(
        f"{OLLAMA_URL}/api/chat",
        json=payload,
        stream=stream_cb is not None,
        timeout=300
    )

    # fallback: if model doesn't support tools, retry without them
    if r.status_code == 400 and "tools" in payload:
        log.warning(f"Model {OLLAMA_MODEL} doesn't support tool calling — chat-only mode")
        payload.pop("tools")
        r = requests.post(
            f"{OLLAMA_URL}/api/chat",
            json=payload,
            stream=stream_cb is not None,
            timeout=300
        )

    r.raise_for_status()

    if stream_cb is not None:
        full_content = ""
        tool_calls   = []
        in_thinking  = True
        try:
            for line in r.iter_lines():
                if not line:
                    continue
                chunk = json.loads(line)
                msg   = chunk.get("message", {})

                # thinking tokens
                thinking_delta = msg.get("thinking", "")
                if thinking_delta and thinking_cb:
                    thinking_cb(thinking_delta)

                delta = msg.get("content", "")
                if delta:
                    if in_thinking and thinking_cb:
                        in_thinking = False
                    stream_cb(delta)
                    full_content += delta
                if msg.get("tool_calls"):
                    tool_calls.extend(msg["tool_calls"])
                if chunk.get("done"):
                    break
        except KeyboardInterrupt:
            r.close()
            raise
        return {"message": {"content": full_content, "tool_calls": tool_calls}}
    else:
        return r.json()


def call_anthropic(messages: list, tools: list = None, **kwargs) -> dict:
    """Fallback: Anthropic Claude API."""
    import anthropic
    client = anthropic.Anthropic(api_key=ANTHROPIC_KEY)
    system_msg = next(
        (m["content"] for m in messages if m["role"] == "system"), ""
    )
    user_msgs = [m for m in messages if m["role"] != "system"]

    active_tools = tools or TOOLS
    anthropic_tools = []
    for t in active_tools:
        f = t["function"]
        anthropic_tools.append({
            "name":         f["name"],
            "description":  f["description"],
            "input_schema": f["parameters"]
        })

    resp = client.messages.create(
        model="claude-sonnet-4-20250514",
        max_tokens=4096,
        system=system_msg,
        messages=user_msgs,
        tools=anthropic_tools
    )
    content = ""
    tool_calls = []
    for block in resp.content:
        if block.type == "text":
            content += block.text
        elif block.type == "tool_use":
            tool_calls.append({
                "function": {"name": block.name, "arguments": json.dumps(block.input)}
            })
    return {"message": {"content": content, "tool_calls": tool_calls}}


def call_model(messages: list, tools: list, stream_cb=None, thinking_cb=None) -> dict:
    if USE_ANTHROPIC and ANTHROPIC_KEY:
        return call_anthropic(messages, tools)
    return call_ollama(messages, tools, stream_cb, thinking_cb=thinking_cb)

# ─── SPINNER ──────────────────────────────────────────────────────────────────
class Spinner:
    """Animated spinner for CLI — shows that agent is thinking."""
    FRAMES = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]

    def __init__(self, label="thinking"):
        self.label = label
        self._stop = threading.Event()
        self._thread = None

    def start(self):
        self._stop.clear()
        self._thread = threading.Thread(target=self._spin, daemon=True)
        self._thread.start()

    def _spin(self):
        frames = itertools.cycle(self.FRAMES)
        while not self._stop.is_set():
            frame = next(frames)
            print(f"\r{C.CYAN}{frame}{C.RESET} {C.DIM}{self.label}...{C.RESET}  ", end="", flush=True)
            time.sleep(0.1)

    def stop(self):
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=1)
        print(f"\r{' ' * 40}\r", end="", flush=True)

# ─── AGENT LOOP ────────────────────────────────────────────────────────────────
def agent_loop(messages: list, session_id: str, policy: PolicyEngine,
               recovery: RecoveryEngine, active_tools: list) -> str:
    """Main agent loop — model -> policy check -> tools -> recovery -> model -> ..."""
    loop_count = 0

    while loop_count < MAX_TOOL_LOOPS:
        loop_count += 1

        # ── context compression ──
        if should_compact(messages, CONTEXT_MAX_TOKENS):
            print(f"\n{C.DIM}[context compression: {estimate_tokens(messages)} tokens]{C.RESET}")
            messages[:] = compact_messages(
                messages, OLLAMA_URL, OLLAMA_MODEL,
                keep_last=6, max_tokens=CONTEXT_MAX_TOKENS
            )

        # ── call model with recovery ──
        spinner = Spinner("thinking" if loop_count == 1 else "analyzing")
        spinner.start()
        first_token = True
        thinking_shown = False

        def thinking_cb(delta):
            nonlocal first_token, thinking_shown
            if first_token:
                spinner.stop()
                first_token = False
            if not thinking_shown:
                print(f"{C.DIM}💭 ", end="", flush=True)
                thinking_shown = True
            print(f"{delta}", end="", flush=True)

        def stream_cb(delta):
            nonlocal first_token, thinking_shown
            if first_token:
                spinner.stop()
                first_token = False
            if thinking_shown:
                print(f"{C.RESET}\n", end="", flush=True)
                thinking_shown = False
            print(f"{C.WHITE}{delta}", end="", flush=True)

        try:
            response, messages[:] = recovery.handle_api_call(
                lambda msgs, **kw: call_model(msgs, active_tools, stream_cb=stream_cb, thinking_cb=thinking_cb),
                messages,
                error_type="api_error"
            )
        except KeyboardInterrupt:
            spinner.stop()
            print(f"\n{C.AMBER}[interrupted]{C.RESET}")
            raise

        if first_token:
            spinner.stop()

        if response is None:
            return f"{C.RED}[error: model unavailable after retry]{C.RESET}"

        msg     = response.get("message", {})
        content = msg.get("content", "")
        tc_list = msg.get("tool_calls", [])

        if not tc_list:
            print(C.RESET, end="", flush=True)
            if not content:
                content = "(no response)"
            messages.append({"role": "assistant", "content": content})
            return content

        # model wants to call tools
        print(C.RESET)
        messages.append({
            "role":       "assistant",
            "content":    content,
            "tool_calls": tc_list
        })

        # ── execute tool calls with policy check ──
        tool_results = []
        for tc in tc_list:
            fn   = tc.get("function", {})
            name = fn.get("name", "")
            raw_args = fn.get("arguments", {})
            if isinstance(raw_args, dict):
                args = raw_args
            else:
                try:
                    args = json.loads(raw_args)
                except (json.JSONDecodeError, TypeError):
                    args = {}

            # ── POLICY CHECK ──
            decision, reason = policy.check(name, args)

            if decision == PolicyDecision.DENY:
                print(f"\n{C.RED}[DENY]{C.RESET} {C.BOLD}{name}{C.RESET}: {C.DIM}{reason}{C.RESET}")
                tool_results.append({
                    "role": "tool",
                    "content": f"[BLOCKED by Policy Engine] {reason}",
                    "name": name
                })
                continue

            if decision == PolicyDecision.ASK:
                prompt_text = policy.format_ask_prompt(name, args, reason)
                print(f"\n{C.AMBER}{prompt_text}{C.RESET}", end="")
                try:
                    answer = input().strip().lower()
                except (EOFError, KeyboardInterrupt):
                    answer = "n"

                if answer not in ("t", "y", "tak", "yes", "zawsze", "always"):
                    print(f"  {C.RED}Rejected by user{C.RESET}")
                    tool_results.append({
                        "role": "tool",
                        "content": "[REJECTED by user]",
                        "name": name
                    })
                    continue

            # ── EXECUTE ──
            print(f"\n{C.AMBER}▶ {name}{C.RESET} ", end="")
            if name == "bash":
                print(f"{C.DIM}{args.get('command', '')[:80]}{C.RESET}")
            elif name in ("read_file", "write_file", "edit_file", "list_dir"):
                print(f"{C.DIM}{args.get('path', '')}{C.RESET}")
            elif name == "grep_search":
                print(f"{C.DIM}{args.get('pattern', '')} in {args.get('path', '.')}{C.RESET}")
            elif name == "glob_find":
                print(f"{C.DIM}{args.get('pattern', '')} in {args.get('path', '.')}{C.RESET}")
            else:
                print(f"{C.DIM}{json.dumps(args)[:60]}{C.RESET}")

            try:
                result = execute_tool(name, args)
            except KeyboardInterrupt:
                result = "[interrupted by user]"
                print(f"\n  {C.AMBER}[interrupted]{C.RESET}")
                tool_results.append({"role": "tool", "content": result, "name": name})
                messages.extend(tool_results)
                raise

            # ── recovery on tool error ──
            if result.startswith("Tool error") or result.startswith("Timeout"):
                action, msg_text = recovery.handle_tool_error(name, args, result)
                if action == RecoveryAction.RETRY:
                    print(f"  {C.AMBER}[retry]{C.RESET}")
                    result = execute_tool(name, args)
                elif action == RecoveryAction.SKIP:
                    print(f"  {C.RED}[skip]{C.RESET}")

            # show truncated result
            preview = result[:150].replace("\n", " ")
            print(f"  {C.GREEN}->{C.RESET} {C.DIM}{preview}{'...' if len(result)>150 else ''}{C.RESET}")

            tool_results.append({
                "role":    "tool",
                "content": result,
                "name":    name
            })

        messages.extend(tool_results)

    return "(tool call loop limit exceeded)"

# ─── SESSION MANAGEMENT ────────────────────────────────────────────────────────
def save_session_to_cs(session_id: str, messages: list):
    """Save session to Consciousness Server."""
    if not CS_URL:
        return
    try:
        conv = [m for m in messages if m.get("role") != "system"]
        requests.post(f"{CS_URL}/api/memory/conversations", json={
            "agent":      AGENT_NAME,
            "session_id": session_id,
            "messages":   conv,
            "timestamp":  datetime.datetime.now().isoformat()
        }, timeout=5)
    except Exception:
        pass

def get_briefing() -> str:
    """Get briefing from CS at session start."""
    if not CS_URL:
        return ""
    try:
        r = requests.get(
            f"{CS_URL}/api/agents/{AGENT_NAME}/briefing",
            params={"hours": 24}, timeout=3
        )
        if r.ok:
            data = r.json()
            if data:
                return json.dumps(data, ensure_ascii=False)
    except Exception:
        pass
    return ""

# ─── SYSTEM PROMPT ─────────────────────────────────────────────────────────────
def build_system_prompt(briefing: str, plugin_info: str = "") -> str:
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
    hostname = socket.gethostname()
    cs_info = f"Consciousness Server: {CS_URL}" if CS_URL else ""
    return f"""You are Cortex — a local AI agent with system access.

Date/time: {now}
Host: {hostname}
Model: {OLLAMA_MODEL}

Available tools:
- bash: execute shell commands
- read_file: read files (with line numbers)
- write_file: write/create files
- edit_file: replace a string in a file (safer than write_file)
- grep_search: search files by regex pattern
- glob_find: find files by glob pattern
- list_dir: list directory contents
- cs_note, cs_task, cs_briefing: Consciousness Server (optional)
{cs_info}
{plugin_info}

Policy Engine protects against dangerous operations:
- DENY: rm -rf, mkfs, dd, fork bomb, chmod 777, curl|bash, shutdown, reboot
- ASK (requires user confirmation): sudo, apt install, pip install, git push --force, kill
- ALLOW: ls, cat, grep, git status/log/diff, ps, python3, node

Rules:
1. EXECUTE FIRST, EXPLAIN AFTER. Do NOT describe what you plan to do — just do it. Call tools immediately. Keep explanations short, after the results.
2. Use tools when the task requires real actions on the system
3. edit_file is safer than write_file for modifying existing files
4. grep_search instead of bash("grep ...") — faster and safer
5. Read a file before editing it
6. Be concise — don't repeat the user's question, answer directly. No filler, no preamble.
7. IMPORTANT: To open files in GUI apps, ALWAYS use: bash("xdg-open /path/to/file &") or bash("typora /path/to/file &"). The '&' is REQUIRED — without it the command will timeout.
8. If a tool returns Timeout, briefly acknowledge it and move on.
9. To list available LLM models, use: bash("ollama list"). Models are managed by Ollama at {OLLAMA_URL}.
10. When given a complex task with multiple steps, execute all steps sequentially using tools. Do NOT stop to ask "should I continue?" — just do it all.
11. When writing reports, include ACTUAL data from tool outputs, not speculation.
12. ZERO HALLUCINATION POLICY: NEVER invent data you did not obtain from a tool call. If you don't know something — run a command to find out. "I don't have this data" is ALWAYS better than a made-up answer.

Respond in the user's language. Be specific and technical.
{"" if not briefing else f"Recent briefing:{chr(10)}{briefing[:800]}"}"""


# ─── PRINT HELPERS ─────────────────────────────────────────────────────────────
ACTIVE_PLUGIN = None  # currently active plugin name (or None for default mode)

def print_banner():
    plugin_str = f"  {C.PURPLE}{ACTIVE_PLUGIN}{C.RESET}  " if ACTIVE_PLUGIN else ""
    print(f"""
{C.BLUE}+==========================================+{C.RESET}
{C.BLUE}|{C.RESET}  {C.BOLD}{C.CYAN}CORTEX{C.RESET}{plugin_str}  {C.DIM}|{C.RESET}  {C.GREEN}{OLLAMA_MODEL}{C.RESET}    {C.BLUE}|{C.RESET}
{C.BLUE}|{C.RESET}  {C.DIM}Local AI Agent{C.RESET}                            {C.BLUE}|{C.RESET}
{C.BLUE}+==========================================+{C.RESET}
{C.DIM}Type /help for commands{C.RESET}
""")

def print_help():
    cmds = [
        ("/help",     "Show this help"),
        ("/exit",     "Save session and exit"),
        ("/clear",    "Clear conversation history"),
        ("/compact",  "Force context compression now"),
        ("/model",    "Show current model and available models"),
        ("/model X",  "Switch to model X"),
        ("/policy",   "Show active policy rules"),
        ("/tokens",   "Show token estimate and context stats"),
        ("/think",    "Toggle thinking mode"),
        ("/status",   "Show agent status (model, CS, tools, plugins)"),
        ("/briefing", "Get briefing from Consciousness Server"),
        ("/rewind",   "Rewind conversation (or press Esc+Esc)"),
        ("/plugins",  "List available plugins"),
    ]
    for cmd, desc in cmds:
        print(f"  {C.AMBER}{cmd:<12}{C.RESET} {C.DIM}{desc}{C.RESET}")

# ─── MAIN ──────────────────────────────────────────────────────────────────────
def main():
    global THINK_MODE, USE_ANTHROPIC, OLLAMA_MODEL, ACTIVE_PLUGIN, TOOLS, PLUGINS

    # parse args
    import argparse
    parser = argparse.ArgumentParser(description="Cortex Agent", add_help=False)
    parser.add_argument("--mode", type=str, default="default",
                        help="Plugin mode to activate (e.g. --mode sec)")
    parser.add_argument("--plugin-dir", type=str, default=None,
                        help="Custom plugin directory (default: ./plugins/)")
    known_args, _ = parser.parse_known_args()

    # ── discover plugins ──
    plugin_dir = Path(known_args.plugin_dir) if known_args.plugin_dir else None
    PLUGINS = discover_plugins(plugin_dir)

    if PLUGINS:
        print(f"\n  {C.GREEN}+{C.RESET} Plugins: {', '.join(PLUGINS.keys())}")

    # ── activate plugin mode ──
    active_tools = list(TOOLS)
    plugin_prompt_extra = ""

    if known_args.mode != "default":
        mode = known_args.mode
        if mode in PLUGINS:
            ACTIVE_PLUGIN = mode
            mod = PLUGINS[mode]
            plugin_tools = getattr(mod, "PLUGIN_TOOLS", [])
            active_tools = TOOLS + plugin_tools
            _rebuild_plugin_tool_map()

            # call on_activate if exists
            if hasattr(mod, "on_activate"):
                try:
                    config = {
                        "ollama_url": OLLAMA_URL,
                        "ollama_model": OLLAMA_MODEL,
                        "cs_url": CS_URL,
                        "agent_name": AGENT_NAME,
                    }
                    mod.on_activate(config)
                except Exception as e:
                    print(f"  {C.AMBER}Plugin {mode} activate warning: {e}{C.RESET}")

            # get plugin prompt addition
            if hasattr(mod, "build_prompt"):
                plugin_prompt_extra = mod.build_prompt("")

            print(f"  {C.PURPLE}▶ Plugin '{mode}' activated ({len(plugin_tools)} tools){C.RESET}")
        else:
            print(f"  {C.RED}Plugin '{mode}' not found{C.RESET}")
            if PLUGINS:
                print(f"  Available: {', '.join(PLUGINS.keys())}")
            sys.exit(1)

    print_banner()

    # ── init modules ──
    policy = PolicyEngine(policy_file=POLICY_FILE or None)
    print(f"  {C.GREEN}+{C.RESET} Policy Engine loaded ({len(policy.policies)} tools)")

    def alert_fn(error_type, message):
        if not CS_URL:
            return
        try:
            requests.post(f"{CS_URL}/api/notes", json={
                "agent": AGENT_NAME,
                "type": "blocker",
                "content": f"[{error_type}] {message}"
            }, timeout=3)
        except Exception:
            pass

    def compact_fn(msgs):
        return compact_messages(msgs, OLLAMA_URL, OLLAMA_MODEL, keep_last=6, max_tokens=CONTEXT_MAX_TOKENS)

    fallback_fn = call_anthropic if ANTHROPIC_KEY else None
    recovery = RecoveryEngine(
        fallback_fn=fallback_fn,
        compact_fn=compact_fn,
        alert_fn=alert_fn
    )
    print(f"  {C.GREEN}+{C.RESET} Recovery Engine (fallback: {'Anthropic' if fallback_fn else 'none'})")
    print(f"  {C.GREEN}+{C.RESET} Context Compactor (limit: {CONTEXT_MAX_TOKENS} tokens)")

    # ── briefing ──
    briefing = get_briefing()
    if briefing:
        print(f"  {C.GREEN}+{C.RESET} Briefing from Consciousness Server loaded\n")
    else:
        cs_status = "not configured" if not CS_URL else "unavailable or no briefing"
        print(f"  {C.DIM}-{C.RESET} CS {cs_status}\n")

    session_id = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

    # Helper to build the full system prompt.
    # Plugin prompts EXTEND the base prompt — they cannot replace the safety rules.
    def _full_prompt(b: str = "") -> str:
        base = build_system_prompt(b, "")
        if ACTIVE_PLUGIN and plugin_prompt_extra:
            return f"{base}\n\n# Plugin: {ACTIVE_PLUGIN}\n{plugin_prompt_extra}"
        return base

    sys_prompt = _full_prompt(briefing)
    messages = [{"role": "system", "content": sys_prompt}]

    # readline history + tab completion
    history_file = Path.home() / ".cortex_history"
    try:
        readline.read_history_file(history_file)
    except FileNotFoundError:
        pass
    readline.set_history_length(500)

    SLASH_COMMANDS = [
        "/help", "/exit", "/clear", "/compact", "/model",
        "/policy", "/tokens", "/think", "/status", "/briefing",
        "/rewind", "/plugins",
    ]

    def completer(text, state):
        if text.startswith("/"):
            matches = [c for c in SLASH_COMMANDS if c.startswith(text)]
        else:
            matches = []
        return matches[state] if state < len(matches) else None

    readline.set_completer(completer)
    readline.set_completer_delims(" \t\n")
    readline.parse_and_bind("tab: complete")
    readline.parse_and_bind("set horizontal-scroll-mode off")
    readline.parse_and_bind("set enable-bracketed-paste on")
    readline.parse_and_bind(r'"\e\e": "\C-a\C-k/rewind\C-m"')

    # ── rewind ──
    def do_rewind(messages):
        user_turns = []
        for i, m in enumerate(messages):
            if m["role"] == "user":
                preview = m["content"][:70].replace("\n", " ")
                user_turns.append((i, preview))

        if not user_turns:
            print(f"  {C.DIM}No history to rewind{C.RESET}")
            return

        print(f"\n  {C.BOLD}Rewind — go back to a previous point:{C.RESET}")
        shown = user_turns[-10:]
        for idx, (msg_idx, preview) in enumerate(shown):
            num = idx + 1
            print(f"  {C.AMBER}{num:>2}{C.RESET}  {C.DIM}{preview}{'...' if len(preview)>=70 else ''}{C.RESET}")
        print(f"  {C.DIM} 0  (cancel){C.RESET}")

        try:
            choice = input(f"\n  {C.GREEN}Rewind to #:{C.RESET} ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return

        if not choice or choice == "0":
            print(f"  {C.DIM}Cancelled{C.RESET}")
            return

        try:
            pick = int(choice)
            if 1 <= pick <= len(shown):
                # Truncate AFTER the selected user message (keep that message,
                # drop everything after it — including its assistant reply)
                target_msg_idx = shown[pick - 1][0]
                messages[:] = messages[:target_msg_idx + 1]
                print(f"  {C.GREEN}+{C.RESET} Rewound. Continue from this point.")
            else:
                print(f"  {C.RED}Invalid number{C.RESET}")
        except ValueError:
            print(f"  {C.RED}Invalid choice{C.RESET}")

    try:
        while True:
            try:
                rl = C.rl
                prompt = f"\n{rl(C.BOLD)}{rl(C.GREEN)}>{rl(C.RESET)} "
                user_input = input(prompt).strip()
            except EOFError:
                print(f"\n{C.DIM}Session ended.{C.RESET}")
                break
            except KeyboardInterrupt:
                print()
                continue

            if not user_input:
                continue

            if user_input == "/rewind":
                do_rewind(messages)
                continue

            if user_input == "/":
                print_help()
                continue

            if user_input == "/exit":
                print(f"{C.DIM}Saving session...{C.RESET}")
                save_session_to_cs(session_id, messages)
                print(f"{C.GREEN}+{C.RESET} Goodbye!")
                break

            elif user_input == "/help":
                print_help()
                continue

            elif user_input == "/plugins":
                if not PLUGINS:
                    print(f"  {C.DIM}No plugins found in plugins/ directory{C.RESET}")
                    print(f"  {C.DIM}See README.md for how to create plugins{C.RESET}")
                else:
                    for pname, mod in PLUGINS.items():
                        desc = getattr(mod, "PLUGIN_DESCRIPTION", "")
                        tools_count = len(getattr(mod, "PLUGIN_TOOLS", []))
                        active = " (active)" if pname == ACTIVE_PLUGIN else ""
                        print(f"  {C.PURPLE}{pname}{C.RESET} — {tools_count} tools{C.GREEN}{active}{C.RESET}")
                        if desc:
                            print(f"    {C.DIM}{desc}{C.RESET}")
                continue

            elif user_input.startswith("/model"):
                parts = user_input.split(maxsplit=1)
                if len(parts) > 1:
                    new_model = parts[1].strip()
                    try:
                        r = requests.get(f"{OLLAMA_URL}/api/tags", timeout=5)
                        available = [m["name"] for m in r.json().get("models", [])]
                        if new_model in available:
                            OLLAMA_MODEL = new_model
                            print(f"  {C.GREEN}+{C.RESET} Model: {C.PURPLE}{OLLAMA_MODEL}{C.RESET}")
                        else:
                            matches = [a for a in available if new_model in a]
                            if len(matches) == 1:
                                OLLAMA_MODEL = matches[0]
                                print(f"  {C.GREEN}+{C.RESET} Model: {C.PURPLE}{OLLAMA_MODEL}{C.RESET}")
                            elif len(matches) > 1:
                                print(f"  {C.AMBER}Multiple matches:{C.RESET}")
                                for m in matches:
                                    print(f"    {C.DIM}{m}{C.RESET}")
                            else:
                                print(f"  {C.RED}Model '{new_model}' not found{C.RESET}")
                                print(f"  Available: {', '.join(available)}")
                    except Exception:
                        OLLAMA_MODEL = new_model
                        print(f"  Model: {C.PURPLE}{OLLAMA_MODEL}{C.RESET} (not verified)")
                else:
                    m = "Anthropic Claude" if USE_ANTHROPIC else OLLAMA_MODEL
                    print(f"  Current: {C.PURPLE}{m}{C.RESET}")
                    try:
                        r = requests.get(f"{OLLAMA_URL}/api/tags", timeout=5)
                        models = [m["name"] for m in r.json().get("models", [])]
                        print(f"  Available: {C.DIM}{', '.join(models)}{C.RESET}")
                        print(f"  Switch: {C.AMBER}/model name{C.RESET}")
                    except Exception:
                        pass
                continue

            elif user_input == "/think":
                THINK_MODE = not THINK_MODE
                state = f"{C.GREEN}ON{C.RESET}" if THINK_MODE else f"{C.RED}OFF{C.RESET}"
                print(f"  Thinking mode: {state}")
                messages[0]["content"] = _full_prompt(briefing)
                continue

            elif user_input == "/briefing":
                result = execute_tool("cs_briefing", {"hours": 24})
                print(f"{C.DIM}{result[:600]}{C.RESET}")
                continue

            elif user_input == "/clear":
                messages = [{"role": "system", "content": _full_prompt(briefing)}]
                recovery.reset()
                print(f"  {C.GREEN}+{C.RESET} History cleared")
                continue

            elif user_input == "/policy":
                for tool_name, rules in policy.policies.items():
                    deny_count = len(rules.get("deny", []))
                    ask_count  = len(rules.get("ask", []))
                    allow_count = len(rules.get("allow", []))
                    print(f"  {C.CYAN}{tool_name:<15}{C.RESET} deny:{C.RED}{deny_count}{C.RESET} ask:{C.AMBER}{ask_count}{C.RESET} allow:{C.GREEN}{allow_count}{C.RESET}")
                continue

            elif user_input == "/tokens":
                tokens = estimate_tokens(messages)
                msg_count = len(messages)
                print(f"  Tokens:  ~{tokens}")
                print(f"  Messages: {msg_count}")
                print(f"  Compress: at {CONTEXT_MAX_TOKENS} tokens")
                print(f"  num_ctx:  {os.getenv('NUM_CTX', '32768')}")
                continue

            elif user_input == "/compact":
                before = estimate_tokens(messages)
                messages[:] = compact_messages(
                    messages, OLLAMA_URL, OLLAMA_MODEL,
                    keep_last=6, max_tokens=CONTEXT_MAX_TOKENS
                )
                after = estimate_tokens(messages)
                print(f"  {C.GREEN}+{C.RESET} Compressed: {before} -> {after} tokens")
                continue

            elif user_input == "/status":
                m = "Anthropic Claude" if USE_ANTHROPIC else OLLAMA_MODEL
                print(f"  Model:    {C.PURPLE}{m}{C.RESET}")
                print(f"  Ollama:   {C.DIM}{OLLAMA_URL}{C.RESET}")
                try:
                    r = requests.get(f"{OLLAMA_URL}/api/tags", timeout=3)
                    models = [m["name"] for m in r.json().get("models", [])]
                    print(f"  Models:   {C.GREEN}{len(models)} available{C.RESET}")
                except Exception:
                    print(f"  Models:   {C.RED}offline{C.RESET}")
                if CS_URL:
                    try:
                        r = requests.get(f"{CS_URL}/health", timeout=3)
                        print(f"  CS:       {C.GREEN}online{C.RESET} ({CS_URL})")
                    except Exception:
                        print(f"  CS:       {C.RED}offline{C.RESET} ({CS_URL})")
                else:
                    print(f"  CS:       {C.DIM}not configured{C.RESET}")
                tokens = estimate_tokens(messages)
                print(f"  Context:  {tokens} tokens / {len(messages)} messages")
                print(f"  Tools:    {len(active_tools)}")
                print(f"  Policy:   {len(policy.policies)} rules")
                if PLUGINS:
                    print(f"  Plugins:  {', '.join(PLUGINS.keys())}")
                if ACTIVE_PLUGIN:
                    print(f"  Mode:     {C.PURPLE}{ACTIVE_PLUGIN}{C.RESET}")
                continue

            elif user_input.startswith("/"):
                print(f"  {C.RED}Unknown command.{C.RESET} Type /help")
                continue

            # normal message
            messages.append({"role": "user", "content": user_input})

            print()

            try:
                agent_loop(messages, session_id, policy, recovery, active_tools)
                print()
            except KeyboardInterrupt:
                print(f"\n{C.AMBER}[interrupted]{C.RESET}")
            except requests.exceptions.ConnectionError:
                print(f"\n{C.RED}x Ollama unavailable ({OLLAMA_URL}){C.RESET}")
                print(f"  Check: {C.DIM}systemctl status ollama{C.RESET}")
            except Exception as e:
                print(f"\n{C.RED}x Error: {e}{C.RESET}")

            # auto-save every message
            save_session_to_cs(session_id, messages)

    finally:
        # deactivate plugin
        if ACTIVE_PLUGIN and ACTIVE_PLUGIN in PLUGINS:
            mod = PLUGINS[ACTIVE_PLUGIN]
            if hasattr(mod, "on_deactivate"):
                try:
                    mod.on_deactivate()
                except Exception:
                    pass
        try:
            readline.write_history_file(history_file)
        except Exception:
            pass

if __name__ == "__main__":
    main()
