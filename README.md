# Cortex

[![License: AGPL v3](https://img.shields.io/badge/License-AGPL_v3-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)
[![Commercial License Available](https://img.shields.io/badge/Commercial_License-Available-green.svg)](LICENSE-COMMERCIAL.md)

Local AI agent with tool calling, powered by Ollama.

Like Claude Code or Cursor — but running entirely on your machine, with your own models, **fully open source forever**.

> **Why Cortex?** Unlike permissively-licensed alternatives, Cortex uses AGPLv3 — meaning every fork, every SaaS deployment, every modification stays open. Your investment in the project is protected: no corporation can absorb Cortex into a closed product. Improvements always flow back to the community.

## Features

- **10 tools**: bash, read/write/edit files, grep, glob, list_dir, and optional Consciousness Server integration
- **Policy Engine**: regex-based deny/ask/allow rules per tool (blocks `rm -rf`, asks before `sudo`)
- **Recovery Engine**: auto-retry on failures, optional fallback to Anthropic API
- **Context Compression**: auto-summarizes old messages when context gets too large
- **Worker mode**: autonomous task execution loop (poll server, execute, report results)
- **Web UI**: browser-based chat with WebSocket streaming
- **Model switching**: change models mid-conversation with `/model`
- **Plugin system**: extend Cortex with custom tools and modes

## Quick Start

```bash
# 1. Install Ollama (https://ollama.com)
curl -fsSL https://ollama.com/install.sh | sh

# 2. Pull a model with tool calling support
ollama pull gemma4:e4b    # 3 GB, fast on CPU
# or
ollama pull gemma4:26b    # 17 GB, needs GPU

# 3. Run Cortex
git clone https://github.com/tmaloziec/cortex.git
cd cortex
./run.sh agent            # Interactive CLI
./run.sh web              # Web UI at http://localhost:8080
./run.sh worker           # Autonomous task worker
```

`run.sh` auto-creates a Python venv and installs dependencies.

## Modes

| Mode | Command | Description |
|------|---------|-------------|
| **CLI** | `./run.sh agent` | Interactive terminal chat with tool calling |
| **Web** | `./run.sh web` | Browser UI with streaming at `http://localhost:8080` |
| **Worker** | `./run.sh worker` | Polls task server, executes tasks, reports results |
| **One-shot** | `./run.sh worker --once` | Execute one pending task and exit |
| **Plugin** | `./run.sh agent --mode NAME` | Activate a plugin by name |

## Commands

| Command | Description |
|---------|-------------|
| `/model` | Show current model and list available |
| `/model <name>` | Switch to a different Ollama model |
| `/policy` | Show active policy rules |
| `/tokens` | Show estimated token count |
| `/think` | Toggle thinking mode |
| `/clear` | Clear conversation history |
| `/status` | Show agent status (model, CS, tools, plugins) |
| `/plugins` | List available plugins |
| `/rewind` | Rewind conversation (or press Esc+Esc) |
| `/exit` | Save session and exit |

## Policy Engine

Cortex includes a rule-based policy engine that checks every tool call before execution:

- **DENY** (blocked silently): `rm -rf /`, `mkfs`, `dd`, fork bombs, `curl | bash`, `shutdown`
- **ASK** (requires user confirmation): `sudo`, `apt install`, `pip install`, `git push --force`, `kill`
- **ALLOW** (runs immediately): `ls`, `cat`, `grep`, `git status`, `ps`, `python3`

Custom rules can be added via a `policy.json` file.

## Security

Cortex is a **local, single-user AI agent**. It trusts the operator of the
machine, the local Ollama instance, and any plugin you load. Filesystem
and shell access are intentionally unsandboxed so the agent can do real
work on your behalf — think `bash`, not browser.

Before deploying outside a single-user workstation (shared host, exposed
network, untrusted plugins), read [SECURITY.md](SECURITY.md). It documents
the threat model, the design decisions that look like vulnerabilities but
aren't, and how to report real security issues.

## Plugins

Cortex supports plugins that add custom tools and modes. Plugins are Python files placed in the `plugins/` directory.

### Creating a Plugin

Create a file in `plugins/` (e.g. `plugins/my_plugin.py`):

```python
PLUGIN_NAME = "my-plugin"
PLUGIN_DESCRIPTION = "What my plugin does"

PLUGIN_TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "my_tool",
            "description": "Description of what my tool does",
            "parameters": {
                "type": "object",
                "properties": {
                    "input": {"type": "string", "description": "Input text"}
                },
                "required": ["input"]
            }
        }
    }
]


def execute_tool(name: str, args: dict) -> str:
    """Handle tool calls for this plugin."""
    if name == "my_tool":
        return f"Result: {args['input']}"
    return f"Unknown tool: {name}"


def build_prompt(briefing: str) -> str:
    """Optional: custom system prompt for this plugin mode."""
    return "You are Cortex with my-plugin capabilities..."


def on_activate(config: dict):
    """Optional: called when plugin mode starts."""
    print("My plugin activated!")


def on_deactivate():
    """Optional: called when plugin mode stops."""
    pass
```

### Using a Plugin

```bash
# Run Cortex with a plugin active
./run.sh agent --mode my-plugin

# List available plugins inside Cortex
/plugins
```

### Plugin API

Each plugin file can expose:

| Attribute | Required | Description |
|-----------|----------|-------------|
| `PLUGIN_NAME` | Yes | Unique plugin name |
| `PLUGIN_DESCRIPTION` | No | Short description |
| `PLUGIN_TOOLS` | Yes | List of tool definitions (Ollama format) |
| `execute_tool(name, args)` | Yes | Handle tool calls, return string result |
| `build_prompt(briefing)` | No | Custom system prompt for this mode |
| `on_activate(config)` | No | Initialization hook |
| `on_deactivate()` | No | Cleanup hook |

## Configuration

All settings via environment variables (see `.env.example`):

```bash
OLLAMA_URL=http://localhost:11434   # Ollama API endpoint
OLLAMA_MODEL=gemma4:e4b             # Default model
CS_URL=                             # Task server URL (optional)
ANTHROPIC_API_KEY=                  # Fallback API key (optional)
WEB_PORT=8080                       # Web UI port
AGENT_NAME=cortex                   # Agent identifier
```

## Architecture

```
cortex/
  agent.py       — CLI agent, 10 tools, model switching, plugin loader
  web.py         — Web UI (FastAPI + WebSocket)
  worker.py      — Autonomous worker daemon
  policy.py      — Policy Engine (deny/ask/allow)
  compactor.py   — Context compression
  recovery.py    — Retry + fallback logic
  run.sh         — Launcher (auto venv, GPU detection)
  plugins/       — Plugin directory (optional)
```

## Models

Any Ollama model with tool calling support works. Tested:

| Model | Size | Speed (CPU) | Speed (GPU) |
|-------|------|-------------|-------------|
| `gemma4:e4b` | 3 GB | ~16s | ~3s |
| `gemma4:26b` | 17 GB | slow | ~20s |
| `gemma4:31b` | 20 GB | very slow | ~25s |

## License

Cortex is **dual-licensed**:

- **[GNU Affero General Public License v3.0 (AGPLv3)](LICENSE)** — free for open source projects, personal use, and any deployment that complies with AGPLv3 terms (including making modifications and SaaS deployments source-available).

- **[Commercial License](LICENSE-COMMERCIAL.md)** — for organizations that need to use Cortex in proprietary products, closed-source SaaS, or where AGPLv3 is incompatible with their policies.

See [LICENSE-COMMERCIAL.md](LICENSE-COMMERCIAL.md) for when you need a commercial license and how to obtain one.

## Contributing

Contributions are welcome! Please read [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

All contributors must sign the [Contributor License Agreement (CLA)](CLA.md) before their Pull Requests can be merged. The [CLA Assistant bot](https://cla-assistant.io/) handles this automatically — one click on your first PR.
