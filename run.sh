#!/bin/bash
# Cortex — launcher
# Usage:
#   ./run.sh agent    — interactive CLI
#   ./run.sh web      — Web UI (http://localhost:8080)
#   ./run.sh worker   — daemon (poll CS → execute → report)
#   ./run.sh worker --once  — one task and exit

set -e

DIR="$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)"
cd "$DIR"

# Venv
if [ ! -d "$DIR/venv" ]; then
    echo "Creating venv..."
    python3 -m venv "$DIR/venv"
    source "$DIR/venv/bin/activate"
    pip install -q fastapi uvicorn websockets requests
else
    source "$DIR/venv/bin/activate"
fi

# Auto-detect GPU
if nvidia-smi &>/dev/null; then
    export OLLAMA_MODEL="${OLLAMA_MODEL:-gemma4:26b}"
    echo "[GPU] Model: $OLLAMA_MODEL"
else
    export OLLAMA_MODEL="${OLLAMA_MODEL:-gemma4:e4b}"
    echo "[CPU] Model: $OLLAMA_MODEL"
fi

# CS URL — Consciousness Server (optional)
export CS_URL="${CS_URL:-}"

export AGENT_NAME="${AGENT_NAME:-cortex}"

# Check Ollama
if ! curl -sf http://localhost:11434/api/tags > /dev/null 2>&1; then
    echo "Ollama not running — start it: systemctl start ollama"
    exit 1
fi

MODE="${1:-agent}"
shift 2>/dev/null || true

case "$MODE" in
    agent|cli|chat)
        python3 "$DIR/agent.py" "$@"
        ;;
    web|ui)
        echo "Web UI: http://localhost:${WEB_PORT:-8080}"
        python3 "$DIR/web.py" "$@"
        ;;
    worker|daemon)
        python3 "$DIR/worker.py" "$@"
        ;;
    *)
        echo "Usage: $0 {agent|web|worker} [options]"
        echo ""
        echo "  agent         Interactive CLI (like Claude Code)"
        echo "  web           Web UI in browser"
        echo "  worker        Daemon — polls CS for tasks automatically"
        echo "  worker --once One task and exit"
        echo ""
        echo "Plugins:"
        echo "  agent --mode NAME   Activate a plugin (e.g. --mode sec)"
        echo "  Plugins are loaded from ./plugins/ directory"
        ;;
esac
