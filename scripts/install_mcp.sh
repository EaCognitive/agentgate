#!/usr/bin/env bash
# ------------------------------------------------------------------
# AgentGate MCP Server Installer
#
# Supports both Claude Code and OpenAI Codex CLI.
#
# Usage:
#   ./scripts/install_mcp.sh                  # auto-detect CLI
#   ./scripts/install_mcp.sh --claude         # force Claude Code
#   ./scripts/install_mcp.sh --codex          # force Codex CLI
#   ./scripts/install_mcp.sh --user           # user scope
#   ./scripts/install_mcp.sh --remove         # uninstall
#
# Prerequisites: claude or codex CLI, uv, python 3.10+
# ------------------------------------------------------------------
set -euo pipefail

SCOPE="project"
REMOVE=false
CLI=""
SERVER_NAME="agentgate"
API_URL="${MCP_API_URL:-http://127.0.0.1:8000}"
DASHBOARD_URL="${AGENTGATE_DASHBOARD_URL:-http://127.0.0.1:3000}"

for arg in "$@"; do
    case "$arg" in
        --claude) CLI="claude" ;;
        --codex)  CLI="codex" ;;
        --user)   SCOPE="user" ;;
        --remove) REMOVE=true ;;
        --help|-h)
            echo "Usage: $0 [--claude|--codex] [--user] [--remove]"
            echo ""
            echo "  --claude  Install for Claude Code"
            echo "  --codex   Install for OpenAI Codex CLI"
            echo "  --user    Install for all projects (user scope)"
            echo "  --remove  Uninstall the MCP server"
            echo "  --help    Show this message"
            echo ""
            echo "If neither --claude nor --codex is given, the"
            echo "script auto-detects whichever CLI is installed."
            exit 0
            ;;
        *)
            echo "Unknown flag: $arg (use --help)"
            exit 1
            ;;
    esac
done

# -- Auto-detect CLI -------------------------------------------------
detect_cli() {
    if [ -n "$CLI" ]; then
        return
    fi
    if command -v claude &>/dev/null && command -v codex &>/dev/null; then
        echo "Both claude and codex CLIs detected."
        echo "Use --claude or --codex to choose. Defaulting to claude."
        CLI="claude"
        return
    fi
    if command -v claude &>/dev/null; then
        CLI="claude"
        return
    fi
    if command -v codex &>/dev/null; then
        CLI="codex"
        return
    fi
    echo "[x] No supported CLI found."
    echo ""
    echo "Install one of:"
    echo "  Claude Code:  npm i -g @anthropic-ai/claude-code"
    echo "  Codex CLI:    npm i -g @openai/codex"
    exit 1
}

detect_cli

# -- Helper: resolve .mcp.json path for Claude -----------------------
claude_mcp_json_path() {
    local script_dir project_dir
    script_dir="$(cd "$(dirname "$0")" && pwd)"
    project_dir="$(cd "$script_dir/.." && pwd)"

    if [ "$SCOPE" = "user" ]; then
        echo "$HOME/.claude/.mcp.json"
    else
        echo "$project_dir/.mcp.json"
    fi
}

# -- Uninstall -------------------------------------------------------
if [ "$REMOVE" = true ]; then
    echo "Removing AgentGate MCP server from $CLI..."
    if [ "$CLI" = "claude" ]; then
        MCP_JSON="$(claude_mcp_json_path)"
        if [ -f "$MCP_JSON" ]; then
            # Remove the agentgate key from .mcp.json using python
            python3 -c "
import json, sys
path = sys.argv[1]
name = sys.argv[2]
with open(path) as f:
    data = json.load(f)
servers = data.get('mcpServers', {})
if name in servers:
    del servers[name]
if not servers:
    import os; os.remove(path)
    print('Removed', path)
else:
    data['mcpServers'] = servers
    with open(path, 'w') as f:
        json.dump(data, f, indent=2)
        f.write('\n')
    print('Removed server entry from', path)
" "$MCP_JSON" "$SERVER_NAME"
            echo "Done. Restart $CLI to apply."
        else
            echo "Server '$SERVER_NAME' not found."
        fi
    else
        $CLI mcp remove "$SERVER_NAME" 2>/dev/null && \
            echo "Done. Restart $CLI to apply." || \
            echo "Server '$SERVER_NAME' not found."
    fi
    exit 0
fi

# -- Preflight checks ------------------------------------------------
echo "AgentGate MCP Installer"
echo "======================="
echo "Target: $CLI"
echo ""

fail=false

echo "[ok] $CLI CLI found"

if ! command -v uv &>/dev/null; then
    echo "[x] uv not found."
    echo "    Install: curl -LsSf https://astral.sh/uv/install.sh | sh"
    fail=true
else
    echo "[ok] uv found"
fi

PY_OK=$(python3 -c \
    "import sys; print(sys.version_info >= (3, 10))" \
    2>/dev/null || echo "False")
if [ "$PY_OK" != "True" ]; then
    echo "[x] Python 3.10+ required"
    fail=true
else
    echo "[ok] Python 3.10+"
fi

if [ "$fail" = true ]; then
    echo ""
    echo "Fix the above and re-run."
    exit 1
fi

# -- Install dependencies --------------------------------------------
echo ""
echo "Installing Python dependencies..."
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

(cd "$PROJECT_DIR" && uv sync --extra server --quiet 2>/dev/null) && \
    echo "[ok] Dependencies installed" || \
    echo "[!] uv sync had warnings (may still work)"

# Verify MCP runtime dependency is actually importable before wiring the server.
if ! (cd "$PROJECT_DIR" && uv run --extra server python -c "import mcp" >/dev/null 2>&1); then
    echo "[x] MCP runtime dependency check failed."
    echo "    The Python package 'mcp' is not importable in this project runtime."
    echo "    Run: uv sync --extra server"
    echo "    Then re-run: ./scripts/install_mcp.sh"
    exit 1
fi
echo "[ok] MCP runtime dependency verified"

# -- Register MCP server ---------------------------------------------
echo ""
echo "Registering MCP server (scope=$SCOPE)..."

if [ "$CLI" = "claude" ]; then
    # Write .mcp.json directly because `claude mcp add` does not
    # support the --cwd flag, which is required so that the MCP
    # server process starts in the project root directory.
    MCP_JSON="$(claude_mcp_json_path)"
    MCP_DIR="$(dirname "$MCP_JSON")"
    mkdir -p "$MCP_DIR"

    # Build the new server entry and merge it into any existing config
    python3 -c "
import json, sys, os

path = sys.argv[1]
name = sys.argv[2]
api_url = sys.argv[3]
project_dir = sys.argv[4]

entry = {
    'type': 'stdio',
    'command': 'uv',
    'args': ['run', '--extra', 'server', 'python', '-m', 'server.mcp'],
    'cwd': project_dir,
    'env': {
        'MCP_API_URL': api_url,
        'MCP_STDIO_TRUSTED': 'true',
        'MCP_LOG_LEVEL': 'WARNING',
        'PRESIDIO_LOG_LEVEL': 'ERROR'
    }
}

data = {}
if os.path.isfile(path):
    with open(path) as f:
        data = json.load(f)

data.setdefault('mcpServers', {})[name] = entry

with open(path, 'w') as f:
    json.dump(data, f, indent=2)
    f.write('\n')

print('[ok] Wrote', path)
" "$MCP_JSON" "$SERVER_NAME" "$API_URL" "$PROJECT_DIR"

elif [ "$CLI" = "codex" ]; then
    codex mcp add \
        --env "MCP_API_URL=$API_URL" \
        --env "MCP_STDIO_TRUSTED=true" \
        --env "MCP_LOG_LEVEL=WARNING" \
        --env "PRESIDIO_LOG_LEVEL=ERROR" \
        "$SERVER_NAME" \
        -- uv run --extra server python -m server.mcp
fi

echo ""
echo "======================="
echo "Installed successfully."
echo ""
echo "Next steps:"
echo "  1. Start the backend:  docker compose up -d"
echo "  2. Restart $CLI (or run /mcp to verify)"
echo "  3. All 48 MCP tools will be available"
echo ""
echo "To uninstall:  ./scripts/install_mcp.sh --remove"

open_url() {
    local url="$1"
    if command -v open >/dev/null 2>&1; then
        open "$url" >/dev/null 2>&1 || true
        return
    fi
    if command -v xdg-open >/dev/null 2>&1; then
        xdg-open "$url" >/dev/null 2>&1 || true
        return
    fi
}

if command -v curl >/dev/null 2>&1; then
    SETUP_CHECK="$(curl -fsS "$API_URL/api/setup/status" 2>/dev/null || true)"
    if [ -n "$SETUP_CHECK" ] && python3 -c "import json,sys; print('1' if json.loads(sys.argv[1]).get('setup_required') else '0')" "$SETUP_CHECK" 2>/dev/null | grep -q '^1$'; then
        echo ""
        echo "Opening browser for first-time setup: $DASHBOARD_URL/setup"
        open_url "$DASHBOARD_URL/setup"
    elif [ -n "$SETUP_CHECK" ] && python3 -c "import json,sys; print('0' if json.loads(sys.argv[1]).get('setup_required') else '1')" "$SETUP_CHECK" 2>/dev/null | grep -q '^1$'; then
        echo ""
        echo "Opening browser for sign in: $DASHBOARD_URL/login"
        open_url "$DASHBOARD_URL/login"
    else
        echo ""
        echo "Setup status unavailable; defaulting to first-time setup: $DASHBOARD_URL/setup"
        open_url "$DASHBOARD_URL/setup"
    fi
else
    echo ""
    echo "curl not found; open $DASHBOARD_URL/setup manually for first-time setup."
fi
