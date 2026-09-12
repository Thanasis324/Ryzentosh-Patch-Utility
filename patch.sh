#!/usr/bin/env bash
# Ryzentosh Patching Utility Quick Launcher
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec python3 "$SCRIPT_DIR/ryzentosh_patcher.py" "$@"
