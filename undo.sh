#!/usr/bin/env bash
# Ryzentosh Patch Revert / Undo Launcher
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec python3 "$SCRIPT_DIR/undo_patcher.py" "$@"
