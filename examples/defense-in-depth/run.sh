#!/usr/bin/env bash
# Run the defense-in-depth demo: build, run, collect evidence, summarize, tear down.
#
# Usage: examples/defense-in-depth/run.sh [--keep] [--out DIR]
#        [--toolguard-src DIR] [--scanner-src DIR]
#
# Python: $PYTHON if set, else this checkout's .venv, else python3. It must be able
# to import agent_sandbox (the driver falls back to this checkout's src/).
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo="$(cd "$here/../.." && pwd)"

python="${PYTHON:-}"
if [ -z "$python" ]; then
    for candidate in "$repo/.venv/bin/python" "$repo/.venv/Scripts/python.exe"; do
        if [ -x "$candidate" ]; then
            python="$candidate"
            break
        fi
    done
fi
python="${python:-python3}"

# Git Bash on Windows would otherwise rewrite container paths such as /workspace.
export MSYS_NO_PATHCONV=1
exec "$python" "$here/demo.py" "$@"
