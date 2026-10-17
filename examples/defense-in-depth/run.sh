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

script="$here/demo.py"
if command -v cygpath >/dev/null 2>&1; then
    # Git Bash on Windows: hand a native path to a Windows Python, and stop MSYS
    # from rewriting other arguments (pass --out and the like as native paths).
    script="$(cygpath -m "$script")"
    export MSYS_NO_PATHCONV=1
fi
exec "$python" "$script" "$@"
