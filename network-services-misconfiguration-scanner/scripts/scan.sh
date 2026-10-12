#!/usr/bin/env bash
# Forward arguments unchanged; exec preserves signals and the Python exit code.
set -euo pipefail
project_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
scanner_python="$project_dir/app/.venv/bin/python"
if [[ ! -x "$scanner_python" ]]; then
    echo 'Run bash scripts/setup.sh once before using this launcher.' >&2
    exit 2
fi
exec "$scanner_python" "$project_dir/app/scanner.py" "$@"
