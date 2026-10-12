#!/usr/bin/env bash
# Prepare a project-local Python environment and check system dependencies.
set -euo pipefail
project_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
command -v python3 >/dev/null || { echo 'Install Python 3.10 or newer.' >&2; exit 2; }
python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3,10) else 1)' || {
    echo 'Python 3.10 or newer is required.' >&2; exit 2;
}
python3 -m venv "$project_dir/app/.venv" || {
    echo 'On Kali/Debian/Ubuntu, install python3-venv and try again.' >&2; exit 2;
}
"$project_dir/app/.venv/bin/python" -m pip install --disable-pip-version-check -r "$project_dir/app/requirements.txt"
missing=()
for executable in nmap smbclient snmpget; do
    command -v "$executable" >/dev/null || missing+=("$executable")
done
if (( ${#missing[@]} )); then
    printf 'Missing system tools: %s\n' "${missing[*]}" >&2
    echo 'On Kali/Debian/Ubuntu: sudo apt install nmap smbclient snmp' >&2
    exit 2
fi
"$project_dir/app/.venv/bin/python" "$project_dir/app/scanner.py" --doctor
echo 'Ready. Run: bash scripts/scan.sh --help'
