#!/bin/sh
# Starts Secure Vault on macOS or Linux. Usage:  sh start.sh
cd "$(dirname "$0")" || exit 1
if command -v python3 >/dev/null 2>&1; then
    exec python3 start.py "$@"
fi
echo "Python 3.11 or newer was not found. Install it from https://www.python.org/downloads/ and try again."
exit 1
