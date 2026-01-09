#!/bin/bash
# Chrome Native Messaging Host Wrapper
# Connects to the Virtual Environment Python to run the host script

# Get absolute path to the directory containing this script
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
CORE_DIR="$(dirname "$DIR")"
VENV_PYTHON="$CORE_DIR/venv/bin/python3"
HOST_SCRIPT="$DIR/host.py"

# Logging for debugging (optional, can be removed in prod)
# echo "Starting Host..." > /tmp/securevault_host.log
# echo "Python: $VENV_PYTHON" >> /tmp/securevault_host.log
# echo "Script: $HOST_SCRIPT" >> /tmp/securevault_host.log

if [ -f "$VENV_PYTHON" ]; then
    exec "$VENV_PYTHON" "$HOST_SCRIPT" "$@"
else
    # Fallback to system python if venv missing (unlikely if setup ran)
    exec python3 "$HOST_SCRIPT" "$@"
fi
