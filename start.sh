#!/usr/bin/env bash

# Configuration and setup
echo "====================================="
echo "    Starting CCAF Firewall Engine    "
echo "====================================="

# Navigate to the script's directory safely across all shells
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" >/dev/null 2>&1 && pwd)"
cd "$SCRIPT_DIR" || exit 1

# Activate the virtual environment if it exists
if [ -d "venv" ]; then
    echo "[*] Found virtual environment 'venv'. Activating..."
    source venv/bin/activate
elif [ -d ".venv" ]; then
    echo "[*] Found virtual environment '.venv'. Activating..."
    source .venv/bin/activate
else
    echo "[!] No virtual environment found. Running using system Python."
fi

# Ensure dependencies are installed (optional, assumes requirements.txt is present)
if [ -f "requirements.txt" ]; then
    echo "[*] Verifying dependencies..."
    pip install -r requirements.txt --quiet
fi

# Determine the correct python executable to use with sudo
if [ -d "venv" ]; then
    PYTHON_EXEC="venv/bin/python3"
elif [ -d ".venv" ]; then
    PYTHON_EXEC=".venv/bin/python3"
else
    PYTHON_EXEC="python3"
fi

# Run the project. We use sudo as the engine requires packet level access
echo "[*] Launching the python engine..."
echo "[*] Note: You may be prompted for your sudo password to allow packet inspection."
sudo "$PYTHON_EXEC" run.py
