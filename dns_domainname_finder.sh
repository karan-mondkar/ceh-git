
#!/bin/bash

TARGET="${1:-192.168.0.222}"

if ! command -v nmap >/dev/null 2>&1; then
    echo "Install Nmap: sudo apt install nmap"
    exit 1
fi

echo "STEP 1: HOST DISCOVERY"
nmap -sn "$TARGET"

echo
echo "STEP 2: NETBIOS DISCOVERY"
nmap -n -Pn -sU -p 137 --script nbstat "$TARGET"

echo
echo "STEP 3: SMB DISCOVERY"
echo "Reading the SMB results directly..."

TMP=$(mktemp) || exit 1
trap 'rm -f "$TMP"' EXIT

nmap -n -Pn -p 139,445 --script smb-os-discovery -oN "$TMP" "$TARGET"

echo
echo "========== COMPLETE SMB OUTPUT =========="
cat "$TMP"
echo "=========================================="
