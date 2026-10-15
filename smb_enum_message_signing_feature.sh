
#!/bin/bash

TARGET="${1:-}"

if [ -z "$TARGET" ]; then
    echo "Usage: ./smb_signing.sh <IP-address>"
    echo "Example: ./smb_signing.sh 192.168.1.10"
    exit 1
fi

if ! command -v nmap >/dev/null 2>&1; then
    echo "Install Nmap: sudo apt install nmap"
    exit 1
fi

TMP=$(mktemp) || exit 1
trap 'rm -f "$TMP"' EXIT

echo "========================================"
echo "SMB MESSAGE SIGNING ENUMERATION"
echo "Target: $TARGET"
echo "========================================"

echo
echo "[1] Checking SMB ports"
nmap -n -Pn -p 139,445 "$TARGET"

echo
echo "[2] Checking SMB security settings"
nmap -n -Pn -p 445 --script smb2-security-mode -oN "$TMP" "$TARGET"

echo
echo "========================================"
echo "FULL SMB ENUMERATION RESULTS"
echo "========================================"
cat "$TMP"

echo
echo "========================================"
echo "SMB MESSAGE SIGNING REQUIRED?"
echo "========================================"

if grep -qiE 'Message signing enabled and required' "$TMP"; then
    echo "Yes"
elif grep -qiE 'Message signing enabled but not required|Message signing disabled' "$TMP"; then
    echo "No"
else
    echo "Unable to determine. Review the Nmap output."
fi

echo "========================================"
