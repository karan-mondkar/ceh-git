
#!/bin/bash

TARGET="${1:-192.168.0.222}"
TMP=$(mktemp) || exit 1
trap 'rm -f "$TMP"' EXIT

if ! command -v nmap >/dev/null 2>&1; then
    echo "Install Nmap: sudo apt install nmap"
    exit 1
fi

echo "========================================"
echo "DNS TREE NAME DISCOVERY"
echo "Target: $TARGET"
echo "========================================"

echo
echo "[1] Scanning DNS, Kerberos and LDAP"
nmap -n -Pn -sT -sV -p 53,88,389 "$TARGET"

echo
echo "[2] Querying LDAP RootDSE"
nmap -n -Pn -p 389 --script ldap-rootdse -oN "$TMP" "$TARGET"

echo
echo "========================================"
echo "RELEVANT DOMAIN INFORMATION"
echo "========================================"

grep -iE 'rootDomainNamingContext|defaultNamingContext|namingContexts|dnsHostName|domain' "$TMP" || echo "No matching naming-context fields found."

TREE=$(sed -nE 's/.*rootDomainNamingContext:[[:space:]]*//p' "$TMP" | head -n 1)

if [ -n "$TREE" ]; then
    DNS_TREE=$(printf '%s\n' "$TREE" | sed -E 's/[[:space:]]//g; s/DC=//Ig; s/,/./g')
    echo
    echo "========================================"
    echo "[+] DNS TREE NAME: $DNS_TREE"
    echo "========================================"
else
    echo
    echo "[!] DNS Tree Name could not be extracted."
    echo "Check whether rootDomainNamingContext appears in the LDAP output."
fi

echo
echo "========================================"
echo "SCAN COMPLETED"
echo "========================================"
