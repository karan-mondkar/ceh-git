
#!/bin/bash

DOMAIN="${1:-}"

if [ -z "$DOMAIN" ]; then
    echo "Usage: ./dns_enum.sh <domain>"
    echo "Example: ./dns_enum.sh example.com"
    exit 1
fi

TMP=$(mktemp) || exit 1
trap 'rm -f "$TMP"' EXIT

if ! command -v nmap >/dev/null 2>&1; then
    echo "Install Nmap: sudo apt install nmap"
    exit 1
fi

if ! command -v dig >/dev/null 2>&1; then
    echo "Install DNS tools: sudo apt install dnsutils"
    exit 1
fi

echo "========================================"
echo "DNS ENUMERATION"
echo "Target domain: $DOMAIN"
echo "========================================"

echo
echo "[1] DNS service discovery"
nmap -n -Pn -sT -sV -p 53 --script dns-nsid "$DOMAIN"

echo
echo "[2] A records"
dig "$DOMAIN" A

echo
echo "[3] AAAA records"
dig "$DOMAIN" AAAA

echo
echo "[4] MX records"
dig "$DOMAIN" MX

echo
echo "[5] TXT records"
dig "$DOMAIN" TXT

echo
echo "[6] SOA records"
dig "$DOMAIN" SOA

echo
echo "[7] NS records"
dig "$DOMAIN" NS

echo
echo "[8] DNS trace"
dig +trace "$DOMAIN" NS

echo
echo "========================================"
echo "NAME SERVER SUMMARY"
echo "========================================"

NS_LIST=$(dig +short NS "$DOMAIN" | sed 's/\.$//' | sort -u)

if [ -n "$NS_LIST" ]; then
    echo "Discovered name servers:"
    printf '%s\n' "$NS_LIST"
    echo
    echo "Answer format:"
    paste -sd ', ' <<< "$NS_LIST"
else
    echo "No name servers returned."
    echo "Check DNS connectivity and the domain."
fi

echo
echo "========================================"
echo "DNS ENUMERATION COMPLETED"
echo "========================================"
