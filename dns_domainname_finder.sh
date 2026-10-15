
#!/usr/bin/env bash

# CEH DNS Domain / DNS Tree Name Finder
# Usage: sudo ./dns_domainname_finder.sh <target-ip>

set -uo pipefail

TARGET="${1:-}"

if [[ -z "$TARGET" ]]; then
    echo "Usage: sudo $0 <target-ip>"
    echo "Example: sudo $0 192.168.10.222"
    exit 1
fi

if ! command -v nmap >/dev/null 2>&1; then
    echo "[ERROR] Nmap is not installed."
    echo "Install with: sudo apt install nmap"
    exit 1
fi

if ! command -v grep >/dev/null 2>&1; then
    echo "[ERROR] grep is required."
    exit 1
fi

WORKDIR="$(mktemp -d)" || exit 1
trap 'rm -rf "$WORKDIR"' EXIT

HOST_OUT="$WORKDIR/host.txt"
NB_OUT="$WORKDIR/netbios.txt"
SMB_OUT="$WORKDIR/smb.txt"
LDAP_OUT="$WORKDIR/ldap.txt"
DNS_OUT="$WORKDIR/dns.txt"

run_scan() {
    local title="$1"
    local outfile="$2"
    shift 2

    echo
    echo "=================================================="
    echo "$title"
    echo "=================================================="

    "$@" -oN "$outfile" 
    local rc=$?

    if [[ -f "$outfile" ]]; then
        cat "$outfile"
    fi

    if (( rc != 0 )); then
        echo "[WARNING] Scan returned status $rc."
    fi
}

echo "=========================================="
echo " CEH DNS DOMAIN / DNS TREE NAME FINDER"
echo "=========================================="
echo "Target: $TARGET"
echo

# STEP 1: Host discovery
run_scan "STEP 1: HOST DISCOVERY" "$HOST_OUT" \
    nmap -n -sn "$TARGET"

# STEP 2: NetBIOS discovery
# UDP 137 commonly requires root privileges.
run_scan "STEP 2: NETBIOS DISCOVERY (UDP 137)" "$NB_OUT" \
    nmap -n -Pn -sU -p 137 --script nbstat "$TARGET"

# STEP 3: SMB discovery
run_scan "STEP 3: SMB OS / DOMAIN DISCOVERY" "$SMB_OUT" \
    nmap -n -Pn -p 139,445 --script smb-os-discovery "$TARGET"

# STEP 4: LDAP RootDSE discovery
# Anonymous RootDSE queries may be allowed even when
# ordinary LDAP directory searches require authentication.
run_scan "STEP 4: LDAP ROOTDSE DISCOVERY" "$LDAP_OUT" \
    nmap -n -Pn -p 389,636 --script ldap-rootdse "$TARGET"

# STEP 5: DNS service check
run_scan "STEP 5: DNS SERVICE CHECK" "$DNS_OUT" \
    nmap -n -Pn -sT -p 53 -sV "$TARGET"

echo
echo "=================================================="
echo " STEP 6: EXTRACTED DOMAIN INFORMATION"
echo "=================================================="

echo
echo "--- SMB domain / computer fields ---"
if ! grep -Ei \
    'Computer name:|NetBIOS computer name:|Domain name:|Forest name:|FQDN:|Workgroup:|OS:' \
    "$SMB_OUT"; then
    echo "No SMB domain fields were returned."
fi

echo
echo "--- LDAP RootDSE fields ---"
if ! grep -Ei \
    'dnsHostName|defaultNamingContext|rootDomainNamingContext|namingContexts|domainFunctionality|forestFunctionality|serverName|ldap-rootdse' \
    "$LDAP_OUT"; then
    echo "No LDAP RootDSE fields were returned."
fi

echo
echo "--- NetBIOS fields ---"
if ! grep -Ei \
    'NetBIOS|Domain|Computer|Workgroup|Names' \
    "$NB_OUT"; then
    echo "No matching NetBIOS fields were returned."
fi

echo
echo "=================================================="
echo " STEP 7: DNS TREE NAME INTERPRETATION"
echo "=================================================="

ROOT_CONTEXT="$(
    grep -Eio 'rootDomainNamingContext[^,|]*([,|].*)?' "$LDAP_OUT" |
    head -n 1 || true
)"

DEFAULT_CONTEXT="$(
    grep -Eio 'defaultNamingContext[^,|]*([,|].*)?' "$LDAP_OUT" |
    head -n 1 || true
)"

DNS_HOST="$(
    grep -Eio 'dnsHostName[^,|]*' "$LDAP_OUT" |
    head -n 1 || true
)"

echo "Root domain context: ${ROOT_CONTEXT:-Not extracted}"
echo "Default domain context: ${DEFAULT_CONTEXT:-Not extracted}"
echo "DNS host name: ${DNS_HOST:-Not extracted}"

echo
echo "IMPORTANT:"
echo "• rootDomainNamingContext identifies the forest root domain context."
echo "• defaultNamingContext identifies the server's default domain context."
echo "• DNS tree names can be derived from DC components in a naming context."
echo "• No result does not prove that the target lacks Active Directory."
echo "• Access restrictions, closed ports, or disabled services may prevent discovery."

echo
echo "Scan complete."
