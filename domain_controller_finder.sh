
#!/bin/sh

# ==========================================================
# CEH ACTIVE DIRECTORY / DOMAIN CONTROLLER FINDER
# POSIX sh compatible - Parrot OS / Kali Linux
# All output is displayed directly in the terminal.
# No report files are created.
# ==========================================================
# Usage:
#   sh dc_verify.sh <IP-or-CIDR>
#
# Examples:
#   sh dc_verify.sh 192.168.10.222
#   sh dc_verify.sh 192.168.10.0/24
# ==========================================================

set -u
LC_ALL=C
export LC_ALL

PORTS="53,88,135,139,389,445,464,636,3268,3269,3389"

banner() {
    echo
    echo "=================================================="
    echo "$1"
    echo "=================================================="
}

if [ "$#" -ne 1 ] || [ -z "$1" ]; then
    echo "Usage: sh dc_verify.sh <IP-or-CIDR>"
    exit 1
fi

TARGET="$1"

if ! command -v nmap >/dev/null 2>&1; then
    echo "ERROR: Nmap is not installed."
    echo "Install with: sudo apt install nmap"
    exit 1
fi

banner "CEH ACTIVE DIRECTORY FINDER"
echo "Target: $TARGET"
echo "Mode: terminal output only"
echo "Ports: $PORTS"

# ----------------------------------------------------------
# Stage 1: Discover hosts with relevant open ports.
# ----------------------------------------------------------

banner "STAGE 1: HOST DISCOVERY"

DISCOVERY=$(nmap -n -Pn -sT -p "$PORTS" --open -oG - "$TARGET" 2>&1)
DISCOVERY_STATUS=$?

printf '%s\n' "$DISCOVERY"

if [ "$DISCOVERY_STATUS" -ne 0 ]; then
    echo "WARNING: Nmap discovery returned exit code $DISCOVERY_STATUS."
fi

case "$TARGET" in
    */*)
        HOSTS=$(printf '%s\n' "$DISCOVERY" | awk '/^Host: / && /Ports:/ {print $2}' | sort -u)
        ;;
    *)
        HOSTS="$TARGET"
        ;;
esac

if [ -z "$HOSTS" ]; then
    echo
    echo "No hosts with selected open ports were found."
    echo "Check the target subnet and network connectivity."
    exit 0
fi

# ----------------------------------------------------------
# Stage 2: Inspect each host.
# ----------------------------------------------------------

banner "STAGE 2: DOMAIN AND DC VERIFICATION"

for IP in $HOSTS
do
    echo
    echo "##################################################"
    echo "Checking host: $IP"
    echo "##################################################"

    DETAIL=$(nmap -n -Pn -sT -sV -p "$PORTS" --script rdp-ntlm-info,smb-os-discovery,ldap-rootdse -oN - "$IP" 2>&1)
    DETAIL_STATUS=$?

    # Print the complete Nmap output directly.
    printf '%s\n' "$DETAIL"

    if [ "$DETAIL_STATUS" -ne 0 ]; then
        echo "WARNING: Detailed scan returned code $DETAIL_STATUS."
    fi

    # Extract AD identity fields.
    NETBIOS_DOMAIN=$(printf '%s\n' "$DETAIL" | grep -i 'NetBIOS_Domain_Name:' | head -n 1 | sed 's/^[[:space:]]*|[[:space:]]*//')
    DNS_DOMAIN=$(printf '%s\n' "$DETAIL" | grep -i 'DNS_Domain_Name:' | head -n 1 | sed 's/^[[:space:]]*|[[:space:]]*//')
    DNS_TREE=$(printf '%s\n' "$DETAIL" | grep -i 'DNS_Tree_Name:' | head -n 1 | sed 's/^[[:space:]]*|[[:space:]]*//')
    COMPUTER=$(printf '%s\n' "$DETAIL" | grep -i 'NetBIOS_Computer_Name:' | head -n 1 | sed 's/^[[:space:]]*|[[:space:]]*//')
    ROOT_CONTEXT=$(printf '%s\n' "$DETAIL" | grep -i 'rootDomainNamingContext:' | head -n 1)
    DEFAULT_CONTEXT=$(printf '%s\n' "$DETAIL" | grep -i 'defaultNamingContext:' | head -n 1)

    # Detect DC-related open services.
    KERBEROS=$(printf '%s\n' "$DETAIL" | grep -E '(^|[[:space:]])88/tcp[[:space:]]+open([[:space:]]|$)' || true)
    LDAP=$(printf '%s\n' "$DETAIL" | grep -E '(^|[[:space:]])389/tcp[[:space:]]+open([[:space:]]|$)' || true)
    GC=$(printf '%s\n' "$DETAIL" | grep -E '(^|[[:space:]])(3268|3269)/tcp[[:space:]]+open([[:space:]]|$)' || true)

    echo
    echo "--------------- IDENTITY SUMMARY ---------------"
    echo "Host IP: $IP"
    echo "NetBIOS domain: ${NETBIOS_DOMAIN:-Not disclosed}"
    echo "DNS domain:     ${DNS_DOMAIN:-Not disclosed}"
    echo "DNS tree:       ${DNS_TREE:-Not disclosed}"
    echo "Computer name:  ${COMPUTER:-Not disclosed}"
    echo "------------------------------------------------"

    # Classify using the actual evidence, not just port 53.
    echo
    echo "--------------- FINAL ASSESSMENT ---------------"

    if [ -n "$ROOT_CONTEXT" ] && [ -n "$DEFAULT_CONTEXT" ]; then
        echo "RESULT: STRONG DOMAIN CONTROLLER EVIDENCE"
        echo "Reason: LDAP returned both RootDSE naming contexts."
        echo "Candidate IP: $IP"
    elif [ -n "$KERBEROS" ] && [ -n "$LDAP" ] && [ -n "$NETBIOS_DOMAIN" ]; then
        echo "RESULT: PROBABLE DOMAIN CONTROLLER"
        echo "Reason: Kerberos, LDAP and domain identity are present."
        echo "Candidate IP: $IP"
    elif [ -n "$GC" ]; then
        echo "RESULT: PROBABLE DOMAIN CONTROLLER"
        echo "Reason: A Global Catalog service is open."
        echo "Candidate IP: $IP"
    elif [ -n "$DNS_TREE" ] && [ -n "$NETBIOS_DOMAIN" ]; then
        echo "RESULT: ACTIVE DIRECTORY DOMAIN IDENTITY FOUND"
        echo "Candidate IP: $IP"
        echo "The RDP NTLM response disclosed the DNS tree and NetBIOS domain."
        echo "DC ROLE: Not independently confirmed by the available port evidence."
    elif [ -n "$NETBIOS_DOMAIN" ] && [ -n "$DNS_DOMAIN" ]; then
        echo "RESULT: DOMAIN IDENTITY FOUND"
        echo "Candidate IP: $IP"
        echo "DC ROLE: Not independently confirmed."
    else
        echo "RESULT: NOT CONFIRMED"
        echo "Insufficient domain-controller evidence was returned."
    fi

    echo "------------------------------------------------"
done

banner "SCAN COMPLETE"
echo "All results were displayed in the terminal."
echo "No output report files were created."
