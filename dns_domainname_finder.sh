
#!/usr/bin/env bash

# CEH DNS Domain / DNS Tree Name Finder
# Use only against systems you own or are authorized to assess.
# Usage:
#   ./hi.sh <target-IP-or-hostname> [AD-domain]
# Examples:
#   ./hi.sh scanme.nmap.org
#   ./hi.sh 192.168.10.222 skill.ceh.com

set -u

# ---------- Colors ----------
if [[ -t 1 ]]; then
    GREEN=$'\033[0;32m'
    YELLOW=$'\033[1;33m'
    RED=$'\033[0;31m'
    CYAN=$'\033[0;36m'
    RESET=$'\033[0m'
else
    GREEN='' YELLOW='' RED='' CYAN='' RESET=''
fi

banner() {
    printf '\n%s\n' "=================================================="
    printf '%s\n' "$1"
    printf '%s\n' "=================================================="
}

# ---------- Validate arguments ----------
if [[ $# -lt 1 || $# -gt 2 || -z "${1:-}" ]]; then
    echo "Usage: $0 <target-IP-or-hostname> [AD-domain]"
    echo "Example: $0 192.168.10.222 skill.ceh.com"
    exit 1
fi

TARGET="$1"
DOMAIN="${2:-}"

if ! command -v nmap >/dev/null 2>&1; then
    echo "${RED}ERROR: Nmap is not installed.${RESET}"
    echo "Install: sudo apt update && sudo apt install nmap"
    exit 1
fi

# If no separate domain was supplied, use a hostname as the
# candidate DNS domain. For an IP target, DNS SRV checks are skipped.
if [[ -z "$DOMAIN" && "$TARGET" == *.* && ! "$TARGET" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    DOMAIN="$TARGET"
fi

# ---------- Persistent report folder ----------
STAMP=$(date +%Y%m%d_%H%M%S)
REPORT_DIR="$PWD/hi_report_$STAMP"

if ! mkdir -p "$REPORT_DIR"; then
    echo "${RED}ERROR: Cannot create report directory.${RESET}"
    exit 1
fi

echo "=================================================="
echo " CEH DNS DOMAIN / DNS TREE NAME FINDER"
echo "=================================================="
echo "Target:  $TARGET"
echo "Domain:  ${DOMAIN:-Not supplied}"
echo "Shell:   $BASH_VERSION"
echo "Reports: $REPORT_DIR"
echo "Nmap:    $(nmap --version | head -n 1)"

# ---------- Step 1: Host discovery ----------
banner "STEP 1: HOST DISCOVERY"

if nmap -n -sn -oN "$REPORT_DIR/host.txt" "$TARGET"; then
    echo "${GREEN}Host discovery completed.${RESET}"
else
    echo "${YELLOW}Host discovery returned an error; see host.txt.${RESET}"
fi

# ---------- Step 2: NetBIOS ----------
banner "STEP 2: NETBIOS DISCOVERY (UDP 137)"

if nmap -n -Pn -sU -p 137 --script nbstat \
    --host-timeout 60s \
    -oN "$REPORT_DIR/netbios.txt" "$TARGET"; then
    echo "${GREEN}NetBIOS scan completed.${RESET}"
else
    echo "${YELLOW}NetBIOS scan returned an error.${RESET}"
fi

# ---------- Step 3: SMB ----------
banner "STEP 3: SMB OS / DOMAIN DISCOVERY"

if nmap -n -Pn -p 139,445 --script smb-os-discovery \
    --host-timeout 60s \
    -oN "$REPORT_DIR/smb.txt" "$TARGET"; then
    echo "${GREEN}SMB scan completed.${RESET}"
else
    echo "${YELLOW}SMB scan returned an error.${RESET}"
fi

# ---------- Step 4: LDAP RootDSE ----------
banner "STEP 4: LDAP ROOTDSE DISCOVERY"

if nmap -n -Pn -p 389,636 --script ldap-rootdse \
    --host-timeout 60s \
    -oN "$REPORT_DIR/ldap.txt" "$TARGET"; then
    echo "${GREEN}LDAP scan completed.${RESET}"
else
    echo "${YELLOW}LDAP scan returned an error.${RESET}"
fi

# ---------- Step 5: DNS TCP/53 ----------
banner "STEP 5: DNS TCP PORT CHECK"

if nmap -n -Pn -sT -p 53 -sV --version-light \
    --host-timeout 60s \
    -oN "$REPORT_DIR/dns-port.txt" "$TARGET"; then
    echo "${GREEN}DNS TCP port check completed.${RESET}"
else
    echo "${YELLOW}DNS port check returned an error.${RESET}"
fi

# ---------- Step 6: DNS SRV records ----------
banner "STEP 6: ACTIVE DIRECTORY DNS SRV DISCOVERY"

if [[ -n "$DOMAIN" ]]; then
    if command -v dig >/dev/null 2>&1; then
        for RECORD in \
            "_ldap._tcp.dc._msdcs.$DOMAIN" \
            "_ldap._tcp.$DOMAIN" \
            "_kerberos._tcp.$DOMAIN"; do

            SAFE_NAME="${RECORD//[^a-zA-Z0-9_.-]/_}"
            OUT="$REPORT_DIR/srv_${SAFE_NAME}.txt"

            echo
            echo "Query: $RECORD"

            if dig +time=3 +tries=1 +noall +answer \
                "$RECORD" SRV > "$OUT"; then
                if [[ -s "$OUT" ]]; then
                    cat "$OUT"
                else
                    echo "No SRV answer returned."
                fi
            else
                echo "DNS query failed; inspect $OUT."
            fi
        done
    else
        echo "dig is unavailable. Install it with:"
        echo "sudo apt install dnsutils"
    fi
else
    echo "No DNS domain supplied; skipping SRV queries."
    echo "For an IP target, run: ./hi.sh <DC-IP> <AD-domain>"
fi

# ---------- Step 7: Extract reported fields ----------
banner "STEP 7: EXTRACTED DOMAIN INFORMATION"

echo
echo "--- SMB fields ---"
if grep -Eiq \
    'NetBIOS computer name:|NetBIOS domain name:|DNS domain name:|FQDN:|OS:|System time:' \
    "$REPORT_DIR/smb.txt"; then
    grep -Ei \
        'NetBIOS computer name:|NetBIOS domain name:|DNS domain name:|FQDN:|OS:|System time:' \
        "$REPORT_DIR/smb.txt"
else
    echo "No SMB domain/computer fields found."
fi

echo
echo "--- LDAP RootDSE fields ---"
if grep -Eiq \
    'rootDomainNamingContext|defaultNamingContext|namingContexts|dnsHostName|ldapServiceName|domainFunctionality|forestFunctionality' \
    "$REPORT_DIR/ldap.txt"; then
    grep -Ei \
        'rootDomainNamingContext|defaultNamingContext|namingContexts|dnsHostName|ldapServiceName|domainFunctionality|forestFunctionality' \
        "$REPORT_DIR/ldap.txt"
else
    echo "No LDAP RootDSE fields found."
fi

echo
echo "--- NetBIOS results ---"
grep -Ei \
    'NetBIOS|Domain|Computer name|137/udp' \
    "$REPORT_DIR/netbios.txt" || echo "No NetBIOS names found."

echo
echo "--- DNS SRV answers ---"
SRV_COUNT=0
for F in "$REPORT_DIR"/srv_*.txt; do
    [[ -f "$F" ]] || continue
    if [[ -s "$F" ]]; then
        cat "$F"
        SRV_COUNT=$((SRV_COUNT + 1))
    fi
done
if [[ "$SRV_COUNT" -eq 0 ]]; then
    echo "No DNS SRV answers were saved."
fi

# ---------- Step 8: Interpretation ----------
banner "STEP 8: DNS TREE NAME INTERPRETATION"

ROOT_CONTEXT=$(grep -i 'rootDomainNamingContext' "$REPORT_DIR/ldap.txt" | head -n 1 || true)
DEFAULT_CONTEXT=$(grep -i 'defaultNamingContext' "$REPORT_DIR/ldap.txt" | head -n 1 || true)
DNS_HOST=$(grep -i 'dnsHostName' "$REPORT_DIR/ldap.txt" | head -n 1 || true)

echo "Root domain context:   ${ROOT_CONTEXT:-Not extracted}"
echo "Default domain context: ${DEFAULT_CONTEXT:-Not extracted}"
echo "DNS host name:         ${DNS_HOST:-Not extracted}"

echo
echo "Interpretation:"
echo "* DC=skill,DC=ceh,DC=com corresponds to skill.ceh.com."
echo "* LDAP naming contexts can reveal directory domain information."
echo "* DNS SRV answers may identify domain controllers and their ports."
echo "* No results do not prove that Active Directory is absent."
echo "* Filtered ports, DNS restrictions, and access controls can block discovery."

echo
echo "${GREEN}Scan complete.${RESET}"
echo "Full reports saved in: $REPORT_DIR"
