#!/bin/bash
NETWORK="${1:-}"
if [ -z "$NETWORK" ]; then
echo "Usage: bash dc_finder.sh 192.168.0.0/24"
exit 1
fi
if ! command -v nmap >/dev/null 2>&1; then
echo "Install Nmap: sudo apt install nmap"
exit 1
fi
TMP=$(mktemp) || exit 1
trap 'rm -f "$TMP"' EXIT
echo "Scanning network: $NETWORK"
nmap -n -Pn -sT --open -T3 --reason -p 53,88,135,139,389,445,464,636,3268,3269,9389 -oN "$TMP" "$NETWORK"
if [ $? -ne 0 ]; then
echo "Nmap scan failed."
exit 1
fi
echo
echo "DOMAIN CONTROLLER CANDIDATES"
while IFS= read -r LINE; do
IP=$(printf '%s\n' "$LINE" | sed -E 's/^Nmap scan report for ([^( ]+)( ([^)]*))?$/\1/')
PORTS=$(sed -n "/^Nmap scan report for /,/^Nmap scan report for /p" "$TMP" | head -n 0)
PORTS=$(grep -A 30 -F "$LINE" "$TMP" | grep -E '^[0-9]+/tcp[[:space:]]+open' | cut -d/ -f1 | tr '\n' ' ')
K=0
L=0
S=0
D=0
R=0
G=0
A=0
[[ " $PORTS " == " 88 " ]] && K=1
[[ " $PORTS " == " 389 " || " $PORTS " == " 636 " ]] && L=1
[[ " $PORTS " == " 139 " || " $PORTS " == " 445 " ]] && S=1
[[ " $PORTS " == " 53 " ]] && D=1
[[ " $PORTS " == " 135 " ]] && R=1
[[ " $PORTS " == " 3268 " || " $PORTS " == " 3269 " ]] && G=1
[[ " $PORTS " == " 9389 " ]] && A=1
echo
echo "IP: $IP"
echo "Open ports: $PORTS"
(( K )) && echo "Evidence: Port 88 Kerberos"
(( L )) && echo "Evidence: Port 389/636 LDAP"
(( S )) && echo "Evidence: Port 139/445 SMB"
(( D )) && echo "Evidence: Port 53 DNS"
(( R )) && echo "Evidence: Port 135 RPC"
(( G )) && echo "Evidence: Port 3268/3269 Global Catalog"
(( A )) && echo "Evidence: Port 9389 AD Web Services"
if (( K && L && (S || R || D) )); then
echo "PROBABLE DOMAIN CONTROLLER: $IP"
echo "Reason: Kerberos and LDAP plus another supporting service are open."
elif (( G || (K && L) || (L && S && R) )); then
echo "POSSIBLE DOMAIN CONTROLLER: $IP"
echo "Reason: Multiple services are consistent with Active Directory."
else
echo "INSUFFICIENT EVIDENCE: $IP"
echo "Reason: The detected port combination is not strong evidence of a DC."
fi
done < <(grep '^Nmap scan report for ' "$TMP")
echo
echo "Scan complete. Confirm candidates with AD DNS records."
