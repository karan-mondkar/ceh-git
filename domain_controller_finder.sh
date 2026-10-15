
#!/usr/bin/env bash
set -Eeuo pipefail

NETWORK="${1:-}"

if [[ -z "$NETWORK" ]]; then
    echo "Usage: $0 <network/CIDR>"
    echo "Example: $0 192.168.10.0/24"
    exit 1
fi

for cmd in nmap python3; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
        echo "[ERROR] Required command not found: $cmd"
        echo "Install with: sudo apt install nmap python3"
        exit 1
    fi
done

TMP="$(mktemp --suffix=.xml)"
trap 'rm -f "$TMP"' EXIT

PORTS="53,88,135,139,389,445,464,636,3268,3269,9389"

echo "=========================================="
echo " DOMAIN CONTROLLER CANDIDATE FINDER"
echo "=========================================="
echo "Network: $NETWORK"
echo "Ports:   $PORTS"
echo

if ! nmap -n -Pn -sT --open -T3 --reason \
    -p "$PORTS" -oX "$TMP" "$NETWORK"; then
    echo "[ERROR] Nmap scan failed."
    exit 1
fi

python3 - "$TMP" <<'PY'
import sys
import xml.etree.ElementTree as ET
from collections import Counter

xml_file = sys.argv[1]

try:
    root = ET.parse(xml_file).getroot()
except (OSError, ET.ParseError) as exc:
    print(f"[ERROR] Could not parse Nmap XML: {exc}")
    sys.exit(1)

PORT_NAMES = {
    53: "DNS",
    88: "Kerberos",
    135: "MS RPC",
    139: "NetBIOS/SMB",
    389: "LDAP",
    445: "SMB",
    464: "Kerberos password service",
    636: "LDAPS",
    3268: "Global Catalog",
    3269: "Global Catalog TLS",
    9389: "AD Web Services",
}

def classify(ports):
    kerberos = 88 in ports or 464 in ports
    ldap = 389 in ports or 636 in ports
    smb = 139 in ports or 445 in ports
    dns = 53 in ports
    global_catalog = 3268 in ports or 3269 in ports
    adws = 9389 in ports

    evidence = []
    if kerberos:
        evidence.append("Kerberos-related port")
    if ldap:
        evidence.append("LDAP/LDAPS")
    if smb:
        evidence.append("SMB/NetBIOS")
    if dns:
        evidence.append("DNS")
    if global_catalog:
        evidence.append("Active Directory Global Catalog")
    if adws:
        evidence.append("AD Web Services")
    if 135 in ports:
        evidence.append("MS RPC")

    # These are heuristics, not definitive identification.
    if kerberos and ldap and (smb or dns or global_catalog or adws):
        label = "PROBABLE DOMAIN CONTROLLER"
        reason = (
            "Kerberos and LDAP are open, with additional "
            "services consistent with Active Directory."
        )
    elif (kerberos and ldap) or (ldap and global_catalog) or (
        kerberos and global_catalog
    ):
        label = "POSSIBLE DOMAIN CONTROLLER"
        reason = "Multiple ports are consistent with Active Directory."
    else:
        label = "INSUFFICIENT EVIDENCE"
        reason = (
            "The open ports do not establish that this host is "
            "a domain controller."
        )

    return label, reason, evidence


hosts = []
for host in root.findall("host"):
    status = host.find("status")
    if status is not None and status.get("state") != "up":
        continue

    addresses = [
        node.get("addr")
        for node in host.findall("address")
        if node.get("addrtype") == "ipv4"
    ]
    if not addresses:
        continue

    ip = addresses[0]
    ports = set()

    for port in host.findall("./ports/port"):
        state = port.find("state")
        if (
            port.get("protocol") == "tcp"
            and state is not None
            and state.get("state") == "open"
        ):
            try:
                ports.add(int(port.get("portid")))
            except (TypeError, ValueError):
                pass

    # --open normally filters these already, but keep output clean.
    if ports:
        hosts.append((ip, ports))

if not hosts:
    print("No hosts with the requested open TCP ports were found.")
    print("Check the network range, routing, and firewall rules.")
    sys.exit(0)

hosts.sort(key=lambda item: tuple(
    int(part) for part in item[0].split(".")
))

print("\n========== DOMAIN CONTROLLER CANDIDATES ==========")

counts = Counter()

for ip, ports in hosts:
    label, reason, evidence = classify(ports)
    counts[label] += 1

    print(f"\nIP: {ip}")
    print("Open TCP ports:", " ".join(map(str, sorted(ports))))

    print("Services:")
    for port in sorted(ports):
        print(f"  {port}/tcp - {PORT_NAMES.get(port, 'Unknown service')}")

    if evidence:
        print("Evidence:", "; ".join(evidence))
    print(f"Result: {label}")
    print("Reason:", reason)

print("\n========== SUMMARY ==========")
print("Hosts with matching open ports:", len(hosts))
for label in (
    "PROBABLE DOMAIN CONTROLLER",
    "POSSIBLE DOMAIN CONTROLLER",
    "INSUFFICIENT EVIDENCE",
):
    print(f"{label}: {counts[label]}")

print("\nIMPORTANT:")
print("Port-based results are only candidates, not proof.")
print("Confirm using LDAP RootDSE, AD DNS SRV records, and domain information.")
PY

echo
echo "Scan complete."
