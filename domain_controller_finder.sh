
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
        echo "[ERROR] Missing required command: $cmd"
        echo "Install with: sudo apt install nmap python3"
        exit 1
    fi
done

REPORT="dc_finder_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$REPORT"
XML="$REPORT/initial_scan.xml"

PORTS="53,88,135,139,389,445,464,636,3268,3269,9389"

echo "=================================================="
echo " ACTIVE DIRECTORY / DOMAIN CONTROLLER FINDER"
echo "=================================================="
echo "Network: $NETWORK"
echo "Report:  $REPORT"
echo

if ! nmap -n -Pn -sT --open -T3 --reason \
    -p "$PORTS" -oX "$XML" "$NETWORK"; then
    echo "[ERROR] Initial Nmap scan failed."
    exit 1
fi

python3 - "$XML" "$REPORT" <<'PY'
import sys
import os
import re
import subprocess
import xml.etree.ElementTree as ET
from collections import Counter

xml_file, report_dir = sys.argv[1:3]

PORT_NAMES = {
    53: "DNS",
    88: "Kerberos",
    135: "MS RPC",
    139: "NetBIOS",
    389: "LDAP",
    445: "SMB",
    464: "Kerberos password service",
    636: "LDAPS",
    3268: "Global Catalog",
    3269: "Global Catalog TLS",
    9389: "AD Web Services",
}

AD_PORTS = {88, 389, 464, 636, 3268, 3269, 9389}

def get_open_tcp_ports(host):
    result = set()
    for port in host.findall("./ports/port"):
        state = port.find("state")
        if (port.get("protocol") == "tcp"
                and state is not None
                and state.get("state") == "open"):
            try:
                result.add(int(port.get("portid")))
            except (TypeError, ValueError):
                pass
    return result

def get_ipv4(host):
    for address in host.findall("address"):
        if address.get("addrtype") == "ipv4":
            return address.get("addr")
    return None

def run_rootdse(ip, ports, filename):
    # Query only ports found open in the initial scan.
    ldap_ports = [p for p in (389, 636, 3268, 3269) if p in ports]
    if not ldap_ports:
        return ""

    cmd = [
        "nmap", "-n", "-Pn", "-sT",
        "-p", ",".join(map(str, ldap_ports)),
        "--script", "ldap-rootdse",
        "--script-timeout", "8s",
        "--host-timeout", "25s",
        "-oN", "-", ip,
    ]

    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=35
        )
        output = (result.stdout or "") + "\n" + (result.stderr or "")
    except subprocess.TimeoutExpired:
        output = "[LDAP probe timed out]\n"
    except OSError as exc:
        output = f"[LDAP probe error: {exc}]\n"

    with open(filename, "w", encoding="utf-8") as f:
        f.write(output)

    return output

def extract_field(output, field):
    # Handles common Nmap ldap-rootdse output formats.
    pattern = rf"(?im)^\s*\|?\s*{re.escape(field)}\s*:\s*(.*?)\s*$"
    match = re.search(pattern, output)
    return match.group(1).strip() if match else ""

def context_to_domain(context):
    if not context:
        return ""
    parts = re.findall(r"(?i)(?:^|,)\s*DC\s*=\s*([^,]+)", context)
    return ".".join(parts)

def classify(ports, ldap_output, srv_found):
    default_nc = extract_field(ldap_output, "defaultNamingContext")
    root_nc = extract_field(ldap_output, "rootDomainNamingContext")
    dns_host = extract_field(ldap_output, "dnsHostName")
    ds_service = extract_field(ldap_output, "dsServiceName")
    naming_contexts = extract_field(ldap_output, "namingContexts")
    global_catalog_ready = extract_field(ldap_output, "isGlobalCatalogReady")

    has_domain_context = bool(default_nc or root_nc)
    has_server_identity = bool(dns_host or ds_service)
    has_ldap_evidence = has_domain_context and has_server_identity
    kerberos = 88 in ports or 464 in ports
    ldap = bool({389, 636, 3268, 3269} & ports)
    smb = bool({139, 445} & ports)
    gc = bool({3268, 3269} & ports)
    adws = 9389 in ports

    evidence = []

    if kerberos:
        evidence.append("Kerberos port open")
    if ldap:
        evidence.append("LDAP/LDAPS/Global Catalog port open")
    if smb:
        evidence.append("SMB/NetBIOS port open")
    if gc:
        evidence.append("Global Catalog port open")
    if adws:
        evidence.append("AD Web Services port open")
    if default_nc:
        evidence.append("LDAP defaultNamingContext returned")
    if root_nc:
        evidence.append("LDAP rootDomainNamingContext returned")
    if dns_host:
        evidence.append("LDAP dnsHostName returned")
    if ds_service:
        evidence.append("LDAP dsServiceName returned")
    if srv_found:
        evidence.append("AD-related DNS SRV record resolved")

    if has_ldap_evidence:
        label = "STRONG EVIDENCE: ACTIVE DIRECTORY DOMAIN CONTROLLER"
        reason = (
            "LDAP returned domain naming context information and "
            "a directory-server identity. This strongly supports an "
            "Active Directory domain controller, but should be "
            "validated against the lab/domain configuration."
        )
    elif (kerberos and ldap and (smb or gc or adws)) or (
        srv_found and (kerberos or ldap)
    ):
        label = "PROBABLE DOMAIN CONTROLLER"
        reason = (
            "Multiple services or DNS records are consistent with "
            "Active Directory, but LDAP identity evidence was incomplete."
        )
    elif ldap or kerberos or gc or adws:
        label = "POSSIBLE DOMAIN CONTROLLER"
        reason = (
            "Some Active Directory-related services are open, "
            "but the available evidence is insufficient to identify a DC."
        )
    else:
        label = "INSUFFICIENT EVIDENCE"
        reason = (
            "The discovered ports do not establish that this host "
            "is a domain controller."
        )

    return label, reason, evidence, default_nc, root_nc, dns_host

try:
    root = ET.parse(xml_file).getroot()
except (OSError, ET.ParseError) as exc:
    print(f"[ERROR] Could not parse Nmap XML: {exc}")
    sys.exit(1)

hosts = []
for host in root.findall("host"):
    status = host.find("status")
    if status is None or status.get("state") != "up":
        continue

    ip = get_ipv4(host)
    ports = get_open_tcp_ports(host)

    if ip and ports:
        hosts.append((ip, ports))

def ip_key(item):
    return tuple(int(x) for x in item[0].split("."))

hosts.sort(key=ip_key)

if not hosts:
    print("\nNo hosts with the requested open TCP ports were found.")
    print("This does not prove that no domain controller exists.")
    print(f"Initial scan XML: {xml_file}")
    sys.exit(0)

counts = Counter()

print("\n========== DOMAIN CONTROLLER ASSESSMENT ==========")

for index, (ip, ports) in enumerate(hosts, start=1):
    print(f"\n[{index}/{len(hosts)}] Host: {ip}")
    print("Open TCP ports:", ", ".join(map(str, sorted(ports))))

    for port in sorted(ports):
        print(f"  {port}/tcp - {PORT_NAMES.get(port, 'Unknown service')}")

    ldap_output = ""
    if ports & {389, 636, 3268, 3269}:
        ldap_file = os.path.join(report_dir, f"ldap_{ip}.txt")
        print("Checking LDAP RootDSE...")
        ldap_output = run_rootdse(ip, ports, ldap_file)

    # Try DNS SRV discovery when a domain can be derived from LDAP.
    default_nc = extract_field(ldap_output, "defaultNamingContext")
    root_nc = extract_field(ldap_output, "rootDomainNamingContext")
    domain = context_to_domain(default_nc or root_nc)
    srv_found = False

    shutil_which = __import__("shutil").which("dig")

    if domain and shutil_which:
        srv_name = f"_ldap._tcp.dc._msdcs.{domain}"
        try:
            srv = subprocess.run(
                [shutil_which, "+time=2", "+tries=1", "+short",
                 "SRV", srv_name],
                capture_output=True, text=True, timeout=6
            )
            srv_file = os.path.join(report_dir, f"srv_{ip}.txt")
            with open(srv_file, "w", encoding="utf-8") as f:
                f.write(srv.stdout or "")
                if srv.stderr:
                    f.write(srv.stderr)

            records = [
                line.strip() for line in (srv.stdout or "").splitlines()
                if line.strip()
            ]
            srv_found = bool(records)
            if records:
                print(f"AD DNS SRV records for {domain}:")
                for record in records:
                    print(" ", record)
        except (subprocess.TimeoutExpired, OSError):
            pass

    label, reason, evidence, default_nc, root_nc, dns_host = classify(
        ports, ldap_output, srv_found
    )
    counts[label] += 1

    print("Evidence:", "; ".join(evidence) if evidence else "None")
    print("LDAP default naming context:", default_nc or "Not returned")
    print("LDAP root naming context:   ", root_nc or "Not returned")
    print("LDAP DNS host name:          ", dns_host or "Not returned")
    print("ASSESSMENT:", label)
    print("Reason:", reason)

print("\n========== SUMMARY ==========")
print("Hosts assessed:", len(hosts))
for label in (
    "STRONG EVIDENCE: ACTIVE DIRECTORY DOMAIN CONTROLLER",
    "PROBABLE DOMAIN CONTROLLER",
    "POSSIBLE DOMAIN CONTROLLER",
    "INSUFFICIENT EVIDENCE",
):
    print(f"{label}: {counts[label]}")

print("\nLimitations:")
print("* Filtered ports can hide a real domain controller.")
print("* LDAP responses may be restricted or unavailable.")
print("* DNS SRV checks use the resolver configured on this machine.")
print("* Strong evidence is not a substitute for authorized domain validation.")
print(f"\nReports saved to: {report_dir}")
PY

echo
echo "Scan complete."
echo "Review the XML and per-host LDAP reports in: $REPORT"
