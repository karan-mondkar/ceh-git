
#!/bin/bash
set -euo pipefail

# ==========================================
# Arguments
# ==========================================
USERNAME_FILE="${1:-}"
WORDLIST="${2:-}"
TARGET="${3:-}"

RESULTS_DIR="${HOME}/sql_lab_results"
SCAN_FILE="$RESULTS_DIR/database_scan.txt"
SCAN_LOG="$RESULTS_DIR/database_scan.log"

# ==========================================
# Validate Inputs
# ==========================================
if [[ -z "$USERNAME_FILE" || -z "$WORDLIST" || -z "$TARGET" ]]; then
    echo "Usage: $0 <users_file> <wordlist> <target_ip_or_subnet>"
    exit 1
fi

if [[ ! -r "$USERNAME_FILE" || ! -f "$USERNAME_FILE" ]]; then
    echo "Error: Username file is missing or unreadable."
    exit 1
fi

if [[ ! -r "$WORDLIST" || ! -f "$WORDLIST" ]]; then
    echo "Error: Wordlist is missing or unreadable."
    exit 1
fi

if ! command -v nmap >/dev/null 2>&1; then
    echo "Error: Nmap is not installed."
    exit 1
fi

mkdir -p -- "$RESULTS_DIR"

# ==========================================
# Database Service Discovery
# ==========================================
echo "=========================================="
echo "DATABASE SERVICE DISCOVERY"
echo "=========================================="
echo "Target: $TARGET"
echo

echo "[1] Scanning common database TCP ports..."


NMAP_ARGS=(
    -n
    -Pn
    -sT
    -sV
    --open
    -p 1433,1521,3306,5432,6379,9042,27017
    -oN "$SCAN_FILE"
    "$TARGET"
)

if nmap "${NMAP_ARGS[@]}" >"$SCAN_LOG" 2>&1; then
    echo "[+] Scan completed."
else
    status=$?
    echo "[-] Nmap failed with exit code $status."
    cat "$SCAN_LOG"
    exit "$status"
fi

if [[ ! -s "$SCAN_FILE" ]]; then
    echo "[-] Nmap report is missing or empty."
    cat "$SCAN_LOG"
    exit 1
fi

# ==========================================
# Display Detected Database Services
# ==========================================
echo
echo "[2] Database services detected"
echo "------------------------------------------"

if grep -Eq '^[0-9]+/tcp[[:space:]]+open' "$SCAN_FILE"; then
    awk '/^[0-9]+\/tcp[[:space:]]+open/ {print}' "$SCAN_FILE"
else
    echo "No open database TCP ports were detected."
fi

# ==========================================
# Stage 3: Service-Specific Placeholders
# ==========================================
echo
echo "[3] Service-specific authentication checks"
echo "------------------------------------------"

# Microsoft SQL Server — TCP 1433
if grep -Eq '^1433/tcp[[:space:]]+open' "$SCAN_FILE"; then
    echo "[+] SQL Server port 1433 detected."
    hydra -L "$USERNAME_FILE" -P "$WORDLIST" mssql://"$TARGET":1433
    # testing procedure here after confirming the service.
fi

# Oracle Database — TCP 1521
if grep -Eq '^1521/tcp[[:space:]]+open' "$SCAN_FILE"; then
    echo "[+] Oracle Database port 1521 detected."
    # TODO: Add your authorized Oracle authentication
    # testing procedure here after confirming the service.
fi

# MySQL / MariaDB — TCP 3306
if grep -Eq '^3306/tcp[[:space:]]+open' "$SCAN_FILE"; then
    echo "[+] MySQL/MariaDB port 3306 detected."
    hydra -L "$USERNAME_FILE" -P "$WORDLIST" mysql://"$TARGET":3306

    # testing procedure here after confirming the service.
fi

# PostgreSQL — TCP 5432
if grep -Eq '^5432/tcp[[:space:]]+open' "$SCAN_FILE"; then
    echo "[+] PostgreSQL port 5432 detected."
    hydra -L "$USERNAME_FILE" -P "$WORDLIST" postgresql://"$TARGET":5432
    # testing procedure here after confirming the service.
fi
# MongoDB — TCP 27017
if grep -Eq '^27017/tcp[[:space:]]+open' "$SCAN_FILE"; then
    echo "[+] MongoDB port 27017 detected."
    hydra -L "$USERNAME_FILE" -P "$WORDLIST" mongo://"$TARGET":27017

    # an appropriate authorized MongoDB assessment tool.
fi

# ==========================================
# Stage 4: Results
# ==========================================
echo
echo "=========================================="
echo "DISCOVERY COMPLETE"
echo "=========================================="
echo "Target:          $TARGET"
echo "Scan report:     $SCAN_FILE"
echo "Diagnostic log:  $SCAN_LOG"
echo "Username file:   $USERNAME_FILE"
echo "Password list:   $WORDLIST"
echo
echo "Review each detected service before selecting"
echo "an authentication-testing or database client."
echo "=========================================="
