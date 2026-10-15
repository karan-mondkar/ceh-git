
#!/usr/bin/env bash
set -uo pipefail

DEST="$HOME/adb_recovered"
mkdir -p "$DEST"

# Input 1: Android phone IP
# Input 2: Filename or extension
PHONE_IP="${1:-}"
PATTERN="${2:-}"

if [[ -z "$PHONE_IP" || -z "$PATTERN" ]]; then
    echo "Usage: $0 <phone-ip> <filename-or-extension>"
    echo "Examples:"
    echo "  $0 192.168.1.50 report.pdf"
    echo "  $0 192.168.1.50 .pdf"
    exit 1
fi

if ! command -v adb >/dev/null 2>&1; then
    echo "[ERROR] Install ADB: sudo apt install adb"
    exit 1
fi

if [[ "$PATTERN" == *"/"* ]]; then
    echo "[ERROR] Supply a filename or extension, not a path."
    exit 1
fi

echo "[*] Connecting to authorized device at $PHONE_IP:5555"
adb start-server >/dev/null

if ! adb connect "$PHONE_IP:5555"; then
    echo "[ERROR] ADB connection failed."
    exit 1
fi

DEVICE="$PHONE_IP:5555"

if [[ "$(adb -s "$DEVICE" get-state 2>/dev/null)" != "device" ]]; then
    echo "[ERROR] Device unavailable or ADB authorization missing."
    echo "Enable and authorize ADB TCP/IP on the phone first."
    exit 1
fi

echo "[*] Searching accessible shared storage..."

LIST="$DEST/file_list.txt"
adb -s "$DEVICE" shell \
    'find /sdcard -type f 2>/dev/null' |
    tr -d '\r' > "$LIST"

FOUND=0

while IFS= read -r REMOTE; do
    [[ -z "$REMOTE" ]] && continue
    BASE="${REMOTE##*/}"

    if [[ "$PATTERN" == .* ]]; then
        [[ "$BASE" == *"$PATTERN" ]] || continue
    else
        [[ "$BASE" == "$PATTERN" ]] || continue
    fi

    FOUND=$((FOUND + 1))
    LOCAL="$DEST/$BASE"

    if [[ -e "$LOCAL" ]]; then
        LOCAL="$DEST/${FOUND}_$BASE"
    fi

    echo "[+] Found: $REMOTE"

    if adb -s "$DEVICE" pull "$REMOTE" "$LOCAL"; then
        SIZE=$(wc -c < "$LOCAL")
        echo "[+] Saved: $LOCAL"
        echo "[+] Size: $SIZE bytes"
    else
        echo "[!] Could not retrieve: $REMOTE"
    fi
done < "$LIST"

if (( FOUND == 0 )); then
    echo "[!] No matching files in accessible shared storage."
fi

echo "[*] Finished. Output directory: $DEST"
adb disconnect "$DEVICE" >/dev/null 2>&1 || true
