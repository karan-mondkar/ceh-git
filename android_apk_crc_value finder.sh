from pathlib import Path

script = r'''#!/usr/bin/env bash
# android_apk_crc.sh
# Extract APK files exposed by Android's package manager over ADB and calculate
# the CRC-32 of each pulled APK file. Use only on devices you own or are
# explicitly authorized to examine.

set -Eeuo pipefail
umask 077

PHONE_IP="${1:-}"
ADB_PORT=5555
MAX_RETRIES=5
RETRY_DELAY=3

log()  { printf '[INFO] %s\n' "$*"; }
warn() { printf '[WARN] %s\n' "$*" >&2; }
die()  { printf '[ERROR] %s\n' "$*" >&2; exit 1; }

if [[ -z "$PHONE_IP" || "$#" -ne 1 ]]; then
    echo "Usage: $0 PHONE_IP"
    echo "Example: $0 192.168.10.121"
    exit 1
fi

command -v python3 >/dev/null 2>&1 ||
    die "python3 is required to calculate standard CRC-32 values."

if ! command -v adb >/dev/null 2>&1; then
    log "ADB is missing. Attempting installation..."
    command -v apt-get >/dev/null 2>&1 ||
        die "Install Android platform-tools (adb) and rerun."
    if [[ "$(id -u)" -eq 0 ]]; then
        apt-get update && apt-get install -y adb ||
            die "ADB installation failed."
    elif command -v sudo >/dev/null 2>&1; then
        sudo apt-get update && sudo apt-get install -y adb ||
            die "ADB installation failed."
    else
        die "Cannot install ADB without administrator privileges."
    fi
fi

DEVICE="${PHONE_IP}:${ADB_PORT}"
SAFE_IP="${PHONE_IP//[^a-zA-Z0-9_.-]/_}"
DEST="$HOME/android_apk_crc_${SAFE_IP}"
APK_DIR="$DEST/apks"
REPORT="$DEST/apk_crc_report.csv"
MATCHES="$DEST/crc_ending_614c.txt"

mkdir -p "$APK_DIR"
adb start-server >/dev/null 2>&1 || true

connected=false
for ((attempt=1; attempt<=MAX_RETRIES; attempt++)); do
    log "Connecting to $DEVICE ($attempt/$MAX_RETRIES)..."
    adb connect "$DEVICE" 2>&1 || true
    state="$(adb -s "$DEVICE" get-state 2>/dev/null || true)"
    if [[ "$state" == "device" ]]; then
        connected=true
        break
    fi
    warn "ADB state: ${state:-unavailable}. Unlock the device and approve debugging if prompted."
    sleep "$RETRY_DELAY"
done
[[ "$connected" == true ]] ||
    die "Could not connect. Check the IP, port 5555, wireless debugging, and authorization."

log "Connected. Listing installed packages..."
PKG_FILE="$DEST/packages.txt"
if ! adb -s "$DEVICE" shell pm list packages > "$PKG_FILE.tmp"; then
    die "Could not list installed packages."
fi
tr -d '\r' < "$PKG_FILE.tmp" | sed -n 's/^package://p' > "$PKG_FILE"
rm -f "$PKG_FILE.tmp"

package_count="$(grep -c . "$PKG_FILE" || true)"
(( package_count > 0 )) || die "No installed packages were returned."

printf 'package,remote_apk,local_apk,crc32,status\n' > "$REPORT"
: > "$MATCHES"

total=0
copied=0
failed=0
matches=0

while IFS= read -r pkg || [[ -n "$pkg" ]]; do
    [[ -n "$pkg" ]] || continue
    paths_file="$DEST/.paths.tmp"

    if ! adb -s "$DEVICE" shell pm path "$pkg" > "$paths_file" 2>/dev/null; then
        warn "Could not get APK path for $pkg"
        failed=$((failed + 1))
        continue
    fi

    tr -d '\r' < "$paths_file" > "$paths_file.clean"
    mv "$paths_file.clean" "$paths_file"

    while IFS= read -r line || [[ -n "$line" ]]; do
        [[ "$line" == package:* ]] || continue
        remote="${line#package:}"
        base="$(basename "$remote")"
        local_file="$APK_DIR/${pkg}_${base}"
        total=$((total + 1))

        # Skip an already-pulled file only if it is non-empty.
        if [[ -s "$local_file" ]]; then
            log "Already pulled: $pkg ($base); recalculating CRC."
        else
            log "Pulling $pkg ($base)..."
            if ! adb -s "$DEVICE" pull "$remote" "$local_file"; then
                warn "Pull failed: $pkg ($remote)"
                rm -f "$local_file"
                printf '"%s","%s","%s","","PULL_FAILED"\n' \
                    "$pkg" "$remote" "$local_file" >> "$REPORT"
                failed=$((failed + 1))
                continue
            fi
        fi

        crc="$(python3 -c 'import sys,zlib; c=0
with open(sys.argv[1], "rb") as f:
    for block in iter(lambda: f.read(1024*1024), b""):
        c = zlib.crc32(block, c)
print(f"{c & 0xffffffff:08x}")' "$local_file")"
        crc="${crc,,}"
        status="OK"
        if [[ "$crc" == *614c ]]; then
            status="MATCH_ENDS_614C"
            matches=$((matches + 1))
            printf 'MATCH: package=%s CRC32=%s file=%s remote=%s\n' \
                "$pkg" "$crc" "$local_file" "$remote" | tee -a "$MATCHES"
        fi

        # CSV-quote fields by doubling any embedded quotes.
        csv_pkg="${pkg//\"/\"\"}"
        csv_remote="${remote//\"/\"\"}"
        csv_local="${local_file//\"/\"\"}"
        printf '"%s","%s","%s","%s","%s"\n' \
            "$csv_pkg" "$csv_remote" "$csv_local" "$crc" "$status" >> "$REPORT"
        printf '[CRC32] %-45s %s  %s\n' "$pkg" "$crc" "$base"
        copied=$((copied + 1))
    done < "$paths_file"

    rm -f "$paths_file"
done < "$PKG_FILE"

printf '\n========== SUMMARY ==========\n'
printf 'Installed packages: %s\n' "$package_count"
printf 'APK paths processed: %s\n' "$total"
printf 'APKs copied and hashed: %s\n' "$copied"
printf 'Failed paths: %s\n' "$failed"
printf 'CRC32 values ending in 614c: %s\n' "$matches"
printf 'APK folder: %s\n' "$APK_DIR"
printf 'Full CRC report: %s\n' "$REPORT"
printf 'Matching CRC entries: %s\n' "$MATCHES"
printf '=============================\n'

if (( matches == 0 )); then
    log "No pulled APK file's whole-file CRC-32 ended with 614c."
    log "If the task refers to a ZIP-entry CRC inside an APK, that is a different check."
fi

adb disconnect "$DEVICE" >/dev/null 2>&1 || true
exit 0
'''
path = Path("/mnt/data/android_apk_crc.sh")
path.write_text(script, encoding="utf-8")
path.chmod(0o755)
print(f"Created {path}")
