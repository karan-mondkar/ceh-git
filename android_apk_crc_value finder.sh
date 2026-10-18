from pathlib import Path

script = r'''#!/usr/bin/env bash
# android_apk_crc.sh
# List installed packages, pull APK files accessible through ADB, calculate
# each APK's CRC-32, print results live, and save a readable text report.
# Use only on devices you own or are authorized to examine.

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
    printf 'Usage: %s PHONE_IP\nExample: %s 192.168.10.121\n' "$0" "$0"
    exit 1
fi

command -v python3 >/dev/null 2>&1 || die "python3 is required for CRC-32 calculation."

if ! command -v adb >/dev/null 2>&1; then
    log "ADB is missing. Attempting installation..."
    command -v apt-get >/dev/null 2>&1 || die "Install Android platform-tools (adb) and rerun."
    if [[ "$(id -u)" -eq 0 ]]; then
        apt-get update && apt-get install -y adb || die "ADB installation failed."
    elif command -v sudo >/dev/null 2>&1; then
        sudo apt-get update && sudo apt-get install -y adb || die "ADB installation failed."
    else
        die "Cannot install ADB without administrator privileges."
    fi
fi

DEVICE="${PHONE_IP}:${ADB_PORT}"
SAFE_IP="${PHONE_IP//[^a-zA-Z0-9_.-]/_}"
DEST="$HOME/android_apk_crc_${SAFE_IP}"
APK_DIR="$DEST/apks"
REPORT="$DEST/apk_crc_report.txt"
mkdir -p "$APK_DIR"
: > "$REPORT"

# Print to the screen and save the same report lines in a plain text file.
report() {
    printf '%s\n' "$*" | tee -a "$REPORT"
}

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
[[ "$connected" == true ]] || die "Could not connect. Check the IP, port 5555, wireless debugging, and authorization."

report "============================================================"
report "ANDROID APK CRC-32 REPORT"
report "Device: $DEVICE"
report "============================================================"
report ""

PKG_FILE="$DEST/packages.txt"
if ! adb -s "$DEVICE" shell pm list packages > "$PKG_FILE.tmp"; then
    die "Could not list installed packages."
fi
tr -d '\r' < "$PKG_FILE.tmp" | sed -n 's/^package://p' > "$PKG_FILE"
rm -f "$PKG_FILE.tmp"
package_count="$(grep -c . "$PKG_FILE" || true)"
(( package_count > 0 )) || die "No installed packages were returned."

report "Installed packages found: $package_count"
report ""
report "APK CRC-32 results:"
report "------------------------------------------------------------"

total=0
copied=0
failed=0
pkg_index=0

while IFS= read -r pkg || [[ -n "$pkg" ]]; do
    [[ -n "$pkg" ]] || continue
    pkg_index=$((pkg_index + 1))
    paths_file="$DEST/.paths.tmp"

    if ! adb -s "$DEVICE" shell pm path "$pkg" > "$paths_file" 2>/dev/null; then
        warn "Could not get APK path for $pkg"
        report "[FAILED] Package: $pkg | Reason: could not retrieve APK path"
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

        report "Package : $pkg"
        report "APK path: $remote"

        if [[ ! -s "$local_file" ]]; then
            log "Pulling $pkg ($base)..."
            if ! adb -s "$DEVICE" pull "$remote" "$local_file"; then
                warn "Pull failed: $pkg ($remote)"
                rm -f "$local_file"
                report "Local   : NOT COPIED"
                report "CRC-32  : unavailable"
                report "Status  : FAILED"
                report "------------------------------------------------------------"
                failed=$((failed + 1))
                continue
            fi
        else
            log "Already pulled: $pkg ($base); recalculating CRC-32."
        fi

        crc="$(python3 -c 'import sys,zlib
c=0
with open(sys.argv[1], "rb") as f:
    for block in iter(lambda: f.read(1024*1024), b""):
        c=zlib.crc32(block,c)
print(f"{c & 0xffffffff:08X}")' "$local_file")"

        report "Local   : $local_file"
        report "Size    : $(wc -c < "$local_file" | tr -d ' ') bytes"
        report "CRC-32  : $crc"
        report "Status  : OK"
        report "------------------------------------------------------------"
        printf '[CRC-32] %s | %s\n' "$pkg" "$crc"
        copied=$((copied + 1))
    done < "$paths_file"
    rm -f "$paths_file"
done < "$PKG_FILE"

report ""
report "======================= SUMMARY ============================"
report "Installed packages : $package_count"
report "APK paths found    : $total"
report "APKs copied/hashed : $copied"
report "Failed APK paths   : $failed"
report "APK directory      : $APK_DIR"
report "Text report        : $REPORT"
report "============================================================"

adb disconnect "$DEVICE" >/dev/null 2>&1 || true
log "Finished. Results were displayed above and saved to $REPORT"
'''
path = Path("/mnt/data/android_apk_crc.sh")
path.write_text(script, encoding="utf-8")
path.chmod(0o755)
import subprocess
check = subprocess.run(["bash", "-n", str(path)], capture_output=True, text=True)
print("Created:", path)
print("bash -n:", "PASS" if check.returncode == 0 else check.stderr)
