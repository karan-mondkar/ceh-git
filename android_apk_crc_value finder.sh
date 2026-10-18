from pathlib import Path
script = r'''#!/usr/bin/env bash
# android_apk_crc.sh
# Enumerate installed packages, query their APK paths, pull accessible APKs,
# calculate CRC-32, print a readable report, and save it as plain text.
# Use only on devices you own or are authorized to examine.

set -uo pipefail
umask 077

PHONE_IP="${1:-}"
PORT=5555
RETRIES=5
DELAY=3

log()  { printf '[INFO] %s\n' "$*"; }
warn() { printf '[WARN] %s\n' "$*" >&2; }
die()  { printf '[ERROR] %s\n' "$*" >&2; exit 1; }

if [[ -z "$PHONE_IP" || "$#" -ne 1 ]]; then
    printf 'Usage: %s PHONE_IP\nExample: %s 192.168.10.121\n' "$0" "$0"
    exit 1
fi

# Reject spaces and malformed IPv4 addresses.
if [[ "$PHONE_IP" == *[[:space:]]* ]] || ! python3 - "$PHONE_IP" <<'PY' >/dev/null 2>&1
import ipaddress, sys
ipaddress.IPv4Address(sys.argv[1])
PY
then
    die "Invalid IPv4 address. Use e.g. 192.168.10.121 with no spaces."
fi

command -v python3 >/dev/null 2>&1 || die "python3 is required for CRC-32."
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

DEVICE="${PHONE_IP}:${PORT}"
DEST="$HOME/android_apk_crc_${PHONE_IP}"
APK_DIR="$DEST/apks"
REPORT="$DEST/apk_crc_report.txt"
PKG_FILE="$DEST/packages.txt"
mkdir -p "$APK_DIR" || die "Cannot create $APK_DIR"
: > "$REPORT"

report() { printf '%s\n' "$*" | tee -a "$REPORT"; }

adb start-server >/dev/null 2>&1 || true
connected=false
for ((i=1; i<=RETRIES; i++)); do
    log "Connecting to $DEVICE ($i/$RETRIES)..."
    adb connect "$DEVICE" 2>&1 || true
    state="$(adb -s "$DEVICE" get-state 2>/dev/null || true)"
    if [[ "$state" == "device" ]]; then connected=true; break; fi
    warn "ADB state: ${state:-unavailable}; check Wi-Fi debugging and authorization."
    sleep "$DELAY"
done
[[ "$connected" == true ]] || die "Could not connect to $DEVICE."

if ! adb -s "$DEVICE" shell pm list packages > "$DEST/packages_raw.txt" 2>"$DEST/packages_error.txt"; then
    die "Could not list installed packages; see $DEST/packages_error.txt"
fi
tr -d '\r' < "$DEST/packages_raw.txt" | sed -n 's/^package://p' > "$PKG_FILE"
package_count="$(grep -c . "$PKG_FILE" 2>/dev/null || true)"
[[ "$package_count" -gt 0 ]] || die "No package names returned by Android."

report "============================================================"
report "ANDROID APK CRC-32 REPORT"
report "Device: $DEVICE"
report "Installed packages: $package_count"
report "============================================================"
report ""

paths_found=0
copied=0
path_fail=0
pull_fail=0
pkg_num=0

while IFS= read -r pkg || [[ -n "$pkg" ]]; do
    [[ -n "$pkg" ]] || continue
    pkg_num=$((pkg_num + 1))
    printf '[PACKAGE %s/%s] %s\n' "$pkg_num" "$package_count" "$pkg"

    # Reconnect if ADB closed between package requests.
    state="$(adb -s "$DEVICE" get-state 2>/dev/null || true)"
    if [[ "$state" != "device" ]]; then
        log "Connection dropped; reconnecting..."
        reconnected=false
        for ((i=1; i<=RETRIES; i++)); do
            adb connect "$DEVICE" >/dev/null 2>&1 || true
            state="$(adb -s "$DEVICE" get-state 2>/dev/null || true)"
            if [[ "$state" == "device" ]]; then reconnected=true; break; fi
            sleep "$DELAY"
        done
        if [[ "$reconnected" != true ]]; then
            warn "Still disconnected; cannot query $pkg"
            path_fail=$((path_fail + 1))
            continue
        fi
    fi

    path_file="$DEST/.path_${BASHPID}.tmp"
    if ! adb -s "$DEVICE" shell pm path "$pkg" > "$path_file" 2>"$DEST/.pm_path_error.tmp"; then
        warn "pm path command failed for $pkg"
        path_fail=$((path_fail + 1))
        rm -f "$path_file"
        continue
    fi

    tr -d '\r' < "$path_file" > "$path_file.clean"
    mv "$path_file.clean" "$path_file"
    mapfile -t remote_paths < <(sed -n 's/^package://p' "$path_file")
    rm -f "$path_file"

    if ((${#remote_paths[@]} == 0)); then
        warn "No package: path returned for $pkg"
        path_fail=$((path_fail + 1))
        continue
    fi

    for remote in "${remote_paths[@]}"; do
        [[ -n "$remote" ]] || continue
        paths_found=$((paths_found + 1))
        base="$(basename "$remote")"
        local_file="$APK_DIR/${pkg}_${base}"
        printf '  APK path: %s\n' "$remote"

        if [[ ! -s "$local_file" ]]; then
            if ! adb -s "$DEVICE" pull "$remote" "$local_file"; then
                warn "Pull failed for $pkg ($remote)"
                rm -f "$local_file"
                report "Package: $pkg | APK: $remote | Status: PULL_FAILED"
                pull_fail=$((pull_fail + 1))
                continue
            fi
        fi

        crc="$(python3 - "$local_file" <<'PY'
import sys, zlib
crc = 0
with open(sys.argv[1], "rb") as f:
    for block in iter(lambda: f.read(1024 * 1024), b""):
        crc = zlib.crc32(block, crc)
print(f"{crc & 0xffffffff:08X}")
PY
)" || {
            warn "CRC calculation failed for $local_file"
            pull_fail=$((pull_fail + 1))
            continue
        }

        size="$(wc -c < "$local_file" | tr -d ' ')"
        report "Package : $pkg"
        report "APK path: $remote"
        report "Local   : $local_file"
        report "Size    : $size bytes"
        report "CRC-32  : $crc"
        report "Status  : OK"
        report "------------------------------------------------------------"
        copied=$((copied + 1))
    done
done < "$PKG_FILE"

report ""
report "========================= SUMMARY ========================="
report "Installed packages        : $package_count"
report "APK paths returned        : $paths_found"
report "APKs copied and hashed    : $copied"
report "Package path failures     : $path_fail"
report "APK pull/CRC failures     : $pull_fail"
report "APK directory             : $APK_DIR"
report "Readable report            : $REPORT"
report "============================================================"

log "Finished. Report displayed above and saved to $REPORT"
adb disconnect "$DEVICE" >/dev/null 2>&1 || true
'''
p=Path("/mnt/data/android_apk_crc.sh")
p.write_text(script, encoding="utf-8")
p.chmod(0o755)
import subprocess
r=subprocess.run(["bash","-n",str(p)],capture_output=True,text=True)
print("Created:", p)
print("bash -n:", "PASS" if r.returncode==0 else r.stderr)
