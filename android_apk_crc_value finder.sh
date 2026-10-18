#!/usr/bin/env bash
# android_apk_crc_finder.sh
# Pull APKs exposed by Android's package manager and calculate CRC-32 of each
# complete APK file (not CRCs of entries inside the APK/ZIP archive).
# Use only on devices you own or are explicitly authorized to examine.

set -uo pipefail
umask 077

if [[ $# -ne 1 || -z "${1:-}" ]]; then
    printf 'Usage: %s PHONE_IP\nExample: %s 192.168.10.121\n' "$0" "$0"
    exit 1
fi

PHONE_IP="$1"
PORT=5555
MAX_RETRIES=5
RETRY_DELAY=3

if [[ "$PHONE_IP" == *[[:space:]]* ]] || ! python3 - "$PHONE_IP" <<'PY' >/dev/null 2>&1
import ipaddress, sys
ipaddress.IPv4Address(sys.argv[1])
PY
then
    printf '[ERROR] Invalid IPv4 address. Enter it without spaces, e.g. 192.168.10.121\n' >&2
    exit 1
fi

command -v python3 >/dev/null 2>&1 || {
    printf '[ERROR] python3 is required to calculate CRC-32.\n' >&2
    exit 1
}

if ! command -v adb >/dev/null 2>&1; then
    printf '[INFO] ADB not found; attempting to install it...\n'
    if ! command -v apt-get >/dev/null 2>&1; then
        printf '[ERROR] Install Android platform-tools (adb) and rerun.\n' >&2
        exit 1
    fi
    if [[ "$(id -u)" -eq 0 ]]; then
        apt-get update && apt-get install -y adb || exit 1
    elif command -v sudo >/dev/null 2>&1; then
        sudo apt-get update && sudo apt-get install -y adb || exit 1
    else
        printf '[ERROR] Cannot install ADB without administrator privileges.\n' >&2
        exit 1
    fi
fi

DEVICE="${PHONE_IP}:${PORT}"
DEST="$HOME/android_apk_crc_${PHONE_IP}"
APK_DIR="$DEST/apks"
REPORT="$DEST/apk_crc_report.txt"
PACKAGES="$DEST/packages.txt"
mkdir -p "$APK_DIR" || {
    printf '[ERROR] Cannot create destination: %s\n' "$APK_DIR" >&2
    exit 1
}
: > "$REPORT"

report() {
    printf '%s\n' "$*" | tee -a "$REPORT"
}

connect_device() {
    local attempt state
    for ((attempt=1; attempt<=MAX_RETRIES; attempt++)); do
        adb connect "$DEVICE" >/dev/null 2>&1 || true
        state="$(adb -s "$DEVICE" get-state 2>/dev/null || true)"
        if [[ "$state" == "device" ]]; then
            return 0
        fi
        printf '[WARN] ADB state: %s; retry %s/%s\n' "${state:-unavailable}" "$attempt" "$MAX_RETRIES" >&2
        sleep "$RETRY_DELAY"
    done
    return 1
}

adb start-server >/dev/null 2>&1 || true
printf '[INFO] Connecting to %s ...\n' "$DEVICE"
connect_device || {
    printf '[ERROR] Cannot connect. Check IP, port 5555, wireless debugging, and authorization.\n' >&2
    exit 1
}

# Query package list with retries so a transient "error: closed" does not
# silently turn into an empty or partial package list.
list_ok=false
for ((attempt=1; attempt<=MAX_RETRIES; attempt++)); do
    if adb -s "$DEVICE" shell pm list packages > "$DEST/packages_raw.tmp" 2> "$DEST/packages_error.tmp"; then
        tr -d '\r' < "$DEST/packages_raw.tmp" | sed -n 's/^package://p' > "$PACKAGES"
        if [[ -s "$PACKAGES" ]]; then
            list_ok=true
            break
        fi
    fi
    printf '[WARN] Could not obtain package list; retry %s/%s\n' "$attempt" "$MAX_RETRIES" >&2
    connect_device || true
    sleep "$RETRY_DELAY"
done
[[ "$list_ok" == true ]] || {
    printf '[ERROR] Could not retrieve installed packages. See %s\n' "$DEST/packages_error.tmp" >&2
    exit 1
}

package_count="$(grep -c . "$PACKAGES" 2>/dev/null || true)"
report '============================================================'
report 'ANDROID APK CRC-32 REPORT'
report "Device: $DEVICE"
report "Installed packages listed: $package_count"
report 'CRC-32 is calculated over each complete downloaded APK file.'
report '============================================================'
report ''

pkg_index=0
paths_found=0
apk_ok=0
path_fail=0
pull_fail=0

while IFS= read -r package || [[ -n "$package" ]]; do
    [[ -n "$package" ]] || continue
    pkg_index=$((pkg_index + 1))
    printf '\n[PACKAGE %s/%s] %s\n' "$pkg_index" "$package_count" "$package"

    # Query the package's base APK and any split APKs, retrying transient errors.
    path_ok=false
    path_output="$DEST/.paths.tmp"
    for ((attempt=1; attempt<=MAX_RETRIES; attempt++)); do
        if adb -s "$DEVICE" shell pm path "$package" > "$path_output" 2> "$DEST/.pm_path_error.tmp"; then
            tr -d '\r' < "$path_output" > "$path_output.clean"
            mv "$path_output.clean" "$path_output"
            if grep -q '^package:' "$path_output"; then
                path_ok=true
                break
            fi
        fi
        printf '[WARN] pm path failed for %s (attempt %s/%s)\n' "$package" "$attempt" "$MAX_RETRIES" >&2
        connect_device || true
        sleep "$RETRY_DELAY"
    done

    if [[ "$path_ok" != true ]]; then
        report "Package: $package | Status: NO_APK_PATH"
        path_fail=$((path_fail + 1))
        continue
    fi

    mapfile -t remote_paths < <(sed -n 's/^package://p' "$path_output")
    for remote in "${remote_paths[@]}"; do
        [[ -n "$remote" ]] || continue
        paths_found=$((paths_found + 1))
        base="$(basename "$remote")"
        local_apk="$APK_DIR/${package}_${base}"

        printf '  Remote APK: %s\n' "$remote"
        pull_ok=false
        if [[ -s "$local_apk" ]]; then
            pull_ok=true
            printf '  Using previously downloaded APK: %s\n' "$local_apk"
        else
            for ((attempt=1; attempt<=MAX_RETRIES; attempt++)); do
                connect_device || true
                printf '  Pull attempt %s/%s...\n' "$attempt" "$MAX_RETRIES"
                if adb -s "$DEVICE" pull "$remote" "$local_apk.tmp"; then
                    if [[ -s "$local_apk.tmp" ]]; then
                        mv -f "$local_apk.tmp" "$local_apk"
                        pull_ok=true
                        break
                    fi
                    rm -f "$local_apk.tmp"
                else
                    rm -f "$local_apk.tmp"
                fi
                sleep "$RETRY_DELAY"
            done
        fi

        if [[ "$pull_ok" != true ]]; then
            printf '[WARN] Could not pull %s\n' "$remote" >&2
            report "Package: $package | APK: $remote | Status: PULL_FAILED"
            pull_fail=$((pull_fail + 1))
            continue
        fi

        crc="$(python3 - "$local_apk" <<'PY'
import sys, zlib
crc = 0
with open(sys.argv[1], "rb") as f:
    for block in iter(lambda: f.read(1024 * 1024), b""):
        crc = zlib.crc32(block, crc)
print(f"{crc & 0xffffffff:08X}")
PY
)"
        if [[ -z "$crc" ]]; then
            report "Package: $package | APK: $remote | Status: CRC_FAILED"
            pull_fail=$((pull_fail + 1))
            continue
        fi

        size="$(wc -c < "$local_apk" | tr -d ' ')"
        report "Package : $package"
        report "APK path: $remote"
        report "Local   : $local_apk"
        report "Size    : $size bytes"
        report "CRC-32  : $crc"
        report 'Status  : OK'
        report '------------------------------------------------------------'
        apk_ok=$((apk_ok + 1))
    done
done < "$PACKAGES"

report ''
report '========================== SUMMARY ========================='
report "Installed packages listed : $package_count"
report "APK paths returned        : $paths_found"
report "APKs downloaded/hashed    : $apk_ok"
report "Packages with path issues : $path_fail"
report "APK pull/hash failures    : $pull_fail"
report "APK directory             : $APK_DIR"
report "Readable text report      : $REPORT"
report '============================================================'
printf '\n[INFO] Results were displayed on screen and saved to:\n%s\n' "$REPORT"
adb disconnect "$DEVICE" >/dev/null 2>&1 || true
