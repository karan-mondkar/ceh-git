#!/usr/bin/env bash
# android_apk_crc_finder.sh
#
# Enumerate installed Android packages over ADB, retrieve every APK path
# exposed by package manager (including split APKs), and calculate CRC-32
# over each complete APK file.
#
# Usage:
#   ./android_apk_crc_finder.sh PHONE_IP
# Example:
#   ./android_apk_crc_finder.sh 192.168.10.121
#
# Use only with devices you own or are explicitly authorized to examine.

set -uo pipefail
umask 077

PORT=5555
MAX_RETRIES=5
RETRY_DELAY=3

if [[ $# -ne 1 || -z "${1:-}" ]]; then
    printf 'Usage: %s PHONE_IP\nExample: %s 192.168.10.121\n' "$0" "$0" >&2
    exit 1
fi

PHONE_IP="$1"

if [[ "$PHONE_IP" == *[[:space:]]* ]] || ! python3 - "$PHONE_IP" <<'PY' >/dev/null 2>&1
import ipaddress, sys
ipaddress.IPv4Address(sys.argv[1])
PY
then
    printf '[ERROR] Invalid IPv4 address. Use no spaces, e.g. 192.168.10.121\n' >&2
    exit 1
fi

command -v python3 >/dev/null 2>&1 || {
    printf '[ERROR] python3 is required for CRC-32 calculation.\n' >&2
    exit 1
}

# Install ADB only if it is missing. Failure here is fatal because no device
# operations can be performed without ADB.
if ! command -v adb >/dev/null 2>&1; then
    printf '[INFO] ADB was not found; attempting installation...\n'
    if ! command -v apt-get >/dev/null 2>&1; then
        printf '[ERROR] Install Android platform-tools (adb), then rerun.\n' >&2
        exit 1
    fi
    if [[ "$(id -u)" -eq 0 ]]; then
        apt-get update && apt-get install -y adb || {
            printf '[ERROR] ADB installation failed.\n' >&2
            exit 1
        }
    elif command -v sudo >/dev/null 2>&1; then
        sudo apt-get update && sudo apt-get install -y adb || {
            printf '[ERROR] ADB installation failed.\n' >&2
            exit 1
        }
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
ERROR_LOG="$DEST/errors.log"

if ! mkdir -p "$APK_DIR"; then
    printf '[ERROR] Cannot create output directory: %s\n' "$APK_DIR" >&2
    exit 1
fi

# Start a fresh report and error log for this run.
if ! : > "$REPORT" || ! : > "$ERROR_LOG"; then
    printf '[ERROR] Cannot write report files in %s\n' "$DEST" >&2
    exit 1
fi

report() {
    local line="$*"
    printf '%s\n' "$line"
    if ! printf '%s\n' "$line" >> "$REPORT"; then
        printf '[WARN] Could not append to report file: %s\n' "$REPORT" >&2
    fi
}

log_error() {
    local line="$*"
    printf '[WARN] %s\n' "$line" >&2
    if ! printf '%s\n' "$line" >> "$ERROR_LOG"; then
        printf '[WARN] Could not append to error log: %s\n' "$ERROR_LOG" >&2
    fi
}

cleanup_temp_files() {
    # Only remove temporary files created by this run; completed APKs remain.
    find "$APK_DIR" -maxdepth 1 -type f -name '*.part' -delete 2>/dev/null || true
    rm -f "$DEST/packages_raw.tmp" "$DEST/packages_error.tmp" \
          "$DEST/.paths.tmp" "$DEST/.pm_path_error.tmp" \
          "$DEST/.paths.tmp.clean" 2>/dev/null || true
}
trap cleanup_temp_files EXIT

connect_device() {
    local attempt state
    for ((attempt=1; attempt<=MAX_RETRIES; attempt++)); do
        adb connect "$DEVICE" >/dev/null 2>&1 || true
        state="$(adb -s "$DEVICE" get-state 2>/dev/null || true)"
        if [[ "$state" == "device" ]]; then
            return 0
        fi
        log_error "ADB state '${state:-unavailable}' for $DEVICE (attempt $attempt/$MAX_RETRIES)."
        sleep "$RETRY_DELAY"
    done
    return 1
}

get_package_paths() {
    local package="$1"
    local output_file="$2"
    local attempt

    : > "$output_file"
    for ((attempt=1; attempt<=MAX_RETRIES; attempt++)); do
        if adb -s "$DEVICE" shell pm path "$package" \
            > "$DEST/.paths.tmp" 2> "$DEST/.pm_path_error.tmp"; then
            tr -d '\r' < "$DEST/.paths.tmp" > "$DEST/.paths.tmp.clean" 2>/dev/null || true
            if grep -q '^package:' "$DEST/.paths.tmp.clean" 2>/dev/null; then
                sed -n 's/^package://p' "$DEST/.paths.tmp.clean" > "$output_file"
                if [[ -s "$output_file" ]]; then
                    return 0
                fi
            fi
        fi

        log_error "Could not obtain APK path for package '$package' (attempt $attempt/$MAX_RETRIES)."
        connect_device || true
        sleep "$RETRY_DELAY"
    done
    return 1
}

pull_apk() {
    local remote="$1"
    local destination="$2"
    local part="${destination}.part"
    local attempt

    rm -f "$part"
    for ((attempt=1; attempt<=MAX_RETRIES; attempt++)); do
        connect_device || true
        rm -f "$part"

        printf '  Pull attempt %s/%s: %s\n' "$attempt" "$MAX_RETRIES" "$remote"
        if adb -s "$DEVICE" pull "$remote" "$part"; then
            if [[ -f "$part" && -s "$part" ]]; then
                if mv -f "$part" "$destination"; then
                    return 0
                fi
                log_error "Downloaded APK but could not move it to '$destination'."
            else
                log_error "ADB returned success but downloaded file was empty/missing: '$remote'."
            fi
        else
            log_error "ADB pull failed for '$remote' (attempt $attempt/$MAX_RETRIES)."
        fi

        rm -f "$part"
        sleep "$RETRY_DELAY"
    done
    return 1
}

calculate_crc32() {
    local file="$1"
    python3 - "$file" <<'PY'
import sys, zlib
crc = 0
try:
    with open(sys.argv[1], "rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            crc = zlib.crc32(block, crc)
    print(f"{crc & 0xffffffff:08X}")
except OSError as exc:
    print(f"CRC_ERROR: {exc}", file=sys.stderr)
    sys.exit(1)
PY
}

adb start-server >/dev/null 2>&1 || true
printf '[INFO] Connecting to %s ...\n' "$DEVICE"

if ! connect_device; then
    report 'ERROR: Could not connect to the Android device.'
    report "Check IP, port $PORT, wireless debugging, and ADB authorization."
    report "Partial/final report: $REPORT"
    exit 1
fi

# Package enumeration is the one prerequisite for the loop. Retry it, and
# stop only if no usable package list can be obtained at all.
list_ok=false
for ((attempt=1; attempt<=MAX_RETRIES; attempt++)); do
    if adb -s "$DEVICE" shell pm list packages \
        > "$DEST/packages_raw.tmp" 2> "$DEST/packages_error.tmp"; then
        tr -d '\r' < "$DEST/packages_raw.tmp" |
            sed -n 's/^package://p' > "$PACKAGES" 2>/dev/null || true
        if [[ -s "$PACKAGES" ]]; then
            list_ok=true
            break
        fi
    fi
    log_error "Could not retrieve a usable package list (attempt $attempt/$MAX_RETRIES)."
    connect_device || true
    sleep "$RETRY_DELAY"
done

if [[ "$list_ok" != true ]]; then
    report 'ERROR: Could not retrieve installed packages; APK processing cannot start.'
    report "See error log: $ERROR_LOG"
    exit 1
fi

package_count="$(grep -c . "$PACKAGES" 2>/dev/null || true)"
report '============================================================'
report 'ANDROID APK CRC-32 REPORT'
report "Device                    : $DEVICE"
report "Installed packages listed : $package_count"
report 'CRC-32 is calculated over each complete downloaded APK file.'
report 'Split APKs are processed individually.'
report '============================================================'
report ''

pkg_index=0
paths_found=0
apk_ok=0
path_fail=0
pull_fail=0
crc_fail=0
package_errors=0
skipped_existing=0

while IFS= read -r package || [[ -n "$package" ]]; do
    [[ -n "$package" ]] || continue
    pkg_index=$((pkg_index + 1))
    printf '\n[PACKAGE %s/%s] %s\n' "$pkg_index" "$package_count" "$package"

    package_failed=false
    path_file="$DEST/.package_paths_${pkg_index}.tmp"

    if ! get_package_paths "$package" "$path_file"; then
        report "Package: $package | Status: NO_APK_PATH"
        path_fail=$((path_fail + 1))
        package_errors=$((package_errors + 1))
        rm -f "$path_file"
        continue
    fi

    mapfile -t remote_paths < "$path_file"
    rm -f "$path_file"

    if [[ ${#remote_paths[@]} -eq 0 ]]; then
        report "Package: $package | Status: EMPTY_APK_PATH_LIST"
        path_fail=$((path_fail + 1))
        package_errors=$((package_errors + 1))
        continue
    fi

    # Sanitize package and APK names so a remote path cannot affect local paths.
    safe_package="$(printf '%s' "$package" | tr -c 'A-Za-z0-9._-' '_')"
    split_index=0

    for remote in "${remote_paths[@]}"; do
        remote="${remote%$'\r'}"
        [[ -n "$remote" ]] || continue
        paths_found=$((paths_found + 1))
        split_index=$((split_index + 1))

        base="$(basename "$remote")"
        safe_base="$(printf '%s' "$base" | tr -c 'A-Za-z0-9._-' '_')"
        [[ -n "$safe_base" && "$safe_base" != "." && "$safe_base" != ".." ]] || safe_base="app.apk"
        local_apk="$APK_DIR/${safe_package}_${split_index}_${safe_base}"

        printf '  Remote APK: %s\n' "$remote"

        # Always retrieve the current APK. This avoids calculating a CRC for a
        # stale APK left from an earlier run. Failed transfers use .part and
        # are deleted; a failed pull is recorded and this APK is skipped.
        if ! pull_apk "$remote" "$local_apk"; then
            report "Package: $package | APK: $remote | Status: PULL_FAILED"
            pull_fail=$((pull_fail + 1))
            package_failed=true
            continue
        fi

        if ! crc="$(calculate_crc32 "$local_apk" 2> "$DEST/.crc_error.tmp")"; then
            crc_detail="$(cat "$DEST/.crc_error.tmp" 2>/dev/null || true)"
            report "Package: $package | APK: $remote | Status: CRC_FAILED"
            log_error "CRC calculation failed for '$local_apk': ${crc_detail:-unknown error}"
            crc_fail=$((crc_fail + 1))
            package_failed=true
            rm -f "$DEST/.crc_error.tmp"
            continue
        fi
        rm -f "$DEST/.crc_error.tmp"

        if [[ ! "$crc" =~ ^[0-9A-Fa-f]{8}$ ]]; then
            report "Package: $package | APK: $remote | Status: CRC_FAILED_INVALID_OUTPUT"
            log_error "CRC tool returned unexpected output for '$local_apk': '$crc'"
            crc_fail=$((crc_fail + 1))
            package_failed=true
            continue
        fi

        size="$(wc -c < "$local_apk" 2>/dev/null | tr -d ' ' || true)"
        size="${size:-unknown}"
        report "Package : $package"
        report "APK path: $remote"
        report "Local   : $local_apk"
        report "Size    : $size bytes"
        report "CRC-32  : ${crc^^}"
        report 'Status  : OK'
        report '------------------------------------------------------------'
        apk_ok=$((apk_ok + 1))
    done

    if [[ "$package_failed" == true ]]; then
        package_errors=$((package_errors + 1))
    fi
done < "$PACKAGES"

report ''
report '========================== SUMMARY ========================='
report "Installed packages listed : $package_count"
report "Packages visited          : $pkg_index"
report "APK paths returned        : $paths_found"
report "APKs successfully hashed  : $apk_ok"
report "Packages with path issues : $path_fail"
report "APK pull failures         : $pull_fail"
report "CRC calculation failures  : $crc_fail"
report "Packages with other errors: $package_errors"
report "Existing APKs reused      : 0 (fresh pulls required)"
report "APK directory             : $APK_DIR"
report "Readable text report      : $REPORT"
report "Error log                 : $ERROR_LOG"
report '============================================================'
printf '\n[INFO] Processing finished. Failures for individual packages/APKs did not stop the loop.\n'
printf '[INFO] Report: %s\n[INFO] Errors: %s\n' "$REPORT" "$ERROR_LOG"

adb disconnect "$DEVICE" >/dev/null 2>&1 || true
exit 0
