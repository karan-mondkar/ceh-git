#!/usr/bin/env bash
# Pull all accessible Android shared-storage contents into one local folder.
# Usage: ./adb_pull_sdcard.sh PHONE_IP [ADB_PORT]

set -uo pipefail
umask 077

PHONE_IP="${1:-}"
ADB_PORT="${2:-5555}"
DEST="$HOME/adb_recovered"
MAX_RETRIES=10
RETRY_DELAY=5

log()  { printf '[INFO] %s\n' "$*"; }
warn() { printf '[WARN] %s\n' "$*" >&2; }
die()  { printf '[ERROR] %s\n' "$*" >&2; exit 1; }

if [[ -z "$PHONE_IP" ]]; then
    printf 'Usage: %s PHONE_IP [ADB_PORT]\n' "$0"
    printf 'Example: %s 192.168.10.121\n' "$0"
    exit 1
fi

[[ "$ADB_PORT" =~ ^[0-9]+$ ]] && (( ADB_PORT >= 1 && ADB_PORT <= 65535 )) || die 'Invalid ADB port.'

if ! command -v adb >/dev/null 2>&1; then
    log 'ADB is missing; installing Android platform-tools...'
    command -v apt-get >/dev/null 2>&1 || die 'apt-get is unavailable; install adb manually.'
    if [[ "$(id -u)" -eq 0 ]]; then
        apt-get update && apt-get install -y adb || die 'ADB installation failed.'
    elif command -v sudo >/dev/null 2>&1; then
        sudo apt-get update && sudo apt-get install -y adb || die 'ADB installation failed.'
    else
        die 'Administrator privileges are required to install ADB.'
    fi
fi

mkdir -p -- "$DEST" || die "Cannot create destination: $DEST"
DEST="$(cd "$DEST" && pwd -P)"
DEVICE="$PHONE_IP:$ADB_PORT"

connect_device() {
    local attempt state
    adb start-server >/dev/null 2>&1 || true
    for ((attempt=1; attempt<=MAX_RETRIES; attempt++)); do
        log "Connecting to $DEVICE ($attempt/$MAX_RETRIES)..."
        adb connect "$DEVICE" 2>&1 || true
        state="$(adb -s "$DEVICE" get-state 2>/dev/null || true)"
        if [[ "$state" == 'device' ]]; then
            log 'Device connected and authorized.'
            return 0
        fi
        if [[ "$state" == 'unauthorized' ]]; then
            warn 'Unlock the Android device and approve the ADB authorization prompt.'
        else
            warn "Device state: ${state:-unavailable}"
        fi
        sleep "$RETRY_DELAY"
    done
    return 1
}

log "Destination: $DEST"
connect_device || die 'Could not connect. Check the IP, port, Wi-Fi debugging, and device authorization.'

# adb pull recursively copies the directory tree. If the connection drops,
# retry the directory pull; already copied files may be transferred again.
for ((attempt=1; attempt<=MAX_RETRIES; attempt++)); do
    state="$(adb -s "$DEVICE" get-state 2>/dev/null || true)"
    if [[ "$state" != 'device' ]]; then
        warn 'Connection dropped; reconnecting...'
        connect_device || { warn 'Reconnect failed.'; sleep "$RETRY_DELAY"; continue; }
    fi

    log "Pulling all accessible contents of /sdcard into $DEST (attempt $attempt/$MAX_RETRIES)..."
    if adb -s "$DEVICE" pull /sdcard/ "$DEST/"; then
        printf '\n========== SUMMARY ==========\n'
        printf 'Source:      /sdcard/\n'
        printf 'Destination: %s\n' "$DEST"
        printf 'Files now present: '
        find "$DEST" -type f 2>/dev/null | wc -l
        printf '=============================\n'
        log 'ADB pull completed.'
        adb disconnect "$DEVICE" >/dev/null 2>&1 || true
        exit 0
    fi

    warn 'Pull did not complete; checking connection before retrying...'
    adb disconnect "$DEVICE" >/dev/null 2>&1 || true
    sleep "$RETRY_DELAY"
done

die "Pull failed after $MAX_RETRIES attempts. Rerun the same command to try again. Destination: $DEST"
