
#!/usr/bin/env bash
# Copy accessible Android shared-storage files over ADB.
# Retries dropped connections and records completed transfers.

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
    echo "Usage: $0 PHONE_IP [ADB_PORT]"
    echo "Example: $0 192.168.10.121"
    exit 1
fi

[[ "$ADB_PORT" =~ ^[0-9]+$ ]] &&
    ((ADB_PORT >= 1 && ADB_PORT <= 65535)) ||
    die "Invalid ADB port."

# Install ADB automatically when missing.
if ! command -v adb >/dev/null 2>&1; then
    log "ADB is missing. Installing automatically..."

    command -v apt-get >/dev/null 2>&1 ||
        die "apt-get is unavailable; install Android platform-tools manually."

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

mkdir -p "$DEST" || die "Cannot create destination directory."
DEST="$(cd "$DEST" && pwd -P)"

DEVICE="$PHONE_IP:$ADB_PORT"
FILE_LIST="$DEST/file_list.txt"
DONE_FILE="$DEST/completed_files.txt"
LOCK="$DEST/.adb_copy_all.lock"

mkdir "$LOCK" 2>/dev/null ||
    die "Another run may be active, or a stale lock exists: $LOCK"

cleanup() {
    rmdir "$LOCK" 2>/dev/null || true
}
trap cleanup EXIT

connect_device() {
    local attempt state

    adb start-server >/dev/null 2>&1 || true

    for ((attempt=1; attempt<=MAX_RETRIES; attempt++)); do
        log "Connecting to $DEVICE ($attempt/$MAX_RETRIES)..."

        adb connect "$DEVICE" 2>&1 || true
        state="$(adb -s "$DEVICE" get-state 2>/dev/null || true)"

        if [[ "$state" == "device" ]]; then
            log "Device connected and authorized."
            return 0
        fi

        if [[ "$state" == "unauthorized" ]]; then
            warn "Unlock the phone and approve the ADB authorization prompt."
        else
            warn "Device state: ${state:-unavailable}"
        fi

        sleep "$RETRY_DELAY"
    done

    return 1
}

ensure_connection() {
    local state
    state="$(adb -s "$DEVICE" get-state 2>/dev/null || true)"

    [[ "$state" == "device" ]] && return 0

    warn "Connection dropped. Reconnecting..."
    connect_device
}

log "Destination: $DEST"
log "Connecting to authorized Android device..."

connect_device ||
    die "Cannot connect. Check the phone IP, port, Wi-Fi debugging and authorization."

# Refresh the file inventory. Keep the completion checkpoint.
log "Listing files accessible under /sdcard..."

listed=false

for ((attempt=1; attempt<=MAX_RETRIES; attempt++)); do
    if ensure_connection &&
       adb -s "$DEVICE" shell \
           'find /sdcard -type f 2>/dev/null' > "$FILE_LIST.tmp"; then

        tr -d '\r' < "$FILE_LIST.tmp" > "$FILE_LIST"
        rm -f "$FILE_LIST.tmp"
        listed=true
        break
    fi

    rm -f "$FILE_LIST.tmp"
    warn "Storage listing failed; retrying..."
    sleep "$RETRY_DELAY"
done

[[ "$listed" == true ]] ||
    die "Could not list shared storage after retries."

TOTAL="$(grep -c . "$FILE_LIST" 2>/dev/null || true)"
log "Found $TOTAL accessible file paths."

completed=0
skipped=0
failed=0
current=0

while IFS= read -r REMOTE || [[ -n "$REMOTE" ]]; do
    [[ -n "$REMOTE" ]] || continue

    # Only copy files within the expected shared-storage root.
    [[ "$REMOTE" == /sdcard/* ]] || {
        warn "Ignoring unexpected path: $REMOTE"
        continue
    }

    current=$((current + 1))

    # Preserve directory structure and prevent same-name collisions.
    RELATIVE="${REMOTE#/sdcard/}"
    LOCAL="$DEST/$RELATIVE"

    # Skip files already confirmed as complete.
    if [[ -f "$LOCAL" ]] &&
       grep -Fqx -- "$REMOTE" "$DONE_FILE" 2>/dev/null; then
        skipped=$((skipped + 1))
        printf '[SKIP] (%s/%s) %s\n' "$current" "$TOTAL" "$RELATIVE"
        continue
    fi

    mkdir -p "$(dirname "$LOCAL")" || {
        warn "Cannot create directory for $RELATIVE"
        failed=$((failed + 1))
        continue
    }

    success=false

    for ((attempt=1; attempt<=MAX_RETRIES; attempt++)); do
        ensure_connection || {
            warn "Reconnect failed; retrying $RELATIVE"
            sleep "$RETRY_DELAY"
            continue
        }

        PART="$LOCAL.adb-part"
        rm -f -- "$PART"

        printf '[COPY] (%s/%s) %s (attempt %s/%s)\n' \
            "$current" "$TOTAL" "$RELATIVE" "$attempt" "$MAX_RETRIES"

        if adb -s "$DEVICE" pull "$REMOTE" "$PART"; then
            if ! mv -f -- "$PART" "$LOCAL"; then
                warn "Could not finalize $LOCAL"
                rm -f -- "$PART"
                break
            fi

            # Record completion only after the transfer succeeds.
            if ! grep -Fqx -- "$REMOTE" "$DONE_FILE" 2>/dev/null; then
                printf '%s\n' "$REMOTE" >> "$DONE_FILE"
            fi

            SIZE="$(wc -c < "$LOCAL")"
            printf '[SAVED] %s (%s bytes)\n' "$LOCAL" "$SIZE"

            success=true
            completed=$((completed + 1))
            break
        fi

        rm -f -- "$PART"
        warn "Transfer failed; checking connection and retrying..."
        ensure_connection || true
        sleep "$RETRY_DELAY"
    done

    if [[ "$success" != true ]]; then
        warn "Could not copy $REMOTE after retries."
        failed=$((failed + 1))
        break
    fi

done < "$FILE_LIST"

printf '\n========== SUMMARY ==========\n'
printf 'Newly copied:       %s\n' "$completed"
printf 'Already completed:  %s\n' "$skipped"
printf 'Failed this run:    %s\n' "$failed"
printf 'Destination:        %s\n' "$DEST"
printf 'File inventory:     %s\n' "$FILE_LIST"
printf 'Checkpoint:         %s\n' "$DONE_FILE"
printf '=============================\n'

if (( failed > 0 )); then
    warn "Rerun the same command to retry. Completed files will be skipped."
    exit 2
fi

log "Copy pass completed."
adb disconnect "$DEVICE" >/dev/null 2>&1 || true
