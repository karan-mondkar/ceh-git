
#!/usr/bin/env bash

# SMB Recursive File Finder and Downloader
# For authorized CEH labs and systems only.
# Downloads all accessible files from discovered disk shares.

set -uo pipefail
umask 077

# -------------------- Input --------------------

read -r -p "Target IP or hostname: " TARGET
read -r -p "SMB username: " USERNAME
read -r -s -p "SMB password: " PASSWORD
printf '\n'

if [[ -z "$TARGET" || -z "$USERNAME" ]]; then
    echo "[ERROR] Target and username are required." >&2
    unset PASSWORD
    exit 1
fi

if [[ "$TARGET" == -* || "$TARGET" == *[[:space:]]* ]]; then
    echo "[ERROR] Enter a valid IP address or hostname." >&2
    unset PASSWORD
    exit 1
fi

# -------------------- Dependencies --------------------

for CMD in smbclient find awk mktemp date sort; do
    if ! command -v "$CMD" >/dev/null 2>&1; then
        echo "[ERROR] Required command is missing: $CMD" >&2
        echo "[INFO] Install SMB client with: sudo apt install smbclient" >&2
        unset PASSWORD
        exit 1
    fi
done

# -------------------- Temporary credentials --------------------

AUTH_FILE="$(mktemp)" || {
    echo "[ERROR] Could not create temporary credentials file." >&2
    unset PASSWORD
    exit 1
}

cleanup() {
    rm -f -- "$AUTH_FILE"
    unset PASSWORD
}

trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

if ! printf 'username = %s\npassword = %s\n' \
    "$USERNAME" "$PASSWORD" > "$AUTH_FILE"; then
    echo "[ERROR] Could not write credentials file." >&2
    exit 1
fi

if ! chmod 600 "$AUTH_FILE"; then
    echo "[ERROR] Could not restrict credentials-file permissions." >&2
    exit 1
fi

unset PASSWORD

# -------------------- Unique output directory --------------------

OUTDIR="$(mktemp -d "$PWD/smb_downloads_$(date +%Y%m%d_%H%M%S)_XXXXXX")" || {
    echo "[ERROR] Could not create output directory." >&2
    exit 1
}

printf '\n'
echo "============================================"
echo "     SMB RECURSIVE FILE DOWNLOADER"
echo "============================================"
echo "Target:          $TARGET"
echo "Download mode:   All accessible files"
echo "Output directory: $OUTDIR"
echo "============================================"

# -------------------- Discover SMB shares --------------------

echo
echo "[INFO] Discovering SMB disk shares on $TARGET ..."

SHARE_OUTPUT="$(smbclient -g -L "//$TARGET" -A "$AUTH_FILE")"
SHARE_STATUS=$?

if (( SHARE_STATUS != 0 )); then
    [[ -z "$SHARE_OUTPUT" ]] || printf '%s\n' "$SHARE_OUTPUT"
    echo "[ERROR] Share enumeration failed (exit code $SHARE_STATUS)." >&2
    echo "[INFO] Check connectivity, credentials, SMB compatibility, and permissions." >&2
    exit 1
fi

[[ -z "$SHARE_OUTPUT" ]] || printf '%s\n' "$SHARE_OUTPUT"

mapfile -t SHARES < <(
    printf '%s\n' "$SHARE_OUTPUT" |
        awk -F'|' '$1 == "Disk" && $2 != "" { print $2 }' |
        sort -u
)

if ((${#SHARES[@]} == 0)); then
    echo "[ERROR] No disk shares found." >&2
    echo "[INFO] Share enumeration may be restricted by the server." >&2
    exit 1
fi

echo
echo "[INFO] Discovered ${#SHARES[@]} disk share(s):"
printf '  - %s\n' "${SHARES[@]}"

# -------------------- Download all accessible files --------------------

SHARES_CHECKED=0
SHARES_FAILED=0
SHARES_WITH_FILES=0
TOTAL_FILES=0

for SHARE in "${SHARES[@]}"; do
    SHARES_CHECKED=$((SHARES_CHECKED + 1))

    printf '\n'
    echo "============================================"
    echo "[SHARE] $SHARE"
    echo "============================================"

    # Sanitize the share name for local directory use.
    SAFE_SHARE="${SHARE//\//_}"
    SAFE_SHARE="${SAFE_SHARE//\\/_}"
    SAFE_SHARE="${SAFE_SHARE//:/_}"

    if [[ -z "$SAFE_SHARE" || "$SAFE_SHARE" == "." || "$SAFE_SHARE" == ".." ]]; then
        SAFE_SHARE="share_$SHARES_CHECKED"
    fi

    DEST="$OUTDIR/$SAFE_SHARE"

    if ! mkdir -p -- "$DEST"; then
        echo "[ERROR] Cannot create local directory: $DEST" >&2
        SHARES_FAILED=$((SHARES_FAILED + 1))
        continue
    fi

    echo "[INFO] Downloading all accessible files recursively."
    echo "[INFO] Destination: $DEST"

    # Escape the local path for smbclient's command parser.
    SMB_DEST="${DEST//\\/\\\\}"
    SMB_DEST="${SMB_DEST//\"/\\\"}"

    # No mask or filename filter: attempt to retrieve all files.
    SMB_COMMAND="lcd \"$SMB_DEST\"; recurse ON; prompt OFF; mget *"

    smbclient "//$TARGET/$SHARE" \
        -A "$AUTH_FILE" \
        -c "$SMB_COMMAND"

    SMB_STATUS=$?

    # Count downloaded regular files in this run's share directory.
    FILE_COUNT="$(find "$DEST" -type f -print | awk 'END { print NR+0 }')"

    if [[ "$FILE_COUNT" =~ ^[0-9]+$ ]] && (( FILE_COUNT > 0 )); then
        echo "[INFO] Local files present: $FILE_COUNT"
        SHARES_WITH_FILES=$((SHARES_WITH_FILES + 1))
        TOTAL_FILES=$((TOTAL_FILES + FILE_COUNT))
    else
        echo "[INFO] No local files detected for this share."
    fi

    if (( SMB_STATUS != 0 )); then
        echo "[ERROR] Download command failed for share: $SHARE (exit code $SMB_STATUS)" >&2
        SHARES_FAILED=$((SHARES_FAILED + 1))
    fi
done

# -------------------- Summary --------------------

printf '\n'
echo "============================================"
echo "                  SUMMARY"
echo "============================================"
echo "Target:                  $TARGET"
echo "Shares discovered:       ${#SHARES[@]}"
echo "Shares checked:          $SHARES_CHECKED"
echo "Shares with local files: $SHARES_WITH_FILES"
echo "Shares with errors:      $SHARES_FAILED"
echo "Local files present:     $TOTAL_FILES"
echo "Output directory:        $OUTDIR"
echo "============================================"

if (( SHARES_FAILED > 0 )); then
    echo "[WARN] Some shares returned errors. Review the terminal output."
fi

if (( TOTAL_FILES > 0 )); then
    echo "[DONE] Files were detected in the output directory."
else
    echo "[INFO] No local files were detected."
    echo "[INFO] Check share permissions and the SMB client output."
fi
