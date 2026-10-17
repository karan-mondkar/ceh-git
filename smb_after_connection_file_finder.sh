
#!/usr/bin/env bash

# SMB Recursive File Finder and Downloader
# For authorized CEH labs and systems only.

set -uo pipefail
umask 077

# -------------------- Input --------------------

read -r -p "Target IP or hostname: " TARGET
read -r -p "SMB username: " USERNAME
read -r -s -p "SMB password: " PASSWORD
printf '\n'
read -r -p "Filename to search (e.g. abc, abc.txt, .txt): " PATTERN

if [[ -z "$TARGET" || -z "$USERNAME" || -z "$PATTERN" ]]; then
    echo "[ERROR] Target, username, and filename pattern are required." >&2
    unset PASSWORD
    exit 1
fi

if [[ "$TARGET" == -* || "$TARGET" == *[[:space:]]* ]]; then
    echo "[ERROR] Enter a valid IP address or hostname." >&2
    unset PASSWORD
    exit 1
fi

# -------------------- Dependencies --------------------

for CMD in smbclient find awk wc mktemp date; do
    if ! command -v "$CMD" >/dev/null 2>&1; then
        echo "[ERROR] Required command is missing: $CMD" >&2
        echo "[INFO] On Parrot OS, install SMB client with:" >&2
        echo "       sudo apt install smbclient" >&2
        unset PASSWORD
        exit 1
    fi
done

# -------------------- Validate filename pattern --------------------

case "$PATTERN" in
    *[!a-zA-Z0-9._-]*)
        echo "[ERROR] Use only letters, numbers, dots, underscores, and hyphens." >&2
        unset PASSWORD
        exit 1
        ;;
esac

# A leading dot means extension search, e.g. .txt -> *.txt.
case "$PATTERN" in
    .*) MASK="*$PATTERN" ;;
    *)  MASK="*$PATTERN*" ;;
esac

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
echo "       SMB RECURSIVE FILE FINDER"
echo "============================================"
echo "Target:            $TARGET"
echo "Filename pattern:  $PATTERN"
echo "SMB filename mask: $MASK"
echo "Output directory:  $OUTDIR"
echo "============================================"

# -------------------- Discover SMB shares --------------------

echo
echo "[INFO] Discovering SMB shares on $TARGET ..."

# Standard output is captured for parsing.
# Standard error remains visible in the terminal.
SHARE_OUTPUT="$(smbclient -g -L "//$TARGET" -A "$AUTH_FILE")"
SHARE_STATUS=$?

if (( SHARE_STATUS != 0 )); then
    [[ -z "$SHARE_OUTPUT" ]] || printf '%s\n' "$SHARE_OUTPUT"
    echo "[ERROR] Share enumeration failed (exit code $SHARE_STATUS)." >&2
    echo "[INFO] Check connectivity, credentials, SMB version, and permissions." >&2
    exit 1
fi

[[ -z "$SHARE_OUTPUT" ]] || printf '%s\n' "$SHARE_OUTPUT"

# smbclient -g formats share entries as:
# Disk|share_name|comment
mapfile -t SHARES < <(
    printf '%s\n' "$SHARE_OUTPUT" |
        awk -F'|' '$1 == "Disk" && $2 != "" { print $2 }' |
        sort -u
)

if ((${#SHARES[@]} == 0)); then
    echo "[ERROR] No disk shares found in the SMB listing." >&2
    echo "[INFO] The server may deny share enumeration, or no disk shares may be available." >&2
    exit 1
fi

echo
echo "[INFO] Discovered ${#SHARES[@]} disk share(s):"
printf '  - %s\n' "${SHARES[@]}"

# -------------------- Search and download --------------------

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

    # Produce a local directory name that cannot escape OUTDIR.
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

    echo "[INFO] Searching recursively for: $MASK"
    echo "[INFO] Destination: $DEST"

    # Escape characters used by smbclient's command parser.
    SMB_DEST="${DEST//\\/\\\\}"
    SMB_DEST="${SMB_DEST//\"/\\\"}"

    # The mask restricts files selected during recursive mget.
    # Prompting is disabled so matching files download automatically.
    SMB_COMMAND="lcd \"$SMB_DEST\"; mask $MASK; recurse ON; prompt OFF; mget *"

    echo "[INFO] Starting SMB search/download..."

    smbclient "//$TARGET/$SHARE" \
        -A "$AUTH_FILE" \
        -c "$SMB_COMMAND"

    SMB_STATUS=$?

    # OUTDIR is unique to this run, so these are files found during
    # this run rather than files left over from an earlier execution.
    FILE_COUNT="$(find "$DEST" -type f -print | awk 'END { print NR+0 }')"

    if [[ "$FILE_COUNT" =~ ^[0-9]+$ ]] && (( FILE_COUNT > 0 )); then
        echo "[INFO] Local files present: $FILE_COUNT"
        SHARES_WITH_FILES=$((SHARES_WITH_FILES + 1))
        TOTAL_FILES=$((TOTAL_FILES + FILE_COUNT))
    else
        echo "[INFO] No local files detected for this share."
    fi

    if (( SMB_STATUS != 0 )); then
        echo "[ERROR] Share command failed: $SHARE (exit code $SMB_STATUS)" >&2
        SHARES_FAILED=$((SHARES_FAILED + 1))
    fi
done

# -------------------- Summary --------------------

printf '\n'
echo "============================================"
echo "                  SUMMARY"
echo "============================================"
echo "Target:                  $TARGET"
echo "Filename pattern:        $PATTERN"
echo "SMB filename mask:       $MASK"
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
    echo "[INFO] Check the SMB output, filename mask, and permissions."
fi
