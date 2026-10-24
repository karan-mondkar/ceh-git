
#!/usr/bin/env bash

# Linux Security Enumeration and Configuration Audit
# For systems you own or are authorized to assess.
# Enumerates configuration; does not exploit findings.

set -uo pipefail
export LC_ALL=C
umask 077

STAMP="$(date +%Y%m%d_%H%M%S)"
OUTDIR="${AUDIT_OUTDIR:-$PWD/linux-audit-results}"

SCANS=0
CHECKS_SKIPPED=0
CHECKS_INCOMPLETE=0
SCAN_ERRORS=0
UPDATE_BASELINE=0
BASELINE_SEEN=0

if [[ "${1:-}" == "--update-baseline" ]]; then
    UPDATE_BASELINE=1
elif [[ $# -gt 0 ]]; then
    printf 'Usage: %s [--update-baseline]\n' "$0" >&2
    exit 2
fi

if [[ ! -e "$OUTDIR" ]]; then
    mkdir -m 700 -p -- "$OUTDIR" || exit 1
elif [[ ! -d "$OUTDIR" ]]; then
    printf 'ERROR: output path is not a directory: %s\n' "$OUTDIR" >&2
    exit 1
fi

REPORT="$OUTDIR/report_$STAMP.txt"
SUMMARY="$OUTDIR/summary_$STAMP.txt"
FINDINGS="$OUTDIR/findings_$STAMP.tsv"
ERRORS="$OUTDIR/errors_$STAMP.txt"
BASELINE="$OUTDIR/baseline.tsv"
DIFF="$OUTDIR/baseline_diff_$STAMP.txt"

for f in "$REPORT" "$SUMMARY" "$FINDINGS" "$ERRORS"; do
    if ! (set -o noclobber; : > "$f") 2>/dev/null; then
        printf 'ERROR: cannot safely create %s\n' "$f" >&2
        exit 1
    fi
done

chmod 600 "$REPORT" "$SUMMARY" "$FINDINGS" "$ERRORS" || exit 1

section() {
    printf '\n========== %s ==========\n' "$1" | tee -a "$REPORT"
}

record_error() {
    SCAN_ERRORS=$((SCAN_ERRORS + 1))
    printf '[ERROR] %s\n' "$*" | tee -a "$ERRORS" "$REPORT" >&2
}

finding() {
    local severity="$1"
    local category="$2"
    local detail="$3"

    severity="${severity//$'\t'/ }"
    severity="${severity//$'\n'/ }"
    category="${category//$'\t'/ }"
    category="${category//$'\n'/ }"
    detail="${detail//$'\t'/ }"
    detail="${detail//$'\n'/ }"

    printf '%s\t%s\t%s\n' \
        "$severity" "$category" "$detail" >> "$FINDINGS"
}

run_check() {
    local title="$1"
    shift
    local tmp rc

    SCANS=$((SCANS + 1))
    section "$title"

    tmp="$(mktemp "$OUTDIR/.scan.XXXXXX")" || {
        record_error "Cannot create temporary output for: $title"
        CHECKS_INCOMPLETE=$((CHECKS_INCOMPLETE + 1))
        return 1
    }

    "$@" > "$tmp" 2>&1
    rc=$?

    cat "$tmp" | tee -a "$REPORT"
    rm -f -- "$tmp"

    if (( rc != 0 )); then
        record_error "$title returned status $rc"
        CHECKS_INCOMPLETE=$((CHECKS_INCOMPLETE + 1))
        return 1
    fi

    return 0
}

inspect_path() {
    local path="$1"

    if [[ -L "$path" ]]; then
        stat -c 'SYMLINK %A %a %U:%G %n -> %N' -- "$path" 2>&1
    elif [[ -e "$path" ]]; then
        stat -c '%F %A %a %U:%G %n' -- "$path" 2>&1
    else
        printf 'MISSING %s\n' "$path"
    fi
}

section "Audit metadata"
{
    printf 'Timestamp: %s\n' "$(date -Is 2>/dev/null || date)"
    printf 'Hostname: %s\n' "$(hostname 2>/dev/null || echo unknown)"
    printf 'User: %s\n' "$(id -un 2>/dev/null || echo unknown)"
    printf 'UID: %s\n' "$(id -u 2>/dev/null || echo unknown)"
    printf 'Output directory: %s\n' "$OUTDIR"
} | tee -a "$REPORT"

run_check "Identity and groups" id || true
run_check "Operating system" cat /etc/os-release || true
run_check "Kernel information" uname -a || true
run_check "PATH environment" printenv PATH || true

section "Sudo permissions"
if command -v sudo >/dev/null 2>&1; then
    run_check "Non-interactive sudo listing" sudo -n -l || true
else
    CHECKS_SKIPPED=$((CHECKS_SKIPPED + 1))
    echo "sudo is not installed." | tee -a "$REPORT"
fi

section "SUID and SGID inventory"

for kind in SUID SGID; do
    case "$kind" in
        SUID) mode=4000 ;;
        SGID) mode=2000 ;;
    esac

    list="$OUTDIR/${kind,,}_$STAMP.txt"
    errfile="$list.errors"

    tmp="$(mktemp "$OUTDIR/.find.XXXXXX")" || {
        record_error "Cannot create temporary file for $kind scan"
        CHECKS_INCOMPLETE=$((CHECKS_INCOMPLETE + 1))
        continue
    }

    SCANS=$((SCANS + 1))
    section "$kind files"

    find / -xdev -type f -perm "-$mode" -print \
        > "$tmp" 2> "$errfile"
    rc=$?

    if ! sort -u "$tmp" > "$list"; then
        record_error "Could not sort $kind results"
        CHECKS_INCOMPLETE=$((CHECKS_INCOMPLETE + 1))
    fi

    cat "$list" | tee -a "$REPORT"
    rm -f -- "$tmp"

    while IFS= read -r path; do
        [[ -n "$path" ]] || continue
        finding INFO "$kind file discovered" "$path"
    done < "$list"

    if (( rc != 0 )) || [[ -s "$errfile" ]]; then
        record_error "$kind scan incomplete; see $errfile"
        CHECKS_INCOMPLETE=$((CHECKS_INCOMPLETE + 1))
    else
        rm -f -- "$errfile"
    fi
done

section "Linux file capabilities"

CAP_LIST="$OUTDIR/capabilities_$STAMP.txt"
CAP_ERRORS="$CAP_LIST.errors"

if command -v getcap >/dev/null 2>&1; then
    SCANS=$((SCANS + 1))

    getcap -r / > "$CAP_LIST" 2> "$CAP_ERRORS"
    rc=$?

    cat "$CAP_LIST" | tee -a "$REPORT"

    while IFS= read -r line; do
        [[ -n "$line" ]] || continue
        finding INFO "File capability discovered" "$line"
    done < "$CAP_LIST"

    if (( rc != 0 )) || [[ -s "$CAP_ERRORS" ]]; then
        record_error "Capability scan may be incomplete; see $CAP_ERRORS"
        CHECKS_INCOMPLETE=$((CHECKS_INCOMPLETE + 1))
    else
        rm -f -- "$CAP_ERRORS"
    fi
else
    CHECKS_SKIPPED=$((CHECKS_SKIPPED + 1))
    echo "getcap unavailable; capability scan skipped." | tee -a "$REPORT"
fi

section "Writable files in selected sensitive directories"

WRITABLE="$OUTDIR/writable_$STAMP.txt"
: > "$WRITABLE"

for dir in /etc /opt /usr/local/bin /usr/local/sbin \
           /etc/cron.d /etc/systemd/system; do
    [[ -d "$dir" ]] || continue

    SCANS=$((SCANS + 1))
    tmp="$(mktemp "$OUTDIR/.writable.XXXXXX")" || {
        record_error "Cannot create temporary file for $dir"
        CHECKS_INCOMPLETE=$((CHECKS_INCOMPLETE + 1))
        continue
    }

    errfile="$tmp.errors"

    find "$dir" -xdev -type f -writable -print \
        > "$tmp" 2> "$errfile"
    rc=$?

    cat "$tmp" >> "$WRITABLE"

    if (( rc != 0 )) || [[ -s "$errfile" ]]; then
        record_error "Writable-file scan incomplete in $dir"
        cat "$errfile" >> "$ERRORS"
        CHECKS_INCOMPLETE=$((CHECKS_INCOMPLETE + 1))
    fi

    rm -f -- "$tmp" "$errfile"
done

if ! sort -u "$WRITABLE" -o "$WRITABLE"; then
    record_error "Could not sort writable-file results"
    CHECKS_INCOMPLETE=$((CHECKS_INCOMPLETE + 1))
fi

cat "$WRITABLE" | tee -a "$REPORT"

while IFS= read -r path; do
    [[ -n "$path" ]] || continue
    finding REVIEW "Writable sensitive file" \
        "$(stat -c '%A %a %U:%G %n' -- "$path" 2>/dev/null || echo "$path")"
done < "$WRITABLE"

section "World-writable directories without sticky bit"

WW="$OUTDIR/world_writable_$STAMP.txt"
WW_ERRORS="$WW.errors"

SCANS=$((SCANS + 1))
find / -xdev -type d -perm -0002 ! -perm -1000 -print \
    > "$WW" 2> "$WW_ERRORS"
rc=$?

cat "$WW" | tee -a "$REPORT"

while IFS= read -r path; do
    [[ -n "$path" ]] || continue
    finding REVIEW "World-writable directory" "$path"
done < "$WW"

if (( rc != 0 )) || [[ -s "$WW_ERRORS" ]]; then
    record_error "World-writable directory scan may be incomplete; see $WW_ERRORS"
    CHECKS_INCOMPLETE=$((CHECKS_INCOMPLETE + 1))
else
    rm -f -- "$WW_ERRORS"
fi

section "Cron configuration"

for path in /etc/crontab /etc/anacrontab; do
    if [[ -r "$path" ]]; then
        cat "$path" | tee -a "$REPORT"
    fi
done

for dir in /etc/cron.d /etc/cron.hourly /etc/cron.daily \
           /etc/cron.weekly /etc/cron.monthly; do
    if [[ -d "$dir" ]]; then
        ls -la "$dir" 2>&1 | tee -a "$REPORT"
    fi
done

section "Scheduled-task file metadata"

# Heuristic path extraction only; this is not a shell parser.
for path in /etc/crontab /etc/anacrontab /etc/cron.d/*; do
    [[ -f "$path" ]] || continue

    inspect_path "$path" | tee -a "$REPORT"
    finding INFO "Scheduled-task configuration" \
        "$(stat -c '%A %a %U:%G %n' -- "$path" 2>/dev/null || echo "$path")"

    while IFS= read -r ref; do
        [[ -n "$ref" && -e "$ref" ]] || continue
        printf '[HEURISTIC PATH REFERENCE] %s\n' "$ref" |
            tee -a "$REPORT"
        inspect_path "$ref" | tee -a "$REPORT"
    done < <(
        grep -Eo '/[^[:space:];|&]+' "$path" 2>/dev/null | sort -u
    )
done

section "Systemd timers and services"

if command -v systemctl >/dev/null 2>&1; then
    run_check "Systemd timers" \
        systemctl list-timers --all --no-pager || true

    run_check "Systemd service unit inventory" \
        systemctl list-unit-files --type=service --no-pager || true
else
    CHECKS_SKIPPED=$((CHECKS_SKIPPED + 1))
    echo "systemctl unavailable." | tee -a "$REPORT"
fi

section "Important configuration file permissions"

for path in /etc/passwd /etc/group /etc/shadow /etc/sudoers \
            /etc/ssh/sshd_config /etc/crontab; do
    inspect_path "$path" | tee -a "$REPORT"
done

section "Available enumeration tools"

for cmd in find getcap sudo systemctl crontab gcc python3 \
           perl ruby curl wget sha256sum; do
    if command -v "$cmd" >/dev/null 2>&1; then
        printf 'FOUND %s: %s\n' "$cmd" "$(command -v "$cmd")" |
            tee -a "$REPORT"
    else
        printf 'NOT FOUND %s\n' "$cmd" | tee -a "$REPORT"
    fi
done

section "Package inventory"

if command -v dpkg-query >/dev/null 2>&1; then
    if ! dpkg-query -W -f='${binary:Package}\t${Version}\n' 2>/dev/null |
        sort | tee -a "$REPORT"; then
        record_error "Package inventory failed"
        CHECKS_INCOMPLETE=$((CHECKS_INCOMPLETE + 1))
    fi
elif command -v rpm >/dev/null 2>&1; then
    if ! rpm -qa 2>/dev/null | sort | tee -a "$REPORT"; then
        record_error "Package inventory failed"
        CHECKS_INCOMPLETE=$((CHECKS_INCOMPLETE + 1))
    fi
else
    CHECKS_SKIPPED=$((CHECKS_SKIPPED + 1))
    echo "No supported package manager detected." | tee -a "$REPORT"
fi

section "Baseline comparison"

if (( UPDATE_BASELINE )); then
    tmp="$(mktemp "$OUTDIR/.baseline.XXXXXX")" || {
        record_error "Cannot create temporary baseline"
        CHECKS_INCOMPLETE=$((CHECKS_INCOMPLETE + 1))
        tmp=""
    }

    if [[ -n "$tmp" ]]; then
        if sort -u "$FINDINGS" > "$tmp"; then
            # Verify the desired permissions before replacing the baseline.
            if chmod 600 "$tmp"; then
                if mv -f -- "$tmp" "$BASELINE"; then
                    # Verify final baseline permissions as well.
                    if chmod 600 "$BASELINE"; then
                        BASELINE_SEEN=1
                        echo "Baseline updated successfully: $BASELINE" |
                            tee -a "$REPORT"
                    else
                        record_error \
                            "Baseline replaced, but chmod 600 failed: $BASELINE"
                        CHECKS_INCOMPLETE=$((CHECKS_INCOMPLETE + 1))
                    fi
                else
                    record_error "Could not replace baseline: $BASELINE"
                    CHECKS_INCOMPLETE=$((CHECKS_INCOMPLETE + 1))
                    rm -f -- "$tmp"
                fi
            else
                record_error "Could not set permissions on temporary baseline"
                CHECKS_INCOMPLETE=$((CHECKS_INCOMPLETE + 1))
                rm -f -- "$tmp"
            fi
        else
            record_error "Could not sort findings for baseline"
            CHECKS_INCOMPLETE=$((CHECKS_INCOMPLETE + 1))
            rm -f -- "$tmp"
        fi
    fi

elif [[ -f "$BASELINE" ]]; then
    BASELINE_SEEN=1

    CURRENT_SORTED="$(mktemp "$OUTDIR/.current.XXXXXX")" || {
        record_error "Cannot create temporary file for baseline comparison"
        CHECKS_INCOMPLETE=$((CHECKS_INCOMPLETE + 1))
        CURRENT_SORTED=""
    }

    if [[ -n "$CURRENT_SORTED" ]]; then
        if sort -u "$FINDINGS" > "$CURRENT_SORTED"; then
            if diff -u "$BASELINE" "$CURRENT_SORTED" > "$DIFF"; then
                echo "No changes in recorded findings." | tee -a "$REPORT"
            else
                rc=$?
                if (( rc == 1 )); then
                    echo "Changes detected; review $DIFF" | tee -a "$REPORT"
                    cat "$DIFF" | tee -a "$REPORT"
                else
                    record_error "Baseline comparison failed with status $rc"
                    CHECKS_INCOMPLETE=$((CHECKS_INCOMPLETE + 1))
                fi
            fi
        else
            record_error "Could not sort current findings"
            CHECKS_INCOMPLETE=$((CHECKS_INCOMPLETE + 1))
        fi

        rm -f -- "$CURRENT_SORTED"
    fi
else
    CHECKS_SKIPPED=$((CHECKS_SKIPPED + 1))
    echo "No baseline found; use --update-baseline after reviewing results." |
        tee -a "$REPORT"
fi

section "Final summary"

INFO_COUNT="$(awk -F '\t' '$1=="INFO"{n++} END{print n+0}' "$FINDINGS")"
REVIEW_COUNT="$(awk -F '\t' '$1=="REVIEW"{n++} END{print n+0}' "$FINDINGS")"

{
    printf 'Host: %s\n' "$(hostname 2>/dev/null || echo unknown)"
    printf 'User: %s\n' "$(id -un 2>/dev/null || echo unknown)"
    printf 'Checks attempted: %s\n' "$SCANS"
    printf 'Checks skipped: %s\n' "$CHECKS_SKIPPED"
    printf 'Checks incomplete: %s\n' "$CHECKS_INCOMPLETE"
    printf 'Reported error events: %s\n' "$SCAN_ERRORS"
    printf 'Informational findings: %s\n' "$INFO_COUNT"
    printf 'Items requiring review: %s\n' "$REVIEW_COUNT"
    printf 'Baseline available: %s\n' "$BASELINE_SEEN"
    printf 'Detailed report: %s\n' "$REPORT"
    printf 'Findings: %s\n' "$FINDINGS"
    printf 'Error log: %s\n' "$ERRORS"
    printf '\nLimitations:\n'
    printf '%s\n' \
        '- Filesystem scans use -xdev and may skip mounted filesystems.' \
        '- Permission errors can prevent complete enumeration.' \
        '- Findings are not confirmed vulnerabilities.' \
        '- Scheduled-task path extraction is heuristic.' \
        '- Baselines compare recorded findings, not the entire system.'
} | tee -a "$SUMMARY" "$REPORT"

echo
echo "Audit completed. Review the summary and error log."
