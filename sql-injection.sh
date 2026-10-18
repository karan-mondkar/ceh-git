#!/usr/bin/env bash
# sql.sh - SQLmap database discovery or full dump of a selected database.
# Use only against systems you own or are explicitly authorized to test.

set -Eeuo pipefail
umask 077

SQLMAP_PATH="/usr/bin/sqlmap"
REQUEST_FILE=""
DATABASE=""
OUTPUT_ROOT="$PWD"
RUN_DIR=""
SQLMAP_OUTPUT_DIR=""
LOG_FILE=""

log_info() { printf '[INFO] %s\n' "$*"; }
log_error() { printf '[ERROR] %s\n' "$*" >&2; }
die() { log_error "$*"; exit 1; }

usage() {
    cat <<'USAGE'
Usage:
  ./sql.sh REQUEST_FILE
      Discover database names and display/save the output.

  ./sql.sh REQUEST_FILE DATABASE
      Attempt to dump all tables and rows from the selected database.
      No table name is required. SQLmap is run in batch mode.

Options:
  --output-root DIR    Parent directory for saved results (default: current directory)
  --sqlmap PATH        SQLmap executable path
  -h, --help           Display this help

Examples:
  ./sql.sh request.txt
  ./sql.sh request.txt GoodShopping
  ./sql.sh request.txt GoodShopping --output-root ./results
  ./sql.sh request.txt --sqlmap /usr/bin/sqlmap

Notes:
  - The request file should be a valid SQLmap -r HTTP request file.
  - Selected-database mode uses: -D DATABASE --dump
  - Results depend on the target, injection point, permissions, and SQLmap capabilities.
USAGE
}

check_dependencies() {
    if [[ ! -x "$SQLMAP_PATH" ]]; then
        SQLMAP_PATH="$(command -v sqlmap || true)"
    fi
    [[ -n "$SQLMAP_PATH" && -x "$SQLMAP_PATH" ]] ||
        die "SQLmap not found. Install it or provide --sqlmap PATH."

    local cmd
    for cmd in realpath tee; do
        command -v "$cmd" >/dev/null 2>&1 || die "Required command missing: $cmd"
    done
}

prepare_output() {
    local safe_name
    if [[ -n "$DATABASE" ]]; then
        safe_name="$(printf '%s' "$DATABASE" | sed 's/[^a-zA-Z0-9_.-]/_/g')"
        [[ -n "$safe_name" ]] || die "Invalid database name."
        RUN_DIR="${OUTPUT_ROOT}/sql_inj_${safe_name}"
    else
        RUN_DIR="${OUTPUT_ROOT}/sql_inj_database_discovery"
    fi

    mkdir -p -- "$RUN_DIR" || die "Cannot create results directory: $RUN_DIR"
    RUN_DIR="$(realpath "$RUN_DIR")"
    SQLMAP_OUTPUT_DIR="${RUN_DIR}/sqlmap_output"
    mkdir -p -- "$SQLMAP_OUTPUT_DIR" || die "Cannot create SQLmap output directory."
    LOG_FILE="${RUN_DIR}/terminal_output.txt"

    log_info "Results directory: $RUN_DIR"
    log_info "SQLmap native output directory: $SQLMAP_OUTPUT_DIR"
    log_info "Terminal transcript: $LOG_FILE"
}

# Display SQLmap output live while saving it. Preserve SQLmap's exit status,
# rather than tee's exit status.
run_sqlmap_live() {
    local status
    local -a pipeline_status

    log_info "Running SQLmap with arguments: $*"
    set +e
    "$SQLMAP_PATH" \
        --batch \
        --disable-coloring \
        "--output-dir=$SQLMAP_OUTPUT_DIR" \
        "$@" 2>&1 | tee -a "$LOG_FILE"
    pipeline_status=("${PIPESTATUS[@]}")
    status="${pipeline_status[0]}"
    set -e

    if (( status != 0 )); then
        log_error "SQLmap exited with status $status."
        return "$status"
    fi
    return 0
}

main() {
    local -a positional=()

    while (($#)); do
        case "$1" in
            --output-root)
                (($# >= 2)) || die "--output-root requires a directory."
                OUTPUT_ROOT="$2"
                shift 2
                ;;
            --sqlmap)
                (($# >= 2)) || die "--sqlmap requires an executable path."
                SQLMAP_PATH="$2"
                shift 2
                ;;
            -h|--help)
                usage
                return 0
                ;;
            --)
                shift
                while (($#)); do positional+=("$1"); shift; done
                ;;
            -* )
                die "Unknown option: $1"
                ;;
            *)
                positional+=("$1")
                shift
                ;;
        esac
    done

    ((${#positional[@]} >= 1 && ${#positional[@]} <= 2)) || {
        usage >&2
        die "Provide a request file and optionally one database name."
    }

    REQUEST_FILE="${positional[0]}"
    if ((${#positional[@]} == 2)); then DATABASE="${positional[1]}"; fi

    [[ -f "$REQUEST_FILE" && -r "$REQUEST_FILE" && -s "$REQUEST_FILE" ]] ||
        die "Request file is missing, unreadable, or empty: $REQUEST_FILE"
    REQUEST_FILE="$(realpath "$REQUEST_FILE")"

    check_dependencies
    prepare_output

    log_info "Request file: $REQUEST_FILE"
    log_info "SQLmap executable: $SQLMAP_PATH"

    if [[ -z "$DATABASE" ]]; then
        log_info "Mode: database-name discovery"
        run_sqlmap_live -r "$REQUEST_FILE" --dbs ||
            die "Database discovery failed. Check the transcript and SQLmap output."
        log_info "Database discovery finished."
    else
        log_info "Mode: dump all tables/rows from selected database: $DATABASE"
        log_info "No table name is required; SQLmap will attempt the selected database's tables."
        run_sqlmap_live -r "$REQUEST_FILE" -D "$DATABASE" --dump ||
            die "Database dump failed or was incomplete. Check the transcript and SQLmap output."
        log_info "SQLmap finished its dump attempt. Review its output for skipped tables or errors."
    fi

    log_info "Results directory: $RUN_DIR"
    log_info "Terminal transcript: $LOG_FILE"
    log_info "SQLmap native results: $SQLMAP_OUTPUT_DIR"
}

main "$@"
