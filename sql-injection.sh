
#!/usr/bin/env bash
# sql.sh - SQLmap database discovery and selected-database enumeration.
# Use only on systems you own or are explicitly authorized to test.

set -Eeuo pipefail
umask 077

SQLMAP_PATH="/usr/bin/sqlmap"
REQUEST_FILE=""
DATABASE=""
OUTPUT_ROOT="${PWD}"
RUN_DIR=""
SQLMAP_OUTPUT_DIR=""
LOG_FILE=""

log_info() {
    printf '[INFO] %s\n' "$*"
}

log_error() {
    printf '[ERROR] %s\n' "$*" >&2
}

die() {
    log_error "$*"
    exit 1
}

usage() {
    cat <<'USAGE'
Usage:
  ./sql.sh REQUEST_FILE
      Discover database names and display the output.

  ./sql.sh REQUEST_FILE DATABASE
      Enumerate tables and columns in the selected database.
      Does not perform database discovery in this mode.

Options:
  --output-root DIR    Parent directory for saved results
  --sqlmap PATH        SQLmap executable path
  -h, --help           Display help

Examples:
  ./sql.sh file.txt
  ./sql.sh file.txt GoodShopping
  ./sql.sh file.txt GoodShopping --output-root ./results
USAGE
}

check_dependencies() {
    if [[ ! -x "$SQLMAP_PATH" ]]; then
        SQLMAP_PATH="$(command -v sqlmap || true)"
    fi

    [[ -n "$SQLMAP_PATH" && -x "$SQLMAP_PATH" ]] ||
        die "SQLmap not found. Install it or use --sqlmap PATH."

    command -v realpath >/dev/null 2>&1 ||
        die "Required command missing: realpath"

    command -v tee >/dev/null 2>&1 ||
        die "Required command missing: tee"
}

prepare_output() {
    local safe_name

    if [[ -n "$DATABASE" ]]; then
        # Keep the database name safe for use in a directory name.
        safe_name="$(printf '%s' "$DATABASE" |
            sed 's/[^a-zA-Z0-9_.-]/_/g')"

        [[ -n "$safe_name" ]] || die "Invalid database name."

        RUN_DIR="${OUTPUT_ROOT}/sql_inj_${safe_name}"
    else
        RUN_DIR="${OUTPUT_ROOT}/sql_inj_database_discovery"
    fi

    mkdir -p -- "$RUN_DIR" ||
        die "Cannot create results directory: $RUN_DIR"

    RUN_DIR="$(realpath "$RUN_DIR")"
    SQLMAP_OUTPUT_DIR="${RUN_DIR}/sqlmap_output"

    mkdir -p -- "$SQLMAP_OUTPUT_DIR" ||
        die "Cannot create SQLmap output directory."

    LOG_FILE="${RUN_DIR}/terminal_output.txt"

    log_info "Results directory: $RUN_DIR"
    log_info "Terminal output file: $LOG_FILE"
}

# Run SQLmap while displaying output immediately and saving the same
# output to a text file. Return SQLmap's actual exit status.
run_sqlmap_live() {
    local status
    local -a pipeline_status

    log_info "Running: sqlmap $*"

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
            -*)
                die "Unknown option: $1"
                ;;
            *)
                positional+=("$1")
                shift
                ;;
        esac
    done

    ((${#positional[@]} >= 1 && ${#positional[@]} <= 2)) ||
        die "Provide a request file and optionally one database name. Use --help."

    REQUEST_FILE="${positional[0]}"

    if ((${#positional[@]} == 2)); then
        DATABASE="${positional[1]}"
    fi

    [[ -f "$REQUEST_FILE" && -r "$REQUEST_FILE" && -s "$REQUEST_FILE" ]] ||
        die "Request file is missing, unreadable, or empty: $REQUEST_FILE"

    REQUEST_FILE="$(realpath "$REQUEST_FILE")"

    check_dependencies
    prepare_output

    log_info "Request file: $REQUEST_FILE"
    log_info "SQLmap executable: $SQLMAP_PATH"

    if [[ -z "$DATABASE" ]]; then
        # Mode 1: only discover and display database names.
        log_info "Discovering database names..."

        run_sqlmap_live -r "$REQUEST_FILE" --dbs ||
            die "Database discovery failed. See the output above."

        log_info "Database discovery finished."
        log_info "Saved output: $LOG_FILE"
        return 0
    fi

    # Mode 2: do not run --dbs. Use the database provided by the user.
    log_info "Selected database: $DATABASE"
    log_info "Enumerating all tables in the selected database..."

    run_sqlmap_live \
        -r "$REQUEST_FILE" \
        -D "$DATABASE" \
        --tables ||
        die "Table enumeration failed. See the output above."

    log_info "Enumerating columns in the selected database..."

    run_sqlmap_live \
        -r "$REQUEST_FILE" \
        -D "$DATABASE" \
        --columns ||
        die "Column enumeration failed. See the output above."

    log_info "Enumeration completed."
    log_info "Results directory: $RUN_DIR"
    log_info "Readable terminal transcript: $LOG_FILE"
    log_info "SQLmap's native results: $SQLMAP_OUTPUT_DIR"
    log_info "No table-row dump was requested by this script."
}

main "$@"
