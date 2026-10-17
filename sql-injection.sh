
#!/usr/bin/env bash
# db.sh - Automated SQLmap Database Audit Tool
# Use only against systems you own or are authorized to test.
# Root privileges are not normally required for this script.

set -Eeuo pipefail
umask 077

# --- Configuration ---
SQLMAP_PATH="/usr/bin/sqlmap"
DEFAULT_OUTPUT_DIR="sqlmap_audit_$(date +%Y%m%d_%H%M%S)"
CONFIG_FILE=""
DRY_RUN=false
EXPORT_SCOPE=""
ROW_LIMIT=100
EXPORT_FORMAT="CSV"

REQUEST_FILE=""
OUTPUT_DIR=""
SELECTED_DB=""
SQLMAP_LAST_OUTPUT=""

STARTED_AT="$(date '+%Y-%m-%d %H:%M:%S')"
ASSESSMENT_STATUS="NOT_RUN"
DATABASE_STATUS="NOT_RUN"
TABLE_STATUS="NOT_RUN"
COLUMN_STATUS="NOT_RUN"
EXPORT_STATUS="NOT_RUN"

# --- Logging functions ---
# Errors go directly to the terminal; no custom error log is created.

function log_info() {
    printf '[INFO] %s\n' "$*"
}

function log_warn() {
    printf '[WARN] %s\n' "$*" >&2
}

function log_error() {
    printf '[ERROR] %s\n' "$*" >&2
}

function log_done() {
    printf '[DONE] %s\n' "$*"
}

function usage() {
    cat <<'USAGE'
Usage:
  ./db.sh REQUEST_FILE [options]

Options:
  --output DIR             Results directory
  --config FILE            Read KEY=VALUE configuration
  --dry-run                Skip actual data exports
  --export-scope SCOPE     Explicit tables: db:DATABASE:TABLE[,db:DATABASE:TABLE]
  --row-limit N            Maximum rows per exported table (default: 100)
  --export-format FORMAT   CSV, HTML, or SQLITE (default: CSV)
  --help                   Display this help

Config keys:
  SQLMAP_PATH
  OUTPUT_DIR
  DRY_RUN
  EXPORT_SCOPE
  ROW_LIMIT
  EXPORT_FORMAT

Examples:
  ./db.sh req.txt
  ./db.sh req.txt --output results
  ./db.sh req.txt --export-scope 'db:FIRST:users' --row-limit 100 --dry-run

FIRST in an export scope means the first database discovered by SQLmap.
USAGE
    exit 0
}

function die() {
    log_error "$*"
    exit 1
}

# --- Read simple KEY=VALUE configuration safely ---
# This does not execute the config file as shell code.

function load_config() {
    local config_file="$1"
    local line key value

    [[ -f "$config_file" && -r "$config_file" ]] ||
        die "Configuration file is missing or unreadable: $config_file"

    while IFS= read -r line || [[ -n "$line" ]]; do
        line="${line%%#*}"
        [[ "$line" =~ ^[[:space:]]*$ ]] && continue

        [[ "$line" == *=* ]] ||
            die "Invalid config line (expected KEY=VALUE): $line"

        key="${line%%=*}"
        value="${line#*=}"

        key="$(printf '%s' "$key" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
        value="$(printf '%s' "$value" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"

        case "$key" in
            SQLMAP_PATH)   SQLMAP_PATH="$value" ;;
            OUTPUT_DIR)    OUTPUT_DIR="$value" ;;
            DRY_RUN)       DRY_RUN="$value" ;;
            EXPORT_SCOPE)  EXPORT_SCOPE="$value" ;;
            ROW_LIMIT)     ROW_LIMIT="$value" ;;
            EXPORT_FORMAT) EXPORT_FORMAT="$value" ;;
            *)
                die "Unknown configuration key: $key"
                ;;
        esac
    done < "$config_file"
}

# --- Parse arguments ---
# Load config first so command-line options override config values.

ARGS=("$@")

for ((i=0; i<${#ARGS[@]}; i++)); do
    if [[ "${ARGS[i]}" == "--config" ]]; then
        if (( i + 1 >= ${#ARGS[@]} )); then
            die "--config requires a file path."
        fi
        CONFIG_FILE="${ARGS[i+1]}"
    fi
done

if [[ -n "$CONFIG_FILE" ]]; then
    load_config "$CONFIG_FILE"
fi

while (($#)); do
    case "$1" in
        --output)
            [[ $# -ge 2 ]] || die "--output requires a directory."
            OUTPUT_DIR="$2"
            shift 2
            ;;
        --config)
            [[ $# -ge 2 ]] || die "--config requires a file path."
            shift 2
            ;;
        --dry-run)
            DRY_RUN=true
            shift
            ;;
        --export-scope)
            [[ $# -ge 2 ]] || die "--export-scope requires a value."
            EXPORT_SCOPE="$2"
            shift 2
            ;;
        --row-limit)
            [[ $# -ge 2 ]] || die "--row-limit requires a number."
            ROW_LIMIT="$2"
            shift 2
            ;;
        --export-format)
            [[ $# -ge 2 ]] || die "--export-format requires a value."
            EXPORT_FORMAT="$2"
            shift 2
            ;;
        --help|-h)
            usage
            ;;
        -*)
            die "Unknown option: $1"
            ;;
        *)
            if [[ -z "$REQUEST_FILE" ]]; then
                REQUEST_FILE="$1"
            else
                die "Unexpected extra argument: $1"
            fi
            shift
            ;;
    esac
done

[[ -n "$REQUEST_FILE" ]] ||
    die "Request file not specified. Use --help for usage."

# --- Dependency checks ---

function check_dependencies() {
    if [[ ! -x "$SQLMAP_PATH" ]]; then
        SQLMAP_PATH="$(command -v sqlmap || true)"
    fi

    [[ -n "$SQLMAP_PATH" && -x "$SQLMAP_PATH" ]] ||
        die "SQLmap executable not found. Check SQLMAP_PATH."

    command -v realpath >/dev/null 2>&1 ||
        die "Required command not found: realpath"

    command -v sed >/dev/null 2>&1 ||
        die "Required command not found: sed"

    log_info "SQLmap executable: $SQLMAP_PATH"
}

# --- Validate request file ---

function validate_request_file() {
    local request_file="$1"

    [[ -f "$request_file" ]] ||
        die "Request file does not exist: $request_file"

    [[ -r "$request_file" ]] ||
        die "Cannot read request file: $request_file"

    [[ -s "$request_file" ]] ||
        die "Request file is empty: $request_file"

    REQUEST_FILE="$(realpath "$request_file")"
    log_info "Validated request file: $REQUEST_FILE"
}

# --- Prepare output directory ---

function prepare_output_directory() {
    OUTPUT_DIR="${OUTPUT_DIR:-$DEFAULT_OUTPUT_DIR}"

    mkdir -p -- "$OUTPUT_DIR" ||
        die "Cannot create output directory: $OUTPUT_DIR"

    OUTPUT_DIR="$(realpath "$OUTPUT_DIR")"
    log_info "Results directory: $OUTPUT_DIR"
}

# --- Execute SQLmap without saving error output to a custom log ---
# stdout is captured in memory for database-name parsing.
# stderr remains connected directly to the terminal.

function run_sqlmap() {
    local output
    local status=0

    if output="$("$SQLMAP_PATH" \
        --batch \
        --disable-coloring \
        "--output-dir=$OUTPUT_DIR" \
        "$@")"; then
        SQLMAP_LAST_OUTPUT="$output"
        [[ -z "$output" ]] || printf '%s\n' "$output"
        return 0
    else
        status=$?
        SQLMAP_LAST_OUTPUT="$output"
        [[ -z "$output" ]] || printf '%s\n' "$output"
        return "$status"
    fi
}

function run_stage() {
    local stage="$1"
    shift

    log_info "Starting stage: $stage"

    if run_sqlmap "$@"; then
        log_info "Stage completed: $stage"
        return 0
    else
        local status=$?
        log_error "Stage failed: $stage (exit code $status)"
        return "$status"
    fi
}

# --- Initial SQL injection assessment ---

function sqlmap_assessment() {
    log_info "Starting SQL injection assessment..."

    run_stage "SQL injection assessment" \
        -r "$REQUEST_FILE" \
        --dbms=MySQL \
        --level=5 \
        --risk=3 \
        --random-agent
}

# --- Discover databases and select the first reported database ---

function discover_databases() {
    local database

    log_info "Discovering databases..."

    if ! run_stage "Database discovery" \
        -r "$REQUEST_FILE" \
        --dbs; then
        DATABASE_STATUS="FAILED"
        return 1
    fi

    local -a DISCOVERED_DATABASES=()

    mapfile -t DISCOVERED_DATABASES < <(
        printf '%s\n' "$SQLMAP_LAST_OUTPUT" |
        awk '
            /available databases[[:space:]]*\[[0-9]+\]:/ {
                inlist=1
                next
            }
            inlist && /^[[:space:]]*\[\*\][[:space:]]*/ {
                sub(/^[[:space:]]*\[\*\][[:space:]]*/, "")
                if (length($0) > 0) print
                next
            }
            inlist && /^[[:space:]]*$/ { next }
            inlist { exit }
        '
    )

    if ((${#DISCOVERED_DATABASES[@]} == 0)); then
        DATABASE_STATUS="FAILED"
        log_error "No database list could be parsed from SQLmap output."
        log_warn "The target may have no accessible databases, or SQLmap output may differ."
        return 1
    fi

    log_info "Databases reported by SQLmap:"
    for database in "${DISCOVERED_DATABASES[@]}"; do
        printf '  - %s\n' "$database"
    done

    # Use exactly the first database reported by SQLmap.
    SELECTED_DB="${DISCOVERED_DATABASES[0]}"
    DATABASE_STATUS="SUCCESS"

    log_info "Selected first discovered database: $SELECTED_DB"
    log_warn "The first database may be a system database; it is not automatically skipped."
}

# --- Enumerate tables in the selected database ---

function enumerate_tables() {
    [[ -n "$SELECTED_DB" ]] ||
        die "Cannot enumerate tables: no database was selected."

    log_info "Enumerating tables in database: $SELECTED_DB"

    run_stage "Table enumeration" \
        -r "$REQUEST_FILE" \
        -D "$SELECTED_DB" \
        --tables
}

# --- Enumerate columns in the selected database ---

function enumerate_columns() {
    [[ -n "$SELECTED_DB" ]] ||
        die "Cannot enumerate columns: no database was selected."

    log_info "Enumerating columns in database: $SELECTED_DB"

    run_stage "Column enumeration" \
        -r "$REQUEST_FILE" \
        -D "$SELECTED_DB" \
        --columns
}

# --- Export explicitly scoped tables only ---

function export_data() {
    local output_dir="$1"
    local export_scope="$2"
    local row_limit="$3"
    local export_format="$4"

    if [[ -z "$export_scope" ]]; then
        EXPORT_STATUS="SKIPPED"
        log_warn "No export scope specified; skipping data export."
        return 0
    fi

    if [[ "$DRY_RUN" == true ]]; then
        log_warn "Dry-run enabled: no table data will be exported."
    fi

    local -a ITEMS=()
    local item scope_kind database table extra

    IFS=',' read -r -a ITEMS <<< "$export_scope"

    for item in "${ITEMS[@]}"; do
        item="$(printf '%s' "$item" |
            sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"

        IFS=':' read -r scope_kind database table extra <<< "$item"

        if [[ "$scope_kind" != "db" ||
              -z "${database:-}" ||
              -z "${table:-}" ||
              -n "${extra:-}" ]]; then
            log_error "Invalid scope '$item'. Expected db:DATABASE:TABLE."
            EXPORT_STATUS="FAILED"
            return 1
        fi

        if [[ "$database" == "FIRST" ]]; then
            [[ -n "$SELECTED_DB" ]] ||
                die "FIRST requested for export, but no database was selected."
            database="$SELECTED_DB"
        fi

        log_info "Export scope: database='$database', table='$table', row limit=$row_limit"

        if [[ "$DRY_RUN" == true ]]; then
            log_info "Dry run: export skipped for $database.$table"
            continue
        fi

        # The HTTP request and database are passed explicitly.
        if ! run_stage "Export $database.$table" \
            -r "$REQUEST_FILE" \
            --random-agent \
            -D "$database" \
            -T "$table" \
            --dump \
            "--limit=$row_limit" \
            "--dump-format=$export_format"; then
            EXPORT_STATUS="FAILED"
            return 1
        fi
    done

    if [[ "$DRY_RUN" == true ]]; then
        EXPORT_STATUS="DRY_RUN"
    else
        EXPORT_STATUS="SUCCESS"
    fi

    log_info "Export-scope processing completed."
}

# --- Generate accurate report ---

function generate_report() {
    local overall_status="$1"
    local report_file="$OUTPUT_DIR/report.txt"
    local finished_at

    finished_at="$(date '+%Y-%m-%d %H:%M:%S')"

    {
        printf 'SQLmap Database Audit Report\n'
        printf '%s\n' '========================================'
        printf 'Started: %s\n' "$STARTED_AT"
        printf 'Finished: %s\n' "$finished_at"
        printf 'Overall status: %s\n' "$overall_status"
        printf 'Request file: %s\n' "$REQUEST_FILE"
        printf 'SQLmap executable: %s\n' "$SQLMAP_PATH"
        printf 'Selected database: %s\n' "${SELECTED_DB:-Not selected}"
        printf 'SQLmap output directory: %s\n' "$OUTPUT_DIR"
        printf '\nStage statuses:\n'
        printf '  Assessment: %s\n' "$ASSESSMENT_STATUS"
        printf '  Database discovery: %s\n' "$DATABASE_STATUS"
        printf '  Table enumeration: %s\n' "$TABLE_STATUS"
        printf '  Column enumeration: %s\n' "$COLUMN_STATUS"
        printf '  Data export: %s\n' "$EXPORT_STATUS"
        printf '\n'
        printf '%s\n' 'Note: SQLmap output files are in its output directory.'
        printf '%s\n' 'This report does not claim that a vulnerability was confirmed.'
    } > "$report_file"

    log_info "Report generated: $report_file"
}

# --- Main workflow ---

function main() {
    local overall_status="SUCCESS"

    check_dependencies
    validate_request_file "$REQUEST_FILE"
    prepare_output_directory

    if sqlmap_assessment; then
        ASSESSMENT_STATUS="SUCCESS"
    else
        ASSESSMENT_STATUS="FAILED"
        generate_report "FAILED"
        die "Assessment failed. See the terminal output above."
    fi

    if discover_databases; then
        :
    else
        generate_report "FAILED"
        die "Database discovery failed. See the terminal output above."
    fi

    if enumerate_tables; then
        TABLE_STATUS="SUCCESS"
    else
        TABLE_STATUS="FAILED"
        generate_report "FAILED"
        die "Table enumeration failed. See the terminal output above."
    fi

    if enumerate_columns; then
        COLUMN_STATUS="SUCCESS"
    else
        COLUMN_STATUS="FAILED"
        generate_report "FAILED"
        die "Column enumeration failed. See the terminal output above."
    fi

    if export_data "$OUTPUT_DIR" "$EXPORT_SCOPE" "$ROW_LIMIT" "$EXPORT_FORMAT"; then
        :
    else
        overall_status="PARTIAL_FAILURE"
        generate_report "$overall_status"
        die "One or more export operations failed."
    fi

    generate_report "$overall_status"
    log_done "Assessment workflow finished."
    log_info "Review the report and SQLmap output directory: $OUTPUT_DIR"
}

# --- Validate configuration values ---

[[ "$DRY_RUN" == true || "$DRY_RUN" == false ]] ||
    die "DRY_RUN must be true or false."

[[ "$ROW_LIMIT" =~ ^[1-9][0-9]*$ ]] ||
    die "ROW_LIMIT must be a positive integer."

EXPORT_FORMAT="${EXPORT_FORMAT^^}"

case "$EXPORT_FORMAT" in
    CSV|HTML|SQLITE) ;;
    *) die "EXPORT_FORMAT must be CSV, HTML, or SQLITE." ;;
esac

main
