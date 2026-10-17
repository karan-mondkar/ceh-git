#!/usr/bin/env bash
# SQLmap database discovery and table enumeration helper.
# Use only on systems you own or are explicitly authorized to test.

set -Eeuo pipefail
umask 077

SQLMAP_PATH="/usr/bin/sqlmap"
OUTPUT_DIR="sqlmap_audit_$(date +%Y%m%d_%H%M%S)"
REQUEST_FILE=""
DATABASE=""
SQLMAP_LAST_OUTPUT=""

SYSTEM_DATABASES=(
    information_schema
    mysql
    performance_schema
    sys
    master
    model
    msdb
    tempdb
)

log_info()  { printf '[INFO] %s\n' "$*"; }
log_error() { printf '[ERROR] %s\n' "$*" >&2; }
die()       { log_error "$*"; exit 1; }

usage() {
    cat <<'USAGE'
Usage:
  ./sql-injection.sh -r REQUEST_FILE
      Discover and display database names only.

  ./sql-injection.sh -r REQUEST_FILE DATABASE
      Discover databases, then enumerate all tables in DATABASE.

  ./sql-injection.sh REQUEST_FILE [DATABASE]
      Equivalent positional-argument form.

Options:
  -r FILE          Request file captured from an authorized test
  --output DIR     SQLmap output directory
  --sqlmap PATH    SQLmap executable path
  -h, --help       Show this help

Examples:
  ./sql-injection.sh -r /home/attacker/req.txt
  ./sql-injection.sh -r /home/attacker/req.txt GoodShopping
  ./sql-injection.sh /home/attacker/req.txt GoodShopping --output results
USAGE
    exit 0
}

is_system_database() {
    local candidate="${1,,}"
    local item

    for item in "${SYSTEM_DATABASES[@]}"; do
        [[ "$candidate" == "$item" ]] && return 0
    done
    return 1
}

check_dependencies() {
    if [[ ! -x "$SQLMAP_PATH" ]]; then
        SQLMAP_PATH="$(command -v sqlmap || true)"
    fi

    [[ -n "$SQLMAP_PATH" && -x "$SQLMAP_PATH" ]] ||
        die "SQLmap executable not found. Install SQLmap or use --sqlmap PATH."
    command -v realpath >/dev/null 2>&1 || die "Required command not found: realpath"
    command -v awk >/dev/null 2>&1 || die "Required command not found: awk"
}

run_sqlmap() {
    local status=0
    local output=""

    if output="$("$SQLMAP_PATH" --batch --disable-coloring "--output-dir=$OUTPUT_DIR" "$@" 2>&1)"; then
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

extract_databases() {
    printf '%s\n' "$1" | awk '
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
}

validate_database_exists() {
    local requested="$1"
    local found_db=""
    local db
    local -a discovered=()

    mapfile -t discovered < <(extract_databases "$SQLMAP_LAST_OUTPUT")

    for db in "${discovered[@]}"; do
        if [[ "${db,,}" == "${requested,,}" ]]; then
            found_db="$db"
            break
        fi
    done

    [[ -n "$found_db" ]] ||
        die "Database '$requested' was not found in SQLmap's discovered database list."

    is_system_database "$found_db" &&
        die "Refusing to enumerate system database '$found_db'."

    DATABASE="$found_db"
}

main() {
    local -a positional=()
    local -a discovered=()
    local db

    while (($#)); do
        case "$1" in
            -r)
                (($# >= 2)) || die "-r requires a request filename."
                [[ -z "$REQUEST_FILE" ]] || die "Request file was specified more than once."
                REQUEST_FILE="$2"
                shift 2
                ;;
            --output)
                (($# >= 2)) || die "--output requires a directory."
                OUTPUT_DIR="$2"
                shift 2
                ;;
            --sqlmap)
                (($# >= 2)) || die "--sqlmap requires an executable path."
                SQLMAP_PATH="$2"
                shift 2
                ;;
            -h|--help)
                usage
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

    # Support both -r FILE [DATABASE] and FILE [DATABASE].
    if [[ -z "$REQUEST_FILE" ]]; then
        ((${#positional[@]} >= 1)) || usage
        REQUEST_FILE="${positional[0]}"
        positional=("${positional[@]:1}")
    fi

    ((${#positional[@]} <= 1)) || die "Expected at most one database name after the request file."
    if ((${#positional[@]} == 1)); then
        [[ -z "$DATABASE" ]] || die "Database was specified more than once."
        DATABASE="${positional[0]}"
    fi

    [[ -f "$REQUEST_FILE" && -r "$REQUEST_FILE" && -s "$REQUEST_FILE" ]] ||
        die "Request file is missing, unreadable, or empty: $REQUEST_FILE"

    REQUEST_FILE="$(realpath "$REQUEST_FILE")"
    check_dependencies

    mkdir -p -- "$OUTPUT_DIR" || die "Cannot create output directory: $OUTPUT_DIR"
    OUTPUT_DIR="$(realpath "$OUTPUT_DIR")"

    log_info "Request file: $REQUEST_FILE"
    log_info "SQLmap executable: $SQLMAP_PATH"
    log_info "Output directory: $OUTPUT_DIR"

    # Always discover databases first.
    log_info "Discovering database names..."
    run_sqlmap -r "$REQUEST_FILE" --dbs || die "Database discovery failed; review SQLmap output above."

    mapfile -t discovered < <(extract_databases "$SQLMAP_LAST_OUTPUT")
    ((${#discovered[@]} > 0)) ||
        die "Could not parse database names from SQLmap output; its output format may differ."

    printf '\nDiscovered databases:\n'
    for db in "${discovered[@]}"; do
        if is_system_database "$db"; then
            printf '  %s [system database]\n' "$db"
        else
            printf '  %s\n' "$db"
        fi
    done

    # No database argument: stop after listing database names.
    if [[ -z "$DATABASE" ]]; then
        printf '\nNext step: ./sql-injection.sh -r "%s" DATABASE\n' "$REQUEST_FILE"
        return 0
    fi

    validate_database_exists "$DATABASE"

    # Enumerate all tables only in the user-selected database.
    log_info "Enumerating all tables in database: $DATABASE"
    run_sqlmap -r "$REQUEST_FILE" -D "$DATABASE" --tables ||
        die "Table enumeration failed; review SQLmap output above."

    log_info "Finished. No columns or table data were requested."
    log_info "SQLmap output directory: $OUTPUT_DIR"
}

main "$@"
