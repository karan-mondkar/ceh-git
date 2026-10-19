#!/usr/bin/env bash
# Batch-extract the three apps shown by PhoneSploit Pro option 36 and calculate CRC32.
# This Bash script drives PhoneSploit through its menus using Expect. It does NOT call adb directly.
# PhoneSploit itself may use ADB internally.
set -Eeuo pipefail

usage() {
  cat <<'USAGE'
Usage:
  ./android_apk_crc_phonesploit_only.sh [PhoneSploit-Pro-directory] [device-ip]

Optional output folder override:
  OUTPUT_DIR="/path/to/output" ./android_apk_crc_phonesploit_only.sh ...

Example:
  ./android_apk_crc_phonesploit_only.sh "$HOME/PhoneSploit-Pro" 192.168.10.121

Requirements: python3, expect, and PhoneSploit Pro.
USAGE
}

PS_DIR="${1:-$HOME/PhoneSploit-Pro}"
DEVICE_IP="${2:-192.168.10.121}"
PS_DIR="$(realpath -m "$PS_DIR")"
PS_SCRIPT="$PS_DIR/phonesploitpro.py"
SAFE_IP="${DEVICE_IP//[^A-Za-z0-9._-]/_}"
# Create a unique output folder beside this script so it is easy to find,
# even if the script is launched from a different working directory.
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
RUN_STAMP="$(date +%Y%m%d_%H%M%S)"
OUT_DIR="${OUTPUT_DIR:-$SCRIPT_DIR/PhoneSploit_CRC32_${SAFE_IP}_${RUN_STAMP}}"
APK_DIR="$OUT_DIR/apks"
STAGING_DIR="$OUT_DIR/phonesploit_staging"
LOG_DIR="$OUT_DIR/logs"
REPORT="$OUT_DIR/crc32_report.txt"
ERRORS="$OUT_DIR/errors.log"

if [[ ! -f "$PS_SCRIPT" ]]; then
  echo "[ERROR] Cannot find $PS_SCRIPT" >&2
  usage >&2
  exit 2
fi
if ! command -v expect >/dev/null 2>&1; then
  echo "[ERROR] Expect is required. Install it with: sudo apt update && sudo apt install expect" >&2
  exit 2
fi
if ! command -v python3 >/dev/null 2>&1; then
  echo "[ERROR] python3 is required for the standard CRC32 calculation." >&2
  exit 2
fi
if [[ ! "$DEVICE_IP" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]]; then
  echo "[ERROR] Enter a valid IPv4 address, for example 192.168.10.121" >&2
  exit 2
fi

mkdir -p "$OUT_DIR" "$APK_DIR" "$STAGING_DIR" "$LOG_DIR"
: > "$REPORT"
: > "$ERRORS"

# These are the exact three package names shown by your PhoneSploit option 36 list.
# The menu index is reselected each time after reopening the app list.
PACKAGES=(
  "org.malwarebytes.antimalware"
  "com.cxinventor.file.explorer"
  "com.antivirus"
)

crc32_file() {
  python3 - "$1" <<'PY'
import sys, zlib
crc = 0
with open(sys.argv[1], 'rb') as f:
    for chunk in iter(lambda: f.read(1024 * 1024), b''):
        crc = zlib.crc32(chunk, crc)
print(f'{crc & 0xffffffff:08X}')
PY
}

# One fresh PhoneSploit session per app keeps menu state predictable.
extract_one() {
  local index="$1" package="$2" destination="$3" marker="$4" log_file="$5" stage_dir="$6"
  mkdir -p "$stage_dir"
  find "$stage_dir" -maxdepth 1 -type f -iname '*.apk' -delete
  PS_DIR_ENV="$PS_DIR" DEVICE_IP_ENV="$DEVICE_IP" APP_INDEX_ENV="$index" \
  EXTRACT_DIR_ENV="$stage_dir" EXPECT_LOG_ENV="$log_file" expect <<'EXPECT_SCRIPT'
set timeout 90
log_user 1
set psdir $env(PS_DIR_ENV)
set ip $env(DEVICE_IP_ENV)
set appindex $env(APP_INDEX_ENV)
set logpath $env(EXPECT_LOG_ENV)
set extractdir $env(EXTRACT_DIR_ENV)
log_file -a $logpath

proc wait_main {} {
  # Match the textual part first; ANSI color codes may appear before the final >.
  expect {
    -re {(?is)Enter.{0,120}selection} {}
    -re {(?is)Main Menu} {
      exp_continue
    }
    timeout { error "Timed out waiting for PhoneSploit main menu" }
    eof { error "PhoneSploit exited while waiting for main menu" }
  }
  expect {
    -re {>} {}
    timeout { error "Timed out waiting for main-menu prompt >" }
    eof { error "PhoneSploit exited at main-menu prompt" }
  }
}

proc send_menu {value} {
  send -- "$value\r"
}

cd $psdir
spawn python3 phonesploitpro.py
# Some installations show a missing-Scrcpy confirmation before the menu.
expect {
  -re {(?is)Do you still want to continue.*Y\s*/\s*N\s*>} {
    send -- "Y\r"
    wait_main
  }
  -re {(?is)Enter.{0,120}selection} {
    expect -re {>}
  }
  timeout { error "Timed out waiting for startup prompt/main menu" }
  eof { error "PhoneSploit exited during startup" }
}

# Connect through PhoneSploit option 1.
send_menu "1"
expect {
  -re {(?is)target phone.{0,100}IP Address} {}
  -re {(?is)IP Address} {}
  timeout { error "PhoneSploit did not ask for the device IP" }
  eof { error "PhoneSploit exited during device connection" }
}
expect {
  -re {[>:]\s*$} {}
  timeout { error "Timed out at device IP prompt" }
}
send -- "$ip\r"
wait_main

# Option 36 is on page 3 in the user's PhoneSploit layout.
send_menu "n"
wait_main
send_menu "n"
wait_main
send_menu "36"
expect {
  -re {(?is)Select.{0,30}from.{0,20}App.{0,20}List} {}
  timeout { error "Option 36 did not show 'Select from App List'" }
  eof { error "PhoneSploit exited before app-list submenu" }
}
# This submenu has a bare > prompt (not 'Enter Selection >').
expect {
  -re {(?is)Enter Package Name Manually} {}
  timeout { error "Option 36 submenu did not display its choices" }
  eof { error "PhoneSploit exited at option 36 submenu" }
}
expect {
  -re {>} {}
  timeout { error "Timed out waiting for option 36 submenu prompt" }
}
send_menu "1"

# Wait for the app-list prompt; menu lines are captured by Expect's terminal stream.
expect {
  -re {(?is)Enter\s+Selection} {}
  timeout { error "PhoneSploit did not show the app selection prompt" }
  eof { error "PhoneSploit exited while listing apps" }
}
expect {
  -re {>} {}
  timeout { error "Timed out at app selection prompt" }
}
send -- "$appindex\r"

# Successful extraction asks for a save location; press Enter for the default directory.
expect {
  -re {(?is)Enter location to save APK file} {
    # Use a dedicated user-writable staging directory instead of PhoneSploit's
    # default Downloaded-Files directory, which may be unwritable or root-owned.
    send -- "$extractdir\r"
    exp_continue
  }
  -re {(?is)Extracting APK} {
    exp_continue
  }
  -re {(?is)Main Menu} {}
  timeout { error "Timed out waiting for APK extraction to finish" }
  eof { error "PhoneSploit exited before asking where to save the APK" }
}
# Wait until PhoneSploit finishes and returns to the main menu.
wait_main
send -- "0\r"
expect eof
EXPECT_SCRIPT

  # PhoneSploit was instructed to save into this per-app staging directory.
  local newest=""
  newest="$(find "$stage_dir" -maxdepth 1 -type f -iname '*.apk' -printf '%T@ %p\n' 2>/dev/null | sort -nr | head -n1 | cut -d' ' -f2- || true)"
  if [[ -z "$newest" || ! -s "$newest" ]]; then
    echo "[FAIL] No newly created/updated APK found for $package" | tee -a "$ERRORS"
    return 1
  fi
  cp -f -- "$newest" "$destination"
  [[ -s "$destination" ]] || { echo "[FAIL] Copied APK is empty for $package" | tee -a "$ERRORS"; return 1; }
  return 0
}

printf 'PhoneSploit menu-only APK CRC32 report\nDevice: %s\nStarted: %s\nOutput directory: %s\n\n' "$DEVICE_IP" "$(date -Is)" "$OUT_DIR" | tee -a "$REPORT"
echo "[INFO] All output will be stored in: $OUT_DIR"

success=0
failures=0
for i in "${!PACKAGES[@]}"; do
  index=$((i + 1))
  package="${PACKAGES[$i]}"
  safe_package="${package//[^A-Za-z0-9._-]/_}"
  marker="$OUT_DIR/.before_${index}"
  dest="$APK_DIR/${safe_package}.apk"
  session_log="$LOG_DIR/phonesploit_${index}.log"
  stage_dir="$STAGING_DIR/app_${index}"
  mkdir -p "$stage_dir"
  touch "$marker"
  echo
  echo "[$index/${#PACKAGES[@]}] $package"
  if extract_one "$index" "$package" "$dest" "$marker" "$session_log" "$stage_dir"; then
    checksum="$(crc32_file "$dest")"
    size="$(stat -c '%s' "$dest")"
    printf '[OK] CRC32=%s | size=%s bytes | file=%s\n' "$checksum" "$size" "$dest"
    printf '%s\tCRC32=%s\tSIZE=%s\tFILE=%s\n' "$package" "$checksum" "$size" "$dest" >> "$REPORT"
    success=$((success + 1))
  else
    printf '%s\tFAILED\n' "$package" >> "$REPORT"
    failures=$((failures + 1))
  fi
  rm -f -- "$marker"
done

printf '\nSummary: attempted=%d success=%d failures=%d\n' "${#PACKAGES[@]}" "$success" "$failures" | tee -a "$REPORT"
printf 'Report: %s\nErrors: %s\n' "$REPORT" "$ERRORS"
[[ "$failures" -eq 0 ]]
