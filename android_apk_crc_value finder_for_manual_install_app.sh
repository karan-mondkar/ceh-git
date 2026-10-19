#!/usr/bin/env python3
"""Batch CRC32 for apps extracted through PhoneSploit Pro's menu only.

This controller does NOT invoke adb directly. PhoneSploit itself may use ADB
internally, as part of its normal operation.

Usage:
  python3 phonesploit_menu_crc_only.py ~/PhoneSploit-Pro 192.168.10.121

It automates: connect device -> next page twice -> option 36 -> option 1
(Select from App List) -> select each listed package -> accept default save path.
APK files are copied from PhoneSploit-Pro/Downloaded-Files into a report folder.
"""
from __future__ import annotations
import argparse
import ipaddress
import re
import shutil
import sys
import time
import zlib
from pathlib import Path

try:
    import pexpect
except ImportError:
    print("[ERROR] pexpect is required. Install it with: sudo apt install python3-pexpect", file=sys.stderr)
    raise SystemExit(2)

MAIN_PROMPT = r"(?i)\[?Main Menu\]?\s*Enter selection\s*>|Enter selection\s*>"
APP_PROMPT = r"(?i)Enter Selection\s*>"
APP_LIST_OPTION = r"(?i)Select from App List"
SAVE_PROMPT = r"(?i)Enter location to save APK file[^\r\n]*"
STARTUP_PROMPT = r"(?is)Do you still want to continue.*?Y\s*/\s*N\s*>"


def safe_name(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]", "_", value)


def crc32_file(path: Path) -> str:
    crc = 0
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            crc = zlib.crc32(chunk, crc)
    return f"{crc & 0xffffffff:08X}"


def apk_snapshot(folder: Path) -> dict[Path, tuple[int, int]]:
    snapshot = {}
    if folder.exists():
        for file in folder.rglob("*.apk"):
            try:
                stat = file.stat()
                snapshot[file.resolve()] = (stat.st_size, stat.st_mtime_ns)
            except OSError:
                pass
    return snapshot


def parse_app_list(text: str) -> list[tuple[int, str]]:
    # PhoneSploit v1.52 shows lines such as "2. com.cxinventor.file.explorer".
    found = []
    for line in text.splitlines():
        match = re.match(r"^\s*(\d+)\.\s+([A-Za-z0-9_.$-]+)\s*$", line.strip())
        if match:
            found.append((int(match.group(1)), match.group(2)))
    # Preserve display order and avoid duplicate entries.
    unique = []
    seen = set()
    for number, package in found:
        if package not in seen:
            unique.append((number, package))
            seen.add(package)
    return unique


def expect_main(child, timeout=90):
    child.expect(MAIN_PROMPT, timeout=timeout)


def launch_and_connect(ps_script: Path, ps_dir: Path, phone_ip: str):
    child = pexpect.spawn(sys.executable, [str(ps_script)], cwd=str(ps_dir),
                          encoding="utf-8", timeout=45, echo=False)
    child.delaybeforesend = 0.15
    index = child.expect([STARTUP_PROMPT, MAIN_PROMPT], timeout=60)
    if index == 0:
        child.sendline("Y")
        expect_main(child, 60)

    # Option 1: PhoneSploit's own Connect a Device menu.
    child.sendline("1")
    child.expect(r"(?i)Enter target phone's IP Address", timeout=25)
    # PhoneSploit versions vary in whether the IP prompt ends with > or :.
    child.expect(r"[>:]\s*", timeout=10)
    child.sendline(phone_ip)
    expect_main(child, 60)

    # Option 36 is on page 3 in the user's PhoneSploit menu; use the menu's
    # next-page key twice, just as confirmed in the user's terminal.
    child.sendline("n")
    expect_main(child, 20)
    child.sendline("n")
    expect_main(child, 20)
    return child


def get_app_list(child) -> list[tuple[int, str]]:
    child.sendline("36")
    child.expect(APP_LIST_OPTION, timeout=20)
    child.expect(MAIN_PROMPT, timeout=15)  # option 1/2 menu prompt
    child.sendline("1")
    child.expect(APP_PROMPT, timeout=45)
    apps = parse_app_list(child.before or "")
    if not apps:
        raise RuntimeError("PhoneSploit opened Select from App List, but no package entries could be parsed. Screen was: " + (child.before or "")[-1200:])
    # At this point the app-selection prompt is waiting for a numeric choice.
    child.sendline("0")
    expect_main(child, 20)
    return apps


def extract_via_menu(child, app_number: int, package: str, download_dir: Path, output_apk: Path):
    before = apk_snapshot(download_dir)
    child.sendline("36")
    child.expect(APP_LIST_OPTION, timeout=20)
    child.expect(MAIN_PROMPT, timeout=15)
    child.sendline("1")
    child.expect(APP_PROMPT, timeout=45)
    apps_now = parse_app_list(child.before or "")
    choices = [number for number, name in apps_now if name == package]
    if not choices:
        child.sendline("0")
        expect_main(child, 20)
        raise RuntimeError(f"Package no longer appears in PhoneSploit's app list: {package}")
    # Select by the current displayed number, not a stale index.
    child.sendline(str(choices[0]))

    # PhoneSploit asks for a destination and Enter accepts its default folder.
    result = child.expect([SAVE_PROMPT, MAIN_PROMPT], timeout=90)
    if result == 0:
        child.sendline("")
        expect_main(child, 120)
    # Capture the extraction output while preserving the current main-menu state.
    output_text = (child.before or "")
    time.sleep(0.25)
    after = apk_snapshot(download_dir)
    changed = []
    for path, stat in after.items():
        if path not in before or before[path] != stat:
            changed.append(path)
    if not changed:
        # Some PhoneSploit builds may not update mtime on overwrite; use the
        # newest APK in the default download folder only as a guarded fallback.
        candidates = list(after)
        if candidates:
            candidates.sort(key=lambda p: p.stat().st_mtime_ns, reverse=True)
            newest = candidates[0]
            if time.time() - newest.stat().st_mtime < 180:
                changed = [newest]
    if not changed:
        raise RuntimeError(f"PhoneSploit returned to its menu but no new/changed APK was detected in {download_dir}. Output: {output_text[-500:]}")
    changed.sort(key=lambda p: p.stat().st_mtime_ns, reverse=True)
    source_apk = changed[0]
    if source_apk.stat().st_size <= 0:
        raise RuntimeError(f"Extracted APK is empty: {source_apk}")
    output_apk.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source_apk, output_apk)
    return source_apk, output_text


def main() -> int:
    parser = argparse.ArgumentParser(description="PhoneSploit menu-only APK extraction and CRC32 for apps listed by PhoneSploit.")
    parser.add_argument("phonesploit_dir", help="Folder containing phonesploitpro.py")
    parser.add_argument("phone_ip", help="Android device IP address (must already be reachable/authorized in PhoneSploit)")
    args = parser.parse_args()
    try:
        ipaddress.ip_address(args.phone_ip)
    except ValueError:
        print("[ERROR] Invalid IP address.", file=sys.stderr)
        return 2

    ps_dir = Path(args.phonesploit_dir).expanduser().resolve()
    ps_script = next((ps_dir / name for name in ("phonesploitpro.py", "phonesploit.py") if (ps_dir / name).is_file()), None)
    if ps_script is None:
        print(f"[ERROR] Could not find phonesploitpro.py or phonesploit.py in {ps_dir}", file=sys.stderr)
        return 2
    download_dir = ps_dir / "Downloaded-Files"
    out_dir = Path.home() / f"phonesploit_menu_crc_{safe_name(args.phone_ip)}"
    apk_dir = out_dir / "apks"
    apk_dir.mkdir(parents=True, exist_ok=True)
    report_file = out_dir / "crc32_report.txt"
    errors_file = out_dir / "errors.log"
    errors: list[str] = []
    rows: list[tuple[str, str, str, str]] = []
    child = None
    try:
        print(f"[INFO] Starting PhoneSploit: {ps_script}")
        child = launch_and_connect(ps_script, ps_dir, args.phone_ip)
        print("[INFO] Connected through PhoneSploit menus; opening option 36 to read its app list.")
        apps = get_app_list(child)
        print(f"[INFO] PhoneSploit lists {len(apps)} apps:")
        for _, package in apps:
            print(f"  - {package}")
        print(f"[INFO] Output folder: {out_dir}")

        for index, (display_number, package) in enumerate(apps, 1):
            print(f"\n[{index}/{len(apps)}] {package}")
            destination = apk_dir / f"{safe_name(package)}.apk"
            try:
                source, _ = extract_via_menu(child, display_number, package, download_dir, destination)
                checksum = crc32_file(destination)
                size = destination.stat().st_size
                rows.append((package, str(source), str(destination), checksum))
                print(f"  [OK] CRC-32: {checksum} ({size} bytes)")
            except Exception as exc:
                message = f"{package}: {type(exc).__name__}: {exc}"
                errors.append(message)
                rows.append((package, "-", str(destination), "FAILED"))
                print(f"  [WARN] {message}")
                # If the menu controller died, do not attempt to send more input.
                if child is None or not child.isalive():
                    break

    except Exception as exc:
        message = f"Controller: {type(exc).__name__}: {exc}"
        errors.append(message)
        print(f"[ERROR] {message}")
        if child is not None:
            try:
                print("[DEBUG] Last PhoneSploit screen:\n" + (child.before or "")[-1500:])
            except Exception:
                pass
    finally:
        if child is not None:
            try:
                if child.isalive():
                    child.sendline("0")
                    child.close(force=True)
            except Exception:
                try:
                    child.close(force=True)
                except Exception:
                    pass

    with report_file.open("w", encoding="utf-8") as report:
        report.write("PhoneSploit Menu-Only APK CRC32 Report\n")
        report.write(f"Device IP: {args.phone_ip}\n")
        report.write(f"Apps listed by PhoneSploit: {len(rows)}\n\n")
        for package, source, local, checksum in rows:
            report.write(f"Package : {package}\nSource  : {source}\nLocal   : {local}\nCRC-32  : {checksum}\n" + "-" * 55 + "\n")
        successes = sum(1 for row in rows if row[3] != "FAILED")
        report.write(f"\nSuccessful hashes: {successes}\nFailed: {len(rows) - successes}\n")
    errors_file.write_text("\n".join(errors) + ("\n" if errors else ""), encoding="utf-8")
    print("\n================ SUMMARY ================")
    print(f"Apps attempted : {len(rows)}")
    print(f"CRC32 success  : {sum(1 for row in rows if row[3] != 'FAILED')}")
    print(f"Failures       : {sum(1 for row in rows if row[3] == 'FAILED')}")
    print(f"Report         : {report_file}")
    print(f"Errors         : {errors_file}")
    print("=========================================")
    return 0 if rows and not errors else (1 if errors else 0)

if __name__ == "__main__":
    raise SystemExit(main())
