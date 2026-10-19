#!/usr/bin/env python3
"""
PhoneSploit Option-36 Batch APK CRC32
Automates PhoneSploit-Pro's menu option 36 for packages with one APK path.
PhoneSploit-Pro's built-in extract_apk() handles only one path reliably; for
split-APK packages, this script uses the same ADB pull workflow per APK path
as a fallback so the whole batch can continue.

Usage:
  python3 phonesploit_crc_batch.py /path/to/PhoneSploit-Pro 192.168.10.121
Optional port is currently PhoneSploit-Pro's default 5555.
Use only with devices you own or are authorized to test.
"""
import argparse
import ipaddress
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import time
import zlib

def run(cmd, timeout=30):
    return subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          text=True, timeout=timeout, check=False)

def crc32_file(path):
    crc = 0
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            crc = zlib.crc32(chunk, crc)
    return f"{crc & 0xffffffff:08X}"

def safe_name(s):
    return re.sub(r"[^A-Za-z0-9._-]", "_", s)

def main():
    parser = argparse.ArgumentParser(description="Automate PhoneSploit option 36 and calculate APK CRC-32 for all installed packages.")
    parser.add_argument("phonesploit_dir", help="Directory containing phonesploitpro.py or phonesploit.py")
    parser.add_argument("phone_ip", help="Authorized Android device IP")
    parser.add_argument("--port", type=int, default=5555, help="ADB port (default: 5555)")
    args = parser.parse_args()

    try:
        ipaddress.ip_address(args.phone_ip)
        if not 1 <= args.port <= 65535:
            raise ValueError()
    except ValueError:
        print("[ERROR] Invalid IP address or port.", file=sys.stderr)
        return 2

    ps_dir = Path(args.phonesploit_dir).expanduser().resolve()
    ps_script = next((ps_dir / n for n in ("phonesploitpro.py", "phonesploit.py") if (ps_dir / n).is_file()), None)
    if ps_script is None:
        print("[ERROR] Could not find phonesploitpro.py or phonesploit.py in:", ps_dir, file=sys.stderr)
        return 2
    if shutil.which("adb") is None:
        print("[ERROR] adb is not installed or not on PATH.", file=sys.stderr)
        return 2
    try:
        import pexpect
    except ImportError:
        print("[ERROR] Python module pexpect is required. On Parrot/Kali install it with:", file=sys.stderr)
        print("        sudo apt install python3-pexpect", file=sys.stderr)
        return 2

    device = f"{args.phone_ip}:{args.port}"
    out_dir = Path.home() / f"phonesploit_crc_{safe_name(args.phone_ip)}_{args.port}"
    apk_dir = out_dir / "apks"
    apk_dir.mkdir(parents=True, exist_ok=True)
    report_path = out_dir / "crc32_report.txt"
    error_path = out_dir / "errors.log"
    pull_log = out_dir / "adb_pull.log"
    errors = []
    rows = []
    counts = {"ok": 0, "failed": 0, "split_paths": 0}

    def log_error(msg):
        print("[WARN]", msg)
        errors.append(msg)

    # Start ADB and connect, then collect the package list. PhoneSploit itself
    # uses ADB for device connection and option 36; this list is used to loop.
    run(["adb", "start-server"])
    con = run(["adb", "connect", device], timeout=15)
    state = run(["adb", "-s", device, "get-state"], timeout=15)
    if state.returncode != 0 or state.stdout.strip() != "device":
        print(f"[ERROR] ADB device is not ready: {device}")
        print((con.stdout + con.stderr + state.stdout + state.stderr).strip())
        print("Enable/authorize wireless debugging and confirm the correct IP/port.")
        return 1

    pk = run(["adb", "-s", device, "shell", "pm", "list", "packages"], timeout=45)
    packages = sorted({line.strip().removeprefix("package:") for line in pk.stdout.splitlines()
                       if line.strip().startswith("package:")})
    if pk.returncode != 0 or not packages:
        print("[ERROR] Could not enumerate installed packages.")
        print(pk.stderr.strip())
        return 1

    print(f"[INFO] Device connected: {device}")
    print(f"[INFO] Packages discovered: {len(packages)}")
    print(f"[INFO] PhoneSploit script: {ps_script}")
    print(f"[INFO] Output directory: {out_dir}")

    # Start PhoneSploit and drive its actual menu flow: connect (1), next page
    # twice (n, n), then option 36. Do not shell-interpolate user-supplied data.
    child = None
    phone_sploit_ready = False
    try:
        child = pexpect.spawn(sys.executable, [str(ps_script)], cwd=str(ps_dir),
                              encoding="utf-8", timeout=35)
        child.delaybeforesend = 0.15
        child.expect(r"Enter selection\s*>\s*")
        child.sendline("1")
        child.expect(r"Enter target phone's IP Address", timeout=20)
        child.expect(r">\s*", timeout=10)
        child.sendline(args.phone_ip)
        child.expect(r"Enter selection\s*>\s*", timeout=30)
        child.sendline("n")
        child.expect(r"Enter selection\s*>\s*", timeout=20)
        child.sendline("n")
        child.expect(r"Enter selection\s*>\s*", timeout=20)
        phone_sploit_ready = True
        print("[INFO] PhoneSploit is connected and positioned on the page containing option 36.")
    except Exception as exc:
        log_error(f"Could not automate PhoneSploit menu: {exc}")
        if child is not None:
            try:
                child.close(force=True)
            except Exception:
                pass
        child = None
        print("[WARN] Batch will continue using the same ADB extraction workflow; PhoneSploit menu automation was unavailable.")

    def phonesploit_extract_one(package, destination):
        """Run option 36 -> manual package mode for one single-APK package."""
        nonlocal child, phone_sploit_ready
        if child is None or not phone_sploit_ready:
            return False, "PhoneSploit menu is not available"
        try:
            child.sendline("36")
            child.expect(r"Enter selection\s*>\s*|Select from App List", timeout=15)
            # In the known v1.52 menu, option 36 asks mode 1/2. If the prompt
            # is the menu prompt, the menu state drifted and this attempt fails.
            if "Select from App List" not in child.before and "Enter selection" in child.after:
                return False, "Unexpected PhoneSploit menu state"
            child.sendline("2")
            child.expect(r"Enter package name", timeout=15)
            child.expect(r">\s*", timeout=10)
            child.sendline(package)
            # The destination is requested only on the first successful call
            # because PhoneSploit stores it in a global variable.
            idx = child.expect([r"Enter location to save APK file", r"Enter selection\s*>\s*"], timeout=40)
            if idx == 0:
                child.expect(r">\s*", timeout=10)
                child.sendline(str(destination))
                child.expect(r"Enter selection\s*>\s*", timeout=45)
            return True, ""
        except Exception as exc:
            try:
                child.close(force=True)
            except Exception:
                pass
            child = None
            phone_sploit_ready = False
            return False, str(exc)

    try:
        for index, package in enumerate(packages, 1):
            print(f"\n[{index}/{len(packages)}] {package}")
            path_result = run(["adb", "-s", device, "shell", "pm", "path", package], timeout=25)
            remote_paths = [line.strip().removeprefix("package:") for line in path_result.stdout.splitlines()
                            if line.strip().startswith("package:")]
            if path_result.returncode != 0 or not remote_paths:
                msg = f"{package}: unable to obtain APK path"
                log_error(msg)
                rows.append((package, "-", "-", "NO_APK_PATH"))
                counts["failed"] += 1
                continue

            # PhoneSploit v1.52's option 36 assumes a single path named base.apk.
            # Use it when safe; use per-path ADB pulls for split APKs so they do
            # not cause every extraction to fail.
            use_phone_sploit = len(remote_paths) == 1
            if len(remote_paths) > 1:
                counts["split_paths"] += 1
                print(f"  [INFO] {len(remote_paths)} split/base APK paths; PhoneSploit option 36 only handles one path, using per-split fallback.")
            if use_phone_sploit:
                package_apk = apk_dir / f"{safe_name(package).replace('.', '_')}.apk"
                # Option 36 writes base.apk in PhoneSploit's working directory,
                # then renames it into its selected output directory.
                ok, reason = phonesploit_extract_one(package, apk_dir)
                if ok and package_apk.is_file() and package_apk.stat().st_size > 0:
                    try:
                        checksum = crc32_file(package_apk)
                        size = package_apk.stat().st_size
                        rows.append((package, remote_paths[0], str(package_apk), checksum))
                        counts["ok"] += 1
                        print(f"  CRC-32: {checksum}  ({size} bytes) [PhoneSploit option 36]")
                        continue
                    except OSError as exc:
                        log_error(f"{package}: CRC failed: {exc}")
                else:
                    log_error(f"{package}: PhoneSploit option 36 extraction failed or output missing ({reason or 'no APK file'}); trying direct path fallback.")
                # Avoid leaving a stale file being mistaken for a new download.
                try:
                    package_apk.unlink(missing_ok=True)
                except OSError:
                    pass

            # Split APK fallback, or retry when the PhoneSploit UI path fails.
            for split_index, remote in enumerate(remote_paths, 1):
                local = apk_dir / f"{safe_name(package)}_{split_index}_{safe_name(Path(remote).name)}"
                try:
                    pulled = run(["adb", "-s", device, "pull", remote, str(local)], timeout=90)
                    with open(pull_log, "a", encoding="utf-8") as log:
                        log.write(f"$ adb -s {device} pull {remote} {local}\n")
                        log.write(pulled.stdout + pulled.stderr + "\n")
                    if pulled.returncode != 0 or not local.is_file() or local.stat().st_size == 0:
                        log_error(f"{package}: pull failed for {remote}")
                        rows.append((package, remote, str(local), "PULL_FAILED"))
                        counts["failed"] += 1
                        local.unlink(missing_ok=True)
                        continue
                    checksum = crc32_file(local)
                    rows.append((package, remote, str(local), checksum))
                    counts["ok"] += 1
                    print(f"  {Path(remote).name}: CRC-32 {checksum} [split/path fallback]")
                except Exception as exc:
                    log_error(f"{package}: error processing {remote}: {exc}")
                    rows.append((package, remote, str(local), "ERROR"))
                    counts["failed"] += 1
                    try:
                        local.unlink(missing_ok=True)
                    except OSError:
                        pass
    finally:
        if child is not None:
            try:
                # Exit PhoneSploit cleanly from its menu.
                child.sendline("0")
                child.close(force=True)
            except Exception:
                pass
        run(["adb", "disconnect", device], timeout=10)

    with report_path.open("w", encoding="utf-8") as report:
        report.write("PhoneSploit Option-36 APK CRC-32 Report\n")
        report.write(f"Device: {device}\nPackages discovered: {len(packages)}\n\n")
        for package, remote, local, checksum in rows:
            report.write(f"Package : {package}\nAPK path: {remote}\nLocal   : {local}\nCRC-32  : {checksum}\n")
            report.write("-" * 60 + "\n")
        report.write("\nSUMMARY\n")
        report.write(f"Packages discovered: {len(packages)}\n")
        report.write(f"APK files hashed: {counts['ok']}\n")
        report.write(f"Failures: {counts['failed']}\n")
        report.write(f"Packages with split paths: {counts['split_paths']}\n")
        report.write(f"APK directory: {apk_dir}\n")
    error_path.write_text("\n".join(errors) + ("\n" if errors else ""), encoding="utf-8")

    print("\n================ SUMMARY ================")
    print(f"Packages discovered : {len(packages)}")
    print(f"APK files hashed    : {counts['ok']}")
    print(f"Failures            : {counts['failed']}")
    print(f"Split-path packages : {counts['split_paths']}")
    print(f"Report              : {report_path}")
    print(f"Errors              : {error_path}")
    print("=========================================")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
