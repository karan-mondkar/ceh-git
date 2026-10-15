
import os
import sys
import re
import csv
import hashlib
import subprocess
import venv
from pathlib import Path
from collections import defaultdict

# ============================================================
# CEH Question 56 - File Integrity Checker
# Original MD5 hashes vs. files inside Archive
# Windows compatible; Python standard library only.
# ============================================================

SCRIPT_DIR = Path(__file__).resolve().parent
VENV_DIR = SCRIPT_DIR / ".hashcheck_venv"
BOOTSTRAP_FLAG = "HASHCHECK_ENV_READY"


def start_in_virtual_environment():
    """Create a venv and relaunch this script inside it."""
    if os.environ.get(BOOTSTRAP_FLAG) == "1":
        return

    python_exe = VENV_DIR / "Scripts" / "python.exe"

    if sys.prefix == sys.base_prefix:
        if not python_exe.exists():
            print("[*] Creating Python virtual environment...")
            venv.EnvBuilder(with_pip=True).create(VENV_DIR)

        env = os.environ.copy()
        env[BOOTSTRAP_FLAG] = "1"

        print("[*] Launching inside virtual environment...\n")
        result = subprocess.run(
            [str(python_exe), str(Path(__file__).resolve()), *sys.argv[1:]],
            env=env
        )
        raise SystemExit(result.returncode)


def md5_file(path):
    """Calculate MD5 in chunks so large files are supported."""
    digest = hashlib.md5()
    with open(path, "rb") as file:
        for chunk in iter(lambda: file.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest().upper()


def normalize_name(name):
    """Normalize manifest paths for Windows/Linux-style separators."""
    name = name.strip().strip('"').strip("'")
    name = name.lstrip("*").replace("\\", "/")
    while name.startswith("./"):
        name = name[2:]
    return name.casefold()


def parse_hash_file(manifest):
    """
    Accept common formats:
      HASH  filename
      HASH *filename
      filename HASH
      filename: HASH
      MD5 (filename) = HASH
    """
    entries = []
    errors = []
    hash_pattern = re.compile(r"(?i)(?<![0-9a-f])[0-9a-f]{32}(?![0-9a-f])")

    try:
        lines = manifest.read_text(
            encoding="utf-8-sig", errors="replace"
        ).splitlines()
    except OSError as exc:
        raise RuntimeError(f"Cannot read manifest: {exc}")

    for line_number, raw_line in enumerate(lines, 1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue

        matches = list(hash_pattern.finditer(line))
        if not matches:
            errors.append((line_number, raw_line, "No 32-character MD5 found"))
            continue

        # Most hash manifests contain one hash per line.
        match = matches[0]
        digest = match.group(0).upper()
        before = line[:match.start()].strip()
        after = line[match.end():].strip()

        # Handle: MD5 (filename) = HASH
        if before.upper().startswith("MD5"):
            filename_match = re.search(r"\((.*?)\)", before)
            filename = filename_match.group(1) if filename_match else ""
        elif after:
            # Standard md5sum: HASH  filename
            filename = after.lstrip(" *\t=:")
        else:
            # filename: HASH or filename HASH
            filename = before.rstrip(":= \t")

        filename = filename.strip().strip('"').strip("'")
        filename = filename.lstrip("*").strip()

        if not filename:
            errors.append((line_number, raw_line, "Filename not found"))
            continue

        entries.append({
            "line": line_number,
            "name": filename,
            "key": normalize_name(filename),
            "hash": digest,
            "raw": raw_line,
        })

    return entries, errors


def choose_paths():
    print("=" * 72)
    print("CEH FILE INTEGRITY CHECKER - MD5 COMPARISON")
    print("=" * 72)

    if len(sys.argv) >= 3:
        manifest = Path(sys.argv[1]).expanduser()
        archive = Path(sys.argv[2]).expanduser()
    else:
        print("Enter the full paths, or press Enter for the defaults.")
        manifest_input = input(
            "Original hash file [Documents\\FileHashes.txt]: "
        ).strip()
        archive_input = input(
            "Archive folder [Documents\\Archive]: "
        ).strip()

        documents = Path.home() / "Documents"
        manifest = Path(manifest_input.strip('"')) if manifest_input else (
            documents / "FileHashes.txt"
        )
        archive = Path(archive_input.strip('"')) if archive_input else (
            documents / "Archive"
        )

    return manifest.resolve(), archive.resolve()


def main():
    manifest, archive = choose_paths()

    print("\n[INPUT PATHS]")
    print(f"Original hash file : {manifest}")
    print(f"Archive folder     : {archive}")

    if not manifest.is_file():
        print(f"\n[ERROR] Hash file not found: {manifest}")
        return 2

    if not archive.is_dir():
        print(f"\n[ERROR] Archive folder not found: {archive}")
        return 2

    expected_entries, parse_errors = parse_hash_file(manifest)

    if not expected_entries:
        print("\n[ERROR] No usable MD5 entries found in FileHashes.txt.")
        print("Check the manifest format.")
        for item in parse_errors:
            print(f"Line {item[0]}: {item[2]}: {item[1]}")
        return 2

    # Build a map of files in Archive, keyed by relative path.
    actual_by_key = defaultdict(list)
    actual_files = sorted(
        (p for p in archive.rglob("*") if p.is_file()),
        key=lambda p: str(p).casefold()
    )

    for file_path in actual_files:
        relative = file_path.relative_to(archive).as_posix()
        key = normalize_name(relative)
        try:
            digest = md5_file(file_path)
            actual_by_key[key].append({
                "path": file_path.resolve(),
                "relative": relative,
                "hash": digest,
                "key": key,
            })
        except OSError as exc:
            print(f"[WARNING] Cannot hash {file_path}: {exc}")

    # Also index by basename for manifests that contain filenames only.
    actual_by_basename = defaultdict(list)
    for records in actual_by_key.values():
        for record in records:
            basename = normalize_name(Path(record["relative"]).name)
            actual_by_basename[basename].append(record)

    results = []
    used_actual_paths = set()

    for expected in expected_entries:
        name = expected["name"]
        key = expected["key"]
        candidates = actual_by_key.get(key, [])

        # If the manifest contains just a basename, match that basename.
        if not candidates and "/" not in key:
            candidates = actual_by_basename.get(key, [])

        if not candidates:
            results.append({
                "status": "MISSING FROM ARCHIVE",
                "name": name,
                "original_path": f"{manifest} (line {expected['line']})",
                "actual_path": "",
                "expected_md5": expected["hash"],
                "actual_md5": "",
            })
            continue

        if len(candidates) > 1:
            # Avoid silently selecting between duplicate basenames.
            results.append({
                "status": "AMBIGUOUS MATCH",
                "name": name,
                "original_path": f"{manifest} (line {expected['line']})",
                "actual_path": "; ".join(
                    str(c["path"]) for c in candidates
                ),
                "expected_md5": expected["hash"],
                "actual_md5": "; ".join(c["hash"] for c in candidates),
            })
            continue

        actual = candidates[0]
        used_actual_paths.add(str(actual["path"]).casefold())

        if expected["hash"] == actual["hash"]:
            status = "MATCH"
        else:
            status = "MISMATCH - POSSIBLY TAMPERED"

        results.append({
            "status": status,
            "name": name,
            "original_path": f"{manifest} (line {expected['line']})",
            "actual_path": str(actual["path"]),
            "expected_md5": expected["hash"],
            "actual_md5": actual["hash"],
        })

    # Files present in Archive but not represented in the manifest.
    for file_path in actual_files:
        if str(file_path.resolve()).casefold() not in used_actual_paths:
            results.append({
                "status": "NOT IN ORIGINAL HASH LIST",
                "name": file_path.name,
                "original_path": str(manifest),
                "actual_path": str(file_path.resolve()),
                "expected_md5": "",
                "actual_md5": md5_file(file_path),
            })

    print("\n" + "=" * 110)
    print("COMPLETE FILE-BY-FILE COMPARISON")
    print("=" * 110)

    for number, row in enumerate(results, 1):
        print(f"\n[{number}] STATUS       : {row['status']}")
        print(f"    Filename          : {row['name']}")
        print(f"    Original reference: {row['original_path']}")
        print(f"    Current file path : {row['actual_path'] or '(not found)'}")
        print(f"    Original MD5      : {row['expected_md5'] or '(none)'}")
        print(f"    Current MD5       : {row['actual_md5'] or '(none)'}")

    counts = defaultdict(int)
    for row in results:
        counts[row["status"]] += 1

    print("\n" + "=" * 72)
    print("SUMMARY")
    print("=" * 72)
    print(f"Manifest entries          : {len(expected_entries)}")
    print(f"Files found in Archive    : {len(actual_files)}")
    print(f"Matching files            : {counts['MATCH']}")
    print(f"Hash mismatches           : {counts['MISMATCH - POSSIBLY TAMPERED']}")
    print(f"Missing from Archive      : {counts['MISSING FROM ARCHIVE']}")
    print(f"Ambiguous matches         : {counts['AMBIGUOUS MATCH']}")
    print(f"Unlisted Archive files    : {counts['NOT IN ORIGINAL HASH LIST']}")

    if parse_errors:
        print(f"Unparsed manifest lines   : {len(parse_errors)}")
        for item in parse_errors:
            print(f"  Line {item[0]}: {item[2]}: {item[1]}")

    # Save the complete report beside the hash manifest.
    report = manifest.parent / "HashComparisonReport.csv"
    fields = [
        "status", "name", "original_path", "actual_path",
        "expected_md5", "actual_md5"
    ]

    try:
        with report.open("w", newline="", encoding="utf-8-sig") as csv_file:
            writer = csv.DictWriter(csv_file, fieldnames=fields)
            writer.writeheader()
            writer.writerows(results)
        print(f"\nCSV report saved to: {report}")
    except OSError as exc:
        print(f"\n[WARNING] Could not save CSV report: {exc}")

    suspicious = [
        row for row in results
        if row["status"] == "MISMATCH - POSSIBLY TAMPERED"
    ]

    print("\n" + "=" * 72)
    print("POTENTIAL HASH MISMATCHES")
    print("=" * 72)

    if suspicious:
        for row in suspicious:
            print(f"Filename (case-sensitive): {row['name']}")
            print(f"Original MD5: {row['expected_md5']}")
            print(f"Current MD5 : {row['actual_md5']}")
    else:
        print("No direct hash mismatches identified.")

    print("\n[!] A hash mismatch indicates different contents, not by itself")
    print("    proof of malicious tampering. Confirm paths and manifest accuracy.")
    return 0


if __name__ == "__main__":
    start_in_virtual_environment()
    raise SystemExit(main())
