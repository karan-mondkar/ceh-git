from pathlib import Path

script = r'''#!/usr/bin/env python3
"""
CipherScope: offline file-format and ciphertext candidate analyzer.

Usage:
  python3 cipherscope.py FILE
  python3 cipherscope.py FILE --top 4
  python3 cipherscope.py FILE --key-hex HEXKEY --algorithm aes --mode CBC --iv-hex HEXIV

Notes:
- This is a heuristic assistant, not a definitive cipher detector.
- Never run unknown decrypted output. It may contain arbitrary data.
- Decryption attempts are optional and require PyCryptodome:
    python3 -m pip install pycryptodome
  On Kali/Parrot, prefer a virtual environment if pip blocks system installs.
"""
from __future__ import annotations

import argparse
import base64
import binascii
import math
import re
import sys
import zlib
from collections import Counter
from pathlib import Path
from typing import Optional

BLOCK_CIPHERS = {
    "AES": {"block_bytes": 16, "keys": [16, 24, 32]},
    "DES": {"block_bytes": 8, "keys": [8]},
    "3DES": {"block_bytes": 8, "keys": [16, 24]},
    "Blowfish": {"block_bytes": 8, "keys": list(range(4, 57))},
    "CAST-128": {"block_bytes": 8, "keys": list(range(5, 17))},
    "IDEA": {"block_bytes": 8, "keys": [16]},
    "Camellia": {"block_bytes": 16, "keys": [16, 24, 32]},
    "SEED": {"block_bytes": 16, "keys": [16]},
    "Twofish": {"block_bytes": 16, "keys": [16, 24, 32]},
    "Serpent": {"block_bytes": 16, "keys": [16, 24, 32]},
}
STREAM_CIPHERS = {
    "ChaCha20": {"keys": [32]},
    "Salsa20": {"keys": [32]},
    "RC4": {"keys": list(range(1, 257))},
}
SIGNATURES = [
    (b"\x89PNG\r\n\x1a\n", "PNG image"),
    (b"\xff\xd8\xff", "JPEG image"),
    (b"GIF87a", "GIF image"),
    (b"GIF89a", "GIF image"),
    (b"%PDF-", "PDF document"),
    (b"PK\x03\x04", "ZIP-based archive / DOCX / XLSX / APK"),
    (b"Rar!\x1a\x07", "RAR archive"),
    (b"7z\xbc\xaf\x27\x1c", "7-Zip archive"),
    (b"\x1f\x8b", "GZIP compressed data"),
    (b"BZh", "BZIP2 compressed data"),
    (b"\xfd7zXZ\x00", "XZ compressed data"),
    (b"SQLite format 3\x00", "SQLite database"),
    (b"RIFF", "RIFF container (WAV/AVI/WebP depending on subtype)"),
    (b"ID3", "MP3 audio"),
    (b"OggS", "Ogg container"),
    (b"\x7fELF", "ELF executable"),
    (b"MZ", "Windows PE/DOS executable"),
    (b"-----BEGIN ", "PEM text (certificate/key or related object)"),
    (b"Salted__", "OpenSSL salted encrypted data marker"),
]

def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    n = len(data)
    return -sum((count / n) * math.log2(count / n) for count in counts.values())

def printable_ratio(data: bytes) -> float:
    if not data:
        return 0.0
    printable = sum((32 <= b <= 126) or b in (9, 10, 13) for b in data)
    return printable / len(data)

def try_decode_text(raw: bytes) -> tuple[bytes, list[str]]:
    """Return likely payload bytes and decoding notes. Does not recursively decode arbitrarily."""
    notes = []
    stripped = raw.strip()
    # Hex text: allow whitespace and common separators, but require a substantial all-hex body.
    compact = re.sub(rb"[\s:_-]", b"", stripped)
    if compact and len(compact) >= 16 and len(compact) % 2 == 0 and re.fullmatch(rb"[0-9a-fA-F]+", compact):
        try:
            decoded = bytes.fromhex(compact.decode("ascii"))
            notes.append(f"Input appears to be hexadecimal text ({len(compact)} hex characters).")
            return decoded, notes
        except ValueError:
            pass
    # Base64: avoid classifying ordinary text as base64 by requiring alphabet/length and a valid decode.
    try:
        candidate = re.sub(rb"\s+", b"", stripped)
        if len(candidate) >= 24 and len(candidate) % 4 == 0 and re.fullmatch(rb"[A-Za-z0-9+/]*={0,2}", candidate):
            decoded = base64.b64decode(candidate, validate=True)
            if decoded:
                notes.append(f"Input appears to be Base64 text ({len(candidate)} characters).")
                return decoded, notes
    except (binascii.Error, ValueError):
        pass
    return raw, notes

def repeated_block_stats(data: bytes, block_size: int) -> tuple[int, int]:
    usable = len(data) - (len(data) % block_size)
    blocks = [data[i:i+block_size] for i in range(0, usable, block_size)]
    counts = Counter(blocks)
    repeated_values = sum(1 for count in counts.values() if count > 1)
    repeated_instances = sum(count - 1 for count in counts.values() if count > 1)
    return repeated_values, repeated_instances

def detect_signature(data: bytes) -> Optional[str]:
    for signature, label in SIGNATURES:
        if data.startswith(signature):
            return label
    return None

def printable_preview(data: bytes, limit: int = 96) -> str:
    if not data:
        return "(empty)"
    sample = data[:limit]
    rendered = "".join(chr(b) if (32 <= b <= 126) else "." for b in sample)
    return rendered + ("..." if len(data) > limit else "")

def rank_candidates(data: bytes, filename: str, top: int = 4) -> list[tuple[float, str, list[str]]]:
    """Heuristic ranking only; length/alignment are weak clues, never proof."""
    scores: dict[str, tuple[float, list[str]]] = {}
    name = filename.lower()
    ent = entropy(data)
    n = len(data)

    def add(algo: str, score: float, reason: str) -> None:
        old_score, old_reasons = scores.get(algo, (0.0, []))
        old_reasons.append(reason)
        scores[algo] = (old_score + score, old_reasons)

    # High entropy suggests compressed/encrypted/random-like bytes, not a particular cipher.
    if ent >= 7.6 and n >= 32:
        for algo in ("AES", "ChaCha20", "Blowfish", "3DES"):
            add(algo, 1.0, f"High byte entropy ({ent:.2f} bits/byte) is compatible with encrypted or compressed data; it does not identify a cipher.")
    elif ent >= 6.5 and n >= 32:
        for algo in ("AES", "Blowfish", "3DES", "Camellia"):
            add(algo, 0.4, f"Moderately high byte entropy ({ent:.2f}) is compatible with many binary formats.")
    else:
        for algo in ("AES", "ChaCha20", "Blowfish", "3DES"):
            add(algo, 0.1, "Ciphertext remains possible, but entropy alone provides little support.")

    # Filename hints should be weak signals only.
    if re.search(r"128", name):
        add("AES", 0.35, "Filename contains '128'; this could refer to a key size, but is not proof.")
        add("Camellia", 0.15, "Filename contains '128'; this is only a weak clue and may mean something else.")
    if re.search(r"(aes|rijndael)", name):
        add("AES", 1.5, "Filename explicitly mentions AES/Rijndael.")
    if re.search(r"(3des|triple.?des)", name):
        add("3DES", 1.5, "Filename explicitly mentions 3DES.")
    if re.search(r"blowfish", name):
        add("Blowfish", 1.5, "Filename explicitly mentions Blowfish.")
    if re.search(r"\bdes\b", name):
        add("DES", 1.2, "Filename explicitly mentions DES.")

    # Block alignment is a weak compatibility clue, not a reliable detector.
    for algo, info in BLOCK_CIPHERS.items():
        bs = info["block_bytes"]
        if n >= bs and n % bs == 0:
            add(algo, 0.25, f"Decoded length ({n} bytes) is a multiple of its {bs}-byte block size; this is weak evidence only.")
        elif n >= bs:
            add(algo, 0.0, f"Length is not aligned to its {bs}-byte block size; modes such as CTR can still produce arbitrary lengths.")
    for algo in STREAM_CIPHERS:
        add(algo, 0.2, "Stream ciphers can produce ciphertext of almost any length; length does not confirm this candidate.")

    # Repeated aligned blocks can sometimes be informative for ECB-like data.
    for bs in (8, 16):
        repeated_values, repeated_instances = repeated_block_stats(data, bs)
        if repeated_instances:
            label = "DES/3DES/Blowfish or another 64-bit-block cipher" if bs == 8 else "AES/Camellia or another 128-bit-block cipher"
            for algo in (("DES", "3DES", "Blowfish", "IDEA", "CAST-128") if bs == 8 else ("AES", "Camellia", "SEED", "Twofish", "Serpent")):
                add(algo, 0.5, f"Repeated {bs}-byte aligned blocks were found ({repeated_instances} extra occurrence(s)); this can support ECB/repeated-plaintext hypotheses, but has many caveats.")

    ranked = []
    for algo, (score, reasons) in scores.items():
        # Convert arbitrary heuristic score to a bounded presentation score, not a statistical probability.
        confidence = min(95, round(100 * (1 - math.exp(-score / 2.2))))
        ranked.append((confidence, algo, list(dict.fromkeys(reasons))))
    ranked.sort(key=lambda item: item[0], reverse=True)
    return ranked[:top]

def try_decrypt(data: bytes, algorithm: str, mode: str, key: bytes, iv: Optional[bytes]) -> bytes:
    try:
        from Crypto.Cipher import AES, DES, DES3, Blowfish, ChaCha20, Salsa20
    except ImportError as exc:
        raise RuntimeError("PyCryptodome is not installed. Install it in a virtual environment: python3 -m pip install pycryptodome") from exc

    alg = algorithm.lower()
    mode_upper = mode.upper()
    if alg == "aes":
        if len(key) not in (16, 24, 32):
            raise ValueError("AES key must be 16, 24, or 32 bytes (128/192/256 bits).")
        if mode_upper == "ECB":
            cipher = AES.new(key, AES.MODE_ECB)
        elif mode_upper == "CBC":
            if iv is None or len(iv) != 16:
                raise ValueError("AES-CBC requires a 16-byte IV.")
            cipher = AES.new(key, AES.MODE_CBC, iv=iv)
        elif mode_upper == "CTR":
            if iv is None:
                raise ValueError("AES-CTR requires a counter/nonce value; provide --iv-hex.")
            # PyCryptodome treats this as the initial counter block when using nonce=b''.
            cipher = AES.new(key, AES.MODE_CTR, nonce=b"", initial_value=int.from_bytes(iv, "big"))
        else:
            raise ValueError("Supported AES modes in this helper: ECB, CBC, CTR.")
    elif alg in ("des", "3des", "tripledes"):
        cls = DES if alg == "des" else DES3
        bs = 8
        if alg == "des" and len(key) != 8:
            raise ValueError("DES key must be 8 bytes (64 bits including parity; 56 effective bits).")
        if alg != "des" and len(key) not in (16, 24):
            raise ValueError("3DES key must be 16 or 24 bytes.")
        if mode_upper == "ECB":
            cipher = cls.new(key, cls.MODE_ECB)
        elif mode_upper == "CBC":
            if iv is None or len(iv) != bs:
                raise ValueError(f"{algorithm}-CBC requires an {bs}-byte IV.")
            cipher = cls.new(key, cls.MODE_CBC, iv=iv)
        else:
            raise ValueError("Supported DES/3DES modes in this helper: ECB, CBC.")
    elif alg == "blowfish":
        if not 4 <= len(key) <= 56:
            raise ValueError("Blowfish key must be 4–56 bytes.")
        if mode_upper == "ECB":
            cipher = Blowfish.new(key, Blowfish.MODE_ECB)
        elif mode_upper == "CBC":
            if iv is None or len(iv) != 8:
                raise ValueError("Blowfish-CBC requires an 8-byte IV.")
            cipher = Blowfish.new(key, Blowfish.MODE_CBC, iv=iv)
        else:
            raise ValueError("Supported Blowfish modes in this helper: ECB, CBC.")
    elif alg in ("chacha20", "salsa20"):
        if len(key) != 32:
            raise ValueError(f"{algorithm} key must be 32 bytes (256 bits).")
        if alg == "chacha20":
            if iv is None:
                raise ValueError("ChaCha20 requires a nonce; provide --iv-hex.")
            if len(iv) not in (8, 12, 24):
                raise ValueError("ChaCha20 nonce length supported here: 8, 12, or 24 bytes depending on variant.")
            cipher = ChaCha20.new(key=key, nonce=iv)
        else:
            if iv is None or len(iv) != 8:
                raise ValueError("Salsa20 requires an 8-byte nonce.")
            cipher = Salsa20.new(key=key, nonce=iv)
        return cipher.decrypt(data)
    else:
        raise ValueError("Manual decryption supports AES, DES, 3DES, Blowfish, ChaCha20, and Salsa20.")
    if len(data) % cipher.block_size != 0 and mode_upper in ("ECB", "CBC"):
        raise ValueError(f"Ciphertext length must be a multiple of {cipher.block_size} bytes for {mode_upper}.")
    return cipher.decrypt(data)

def main() -> int:
    parser = argparse.ArgumentParser(description="CipherScope: offline file-type and encryption-candidate analyzer")
    parser.add_argument("file", help="Path to input file (binary, hex text, or Base64 text)")
    parser.add_argument("--top", type=int, default=4, help="Number of ranked algorithm candidates to display (default: 4)")
    parser.add_argument("--key-hex", help="Optional known key in hexadecimal for a manual decryption attempt")
    parser.add_argument("--algorithm", choices=["aes", "des", "3des", "blowfish", "chacha20", "salsa20"], help="Algorithm for optional manual decryption")
    parser.add_argument("--mode", default="CBC", choices=["ECB", "CBC", "CTR"], help="Mode for block-cipher decryption (default: CBC)")
    parser.add_argument("--iv-hex", help="Optional IV/nonce in hexadecimal")
    parser.add_argument("--output", help="Optional path to save decrypted bytes")
    args = parser.parse_args()

    if args.top < 1 or args.top > 20:
        parser.error("--top must be between 1 and 20")

    path = Path(args.file).expanduser()
    try:
        raw = path.read_bytes()
    except OSError as exc:
        print(f"[!] Cannot read input file: {exc}", file=sys.stderr)
        return 2

    data, notes = try_decode_text(raw)
    print("=" * 72)
    print("CipherScope | Offline File & Cipher Candidate Analyzer")
    print("=" * 72)
    print(f"File                 : {path}")
    print(f"Original file size   : {len(raw)} bytes")
    print(f"Analyzed data size   : {len(data)} bytes")
    print(f"Shannon entropy      : {entropy(data):.3f} bits/byte (maximum 8.0)")
    print(f"Printable ratio      : {printable_ratio(data) * 100:.1f}%")
    print(f"First bytes (hex)    : {data[:32].hex(' ') or '(empty)'}")
    print(f"Preview              : {printable_preview(data)}")
    for note in notes:
        print(f"[i] {note}")

    signature = detect_signature(data)
    if signature:
        print(f"\n[+] Recognized file signature: {signature}")
    else:
        print("\n[?] No recognized signature at the beginning of analyzed data.")

    # Try safe decompression checks; only report success if decoder accepts stream.
    if data.startswith(b"\x1f\x8b"):
        print("[+] GZIP signature present.")
    if data.startswith(b"PK\x03\x04"):
        print("[+] ZIP-family signature present.")
    if data.startswith(b"Salted__"):
        print("[+] OpenSSL salted-data marker present; password/format details may still be needed.")

    print("\nTop algorithm candidates (heuristic, NOT probabilities):")
    candidates = rank_candidates(data, path.name, args.top)
    for index, (score, algo, reasons) in enumerate(candidates, 1):
        print(f"\n{index}. {algo} — heuristic score: {score}/100")
        for reason in reasons[:4]:
            print(f"   - {reason}")
        info = BLOCK_CIPHERS.get(algo) or STREAM_CIPHERS.get(algo)
        if info:
            if "block_bytes" in info:
                print(f"   - Block size: {info['block_bytes'] * 8} bits")
            key_sizes = info["keys"]
            if algo == "Blowfish":
                print("   - Supported key sizes: 32–448 bits (implementation constraints apply)")
            elif algo == "RC4":
                print("   - Key sizes: variable; not recommended for modern security")
            elif algo in ("DES", "3DES"):
                if algo == "DES":
                    print("   - Key size: 64-bit key representation; 56 effective key bits")
                else:
                    print("   - Keying options commonly use 112 or 168 effective bits")
            else:
                print("   - Key sizes: " + ", ".join(str(size * 8) for size in key_sizes) + " bits")

    if args.key_hex:
        if not args.algorithm:
            parser.error("--key-hex requires --algorithm")
        try:
            key = bytes.fromhex(args.key_hex)
            iv = bytes.fromhex(args.iv_hex) if args.iv_hex else None
            plaintext = try_decrypt(data, args.algorithm, args.mode, key, iv)
            print("\n[!] Decryption command completed, but output is NOT automatically proven correct.")
            print(f"Decrypted bytes       : {len(plaintext)}")
            print(f"Plaintext preview     : {printable_preview(plaintext, 160)}")
            if args.output:
                out = Path(args.output).expanduser()
                out.write_bytes(plaintext)
                print(f"Saved decrypted data  : {out}")
            else:
                print("No output file saved. Use --output decrypted.bin to save the bytes.")
            print("Validate the result by checking known text, file signatures, padding, or challenge-specific format.")
        except (ValueError, RuntimeError) as exc:
            print(f"[!] Decryption attempt failed: {exc}", file=sys.stderr)
            return 3

    print("\nImportant: encrypted/compressed data can look alike. Candidate ranking is heuristic;")
    print("cipher, mode, IV/nonce, key/password derivation, and padding may be unknown.")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
'''

path = Path("/mnt/data/cipherscope.py")
path.write_text(script, encoding="utf-8")
# Verify syntax and basic behavior on a temporary hex-text sample.
import py_compile, subprocess, tempfile, os
py_compile.compile(str(path), doraise=True)
sample = Path("/mnt/data/cipherscope_sample.hex")
sample.write_text("48656c6c6f20776f726c64212054686973206973206120746573742066696c652e", encoding="ascii")
run = subprocess.run(["python3", str(path), str(sample), "--top", "4"], capture_output=True, text=True)
print("Created:", path)
print("Syntax check: passed")
print("Smoke test exit code:", run.returncode)
print("\n".join(run.stdout.splitlines()[:22]))
