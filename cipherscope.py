#!/usr/bin/env python3
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

# Catalogue follows the algorithms/procedure families visible in CrypTool.
# These metadata entries do NOT mean every algorithm has an installed decryptor.
BLOCK_CIPHERS = {
    "AES": {"block_bytes": 16, "keys": [16, 24, 32]},
    "DES": {"block_bytes": 8, "keys": [8]},
    "Triple DES": {"block_bytes": 8, "keys": [16, 24]},
    "Blowfish": {"block_bytes": 8, "keys": list(range(4, 57))},
    "IDEA": {"block_bytes": 8, "keys": [16]},
    "RC2": {"block_bytes": 8, "keys": list(range(1, 129))},
    "MARS": {"block_bytes": 16, "keys": list(range(16, 57))},
    "RC6": {"block_bytes": 16, "keys": [16, 24, 32]},
    "Serpent": {"block_bytes": 16, "keys": [16, 24, 32]},
    "Twofish": {"block_bytes": 16, "keys": [16, 24, 32]},
    "Camellia": {"block_bytes": 16, "keys": [16, 24, 32]},
    "DESX": {"block_bytes": 8, "keys": [24]},
    "DESL": {"block_bytes": 8, "keys": [8]},
    "DESXL": {"block_bytes": 8, "keys": [24]},
}
STREAM_CIPHERS = {
    "RC4": {"keys": list(range(1, 257))},
    "ChaCha20": {"keys": [32]},
    "Salsa20": {"keys": [32]},
}
CLASSICAL_CIPHERS = [
    "Caesar / ROT-13", "Vigenere", "Hill", "Substitution / Atbash",
    "Playfair", "ADFGVX", "Byte Addition", "XOR", "Vernam / OTP",
    "Homophone", "Permutation / Transposition", "Solitaire",
    "Scytale / Rail Fence",
]
ASYMMETRIC_HYBRID = [
    "RSA Encryption / Decryption", "RSA Demonstration", "RSA-AES Hybrid",
    "ECC-AES Hybrid", "Digital Signatures / PKI",
]

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

def rank_candidates(data: bytes, filename: str, top: int = 0) -> list[tuple[float, str, list[str]]]:
    """Return heuristic compatibility scores, not probabilities of the true algorithm."""
    name = filename.lower()
    ent = entropy(data)
    n = len(data)
    scores: dict[str, list] = {}

    # All named CrypTool candidates are shown, even when evidence is neutral.
    names = list(BLOCK_CIPHERS) + list(STREAM_CIPHERS) + CLASSICAL_CIPHERS + ASYMMETRIC_HYBRID
    mode_variants = ["DES (ECB)", "DES (CBC)", "Triple DES (ECB)", "Triple DES (CBC)", "AES (CBC)", "AES (ECB)", "AES (CTR)"]
    names += mode_variants + ["AES (self-extracting)"]
    for candidate in dict.fromkeys(names):
        scores[candidate] = [18.0, ["Baseline only: ciphertext appearance alone cannot identify this algorithm."]]

    def add(candidate: str, amount: float, reason: str) -> None:
        if candidate not in scores:
            scores[candidate] = [18.0, ["Baseline only; insufficient evidence to distinguish this candidate."]]
        scores[candidate][0] += amount
        scores[candidate][1].append(reason)

    if ent >= 7.6 and n >= 32:
        for a in list(BLOCK_CIPHERS) + list(STREAM_CIPHERS) + mode_variants:
            add(a, 8, f"High entropy ({ent:.2f}/8 bits per byte) is consistent with encryption or compression, but is not cipher-specific.")
        for a in CLASSICAL_CIPHERS:
            add(a, -3, "High entropy is less typical of ordinary classical-cipher output, though binary encodings can change this.")
    elif ent < 5.5 and n > 0:
        for a in CLASSICAL_CIPHERS:
            add(a, 7, f"Lower entropy ({ent:.2f}/8) can be compatible with classical/text-oriented procedures; this is weak evidence.")
        for a in list(BLOCK_CIPHERS) + list(STREAM_CIPHERS):
            add(a, -2, "Lower entropy is less typical of modern ciphertext, but short files and encodings can mislead.")
    else:
        for a in list(BLOCK_CIPHERS) + list(STREAM_CIPHERS) + mode_variants:
            add(a, 3, f"Entropy ({ent:.2f}/8) is inconclusive and compatible with many binary payloads.")

    if re.search(r"twofish", name): add("Twofish", 45, "Filename explicitly contains 'Twofish'.")
    if re.search(r"serpent", name): add("Serpent", 45, "Filename explicitly contains 'Serpent'.")
    if re.search(r"idea", name): add("IDEA", 45, "Filename explicitly contains 'IDEA'.")
    if re.search(r"rc2", name): add("RC2", 45, "Filename explicitly contains 'RC2'.")
    if re.search(r"rc4", name): add("RC4", 45, "Filename explicitly contains 'RC4'.")
    if re.search(r"mars", name): add("MARS", 45, "Filename explicitly contains 'MARS'.")
    if re.search(r"rc6", name): add("RC6", 45, "Filename explicitly contains 'RC6'.")
    if re.search(r"desxl", name): add("DESXL", 45, "Filename explicitly contains 'DESXL'.")
    elif re.search(r"desl", name): add("DESL", 45, "Filename explicitly contains 'DESL'.")
    elif re.search(r"desx", name): add("DESX", 45, "Filename explicitly contains 'DESX'.")
    if re.search(r"(aes|rijndael)", name):
        for a in ("AES", "AES (CBC)", "AES (ECB)", "AES (CTR)", "AES (self-extracting)", "RSA-AES Hybrid", "ECC-AES Hybrid"):
            add(a, 30, "Filename explicitly mentions AES/Rijndael; this is a filename clue, not proof.")
    if re.search(r"(3des|triple.?des)", name):
        for a in ("Triple DES", "Triple DES (ECB)", "Triple DES (CBC)"):
            add(a, 30, "Filename explicitly mentions Triple DES; this is a filename clue, not proof.")
    if re.search(r"des", name):
        for a in ("DES", "DES (ECB)", "DES (CBC)"):
            add(a, 25, "Filename explicitly mentions DES; this does not distinguish ECB from CBC.")
    if "128" in name:
        for a in ("AES", "Twofish", "Serpent", "RC6", "MARS", "Camellia"):
            add(a, 4, "Filename contains '128'; this may refer to key size but is only a weak clue.")

    # Alignment is a weak compatibility hint. Stream/classical/hybrid procedures don't require it.
    for algo, info in BLOCK_CIPHERS.items():
        bs = info["block_bytes"]
        if n >= bs and n % bs == 0:
            add(algo, 4, f"Payload length ({n} bytes) is a multiple of the {bs}-byte block size; weak evidence only.")
        for variant in mode_variants:
            if variant.startswith(algo + " (") and n >= bs and n % bs == 0:
                add(variant, 4, f"Payload length is aligned to {bs}-byte blocks; ECB/CBC still cannot be distinguished by length alone.")
    for bs in (8, 16):
        _, repeated_instances = repeated_block_stats(data, bs)
        if repeated_instances:
            related = ("DES", "Triple DES", "Blowfish", "IDEA", "RC2", "DESX", "DESL", "DESXL") if bs == 8 else ("AES", "Twofish", "Serpent", "MARS", "RC6", "Camellia")
            for a in related:
                add(a, 9, f"Found {repeated_instances} extra occurrence(s) of repeated {bs}-byte blocks; this can support an ECB/repeated-plaintext hypothesis, not prove it.")
            for a in mode_variants:
                if (bs == 8 and (a.startswith("DES (") or a.startswith("Triple DES ("))) or (bs == 16 and a.startswith("AES (")):
                    if "ECB" in a: add(a, 12, "Repeated aligned blocks can be a clue for ECB mode; other explanations remain possible.")

    # Convert raw evidence points to a bounded compatibility score. It is NOT a probability.
    ranked = []
    for candidate, (raw_score, reasons) in scores.items():
        value = max(1, min(99, round(raw_score)))
        ranked.append((value, candidate, list(dict.fromkeys(reasons))))
    ranked.sort(key=lambda x: (-x[0], x[1]))
    return ranked if top == 0 else ranked[:top]

def try_decrypt(data: bytes, algorithm: str, mode: str, key: bytes, iv: Optional[bytes]) -> bytes:
    alg = algorithm.lower()
    mode_upper = mode.upper()
    if alg == "aes":
        try:
            from Crypto.Cipher import AES
        except ImportError as exc:
            raise RuntimeError("PyCryptodome is not installed. In a virtual environment run: python3 -m pip install pycryptodome") from exc
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
        try:
            from Crypto.Cipher import DES, DES3
        except ImportError as exc:
            raise RuntimeError("PyCryptodome is not installed. In a virtual environment run: python3 -m pip install pycryptodome") from exc
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
        try:
            from Crypto.Cipher import Blowfish
        except ImportError as exc:
            raise RuntimeError("PyCryptodome is not installed. In a virtual environment run: python3 -m pip install pycryptodome") from exc
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
    elif alg == "twofish":
        if len(key) not in (16, 24, 32):
            raise ValueError("Twofish key must be 16, 24, or 32 bytes (128/192/256 bits).")
        if mode_upper != "ECB":
            raise ValueError("This optional Twofish backend currently supports ECB only; CBC needs a separate mode wrapper and IV.")
        try:
            from twofish import Twofish
        except ImportError as exc:
            raise RuntimeError("Twofish backend missing. In a virtual environment, try: python3 -m pip install twofish") from exc
        if len(data) % 16:
            raise ValueError("Twofish-ECB ciphertext length must be a multiple of 16 bytes.")
        tf = Twofish(key)
        return b"".join(tf.decrypt(data[i:i+16]) for i in range(0, len(data), 16))
    elif alg in ("chacha20", "salsa20"):
        try:
            from Crypto.Cipher import ChaCha20, Salsa20
        except ImportError as exc:
            raise RuntimeError("PyCryptodome is not installed. In a virtual environment run: python3 -m pip install pycryptodome") from exc
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
        raise ValueError("Manual decryption supports AES, DES, 3DES, Blowfish, Twofish (ECB via optional library), ChaCha20, and Salsa20.")
    if len(data) % cipher.block_size != 0 and mode_upper in ("ECB", "CBC"):
        raise ValueError(f"Ciphertext length must be a multiple of {cipher.block_size} bytes for {mode_upper}.")
    return cipher.decrypt(data)

def main() -> int:
    parser = argparse.ArgumentParser(description="CipherScope: offline file-type and encryption-candidate analyzer")
    parser.add_argument("file", help="Path to input file (binary, hex text, or Base64 text)")
    parser.add_argument("--top", type=int, default=0, help="Number of candidates to display; 0 shows all candidates (default: all)")
    parser.add_argument("--key-hex", help="Optional known key in hexadecimal for a manual decryption attempt")
    parser.add_argument("--algorithm", choices=["aes", "des", "3des", "blowfish", "twofish", "chacha20", "salsa20"], help="Algorithm for optional manual decryption")
    parser.add_argument("--mode", default="CBC", choices=["ECB", "CBC", "CTR"], help="Mode for block-cipher decryption (default: CBC)")
    parser.add_argument("--iv-hex", help="Optional IV/nonce in hexadecimal")
    parser.add_argument("--output", help="Optional path to save decrypted bytes")
    args = parser.parse_args()

    if args.top < 0 or args.top > 100:
        parser.error("--top must be between 0 and 100 (0 means all candidates)")

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

    print("\nCrypTool candidate compatibility scores (heuristic, NOT probabilities):")
    candidates = rank_candidates(data, path.name, args.top)
    for index, (score, algo, reasons) in enumerate(candidates, 1):
        print(f"\n{index}. {algo} — compatibility score: {score}/100 (NOT a probability)")
        for reason in reasons[:4]:
            print(f"   - {reason}")
        base_algo = algo.split(" (")[0]
        info = BLOCK_CIPHERS.get(base_algo) or STREAM_CIPHERS.get(base_algo)
        if info:
            if "block_bytes" in info:
                print(f"   - Block size: {info['block_bytes'] * 8} bits")
            key_sizes = info["keys"]
            if base_algo == "Blowfish":
                print("   - Supported key sizes: 32–448 bits (implementation constraints apply)")
            elif base_algo == "RC4":
                print("   - Key sizes: variable; not recommended for modern security")
            elif base_algo in ("DES", "3DES", "Triple DES"):
                if base_algo == "DES":
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

    print("\nScore interpretation: values are heuristic compatibility scores, NOT statistical probabilities or calibrated chances.")
    print("A high score means only that the available clues fit; it does not verify the algorithm.")
    print("Some CrypTool entries are modes, procedures, or hybrid systems, not standalone ciphers.")
    print("Decryption requires the correct key/password and often an IV/nonce; only a subset has a backend here.")
    print("Encrypted and compressed data can look alike; the cipher, mode, IV/nonce, key derivation, and padding may be unknown.")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
