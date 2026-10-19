
#!/usr/bin/env python3
"""
CipherScope: Offline file-type and encryption candidate analyzer.

Usage:
    python3 cipherscope.py FILE
    python3 cipherscope.py FILE --top 4

Optional decryption with a known key:
    python3 cipherscope.py FILE --algorithm aes --mode CBC \
        --key-hex HEXKEY --iv-hex HEXIV --output plaintext.bin

This tool ranks plausible candidates. It cannot reliably identify a cipher
from ciphertext alone.
"""

import argparse
import base64
import binascii
import math
import re
import sys
from collections import Counter
from pathlib import Path


BLOCK_CIPHERS = {
    "AES": (16, "128, 192, 256"),
    "DES": (8, "64-bit representation / 56 effective"),
    "3DES": (8, "112 or 168 effective"),
    "Blowfish": (8, "32–448 variable"),
    "CAST-128": (8, "40–128 variable"),
    "IDEA": (8, "128"),
    "Camellia": (16, "128, 192, 256"),
    "SEED": (16, "128"),
    "Twofish": (16, "128, 192, 256"),
    "Serpent": (16, "128, 192, 256"),
}

STREAM_CIPHERS = {
    "ChaCha20": "256",
    "Salsa20": "256",
    "RC4": "variable (obsolete/insecure)",
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
    (b"RIFF", "RIFF container"),
    (b"ID3", "MP3 audio"),
    (b"OggS", "Ogg container"),
    (b"\x7fELF", "ELF executable"),
    (b"MZ", "Windows PE/DOS executable"),
    (b"Salted__", "OpenSSL salted-data marker"),
]


def entropy(data):
    """Calculate Shannon entropy in bits per byte."""
    if not data:
        return 0.0

    counts = Counter(data)
    size = len(data)

    return -sum(
        (count / size) * math.log2(count / size)
        for count in counts.values()
    )


def printable_ratio(data):
    """Return the fraction of printable bytes."""
    if not data:
        return 0.0

    printable = sum(
        (32 <= byte <= 126) or byte in (9, 10, 13)
        for byte in data
    )

    return printable / len(data)


def decode_container(raw):
    """Decode hexadecimal or Base64 text when it is clearly recognizable."""
    stripped = raw.strip()

    # Hexadecimal text, allowing whitespace and common separators.
    compact = re.sub(rb"[\s:_-]", b"", stripped)

    if (
        len(compact) >= 16
        and len(compact) % 2 == 0
        and re.fullmatch(rb"[0-9a-fA-F]+", compact)
    ):
        try:
            decoded = bytes.fromhex(compact.decode("ascii"))
            return decoded, [
                f"Decoded hexadecimal text ({len(compact)} hex characters)."
            ]
        except ValueError:
            pass

    # Base64 text.
    candidate = re.sub(rb"\s+", b"", stripped)

    if (
        len(candidate) >= 24
        and len(candidate) % 4 == 0
        and re.fullmatch(rb"[A-Za-z0-9+/]*={0,2}", candidate)
    ):
        try:
            decoded = base64.b64decode(candidate, validate=True)

            if decoded:
                return decoded, [
                    f"Decoded Base64 text ({len(candidate)} characters)."
                ]

        except (binascii.Error, ValueError):
            pass

    return raw, []


def preview(data, limit=100):
    """Display printable bytes and replace other bytes with dots."""
    sample = data[:limit]

    result = "".join(
        chr(byte) if 32 <= byte <= 126 else "."
        for byte in sample
    )

    if len(data) > limit:
        result += "..."

    return result if data else "(empty)"


def detect_signature(data):
    """Identify common file signatures at the beginning of data."""
    for magic, description in SIGNATURES:
        if data.startswith(magic):
            return description

    return None


def repeated_block_count(data, block_size):
    """Count repeated aligned blocks, a possible clue for ECB-like data."""
    usable_length = len(data) - len(data) % block_size

    blocks = [
        data[index:index + block_size]
        for index in range(0, usable_length, block_size)
    ]

    counts = Counter(blocks)

    return sum(
        count - 1
        for count in counts.values()
        if count > 1
    )


def rank_candidates(data, filename, top=4):
    """Rank candidates using weak clues, not statistical probabilities."""
    scores = {}

    def add(name, points, reason):
        score, reasons = scores.get(name, (0.0, []))
        reasons.append(reason)
        scores[name] = (score + points, reasons)

    size = len(data)
    data_entropy = entropy(data)
    lower_name = filename.lower()

    # Entropy indicates randomness, not a particular algorithm.
    if size >= 32 and data_entropy >= 7.6:
        for algorithm in (
            "AES", "ChaCha20", "Blowfish", "3DES", "Camellia"
        ):
            add(
                algorithm,
                1.0,
                f"High entropy ({data_entropy:.2f}/8) is "
                "compatible with encrypted or compressed data."
            )

    elif size >= 16 and data_entropy >= 6.2:
        for algorithm in (
            "AES", "Blowfish", "3DES", "Camellia", "ChaCha20"
        ):
            add(
                algorithm,
                0.5,
                f"Relatively high entropy ({data_entropy:.2f}/8) "
                "fits many binary formats."
            )

    else:
        for algorithm in ("AES", "ChaCha20", "Blowfish", "3DES"):
            add(
                algorithm,
                0.1,
                "Entropy provides little evidence for or against encryption."
            )

    # Filename hints are weak clues, not proof.
    if "128" in lower_name:
        add(
            "AES",
            0.35,
            "Filename contains '128'; it might refer to a key size."
        )
        add(
            "Camellia",
            0.15,
            "Filename contains '128'; this is only a weak hint."
        )

    if re.search(r"aes|rijndael", lower_name):
        add("AES", 1.5, "Filename explicitly mentions AES/Rijndael.")

    if re.search(r"3des|triple.?des", lower_name):
        add("3DES", 1.5, "Filename explicitly mentions 3DES.")

    if "blowfish" in lower_name:
        add("Blowfish", 1.5, "Filename explicitly mentions Blowfish.")

    if re.search(r"(^|[^a-z])des([^a-z]|$)", lower_name):
        add("DES", 1.2, "Filename explicitly mentions DES.")

    # Block alignment is compatible with some modes, but not conclusive.
    for algorithm, (block_size, key_sizes) in BLOCK_CIPHERS.items():
        if size >= block_size and size % block_size == 0:
            add(
                algorithm,
                0.25,
                f"Length ({size} bytes) aligns to "
                f"{block_size}-byte blocks; weak clue only."
            )

    for algorithm in STREAM_CIPHERS:
        add(
            algorithm,
            0.15,
            "Stream ciphers support many ciphertext lengths; "
            "length does not confirm this candidate."
        )

    # Repeated aligned blocks may be relevant to ECB-like encryption.
    block_groups = [
        (8, ("DES", "3DES", "Blowfish", "IDEA", "CAST-128")),
        (16, ("AES", "Camellia", "SEED", "Twofish", "Serpent")),
    ]

    for block_size, algorithms in block_groups:
        repeats = repeated_block_count(data, block_size)

        if repeats:
            for algorithm in algorithms:
                add(
                    algorithm,
                    0.45,
                    f"Found {repeats} repeated aligned "
                    f"{block_size}-byte block occurrence(s); "
                    "this is not proof of the algorithm."
                )

    ranked = []

    for algorithm, (score, reasons) in scores.items():
        # Display score is a heuristic index, NOT a probability.
        display_score = min(
            99,
            round(100 * (1 - math.exp(-score / 2.2)))
        )

        ranked.append(
            (display_score, algorithm, list(dict.fromkeys(reasons)))
        )

    ranked.sort(key=lambda item: (item[0], item[1]), reverse=True)

    return ranked[:top]


def decrypt_known(data, algorithm, mode, key, iv):
    """Attempt decryption when the algorithm, key and parameters are known."""
    try:
        from Crypto.Cipher import (
            AES, DES, DES3, Blowfish, ChaCha20, Salsa20
        )
    except ImportError as exc:
        raise RuntimeError(
            "PyCryptodome is missing. Install it in a virtual environment "
            "with: python3 -m pip install pycryptodome"
        ) from exc

    algorithm = algorithm.lower()
    mode = mode.upper()

    if algorithm == "aes":
        if len(key) not in (16, 24, 32):
            raise ValueError("AES key must be 16, 24, or 32 bytes.")

        if mode == "ECB":
            cipher = AES.new(key, AES.MODE_ECB)

        elif mode == "CBC":
            if iv is None or len(iv) != 16:
                raise ValueError("AES-CBC requires a 16-byte IV.")

            cipher = AES.new(key, AES.MODE_CBC, iv=iv)

        elif mode == "CTR":
            if iv is None or len(iv) != 16:
                raise ValueError(
                    "This AES-CTR helper expects a 16-byte initial "
                    "counter supplied with --iv-hex."
                )

            cipher = AES.new(
                key,
                AES.MODE_CTR,
                nonce=b"",
                initial_value=int.from_bytes(iv, "big")
            )

        else:
            raise ValueError("AES mode must be ECB, CBC, or CTR.")

    elif algorithm in ("des", "3des", "blowfish"):
        if algorithm == "des":
            cipher_class, block_size = DES, 8

            if len(key) != 8:
                raise ValueError(
                    "DES key must be 8 bytes (56 effective bits)."
                )

        elif algorithm == "3des":
            cipher_class, block_size = DES3, 8

            if len(key) not in (16, 24):
                raise ValueError("3DES key must be 16 or 24 bytes.")

        else:
            cipher_class, block_size = Blowfish, 8

            if not 4 <= len(key) <= 56:
                raise ValueError("Blowfish key must be 4–56 bytes.")

        if mode == "ECB":
            cipher = cipher_class.new(key, cipher_class.MODE_ECB)

        elif mode == "CBC":
            if iv is None or len(iv) != block_size:
                raise ValueError(
                    f"{algorithm.upper()}-CBC requires a "
                    f"{block_size}-byte IV."
                )

            cipher = cipher_class.new(
                key, cipher_class.MODE_CBC, iv=iv
            )

        else:
            raise ValueError(
                f"{algorithm.upper()} supports ECB or CBC here."
            )

    elif algorithm in ("chacha20", "salsa20"):
        if len(key) != 32:
            raise ValueError(f"{algorithm} key must be 32 bytes.")

        if iv is None:
            raise ValueError(f"{algorithm} requires a nonce.")

        if algorithm == "chacha20":
            cipher = ChaCha20.new(key=key, nonce=iv)

        else:
            if len(iv) != 8:
                raise ValueError("Salsa20 requires an 8-byte nonce.")

            cipher = Salsa20.new(key=key, nonce=iv)

        return cipher.decrypt(data)

    else:
        raise ValueError("Unsupported algorithm.")

    if mode in ("ECB", "CBC") and len(data) % cipher.block_size:
        raise ValueError(
            f"Ciphertext length must be a multiple of "
            f"{cipher.block_size} bytes for {mode}."
        )

    return cipher.decrypt(data)


def main():
    parser = argparse.ArgumentParser(
        description="Offline file and encryption candidate analyzer"
    )

    parser.add_argument(
        "file",
        help="Input file path (binary, hexadecimal text, or Base64 text)"
    )

    parser.add_argument(
        "--top",
        type=int,
        default=4,
        help="Number of candidate algorithms to display (1–20)"
    )

    parser.add_argument(
        "--algorithm",
        choices=["aes", "des", "3des", "blowfish", "chacha20", "salsa20"]
    )

    parser.add_argument(
        "--mode",
        choices=["ECB", "CBC", "CTR"],
        default="CBC"
    )

    parser.add_argument("--key-hex", help="Known key in hexadecimal")
    parser.add_argument("--iv-hex", help="Known IV/nonce in hexadecimal")
    parser.add_argument("--output", help="Save decrypted bytes to this path")

    args = parser.parse_args()

    if not 1 <= args.top <= 20:
        parser.error("--top must be between 1 and 20")

    if args.key_hex and not args.algorithm:
        parser.error("--key-hex requires --algorithm")

    if args.algorithm and not args.key_hex:
        parser.error("--algorithm requires --key-hex for decryption")

    if args.output and not args.key_hex:
        parser.error("--output requires a decryption attempt")

    input_path = Path(args.file).expanduser()

    try:
        raw = input_path.read_bytes()
    except OSError as exc:
        print(
            f"[ERROR] Cannot read '{input_path}': {exc}",
            file=sys.stderr
        )
        return 2

    data, notes = decode_container(raw)

    print("=" * 68)
    print("CipherScope | Offline File & Encryption Candidate Analyzer")
    print("=" * 68)
    print(f"File               : {input_path}")
    print(f"Original size      : {len(raw)} bytes")
    print(f"Analyzed data size : {len(data)} bytes")
    print(f"Entropy            : {entropy(data):.3f} bits/byte (max 8.0)")
    print(f"Printable bytes    : {printable_ratio(data) * 100:.1f}%")
    print(f"First 32 bytes     : {data[:32].hex(' ') or '(empty)'}")
    print(f"Preview            : {preview(data)}")

    for note in notes:
        print(f"[INFO] {note}")

    detected = detect_signature(data)
    print(f"Signature          : {detected or 'No recognized signature'}")

    if data.startswith(b"Salted__"):
        print(
            "[INFO] OpenSSL salted-data marker found; "
            "additional password/cipher details may be required."
        )

    print("\nTop candidates (heuristic scores, NOT probabilities):")

    for index, (score, algorithm, reasons) in enumerate(
        rank_candidates(data, input_path.name, args.top), 1
    ):
        print(f"\n{index}. {algorithm} — heuristic score {score}/100")

        for reason in reasons[:4]:
            print(f"   - {reason}")

        if algorithm in BLOCK_CIPHERS:
            block_size, key_sizes = BLOCK_CIPHERS[algorithm]
            print(f"   - Block size: {block_size * 8} bits")
            print(f"   - Key size(s): {key_sizes} bits")

        elif algorithm in STREAM_CIPHERS:
            print(f"   - Key size: {STREAM_CIPHERS[algorithm]} bits")

    if args.key_hex:
        try:
            key = bytes.fromhex(args.key_hex)
            iv = bytes.fromhex(args.iv_hex) if args.iv_hex else None

            plaintext = decrypt_known(
                data, args.algorithm, args.mode, key, iv
            )

            print(
                "\n[!] Decryption completed, but the output "
                "is not automatically verified."
            )
            print(f"Decrypted size     : {len(plaintext)} bytes")
            print(f"Preview            : {preview(plaintext, 160)}")

            if args.output:
                output_path = Path(args.output).expanduser()
                output_path.parent.mkdir(parents=True, exist_ok=True)
                output_path.write_bytes(plaintext)
                print(f"Saved output       : {output_path}")

            print(
                "Validate the result using expected text, "
                "a file signature, or challenge clues."
            )

        except (ValueError, RuntimeError, OSError) as exc:
            print(f"[ERROR] Decryption failed: {exc}", file=sys.stderr)
            return 3

    print(
        "\nNote: ciphertext alone usually cannot identify the exact "
        "cipher, mode, key, or padding."
    )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
