"""Crypto lab: cipher identification, entropy signatures, embedded-key
detection, XOR brute force, base64/hex multi-decoder and a string-entropy
triage — the static cryptanalysis corner of GlassScope.

- identify_crypto(): flags known protocol/algorithm markers (PEM headers,
  TLS key material, TrueCrypt/BitLocker magics, wallet formats...)
- xor_analysis(): single-byte XOR brute + repeating-key XOR (repeated-length
  scoring, index-of-coincidence), hex/rot13 string decoding
- decode_layers(): recursive base64/hex/base32 decoding with depth limit
- find_embedded_keys(): high-entropy 32-byte blocks (AES keys), PEM blocks
  and their key lengths
"""

from __future__ import annotations

import base64
import binascii
import os
import re
import string

from .util import MAX_STREAM_READ, shannon_entropy

_PEM_PATTERNS = [
    (rb"-----BEGIN (RSA PRIVATE|EC PRIVATE|DSA PRIVATE|OPENSSH PRIVATE|"
     rb"ENCRYPTED PRIVATE|PRIVATE|PUBLIC|CERTIFICATE) KEY?-----",
     "PEM block"),
]
_CRYPTO_MAGICS = [
    (b"\x62\x67\x73\x2e\x61\x73\x63\x72\x79", "AWS credentials file"),
    (b"Rar!\x1a\x07\x01\x00", "encrypted RAR5 (AES)"),
    (b"TRUE", "TrueCrypt/le container"),
    (b"\xef\xcd\xab\x89", "dmg/Apple encrypted image"),
    (b"LUKS\xba\xbe", "LUKS encrypted volume header"),
    (b"PGPGPCGP", "PGP message"),
    (b"-----", "PEM armoured data"),
    (b"Salted__", "OpenSSL enc'd (AES)"),
    (b"$1$", "MD5-crypt hash"),
    (b"$2b$", "bcrypt hash"),
    (b"$6$", "SHA-512-crypt hash"),
    (b"$argon2i", "argon2 hash"),
    (b"\x00\x00\x00\x00\x00\x00\x00\x63", "7-Zip header"),
]
_KEY_LEN_HINTS = (
    (32, "AES-256 / ChaCha20 / Ed25519 key size"),
    (16, "AES-128 / MD5-size key material"),
    (24, "AES-192 / 3DES key material"),
    (64, "AES-512-class / RSA component chunk"),
)
_ROT = {1: "ROT13", 2: "ROT-N"}
_PRINTABLE_SET = set(string.printable[:95])

_BASE64_RE = re.compile(rb"[A-Za-z0-9+/]{16,}={0,2}")
_HEX_RE = re.compile(rb"(?i)[0-9a-f]{16,}")
_B32_RE = re.compile(rb"[A-Z2-7]{16,}={0,6}")


def identify_crypto(path: str) -> dict:
    """Detect crypto containers/protocols/markers in a file."""
    out: dict = {"ok": False, "warnings": [], "errors": []}
    try:
        with open(path, "rb") as fh:
            data = fh.read(MAX_STREAM_READ)
    except OSError as exc:
        out["errors"].append(f"read failed: {exc}")
        return out
    found: list[dict] = []
    for magic, label in _CRYPTO_MAGICS:
        offset = data.find(magic)
        if offset >= 0:
            found.append({"marker": label, "offset": offset,
                          "severity": "info"})
    for pat, label in _PEM_PATTERNS:
        for m in re.finditer(pat, data):
            found.append({"marker": label, "offset": m.start(),
                          "severity": "high"})
    # hash-string formats ($...$)
    for hpat in (rb"\$2[aby]\$[0-9]{2}\$", rb"\$argon2[id]?\$",
                 rb"\$sha512\$", rb"\$6\$rounds=", rb"\$1\$[./A-Za-z0-9]{8}\$"):
        for m in re.finditer(hpat, data):
            found.append({"marker": "password hash string", "offset":
                          m.start(), "severity": "medium"})
    out["markers"] = found
    out["entropy"] = shannon_entropy(data[:1024 * 512])
    if not found and out["entropy"] > 7.9 and len(data) > 4096:
        found.append({"marker": "near-max entropy — encrypted or "
                     "compressed", "offset": 0, "severity": "info"})
    out["ok"] = True
    return out


def xor_analysis(path: str, known_plaintext: bytes = b"",
                 max_key_len: int = 24) -> dict:
    """Single-byte XOR brute force + repeating-key XOR key-length scoring
    (index of coincidence) over the first 64 KiB."""
    out: dict = {"ok": False, "warnings": [], "errors": []}
    try:
        with open(path, "rb") as fh:
            data = fh.read(65536)
    except OSError as exc:
        out["errors"].append(f"read failed: {exc}")
        return out
    if len(data) < 32:
        out["warnings"].append("file too small for XOR analysis")
    # ---- single-byte XOR -----------------------------------------------
    candidates: list[dict] = []
    for k in range(256):
        dec = bytes(b ^ k for b in data[:2048])
        printable = sum(1 for c in dec if c in _PRINTABLE_SET)
        score = printable / len(dec) if dec else 0
        if score > 0.85:
            text = dec[:64]
            candidates.append({"key": f"{k:#04x}",
                               "printable_ratio": round(score, 3),
                               "preview": text.decode("ascii",
                                                      "replace")[:64]})
    out["single_byte_candidates"] = sorted(
        candidates, key=lambda c: -c["printable_ratio"])[:8]
    if known_plaintext:
        idx = data.find(known_plaintext[:4] if False else None) \
            if False else -1
    # ---- repeating key length (index of coincidence) ---------------------
    best: list[dict] = []
    for klen in range(2, max_key_len + 1):
        cols = [data[i::klen] for i in range(klen)]
        ic = 0.0
        for col in cols[:8]:  # sample first 8 columns
            if len(col) < 32:
                continue
            counts = [0] * 256
            for b in col:
                counts[b] += 1
            n = len(col)
            ic += sum(c * (c - 1) for c in counts) / (n * (n - 1)) \
                if n > 1 else 0
        best.append({"key_length": klen, "ioc": round(ic / min(klen, 8), 5)})
    best.sort(key=lambda b: -b["ioc"])
    out["likely_key_lengths"] = best[:5]
    if best and best[0]["ioc"] > 0.06:
        out["verdict"] = (f"repeating-key XOR likely (length "
                           f"{best[0]['key_length']}, IoC "
                           f"{best[0]['ioc']})")
    elif out["single_byte_candidates"]:
        out["verdict"] = "single-byte XOR likely"
    else:
        out["verdict"] = "no obvious XOR structure"
    out["ok"] = True
    return out


def decode_layers(blob: bytes, depth: int = 0, max_depth: int = 6) -> dict:
    """Recursively decode base64/hex/base32 layers (packed droppers)."""
    out: dict = {"ok": False, "layers": [], "warnings": [], "errors": []}
    cur = blob.strip()
    if depth > max_depth:
        out["warnings"].append("max decode depth reached")
        return out
    decoded = None
    kind = None
    # try base64 first
    m = _BASE64_RE.search(cur)
    if m:
        try:
            decoded = base64.b64decode(m.group() + b"=" * (-len(m.group()) % 4))
            kind = "base64"
        except (binascii.Error, ValueError):
            pass
    if decoded is None:
        m = _HEX_RE.search(cur)
        if m:
            try:
                decoded = bytes.fromhex(m.group().decode())
                kind = "hex"
            except ValueError:
                pass
    if decoded is None:
        m = _B32_RE.search(cur)
        if m:
            try:
                decoded = base64.b32decode(m.group())
                kind = "base32"
            except (binascii.Error, ValueError):
                pass
    if decoded is None:
        out["ok"] = True
        return out
    preview = decoded[:80]
    out["layers"].append({"encoding": kind, "bytes": len(decoded),
                          "preview_hex": preview.hex()[:96],
                          "preview_ascii": "".join(
                              chr(c) if 32 <= c < 127 else "." for c in
                              preview)})
    sub = decode_layers(decoded, depth + 1, max_depth)
    out["layers"] += sub.get("layers", [])
    out["warnings"] += sub.get("warnings", [])
    out["ok"] = True
    return out


def find_embedded_keys(path: str) -> dict:
    """Scan for embedded key material: PEM blocks and high-entropy runs
    at common key sizes."""
    out: dict = {"ok": False, "findings": [], "warnings": [], "errors": []}
    try:
        with open(path, "rb") as fh:
            data = fh.read(MAX_STREAM_READ)
    except OSError as exc:
        out["errors"].append(f"read failed: {exc}")
        return out
    # PEM blocks
    for pat, label in _PEM_PATTERNS:
        for m in re.finditer(pat, data):
            end = data.find(b"-----END", m.start())
            length = (end - m.start()) if end > 0 else len(data) - m.start()
            out["findings"].append({
                "kind": label, "offset": m.start(),
                "block_length": length,
                "hint": "extract with openssl for inspection"})
    # high-entropy runs at key sizes (slide with 8-byte steps)
    if len(data) >= 4096:
        step = 8
        window = 32
        hits = 0
        for off in range(0, min(len(data) - window, 4 * 1024 * 1024), step):
            ent = shannon_entropy(data[off:off + window])
            if ent >= 7.5:
                out["findings"].append({
                    "kind": "high-entropy 32-byte block (possible key)",
                    "offset": off, "entropy": round(ent, 2),
                    "hex": data[off:off + 8].hex()})
                hits += 1
                if hits >= 40:
                    out["warnings"].append("key-scan capped at 40 hits")
                    break
    out["ok"] = True
    return out


def string_entropy(text: str) -> dict:
    """Character-entropy triage of a string (base64/hex randomness check)."""
    out: dict = {"ok": True, "warnings": [], "errors": []}
    if not text:
        out["entropy"] = 0.0
        return out
    counts: dict[str, int] = {}
    for ch in text:
        counts[ch] = counts.get(ch, 0) + 1
    import math

    n = len(text)
    ent = -sum((c / n) * math.log2(c / n) for c in counts.values())
    out["entropy"] = round(ent, 3)
    out["unique_chars"] = len(counts)
    out["looks_random"] = ent > (min(4.0, len(counts)) * 0.9)
    return out
