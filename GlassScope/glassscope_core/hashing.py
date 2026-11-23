"""Hash toolkit: full digest set, fuzzy (context-triggered piecewise)
hashing for similarity, PE imphash, ELF symbol hash and entropy fingerprint.

- hashes(): md5, sha1, sha256, sha384, sha512, sha3-256, blake2b/s,
  crc32, plus size — everything stdlib offers.
- fuzzy_hash(): a self-contained ssdeep-like piecewise hash (rolling
  window, 64 block pieces, two normalized signatures) so similar binaries
  can be compared without external libraries.
- fuzzy_compare(): similarity score of two fuzzy hashes (0–100).
- imphash(): MD5 over the sorted import list — the classic malware
  clustering trick, works on PE files via pe.parse_pe imports.
- elf_symhash(): MD5 over exported ELF symbol names for correlation.
"""

from __future__ import annotations

import hashlib
import zlib

from .util import READ_CHUNK


def hashes(path: str) -> dict:
    """Every stdlib digest of a file plus size and crc32."""
    out: dict = {"ok": False, "warnings": [], "errors": []}
    algs = ("md5", "sha1", "sha256", "sha384", "sha512", "sha3_256",
            "sha3_512", "blake2b", "blake2s")
    makers = {a: hashlib.new(a) for a in algs}
    crc = 0
    size = 0
    try:
        with open(path, "rb") as fh:
            while True:
                chunk = fh.read(READ_CHUNK)
                if not chunk:
                    break
                size += len(chunk)
                crc = zlib.crc32(chunk, crc)
                for h in makers.values():
                    h.update(chunk)
    except OSError as exc:
        out["errors"].append(f"read failed: {exc}")
        return out
    out["ok"] = True
    out["size"] = size
    out["crc32"] = f"{crc & 0xFFFFFFFF:08x}"
    for name, h in makers.items():
        out[name] = h.hexdigest()
    return out


# ---------------------------------------------------------------------------
# fuzzy hashing (ssdeep-style piecewise hash, pure Python)
# ---------------------------------------------------------------------------

_ROLL_WINDOW = 7


class _Rolling:
    """Simple rolling hash over a 7-byte window (ssdeep's trigger)."""

    def __init__(self) -> None:
        self.win = bytearray()
        self.h1 = 0
        self.h2 = 0
        self.h3 = 0

    def update(self, b: int) -> None:
        self.win.append(b)
        if len(self.win) > _ROLL_WINDOW:
            self.win.pop(0)
        if len(self.win) == _ROLL_WINDOW:
            self.h1 = (self.win[0] + self.win[3]) & 0xFFFFFFFF
            self.h2 = (sum(self.win)) & 0xFFFFFFFF
            self.h3 = (self.win[1] * self.win[4] * self.win[7 - 1]
                       if len(self.win) > 5 else 0) & 0xFFFFFFFF

    def value(self) -> int:
        return (self.h1 + self.h2 + self.h3) & 0xFFFFFFFF


def _b64_chars(n: int) -> str:
    """Map a number into the ssdeep base64 alphabet (subset)."""
    alphabet = ("ABCDEFGHIJKLMNOPQRSTUVWXYZ"
               "abcdefghijklmnopqrstuvwxyz0123456789+/=")
    out = []
    n = n & 0xFFFFFFFF
    while n and len(out) < 3:
        out.append(alphabet[n & 0x3F])
        n >>= 6
    return "".join(out) or alphabet[0]


def fuzzy_hash(path: str) -> dict:
    """Piecewise hash with two block sizes (like ssdeep's two signatures).

    Returns {ok, signature, block_size, signature2, block_size2, warnings,
    errors}. Reading is capped at 8 MiB; bigger files are hashed on their
    prefix (a warning is added) — same behaviour as ssdeep on huge blobs.
    """
    out: dict = {"ok": False, "warnings": [], "errors": []}
    try:
        import os

        size = os.path.getsize(path)
        limit = 8 * 1024 * 1024
        with open(path, "rb") as fh:
            data = fh.read(limit)
        if size > limit:
            out["warnings"].append(
                f"file larger than 8 MiB — fuzzy hash covers the first 8 MiB")
    except OSError as exc:
        out["errors"].append(f"read failed: {exc}")
        return out
    if not data:
        out["errors"].append("empty file")
        return out

    sigs = []
    for block in (3, 6):  # two block sizes -> two signatures
        parts: list[str] = []
        roll = _Rolling()
        count = 0
        for b in data:
            roll.update(b)
            count += 1
            if count >= block and roll.value() % block == (block - 1):
                parts.append(_b64_chars(roll.value()))
                count = 0
                if len(parts) >= 64:
                    break
        if count and len(parts) < 64:
            parts.append(_b64_chars(roll.value()))
        sigs.append("".join(parts[:64]))
    out["signature"] = sigs[0]
    out["block_size"] = 3
    out["signature2"] = sigs[1]
    out["block_size2"] = 6
    out["ok"] = True
    return out


def _seq_chunks(sig: str) -> list[str]:
    """Split a signature into normalized runs of identical chars."""
    chunks: list[str] = []
    last = ""
    run = 0
    for ch in sig:
        if ch == last:
            run += 1
        else:
            if last:
                chunks.append(last * min(run, 3))  # clamp long runs
            last = ch
            run = 1
    if last:
        chunks.append(last * min(run, 3))
    return chunks


def fuzzy_compare(sig_a: str, sig_b: str) -> int:
    """Similarity score 0–100 between two signatures (weighted LCS-ish)."""
    if not sig_a or not sig_b:
        return 0
    a = _seq_chunks(sig_a)
    b = _seq_chunks(sig_b)
    if not a or not b:
        return 0
    # classic dynamic-programming edit distance over normalized chunks
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cost = 0 if ca == cb else 1
            cur.append(min(prev[j] + 1, cur[j - 1] + 1,
                           prev[j - 1] + cost))
        prev = cur
    dist = prev[-1]
    denom = max(len(a), len(b))
    return int(100 * (1 - dist / denom)) if denom else 0


def fuzzy_files(path_a: str, path_b: str) -> dict:
    """Compare two files with the fuzzy hashing toolkit."""
    out: dict = {"ok": False, "warnings": [], "errors": []}
    ha = fuzzy_hash(path_a)
    hb = fuzzy_hash(path_b)
    if not ha.get("ok") or not hb.get("ok"):
        out["errors"] = ha.get("errors", []) + hb.get("errors", [])
        return out
    score = fuzzy_compare(ha["signature"], hb["signature"])
    score2 = fuzzy_compare(ha["signature2"], hb["signature2"])
    out["similarity"] = max(score, score2)
    out["similarity_signature1"] = score
    out["similarity_signature2"] = score2
    out["a"] = ha
    out["b"] = hb
    out["ok"] = True
    return out


# ---------------------------------------------------------------------------
# import / symbol hashing for clustering
# ---------------------------------------------------------------------------

def imphash(path: str) -> dict:
    """MD5 over the sorted PE import list (malware clustering trick)."""
    out: dict = {"ok": False, "warnings": [], "errors": []}
    try:
        from .pe import parse_pe

        pe = parse_pe(path)
        if not pe.get("ok"):
            out["errors"] = pe.get("errors", [])
            return out
        imports = []
        for d in pe.get("imports", []):
            dll = d.get("dll", "").lower()
            for f in d.get("functions", []):
                imports.append(f"{dll}!{f.get('name', '').lower()}")
        imports.sort()
        joined = ",".join(imports)
        out["imphash"] = hashlib.md5(joined.encode()).hexdigest()
        out["import_count"] = len(imports)
        out["ok"] = True
    except Exception as exc:  # defensive: never raise
        out["errors"].append(f"imphash failed: {exc}")
    return out


def elf_symhash(path: str) -> dict:
    """MD5 over exported ELF symbol names (from the existing elf module)."""
    out: dict = {"ok": False, "warnings": [], "errors": []}
    try:
        from .elf import parse_elf

        info = parse_elf(path)
        if not info.get("ok"):
            out["errors"] = info.get("errors", []) or ["not an ELF"]
            return out
        names = sorted((s.get("name", "") for s in info.get("symbols", [])
                        if s.get("name")), key=str.lower)
        joined = ",".join(names)
        out["symhash"] = hashlib.md5(joined.encode()).hexdigest()
        out["symbol_count"] = len(names)
        out["ok"] = True
    except Exception as exc:
        out["errors"].append(f"elf_symhash failed: {exc}")
    return out
