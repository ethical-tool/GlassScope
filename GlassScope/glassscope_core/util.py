"""Shared helpers: hashing, entropy, magic detection, safe IO, OS check."""

from __future__ import annotations

import hashlib
import math
import os
import platform
import re

READ_CHUNK = 1024 * 1024          # 1 MiB per chunk while hashing / sampling
MAX_SNIPPET_READ = 2 * 1024 * 1024  # cap for reading text files into memory
MAX_STREAM_READ = 8 * 1024 * 1024   # cap for any single scan read


def human_size(n: int | float) -> str:
    n = float(n)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024.0 or unit == "TB":
            if unit == "B":
                return f"{int(n)} {unit}"
            return f"{n:.1f} {unit}"
        n /= 1024.0
    return f"{n:.1f} TB"


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        while True:
            chunk = fh.read(READ_CHUNK)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def sha1_file(path: str) -> str:
    h = hashlib.sha1()
    with open(path, "rb") as fh:
        while True:
            chunk = fh.read(READ_CHUNK)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def md5_file(path: str) -> str:
    h = hashlib.md5()
    with open(path, "rb") as fh:
        while True:
            chunk = fh.read(READ_CHUNK)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def file_hashes(path: str) -> dict[str, str]:
    return {"md5": md5_file(path), "sha1": sha1_file(path), "sha256": sha256_file(path)}


def shannon_entropy(data: bytes) -> float:
    """Shannon entropy of a byte string (0.0 – 8.0 bits/byte). Empty -> 0."""
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    total = len(data)
    ent = 0.0
    for c in counts:
        if c:
            p = c / total
            ent -= p * math.log2(p)
    return round(ent, 3)


def entropy_of_file(path: str, sample_bytes: int = READ_CHUNK) -> float:
    """Entropy of the first `sample_bytes` of a file (fast, deterministic)."""
    size = os.path.getsize(path)
    if size == 0:
        return 0.0
    with open(path, "rb") as fh:
        data = fh.read(min(sample_bytes, size))
    return shannon_entropy(data)


_MAGIC_TABLE: list[tuple[bytes, str]] = [
    (b"\x7fELF", "ELF executable / shared object"),
    (b"MZ", "Windows PE executable"),
    (b"\xfe\xed\xfa\xce", "Mach-O (32-bit BE)"),
    (b"\xfe\xed\xfa\xcf", "Mach-O (64-bit BE)"),
    (b"\xcf\xfa\xed\xfe", "Mach-O (64-bit LE)"),
    (b"\xca\xfe\xba\xbe", "Mach-O universal / Java class"),
    (b"PK\x03\x04", "ZIP container (apk/jar/docx/...)"),
    (b"\x1f\x8b", "gzip compressed data"),
    (b"BZh", "bzip2 compressed data"),
    (b"\xfd7zXZ\x00", "xz compressed data"),
    (b"7z\xbc\xaf\x27\x1c", "7-Zip archive"),
    (b"Rar!", "RAR archive"),
    (b"%PDF", "PDF document"),
    (b"\x89PNG", "PNG image"),
    (b"GIF8", "GIF image"),
    (b"\xff\xd8\xff", "JPEG image"),
    (b"SQLite format 3\x00", "SQLite database"),
    (b"ID3", "MP3 audio (ID3)"),
    (b"OggS", "Ogg container"),
    (b"RIFF", "RIFF container (wav/avi/webp)"),
]


def magic_sniff(path: str) -> str:
    """Best-effort file-type detection from the first 64 KiB."""
    try:
        with open(path, "rb") as fh:
            head = fh.read(64 * 1024)
    except OSError:
        return "unreadable"
    if not head:
        return "empty file"
    for magic, label in _MAGIC_TABLE:
        if head.startswith(magic):
            return label
    # ASAR: Chromium Pickle header — [u32=4][u32 header len][u32 json len]...
    if len(head) >= 12:
        import struct

        first, header_len, json_len = struct.unpack_from("<III", head, 0)
        if first == 4 and 4 <= json_len <= header_len and 8 + header_len < len(head) + (1 << 40):
            # json starts at 12; validate it really is JSON below
            try:
                head[12 : 12 + min(json_len, 256)].decode("utf-8", "ignore")
                if head[12:13] in (b"{", b" "):
                    return "Electron ASAR archive"
            except Exception:
                pass
    # Text-ish detection
    sample = head[:4096]
    if b"\x00" not in sample:
        try:
            sample.decode("utf-8")
            text_kind = "text"
            if sample.lstrip().startswith(b"#!"):
                shebang = sample.splitlines()[0].decode("utf-8", "replace").strip()
                return f"{text_kind}: script ({shebang})"
            if sample.lstrip()[:1] in (b"{", b"["):
                return f"{text_kind}: JSON document"
            if re.search(rb"<html|<!doctype html", sample[:512], re.I):
                return f"{text_kind}: HTML document"
            return f"{text_kind} file"
        except UnicodeDecodeError:
            pass
    return "binary data"


def safe_read_head(path: str, limit: int = MAX_SNIPPET_READ) -> bytes:
    with open(path, "rb") as fh:
        return fh.read(limit)


def is_kali_linux() -> bool:
    """True when running on Kali Linux (checks /etc/os-release strictly)."""
    try:
        with open("/etc/os-release", "r", encoding="utf-8", errors="replace") as fh:
            content = fh.read()
    except OSError:
        return platform.release().lower().find("kali") >= 0
    fields: dict[str, str] = {}
    for line in content.splitlines():
        if "=" in line:
            key, _, val = line.partition("=")
            fields[key.strip()] = val.strip().strip('"')
    distro_id = fields.get("ID", "").lower()
    distro_like = fields.get("ID_LIKE", "").lower()
    pretty = fields.get("PRETTY_NAME", "").lower()
    return "kali" in (distro_id, distro_like, pretty)


def os_release_pretty() -> str:
    """Human-readable distro name for messages (fallback: sys.platform)."""
    try:
        with open("/etc/os-release", "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                if line.startswith("PRETTY_NAME="):
                    return line.partition("=")[2].strip().strip('"')
    except OSError:
        pass
    return platform.system() or "unknown OS"


def sanitize_rel_path(name: str) -> str | None:
    """Reject path tricks used by archives (zip-slip / asar entries)."""
    if not name:
        return None
    name = name.replace("\\", "/")
    if name.startswith("/") or (len(name) > 1 and name[1] == ":"):
        return None
    parts = []
    for part in name.split("/"):
        if part in ("", "."):
            continue
        if part == "..":
            return None
        parts.append(part)
    if not parts:
        return None
    return os.path.join(*parts)


def find_offset_of(data: bytes, line_no: int) -> tuple[int, int]:
    """Return (start,end) byte offsets of a 1-based line inside data."""
    pos = 0
    line = 1
    start = 0
    while line < line_no:
        idx = data.find(b"\n", pos)
        if idx < 0:
            return len(data), len(data)
        pos = idx + 1
        line += 1
    start = pos
    idx = data.find(b"\n", pos)
    end = len(data) if idx < 0 else idx
    return start, end
