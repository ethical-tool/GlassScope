"""Byte-level analysis: strings extraction, hexdump, entropy map.

Covers the REA byte-inspection needs (`strings`-style extraction with
filtering and offset evidence, hexdump with offset navigation, and a sliding
window entropy map for packing/obfuscation detection). Every function is
defensive and bounded: a huge target can never hang the GUI.
"""

from __future__ import annotations

import os
import re
import struct

from .util import MAX_STREAM_READ, shannon_entropy

PRINTABLE = re.compile(rb"[\x20-\x7e]{4,}")
UTF16LE = re.compile(rb"(?:[\x20-\x7e]\x00){4,}")


def extract_strings(path: str, min_length: int = 4, utf16: bool = False,
                    pattern: str = "", limit: int = 20000) -> dict:
    """Extract printable strings with byte offsets.

    pattern: optional regex applied to the decoded text (case-insensitive).
    Returns {"ok", "strings": [{offset, text, encoding}], "count", "truncated",
    "warnings", "errors"}.
    """
    out: dict = {"ok": False, "strings": [], "count": 0, "truncated": False,
                 "warnings": [], "errors": []}
    try:
        size = os.path.getsize(path)
        if size == 0:
            out["warnings"].append("empty file")
            out["ok"] = True
            return out
        if size > MAX_STREAM_READ:
            out["warnings"].append(
                f"file larger than {MAX_STREAM_READ // (1 << 20)} MiB; "
                f"reading first {MAX_STREAM_READ // (1 << 20)} MiB only")
        with open(path, "rb") as fh:
            data = fh.read(min(size, MAX_STREAM_READ))
    except OSError as exc:
        out["errors"].append(f"read failed: {exc}")
        return out

    if min_length < 4:
        min_length = 4
    rx = None
    if pattern:
        try:
            rx = re.compile(pattern, re.IGNORECASE)
        except re.error as exc:
            out["errors"].append(f"bad filter regex: {exc}")
            return out

    results: list[dict] = []
    if not utf16:
        for m in PRINTABLE.finditer(data):
            text = m.group().decode("ascii", "replace")
            if len(text) < min_length:
                continue
            if rx is not None and not rx.search(text):
                continue
            results.append({"offset": m.start(), "text": text,
                            "encoding": "ascii"})
            if len(results) >= limit:
                out["truncated"] = True
                break
    else:
        for m in UTF16LE.finditer(data):
            text = m.group().decode("utf-16-le", "replace")
            if len(text) < min_length:
                continue
            if rx is not None and not rx.search(text):
                continue
            results.append({"offset": m.start(), "text": text,
                            "encoding": "utf-16"})
            if len(results) >= limit:
                out["truncated"] = True
                break
    results.sort(key=lambda r: r["offset"])
    out["strings"] = results
    out["count"] = len(results)
    out["ok"] = True
    return out


def hexdump(path: str, offset: int = 0, length: int = 512) -> dict:
    """Classic hexdump of a window into a file: 16 bytes per row.

    Returns rows of {offset, hex, ascii} plus a hint whether more data
    exists before/after the window.
    """
    out: dict = {"ok": False, "rows": [], "offset": offset, "length": 0,
                 "file_size": 0, "has_before": False, "has_after": False,
                 "warnings": [], "errors": []}
    try:
        size = os.path.getsize(path)
        out["file_size"] = size
        if offset < 0:
            offset = 0
        if offset >= size and size > 0:
            out["errors"].append("offset beyond end of file")
            return out
        length = max(16, min(int(length), 64 * 1024))
        with open(path, "rb") as fh:
            fh.seek(offset)
            data = fh.read(min(length, size - offset))
    except (OSError, ValueError) as exc:
        out["errors"].append(f"read failed: {exc}")
        return out

    rows = []
    for i in range(0, len(data), 16):
        chunk = data[i:i + 16]
        hexs = " ".join(f"{b:02x}" for b in chunk)
        pad = " ".join("  " for _ in range(16 - len(chunk)))
        text = "".join(chr(b) if 0x20 <= b <= 0x7e else "." for b in chunk)
        rows.append({"offset": offset + i, "hex": (hexs + pad).rstrip(),
                     "ascii": text})
    out["rows"] = rows
    out["length"] = len(data)
    out["offset"] = offset
    out["has_before"] = offset > 0
    out["has_after"] = (offset + len(data)) < size
    out["ok"] = True
    return out


def entropy_map(path: str, windows: int = 128) -> dict:
    """Sliding-window entropy across the whole file (for charts).

    Splits the file into `windows` equal blocks (max 1 MiB read per block,
    centered on each window) and returns normalized entropy values plus a
    verdict on packing.
    """
    out: dict = {"ok": False, "points": [], "min": 0.0, "max": 0.0,
                 "avg": 0.0, "file_size": 0, "high_ratio": 0.0,
                 "warnings": [], "errors": []}
    try:
        size = os.path.getsize(path)
        out["file_size"] = size
        if size == 0:
            out["warnings"].append("empty file")
            out["ok"] = True
            return out
        windows = max(16, min(int(windows), 512))
        block = min(64 * 1024, max(256, size // windows))
        with open(path, "rb") as fh:
            values = []
            for w in range(windows):
                center = int((w + 0.5) * (size / windows))
                start = max(0, min(center - block // 2, size - block))
                fh.seek(start)
                data = fh.read(block)
                if data:
                    values.append(shannon_entropy(data))
    except (OSError, ValueError) as exc:
        out["errors"].append(f"read failed: {exc}")
        return out
    if not values:
        out["errors"].append("no data")
        return out
    out["points"] = values
    out["min"] = round(min(values), 2)
    out["max"] = round(max(values), 2)
    out["avg"] = round(sum(values) / len(values), 2)
    out["high_ratio"] = round(sum(1 for v in values if v >= 7.0) / len(values), 3)
    out["ok"] = True
    return out


def disasm_hint(data: bytes) -> str:
    """Tiny helper: recognize common instruction preambles (x86/x64/arm)."""
    if data.startswith(b"\x55\x48\x89\xe5"):
        return "x86_64 function prologue (push rbp; mov rbp, rsp)"
    if data.startswith(b"\x55\x89\xe5"):
        return "x86_32 function prologue (push ebp; mov ebp, esp)"
    if data[:4] in (b"\x1f\x0b\x00\x00",):
        return "ARM64 ADRP-heavy block"
    if data.startswith(b"\x60\x80\x60\x40"):
        return "EVM runtime bytecode preamble"
    return "unknown"
