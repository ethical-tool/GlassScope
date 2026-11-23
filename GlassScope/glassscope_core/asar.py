"""Electron ASAR archive reader.

Format layout (validated against the upstream REA implementation, whose
extent math was audited and found correct):

    [0..3]   u32  == 4                 (size-pickle payload length)
    [4..7]   u32  headerBytes          (header pickle buffer length)
    [8..8+headerBytes]  header pickle  (u32 jsonBytes, then JSON, padded to 4)
    payload starts at 8 + headerBytes
    member data at payloadBase + int(entry["offset"]), entry["size"] bytes

All extents are bounds-checked before any read; malformed archives produce
warnings instead of exceptions. Entries with "unpacked": true are read from
the companion `<archive>.unpacked/` directory on disk.
"""

from __future__ import annotations

import json
import os
import struct

from .util import sanitize_rel_path


class AsarError(Exception):
    pass


def parse_asar(path: str) -> dict:
    result: dict = {
        "ok": False, "kind": "ASAR", "path": os.path.abspath(path),
        "warnings": [], "header": {}, "entries": [], "stats": {},
    }
    warnings = result["warnings"]
    try:
        size = os.path.getsize(path)
        with open(path, "rb") as fh:
            data = fh.read()
    except OSError as exc:
        warnings.append(f"Read failed: {exc}")
        return result

    if size < 16:
        warnings.append(f"Too small ({size} bytes) to be an ASAR archive.")
        return result
    if len(data) != size:
        warnings.append("File changed while reading; parsed the shorter snapshot.")

    first, header_bytes, json_bytes = struct.unpack_from("<III", data, 0)
    if first != 4:
        warnings.append(f"Bad pickle magic {first} (expected 4); not an ASAR file?")
        return result
    if json_bytes < 4 or json_bytes > header_bytes - 4:
        warnings.append(
            f"Header extents invalid (jsonBytes={json_bytes}, headerBytes={header_bytes}).")
        return result
    if 8 + header_bytes > len(data):
        warnings.append(
            f"Header exceeds archive size ({8 + header_bytes} > {len(data)}).")
        return result

    json_start = 12  # 8 + 4-byte pickle length prefix inside the header buffer
    raw_json = data[json_start : json_start + json_bytes]
    try:
        header = json.loads(raw_json.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        warnings.append(f"Header JSON parse failed: {exc}")
        return result

    payload_base = 8 + header_bytes
    result["header"] = header
    result["ok"] = True

    entries: list[dict] = []

    def walk(node: dict, prefix: str) -> None:
        files = node.get("files") or {}
        if not isinstance(files, dict):
            return
        for name, meta in sorted(files.items()):
            if not isinstance(meta, dict):
                continue
            child_path = f"{prefix}/{name}" if prefix else name
            if "files" in meta:
                entries.append({"path": child_path, "type": "directory", "size": 0})
                walk(meta, child_path)
            else:
                entries.append({
                    "path": child_path,
                    "type": "file",
                    "size": int(meta.get("size", 0) or 0),
                    "offset": meta.get("offset", ""),
                    "unpacked": bool(meta.get("unpacked", False)),
                    "executable": bool(meta.get("executable", False)),
                })

    walk(header, "")
    result["entries"] = entries
    files = [e for e in entries if e["type"] == "file"]
    result["stats"] = {
        "total_entries": len(entries),
        "files": len(files),
        "directories": len(entries) - len(files),
        "total_file_bytes": sum(e["size"] for e in files),
        "unpacked_entries": sum(1 for e in files if e.get("unpacked")),
        "payload_base": payload_base,
        "archive_size": size,
    }
    return result


def _check_member_range(path: str, entry: dict, payload_base: int, archive_size: int) -> tuple[int, int]:
    offset_str = entry.get("offset", "")
    try:
        offset = int(offset_str)
    except (TypeError, ValueError):
        raise AsarError(f"entry {entry.get('path')!r} has invalid offset {offset_str!r}")
    fsize = int(entry.get("size", 0) or 0)
    start = payload_base + offset
    if start < payload_base:
        raise AsarError("integer overflow in member offset")
    if start + fsize > archive_size:
        raise AsarError(
            f"member {entry.get('path')!r} extends beyond archive "
            f"({start + fsize} > {archive_size})")
    return start, fsize


def read_asar_member(path: str, entry: dict, parsed: dict | None = None) -> bytes:
    """Read one file entry's bytes (with full bounds checking)."""
    p = parsed or parse_asar(path)
    if not p.get("ok"):
        raise AsarError("archive is not a valid ASAR")
    archive_size = p["stats"]["archive_size"]
    payload_base = p["stats"]["payload_base"]
    if entry.get("unpacked"):
        rel = sanitize_rel_path(entry.get("path", ""))
        if not rel:
            raise AsarError("unsafe unpacked path")
        unpacked_dir = path + ".unpacked"
        disk_path = os.path.join(unpacked_dir, rel)
        with open(disk_path, "rb") as fh:
            return fh.read()
    start, fsize = _check_member_range(path, entry, payload_base, archive_size)
    with open(path, "rb") as fh:
        fh.seek(start)
        data = fh.read(fsize)
    if len(data) != fsize:
        raise AsarError("short read on member data")
    return data


def extract_asar(path: str, dest_dir: str, parsed: dict | None = None,
                 on_progress=None, limit_files: int = 200_000) -> dict:
    """Extract the whole archive into dest_dir. Returns {extracted, skipped, errors}."""
    p = parsed or parse_asar(path)
    if not p.get("ok"):
        raise AsarError("archive is not a valid ASAR")
    os.makedirs(dest_dir, exist_ok=True)
    extracted, skipped, errors = 0, 0, []
    archive_size = p["stats"]["archive_size"]
    payload_base = p["stats"]["payload_base"]
    files = [e for e in p["entries"] if e["type"] == "file"]
    if len(files) > limit_files:
        raise AsarError(f"too many entries ({len(files)}); refusing extraction")
    for i, entry in enumerate(files):
        rel = sanitize_rel_path(entry.get("path", ""))
        if not rel:
            skipped += 1
            errors.append(f"unsafe path skipped: {entry.get('path')!r}")
            continue
        dest = os.path.join(dest_dir, rel)
        parent = os.path.dirname(dest)
        if os.path.commonpath([os.path.abspath(dest_dir), os.path.abspath(dest)]) != os.path.abspath(dest_dir):
            skipped += 1
            errors.append(f"escape attempt skipped: {entry.get('path')!r}")
            continue
        try:
            if parent:
                os.makedirs(parent, exist_ok=True)
            data = read_asar_member(path, entry, p)
            with open(dest, "wb") as fh:
                fh.write(data)
            extracted += 1
        except (AsarError, OSError) as exc:
            errors.append(f"{entry.get('path')}: {exc}")
            skipped += 1
        if on_progress and i % 200 == 0:
            on_progress(i + 1, len(files))
    return {"extracted": extracted, "skipped": skipped, "errors": errors}
