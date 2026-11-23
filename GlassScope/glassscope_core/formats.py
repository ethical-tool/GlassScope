"""Format dispatch + generic artifact inspection (REA `inspector` parity).

detect_format() routes any target to the right parser (used by Overview and
the Firmware/Formats page). carve_signatures() finds embedded files (zip,
PE, ELF, images, GDPC, devicetree, fuse wire...) inside any blob. Also:
WASM section walk, Go buildinfo, Dart/Flutter snapshot detection, EVM hints
and ML model artifacts.
"""

from __future__ import annotations

import os
import struct

from .util import MAX_STREAM_READ

SCAN_LIMIT = 16 * 1024 * 1024

# magic -> (label, kind) checked at offset 0, in priority order
_LEADING = [
    (b"\x7fELF", "ELF executable / shared object", "elf"),
    (b"MZ", "Windows PE / .NET executable", "pe"),
    (b"\xcf\xfa\xed\xfe", "Mach-O binary", "macho"),
    (b"\xfe\xed\xfa\xcf", "Mach-O binary", "macho"),
    (b"dex\n", "Dalvik DEX file", "dex"),
    (b"PK\x03\x04", "ZIP container", "zip"),
    (b"SQLite format 3\x00", "SQLite database", "sqlite"),
    (b"\x00asm", "WebAssembly module", "wasm"),
    (b"\xd0\x0d\xfe\xed", "Flattened devicetree (DTB)", "dtb"),
    (b"GDPC", "Godot PCK package", "pck"),
    (b"FOR1", "Erlang BEAM (IFF container)", "beam"),
    (b"TFL3", "TFLite model", "tflite"),
    (b"%PDF", "PDF document", "pdf"),
    (b"\x89PNG", "PNG image", "png"),
    (b"\xff\xd8\xff", "JPEG image", "jpeg"),
    (b"\x1f\x8b", "gzip stream", "gzip"),
    (b"IKCFG_ST", "embedded kernel config (IKCONFIG)", "ikconfig"),
]

# signature -> name (searched anywhere in the blob by carve_signatures)
_CARVE_SIGS = [
    (b"PK\x03\x04", "ZIP"),
    (b"PK\x05\x06", "ZIP end-of-central-dir"),
    (b"\x7fELF", "ELF"),
    (b"MZ", "PE/MZ"),
    (b"\x89PNG\r\n\x1a\n", "PNG"),
    (b"\xff\xd8\xff", "JPEG"),
    (b"GIF8", "GIF"),
    (b"%PDF", "PDF"),
    (b"\x1f\x8b\x08", "gzip"),
    (b"7z\xbc\xaf\x27\x1c", "7-Zip"),
    (b"Rar!", "RAR"),
    (b"SQLite format 3\x00", "SQLite"),
    (b"GDPC", "Godot PCK"),
    (b"\xd0\x0d\xfe\xed", "devicetree"),
    (b"FOR1\x00\x00\x00\x04BEAM", "Erlang BEAM"),
    (b"IKCFG_ST", "IKCONFIG kernel config"),
    (b"dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX", "Electron fuse wire"),
    (b"APK Sig Block 42", "APK signing block"),
    (b"\x00asm", "WebAssembly"),
    (b"BSJB", ".NET metadata"),
]


def detect_format(path: str) -> dict:
    """Identify the target kind; returns {"ok", "label", "kind", "hints"}."""
    out: dict = {"ok": False, "label": "unknown", "kind": None,
                 "hints": [], "warnings": [], "errors": []}
    try:
        size = os.path.getsize(path)
        out["size"] = size
        with open(path, "rb") as fh:
            head = fh.read(64 * 1024)
            fh.seek(max(0, min(size, SCAN_LIMIT) - 4096))
            tail = fh.read()
    except OSError as exc:
        out["errors"].append(f"read failed: {exc}")
        return out
    if not head:
        out["label"] = "empty file"
        out["kind"] = "empty"
        out["ok"] = True
        return out
    for magic, label, kind in _LEADING:
        if head.startswith(magic):
            out["label"], out["kind"] = label, kind
            break
    if out["kind"] is None:
        # Electron ASAR: Chromium Pickle header [u32=4][u32 header len][json]
        if len(head) >= 12:
            first, header_len, json_len = struct.unpack_from("<III", head, 0)
            if first == 4 and 4 <= json_len <= header_len and \
                    head[12:13] in (b"{", b" "):
                try:
                    head[12:12 + min(json_len, 256)].decode("utf-8", "ignore")
                    out["label"] = "Electron ASAR archive"
                    out["kind"] = "asar"
                except Exception:
                    pass
    if out["kind"] is None:
        if b"BSJB" in head[:4096]:
            out["label"], out["kind"] = ".NET metadata (BSJB)", "dotnet-meta"
        elif struct.pack("<I", 0xFAB11BAF) in head[:4096]:
            out["label"], out["kind"] = "il2cpp global-metadata.dat", "il2cpp-meta"
        elif head[:4] == b"\xf5\xf5\xdc\xdc":
            out["label"], out["kind"] = "Dart/Flutter AOT snapshot", "dart"
        elif b"\xff Go buildinf:" in head[:4096]:
            out["label"], out["kind"] = "Go binary (buildinfo)", "go"
        elif b"AndroidManifest.xml" in head[:2048] or \
                b"classes.dex" in head[:2048]:
            out["label"], out["kind"] = "Android/Java entry", "android"
        else:
            # trailing-magic formats
            if b"d3n0landndm0d1e5" in tail:
                out["label"], out["kind"] = "Deno standalone binary", "deno"
            elif b"------Bun!------" in tail:
                out["label"], out["kind"] = "Bun standalone binary", "bun"
            elif b"Linux version " in head or b"Linux version " in tail:
                out["label"], out["kind"] = "kernel image / blob", "kernel"
            elif b"<!DOCTYPE html" in head[:512].lower() or \
                    b"<html" in head[:512].lower():
                out["label"], out["kind"] = "HTML document", "html"
            elif head[:64].lstrip().startswith(b"{") and b'"log"' in head[:2048]:
                out["label"], out["kind"] = "JSON document (log/HAR?)", "json"
    out["ok"] = True
    return out


def carve_signatures(path: str, max_hits: int = 200) -> dict:
    """Scan a blob for embedded file signatures (static carving)."""
    out: dict = {"ok": False, "format": "carve", "hits": [], "scanned": 0,
                 "warnings": [], "errors": []}
    try:
        size = os.path.getsize(path)
        with open(path, "rb") as fh:
            data = fh.read(min(size, SCAN_LIMIT))
    except OSError as exc:
        out["errors"].append(f"read failed: {exc}")
        return out
    out["scanned"] = len(data)
    if len(data) < size:
        out["warnings"].append(
            f"scanned first {len(data) // (1 << 20)} MiB of "
            f"{size // (1 << 20)} MiB file")
    hits: list[dict] = []
    for sig, name in _CARVE_SIGS:
        start = 0
        while len(hits) < max_hits:
            idx = data.find(sig, start)
            if idx < 0:
                break
            if idx > 0:  # offset 0 = the file itself, not "embedded"
                hits.append({"signature": name, "offset": idx,
                             "hex": sig[:8].hex()})
            start = idx + max(1, len(sig) - 1)
        if len(hits) >= max_hits:
            out["warnings"].append(f"hit cap {max_hits} reached")
            break
    hits.sort(key=lambda h: h["offset"])
    out["hits"] = hits
    out["hit_count"] = len(hits)
    out["ok"] = True
    return out


# --- generic artifacts -------------------------------------------------------
def _leb128(data: bytes, pos: int) -> tuple[int, int]:
    """Decode unsigned LEB128; return (value, next_pos)."""
    result = 0
    shift = 0
    while pos < len(data):
        b = data[pos]
        pos += 1
        result |= (b & 0x7F) << shift
        if not b & 0x80:
            return result, pos
        shift += 7
        if shift > 42:
            raise ValueError("LEB128 too long")
    raise ValueError("LEB128 truncated")


WASM_SECTIONS = {0: "custom", 1: "type", 2: "import", 3: "function",
                 4: "table", 5: "memory", 6: "global", 7: "export",
                 8: "start", 9: "element", 10: "code", 11: "data",
                 12: "data-count"}


def wasm_info(path: str) -> dict:
    out: dict = {"ok": False, "format": "wasm", "sections": [],
                 "warnings": [], "errors": []}
    try:
        with open(path, "rb") as fh:
            data = fh.read(min(os.path.getsize(path), MAX_STREAM_READ))
    except OSError as exc:
        out["errors"].append(f"read failed: {exc}")
        return out
    if data[:4] != b"\x00asm":
        out["errors"].append("bad WASM magic")
        return out
    out["version"] = struct.unpack_from("<I", data, 4)[0]
    pos = 8
    while pos < len(data) and len(out["sections"]) < 64:
        try:
            sid, after_id = _leb128(data, pos)
            size, body = _leb128(data, after_id)
        except ValueError as exc:
            out["warnings"].append(f"section walk stopped: {exc}")
            break
        entry = {"id": sid, "name": WASM_SECTIONS.get(sid, str(sid)),
                 "size": size, "offset": body}
        if body < len(data):
            try:
                count, _ = _leb128(data, body)
                if sid in (1, 2, 3, 4, 5, 7, 9, 10, 11, 12):
                    entry["count"] = count
                if sid == 0:  # custom: first LEB is name length
                    nlen, npos = _leb128(data, body)
                    if npos + nlen <= len(data) and nlen < 256:
                        entry["custom_name"] = data[npos:npos + nlen].decode(
                            "utf-8", "replace")
            except ValueError:
                pass
        out["sections"].append(entry)
        pos = body + size
    out["ok"] = True
    return out


def go_buildinfo(path: str) -> dict:
    out: dict = {"ok": False, "format": "go-binary", "warnings": [],
                 "errors": []}
    try:
        with open(path, "rb") as fh:
            data = fh.read(64 * 1024)
    except OSError as exc:
        out["errors"].append(f"read failed: {exc}")
        return out
    idx = data.find(b"\xff Go buildinf:")
    if idx < 0:
        out["errors"].append("Go buildinfo magic not found (stripped or "
                             "not a Go binary)")
        return out
    pos = idx + len(b"\xff Go buildinf:")
    if pos + 2 > len(data):
        out["errors"].append("buildinfo header truncated")
        return out
    ptrsize, flags = data[pos], data[pos + 1]
    out["ptr_size"] = ptrsize
    strings = []
    if flags & 0x2:
        p = pos + 2
        for _ in range(3):
            try:
                n, p = _leb128(data, p)
            except ValueError:
                break
            if p + n > len(data) or n > 4096:
                break
            strings.append(data[p:p + n].decode("utf-8", "replace"))
            p += n
    labels = ["module_path", "module_version_or_arch", "arch_or_version"]
    out["buildinfo"] = {labels[i]: s for i, s in enumerate(strings)}
    if not strings:
        out["warnings"].append("legacy buildinfo layout (inline strings "
                               "missing); module data not decoded")
    out["ok"] = True
    return out


def dart_snapshot_info(path: str) -> dict:
    out: dict = {"ok": False, "format": "dart-snapshot", "warnings": [],
                 "errors": []}
    try:
        with open(path, "rb") as fh:
            head = fh.read(64)
    except OSError as exc:
        out["errors"].append(f"read failed: {exc}")
        return out
    if head[:4] != b"\xf5\xf5\xdc\xdc":
        out["errors"].append("bad Dart snapshot magic (f5 f5 dc dc)")
        return out
    out["version_hash"] = head[4:36].hex()
    out["ok"] = True
    return out


def evm_hints(path: str) -> dict:
    out: dict = {"ok": False, "format": "evm", "warnings": [], "errors": []}
    try:
        with open(path, "rb") as fh:
            data = fh.read(2 * 1024 * 1024)
    except OSError as exc:
        out["errors"].append(f"read failed: {exc}")
        return out
    if data.startswith(b"\x60\x80\x60\x40"):
        out["runtime_preamble"] = True
        out["ok"] = True
    idx = data.find(bytes.fromhex("a165627a7a72305820"))
    if idx >= 0:
        out["solc_metadata"] = "bzzr0"
        out["ipfs_or_swarm_hash"] = data[idx + 9: idx + 41].hex()
        out["metadata_offset"] = idx
        out["ok"] = True
    if not out["ok"]:
        out["errors"].append("no EVM runtime preamble or solc metadata found")
    return out


def model_info(path: str) -> dict:
    out: dict = {"ok": False, "format": "ml-model", "warnings": [],
                 "errors": []}
    ext = os.path.splitext(path)[1].lower()
    try:
        with open(path, "rb") as fh:
            head = fh.read(64)
    except OSError as exc:
        out["errors"].append(f"read failed: {exc}")
        return out
    if head[4:8] == b"TFL3" or head[:4] == b"TFL3":
        out["model"] = "TensorFlow Lite flatbuffer"
        out["ok"] = True
    elif head[:2] == b"\x08\x07" or ext in (".onnx", ".pb"):
        out["model"] = f"protobuf-style model ({ext or 'onnx?'}) — low confidence"
        out["warnings"].append("protobuf magic is not unique; verify manually")
        out["ok"] = True
    elif ext == ".gguf" and head[:4] == b"GGUF":
        out["model"] = "GGUF model"
        out["ok"] = True
    else:
        out["errors"].append("no known ML-model signature")
    return out
