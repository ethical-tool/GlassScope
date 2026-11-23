""".NET assembly & il2cpp analysis (REA `dotnet` / `inspect-il` parity).

Pure-stdlib PE/CLI metadata reader: DOS/PE headers, section table, CLR
runtime header, metadata streams (#~, #Strings, #US, #GUID, #Blob) and row
counts for the interesting metadata tables, plus il2cpp global-metadata
detection. Defensive and bounded; never raises.
"""

from __future__ import annotations

import os
import struct
from .util import MAX_STREAM_READ

MACHINE_NAMES = {0x014C: "x86", 0x8664: "x64", 0x01C0: "ARM",
                 0xAA64: "ARM64", 0x200: "IA64"}

# metadata table ids we report (subset; counts only, no row decoding)
NAMED_TABLES = {
    0x00: "Module", 0x01: "TypeRef", 0x02: "TypeDef", 0x04: "Field",
    0x06: "MethodDef", 0x08: "Param", 0x25: "ManifestResource",
    0x26: "NestedClass", 0x27: "AssemblyRef", 0x35: "Assembly",
}


def _rva_to_offset(rva: int, sections: list[dict]) -> int | None:
    for s in sections:
        if s["va"] <= rva < s["va"] + max(s["vsize"], s["rsize"]):
            return s["roff"] + (rva - s["va"])
    return None


def _parse_pe(data: bytes) -> dict:
    out: dict = {"ok": False, "errors": [], "sections": [], "is_dotnet": False}
    if len(data) < 0x40 or data[:2] != b"MZ":
        out["errors"].append("not a PE (no MZ)")
        return out
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    if e_lfanew <= 0 or e_lfanew + 24 > len(data) or data[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
        out["errors"].append("bad PE signature")
        return out
    coff = e_lfanew + 4
    machine, nsec, _ts, _sym, _nsym, opt_size, chars = \
        struct.unpack_from("<HHIIIHH", data, coff)
    out["machine"] = MACHINE_NAMES.get(machine, f"{machine:#06x}")
    out["num_sections"] = nsec
    out["characteristics"] = chars
    opt = coff + 20
    if opt_size < 96 or opt + opt_size > len(data):
        out["errors"].append("optional header too small")
        return out
    magic = struct.unpack_from("<H", data, opt)[0]
    if magic == 0x10B:
        ddir = opt + 96
    elif magic == 0x20B:
        ddir = opt + 112
    else:
        out["errors"].append(f"unknown optional header magic {magic:#06x}")
        return out
    out["pe_format"] = "PE32" if magic == 0x10B else "PE32+"
    if ddir + 16 * 8 > len(data):
        out["errors"].append("data directory table truncated")
        return out
    clr_rva, clr_size = struct.unpack_from("<II", data, ddir + 14 * 8)
    sec_tbl = opt + opt_size
    for i in range(min(nsec, 16)):
        s = sec_tbl + i * 40
        if s + 40 > len(data):
            break
        name = data[s:s + 8].rstrip(b"\x00").decode("ascii", "replace")
        vsize, va, rsize, roff = struct.unpack_from("<IIII", data, s + 8)
        out["sections"].append({"name": name, "vsize": vsize, "va": va,
                                "rsize": rsize, "roff": roff})
    out["clr_rva"], out["clr_size"] = clr_rva, clr_size
    out["ok"] = clr_rva != 0
    out["is_dotnet"] = clr_rva != 0
    return out


def dotnet_info(path: str) -> dict:
    out: dict = {"ok": False, "format": "dotnet", "warnings": [],
                 "errors": [], "streams": [], "tables": []}
    try:
        with open(path, "rb") as fh:
            data = fh.read(min(os.path.getsize(path), MAX_STREAM_READ))
    except OSError as exc:
        out["errors"].append(f"read failed: {exc}")
        return out
    pe = _parse_pe(data)
    if not pe["ok"]:
        out["errors"].extend(pe["errors"])
        return out
    out["machine"] = pe["machine"]
    out["pe_format"] = pe.get("pe_format")
    out["sections"] = [s["name"] for s in pe["sections"]]
    clr_off = _rva_to_offset(pe["clr_rva"], pe["sections"])
    if clr_off is None or clr_off + 72 > len(data):
        out["errors"].append("CLR header RVA unmapped or truncated")
        return out
    cb, rt_major, rt_minor, md_rva, md_size, flags, ep_token = \
        struct.unpack_from("<IHHIIII", data, clr_off)
    if cb != 72:
        out["warnings"].append(f"unexpected CLR header size {cb}")
    out["runtime_version"] = f"{rt_major}.{rt_minor}"
    out["il_only"] = bool(flags & 0x1)
    out["strong_name_signed"] = bool(flags & 0x8)
    out["entrypoint_token"] = f"{ep_token:#010x}"
    md_off = _rva_to_offset(md_rva, pe["sections"])
    if md_off is None or md_off + 16 > len(data) or \
            data[md_off:md_off + 4] != b"BSJB":
        out["errors"].append("metadata root missing/invalid (BSJB)")
        return out
    md_major, md_minor, _rsv, ver_len = struct.unpack_from("<HHII", data, md_off + 4)
    ver = data[md_off + 16: md_off + 16 + ver_len].rstrip(b"\x00").decode(
        "utf-8", "replace")
    out["metadata_version"] = ver
    pos = md_off + 16 + ver_len
    _flags, nstreams = struct.unpack_from("<HH", data, pos)
    pos += 4
    tables_stream_off = None
    for _ in range(min(nstreams, 8)):
        soff, ssize = struct.unpack_from("<II", data, pos)
        pos += 8
        nend = data.find(b"\x00", pos)
        sname = data[pos:nend].decode("ascii", "replace")
        pos = (nend + 1 + 3) & ~3
        out["streams"].append({"name": sname, "offset": soff, "size": ssize})
        if sname == "#~":
            tables_stream_off = md_off + soff
        elif sname == "#Strings":
            out["strings_heap_size"] = ssize
        elif sname == "#US":
            out["us_heap_size"] = ssize
    if tables_stream_off is None:
        out["warnings"].append("no #~ tables stream (broken metadata)")
        out["ok"] = True
        return out
    t = tables_stream_off
    if t + 24 > len(data):
        out["errors"].append("#~ header truncated")
        return out
    _rsv, tmaj, tmin, heaps, _r2, valid, _sorted = \
        struct.unpack_from("<IBBBBQQ", data, t)
    pos_t = t + 24
    for bit in range(64):
        if valid & (1 << bit):
            if pos_t + 4 > len(data):
                out["warnings"].append("row counts truncated")
                break
            rows = struct.unpack_from("<I", data, pos_t)[0]
            pos_t += 4
            if bit in NAMED_TABLES:
                out["tables"].append({"table": NAMED_TABLES[bit], "rows": rows})
    out["ok"] = True
    return out


def global_metadata_info(path: str) -> dict:
    """Unity il2cpp global-metadata.dat sanity check (magic FAB11BAF)."""
    out: dict = {"ok": False, "format": "il2cpp-metadata", "warnings": [],
                 "errors": []}
    try:
        with open(path, "rb") as fh:
            head = fh.read(64)
        if len(head) < 8:
            out["errors"].append("too small")
            return out
        magic, version = struct.unpack_from("<II", head, 0)
        if magic != 0xFAB11BAF:
            out["errors"].append(f"bad il2cpp metadata magic {magic:#010x}")
            return out
        out["metadata_version"] = version
        out["ok"] = True
        return out
    except OSError as exc:
        out["errors"].append(f"read failed: {exc}")
        return out
