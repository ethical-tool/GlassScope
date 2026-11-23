"""Windows PE parser: headers, sections, imports, exports, resources,
relocations, security mitigations (checksec-style), Rich header and the
version-info block — pure standard library, fully defensive.

Complements dotnet.py (which focuses on the CLR header): this module walks the
whole COFF structure so a native PE can be triaged without any external tool.
"""

from __future__ import annotations

import struct
from datetime import datetime, timezone

from .util import MAX_STREAM_READ

MACHINES = {
    0x014c: "x86", 0x8664: "x86-64 (AMD64)", 0x01c0: "ARM",
    0x01c4: "ARMNT (Thumb-2)", 0xAA64: "ARM64",
    0x0200: "Itanium (IA-64)", 0x0ebc: "EFI byte code",
    0x5032: "RISC-V 32", 0x5064: "RISC-V 64", 0x9041: "ARM64EC",
    0x0162: "MIPS R3000", 0x0286: "MIPS R4000", 0x01f0: "PowerPC",
}
SUBSYSTEMS = {
    0: "unknown", 1: "native", 2: "Windows GUI", 3: "Windows console (CUI)",
    5: "OS/2 console", 7: "POSIX CUI", 9: "Windows CE GUI",
    10: "EFI application", 11: "EFI boot driver", 12: "EFI runtime driver",
    13: "EFI ROM", 14: "Xbox", 16: "Windows boot GUI",
}
CHARACTERISTICS = {
    0x0001: "relocations stripped", 0x0002: "executable",
    0x0004: "line numbers stripped", 0x0008: "local symbols stripped",
    0x0010: "aggressive WS trim", 0x0020: "large address aware",
    0x0080: "bytes reversed (32-bit)", 0x0100: "32-bit word machine",
    0x0200: "debug stripped", 0x0400: "removable run from swap",
    0x0800: "net run from swap", 0x1000: "system file",
    0x2000: "DLL image", 0x4000: "uniprocessor only",
    0x8000: "big-endian",
}
DLL_CHARACTERISTICS = {
    0x0020: "HIGHENTROPYVA", 0x0040: "DYNAMIC_BASE (ASLR)",
    0x0100: "FORCE_INTEGRITY", 0x0200: "NX (DEP)",
    0x0400: "NO_ISOLATION", 0x0800: "NO_SEH",
    0x1000: "NO_BIND", 0x2000: "APPCONTAINER",
    0x4000: "WDM_DRIVER", 0x8000: "GUARD_CF (CFG)",
    0x10000: "TERMINAL_SERVER_AWARE",
}
SECTION_FLAGS = {
    0x00000020: "code", 0x00000040: "initialized data",
    0x00000080: "uninitialized data", 0x02000000: "discardable",
    0x04000000: "not cacheable", 0x08000000: "not pageable",
    0x10000000: "shared", 0x20000000: "executable", 0x40000000: "readable",
    0x80000000: "writable",
}
PACKER_PREFIXES = ("upx", "aspack", "petite", "mpress", "nspack", "themida",
                   "vmprotect", ".themida", ".vmp", "pecompact")

_DIR_NAMES = ("export", "import", "resource", "exception", "security",
              "basereloc", "debug", "architecture", "global_ptr", "tls",
              "load_config", "bound_import", "iat", "delay_import",
              "clr", "reserved")


def _rva_to_offset(rva: int, sections: list[dict]) -> int | None:
    for s in sections:
        if s["_va"] <= rva < s["_va"] + max(s["virtual_size"], s["raw_size"]):
            delta = rva - s["_va"]
            if delta >= s["raw_size"]:
                return None  # inside virtual-only padding
            return s["_raw"] + delta
    if 0 <= rva < 0x400:  # inside the headers themselves
        return rva
    return None


def parse_pe(path: str) -> dict:
    """Full static PE triage: header, sections, imports, exports, version
    info, Rich header and checksec-style mitigations."""
    out: dict = {"ok": False, "warnings": [], "errors": []}
    try:
        with open(path, "rb") as fh:
            data = fh.read(MAX_STREAM_READ)
    except OSError as exc:
        out["errors"].append(f"read failed: {exc}")
        return out
    if len(data) < 0x40 or data[:2] != b"MZ":
        out["errors"].append("not a PE file (no MZ signature)")
        return out

    try:
        out["file_size"] = len(data)
        (e_lfanew,) = struct.unpack_from("<I", data, 0x3C)
        if e_lfanew + 4 > len(data):
            raise ValueError("bad e_lfanew")
        if data[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
            out["errors"].append("missing PE signature")
            return out

        coff = e_lfanew + 4
        (machine, num_sections, timestamp, _ptr_symtab, _num_syms,
         opt_size, chars) = struct.unpack_from("<HHIIIHH", data, coff)
        now = datetime.now(timezone.utc).timestamp()
        header: dict = {
            "machine": MACHINES.get(machine, f"unknown ({machine:#06x})"),
            "machine_code": machine,
            "timestamp": timestamp,
            "timestamp_human": (datetime.fromtimestamp(
                timestamp, timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
                if 0 < timestamp < 0xF0000000 else "invalid/epoch"),
            "num_sections": num_sections,
            "characteristics": [v for bit, v in CHARACTERISTICS.items()
                                if chars & bit],
            "is_dll": bool(chars & 0x2000),
            "is_exe": bool(chars & 0x0002 and not chars & 0x2000),
            "relocs_stripped": bool(chars & 0x0001),
            "timestamp_in_future": timestamp > now + 86400,
            "timestamp_epoch": timestamp < 1000,
        }
        out["header"] = header

        opt_off = coff + 20
        if opt_size == 0:
            out["warnings"].append("no optional header (object file?)")
            out["ok"] = True
            return out
        magic = struct.unpack_from("<H", data, opt_off)[0]
        is_pe32plus = magic == 0x20B
        if magic not in (0x10B, 0x20B):
            out["warnings"].append(f"unknown optional-header magic {magic:#x}")
        entry_rva = struct.unpack_from("<I", data, opt_off + 16)[0]
        image_base = (struct.unpack_from("<Q", data, opt_off + 24)[0]
                     if is_pe32plus else
                     struct.unpack_from("<I", data, opt_off + 28)[0])
        sect_align, file_align = struct.unpack_from("<II", data,
                                                    opt_off + 32)
        size_image, size_headers, checksum, subsystem, dll_chars = \
            struct.unpack_from("<II I H H", data, opt_off + 56)
        stack_res, _stack_com, heap_res, _heap_com = struct.unpack_from(
            "<IIII", data, opt_off + 72 if not is_pe32plus else opt_off + 84)
        code_size, init_size, uninit_size = struct.unpack_from(
            "<III", data, opt_off + 4)
        opt: dict = {
            "magic": "PE32+" if is_pe32plus else "PE32",
            "entry_point_rva": f"{entry_rva:#x}",
            "entry_point": f"{image_base + entry_rva:#x}",
            "image_base": f"{image_base:#x}",
            "size_of_code": code_size,
            "size_of_initialized_data": init_size,
            "size_of_uninitialized_data": uninit_size,
            "section_alignment": sect_align,
            "file_alignment": file_align,
            "size_of_image": size_image, "size_of_headers": size_headers,
            "checksum": f"{checksum:#010x}",
            "subsystem": SUBSYSTEMS.get(subsystem, f"unknown ({subsystem})"),
            "stack_reserve": stack_res, "heap_reserve": heap_res,
            "dll_characteristics": [v for bit, v in DLL_CHARACTERISTICS.items()
                                    if dll_chars & bit],
            "dll_characteristics_raw": f"{dll_chars:#06x}",
        }
        out["optional_header"] = opt

        # ---- data directories -------------------------------------------
        dd_off = opt_off + (112 if is_pe32plus else 96)
        num_dirs = max(0, (opt_size - (dd_off - opt_off)) // 8)
        directories: dict = {}
        for i in range(min(num_dirs, 16)):
            rva, size = struct.unpack_from("<II", data, dd_off + i * 8)
            if rva or size:
                directories[_DIR_NAMES[i]] = {"rva": rva, "size": size}
        out["data_directories"] = directories
        out["is_dotnet"] = bool(directories.get("clr", {}).get("size"))
        out["has_tls"] = bool(directories.get("tls", {}).get("size"))
        out["has_exceptions"] = bool(directories.get("exception", {}).get("size"))
        out["has_debug"] = bool(directories.get("debug", {}).get("size"))
        out["signed"] = bool(directories.get("security", {}).get("size"))
        if out["signed"]:
            out["signature_size"] = directories["security"]["size"]

        # ---- sections ----------------------------------------------------
        sec_off = opt_off + opt_size
        sections: list[dict] = []
        packed = False
        for i in range(min(num_sections, 96)):
            so = sec_off + i * 40
            if so + 40 > len(data):
                out["warnings"].append("section table truncated")
                break
            sec_name = data[so:so + 8].rstrip(b"\x00").decode("ascii",
                                                             "replace")
            vsize, va, raw_size, raw_ptr = struct.unpack_from(
                "<IIII", data, so + 8)
            _relocs, _lineno, _nreloc, _nline, sflags = struct.unpack_from(
                "<IIHHI", data, so + 24)
            flag_labels = [v for bit, v in SECTION_FLAGS.items()
                           if sflags & bit]
            if any(sec_name.lower().startswith(p) for p in PACKER_PREFIXES):
                packed = True
            sections.append({
                "name": sec_name, "virtual_size": vsize,
                "virtual_address": f"{va:#x}", "raw_size": raw_size,
                "raw_pointer": f"{raw_ptr:#x}",
                "flags": f"{sflags:#010x}", "flags_meaning": flag_labels,
                "raw/virtual ratio": round(raw_size / vsize, 2)
                if vsize else None,
                "_va": va, "_raw": raw_ptr,
            })
        out["sections"] = sections
        out["packed_hint"] = packed
        if packed:
            out["warnings"].append(
                "packer-style section names detected (UPX/Themida/...)")
        if entry_rva and entry_rva < size_headers and entry_rva > 0:
            out["warnings"].append(
                "entry point inside the PE headers — typical packer stub")

        # ---- imports / exports / resources --------------------------------
        imports = _parse_imports(data, directories, sections, is_pe32plus)
        out["imports"] = imports
        out["import_count"] = sum(len(d["functions"]) for d in imports)

        exports = _parse_exports(data, directories, sections)
        out["exports"] = exports
        out["export_count"] = len(exports.get("functions", []))

        res = directories.get("resource")
        if res and res.get("size"):
            out["has_resources"] = True
        version_info = _parse_version_info(data)
        if version_info:
            out["version_info"] = version_info

        rich = _parse_rich_header(data, e_lfanew)
        if rich:
            out["rich_header"] = rich

        # ---- mitigations (checksec-style) --------------------------------
        mitigations: dict = {
            "nx (DEP)": bool(dll_chars & 0x0200),
            "aslr": (not header["relocs_stripped"]
                     and bool(dll_chars & 0x0040)),
            "high entropy va": bool(dll_chars & 0x0020) and is_pe32plus,
            "cfg (guard cf)": bool(dll_chars & 0x8000),
            "force integrity": bool(dll_chars & 0x0100),
            "no seh": bool(dll_chars & 0x0800),
            "appcontainer": bool(dll_chars & 0x2000),
            "relocs stripped": header["relocs_stripped"],
        }
        # SAFE_SEH / GS via the load-config directory
        lc = directories.get("load_config")
        if lc:
            lc_off = _rva_to_offset(lc["rva"], sections)
            if lc_off is not None and lc_off + 64 <= len(data):
                (size, _ts, _ver_major, _ver_minor, _flags, list_off,
                 _list_size) = struct.unpack_from("<IIHHIII", data, lc_off)
                security_cookie = struct.unpack_from(
                    "<Q" if is_pe32plus else "<I", data, lc_off + 60)[0]
                mitigations["gs (stack cookie)"] = security_cookie not in (
                    0, 0xBB40E64E, 0x2BBC4064) and size >= 64
                if list_off and size >= 92:
                    mitigations["safe seh"] = True  # SEH table registered
        out["mitigations"] = mitigations

        out["ok"] = True
    except (struct.error, ValueError) as exc:
        out["errors"].append(f"truncated/corrupt PE structure: {exc}")
    return out


def _parse_imports(data: bytes, directories: dict, sections: list[dict],
                   is_pe32plus: bool) -> list[dict]:
    """Walk the import directory: one descriptor per DLL with its functions."""
    imports: list[dict] = []
    d = directories.get("import")
    if not d:
        return imports
    off = _rva_to_offset(d["rva"], sections)
    if off is None:
        return imports
    width = 8 if is_pe32plus else 4
    ordinal_flag = 1 << (63 if is_pe32plus else 31)
    try:
        for i in range(64):
            desc = off + i * 20
            if desc + 20 > len(data):
                break
            (_oft, _ts, _fc, name_rva, fthunk_rva) = struct.unpack_from(
                "<IIIII", data, desc)
            if name_rva == 0 and fthunk_rva == 0:
                break
            name_off = _rva_to_offset(name_rva, sections)
            if name_off is None:
                continue
            end = data.find(b"\x00", name_off)
            dll = data[name_off:end].decode("ascii", "replace")
            funcs: list[dict] = []
            thunk_off = _rva_to_offset(fthunk_rva, sections)
            if thunk_off is not None:
                for j in range(2048):
                    to = thunk_off + j * width
                    if to + width > len(data):
                        break
                    val = struct.unpack_from("<Q" if width == 8 else "<I",
                                              data, to)[0]
                    if val == 0:
                        break
                    if val & ordinal_flag:
                        funcs.append({"name": f"ordinal #{val & 0xFFFF}",
                                      "ordinal": val & 0xFFFF})
                    else:
                        n_off = _rva_to_offset(val + 2, sections)
                        if n_off is not None:
                            nend = data.find(b"\x00", n_off)
                            fname = data[n_off:nend].decode("ascii",
                                                            "replace")
                            funcs.append({"name": fname})
                        else:
                            funcs.append({"name": f"<rva {val:#x}>"})
                    if len(funcs) >= 512:
                        break
            imports.append({"dll": dll, "count": len(funcs),
                            "functions": funcs})
    except (struct.error, ValueError):
        pass
    return imports


def _parse_exports(data: bytes, directories: dict,
                   sections: list[dict]) -> dict:
    """Export directory: module name, functions with ordinals, forwarders."""
    out: dict = {"name": None, "functions": [], "forwarders": []}
    d = directories.get("export")
    if not d:
        return out
    off = _rva_to_offset(d["rva"], sections)
    if off is None:
        return out
    try:
        (_flags, _ts, _maj, _min, name_rva, _base, nfunc, nnames,
         addr_funcs, addr_names, addr_ord) = struct.unpack_from(
            "<IIHHIIIIIII", data, off)
        if name_rva:
            n_off = _rva_to_offset(name_rva, sections)
            if n_off is not None:
                end = data.find(b"\x00", n_off)
                out["name"] = data[n_off:end].decode("ascii", "replace")
        nfunc, nnames = min(nfunc, 4096), min(nnames, 4096)
        names_off = _rva_to_offset(addr_names, sections)
        funcs_off = _rva_to_offset(addr_funcs, sections)
        ord_off = _rva_to_offset(addr_ord, sections)
        if names_off is None:
            return out
        for i in range(nnames):
            no = names_off + i * 4
            if no + 4 > len(data):
                break
            rva = struct.unpack_from("<I", data, no)[0]
            str_off = _rva_to_offset(rva, sections)
            if str_off is None:
                continue
            end = data.find(b"\x00", str_off)
            fname = data[str_off:end].decode("ascii", "replace")
            entry: dict = {"name": fname}
            if ord_off is not None and ord_off + i * 2 + 2 <= len(data):
                idx = struct.unpack_from("<H", data, ord_off + i * 2)[0]
                entry["ordinal"] = _base + idx
                if funcs_off is not None:
                    fo = funcs_off + idx * 4
                    if fo + 4 <= len(data):
                        frva = struct.unpack_from("<I", data, fo)[0]
                        # RVA that no section maps => forwarder string
                        if frva and _rva_to_offset(frva, sections) is None \
                                and frva >= 0x10000:
                            f_off = None
                            entry["forwarder"] = True
                            out["forwarders"].append(fname)
            out["functions"].append(entry)
    except (struct.error, ValueError, IndexError):
        pass
    return out


def _parse_version_info(data: bytes) -> dict:
    """Extract VS_VERSION_INFO strings (UTF-16LE keys) from the whole file."""
    out: dict = {}
    keys = ("FileVersion", "CompanyName", "ProductName", "ProductVersion",
            "FileDescription", "InternalName", "OriginalFilename",
            "LegalCopyright", "Comments")
    for key in keys:
        needle = key.encode("utf-16-le")
        idx = data.find(needle)
        if idx < 0:
            continue
        pos = idx + len(needle)
        # scan forward for the first printable UTF-16LE value string
        for _ in range(6):
            if pos + 2 > len(data):
                break
            if data[pos:pos + 2] == b"\x00\x00":
                pos += 2
                continue
            chars = []
            p = pos
            while p + 1 < len(data) and len(chars) < 128:
                pair = data[p:p + 2]
                if pair == b"\x00\x00":
                    break
                try:
                    chars.append(pair.decode("utf-16-le"))
                except UnicodeDecodeError:
                    break
                p += 2
            s = "".join(chars)
            if s and sum(c.isprintable() for c in s) >= len(s):
                out[key] = s[:120]
                break
            pos += 2
    return out


def _parse_rich_header(data: bytes, e_lfanew: int) -> dict | None:
    """Decode the Rich header (MSVC toolchain build evidence)."""
    try:
        end = data.find(b"Rich", 0, e_lfanew)
        if end <= 0:
            return None
        (xor_key,) = struct.unpack_from("<I", data, end + 4)
        salt = bytes((b ^ (xor_key & 0xFF)) for b in b"DanS")
        start = data.find(salt, 0, end)
        if start < 0:
            return None
        entries = []
        pos = start + 16
        while pos + 8 <= end and len(entries) < 64:
            comp_id, count = struct.unpack_from("<II", data, pos)
            if comp_id == 0 and count == 0:
                pos += 8
                continue
            entries.append({"id": f"{comp_id & 0xFFFF:#06x}",
                            "build": comp_id >> 16, "count": count})
            pos += 8
        if entries:
            return {"entries": entries, "tools_count": len(entries)}
    except (struct.error, ValueError):
        pass
    return None
