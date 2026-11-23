"""Pure-Python ELF parser (32/64-bit, LE/BE) — no external dependencies.

Returns a dict result with `ok`, `warnings`, and structured tables. Any
malformed or truncated file yields warnings, never an exception.
"""

from __future__ import annotations

import os
import struct

from .util import READ_CHUNK, shannon_entropy

SHT_NAMES = {
    0: "NULL", 1: "PROGBITS", 2: "SYMTAB", 3: "STRTAB", 4: "RELA", 5: "HASH",
    6: "DYNAMIC", 7: "NOTE", 8: "NOBITS", 9: "REL", 10: "SHLIB", 11: "DYNSYM",
    14: "INIT_ARRAY", 15: "FINI_ARRAY", 16: "PREINIT_ARRAY", 17: "GROUP",
    18: "SYMTAB_SHNDX", 0x6FFFFFF5: "GNU_ATTRIBUTES", 0x6FFFFFF6: "GNU_HASH",
    0x6FFFFFFD: "GNU_VERDEF", 0x6FFFFFFE: "GNU_VERNEED", 0x6FFFFFFF: "GNU_VERSYM",
}

ET_NAMES = {
    0: "ET_NONE", 1: "ET_REL (relocatable)", 2: "ET_EXEC (executable)",
    3: "ET_DYN (shared object / PIE)", 4: "ET_CORE",
}

MACHINES = {
    0x02: "SPARC", 0x03: "x86", 0x08: "MIPS", 0x0E: "HP-PA", 0x14: "PowerPC",
    0x15: "PowerPC64", 0x16: "S390", 0x28: "ARM", 0x2A: "SuperH",
    0x32: "IA-64", 0x3E: "x86-64", 0xB7: "AArch64", 0xF3: "RISC-V",
}

PT_TYPES = {
    1: "LOAD", 2: "DYNAMIC", 3: "INTERP", 4: "NOTE", 6: "PHDR", 7: "TLS",
    0x6474E550: "GNU_EH_FRAME", 0x6474E551: "GNU_STACK", 0x6474E552: "GNU_RELRO",
    0x6474E553: "GNU_PROPERTY",
}

DT_NAMES = {
    0: "DT_NULL", 1: "DT_NEEDED", 2: "DT_PLTRELSZ", 3: "DT_PLTGOT", 5: "DT_STRTAB",
    6: "DT_SYMTAB", 10: "DT_STRSZ", 11: "DT_SYMENT", 12: "DT_INIT", 13: "DT_FINI",
    14: "DT_SONAME", 15: "DT_RPATH", 16: "DT_SYMBOLIC", 17: "DT_REL", 18: "DT_RELSZ",
    20: "DT_PLTREL", 21: "DT_DEBUG", 22: "DT_TEXTREL", 23: "DT_JMPREL",
    24: "DT_BIND_NOW", 25: "DT_INIT_ARRAY", 26: "DT_FINI_ARRAY", 29: "DT_RUNPATH",
    30: "DT_FLAGS", 0x6FFFFEF5: "DT_GNU_HASH", 0x6FFFFFF0: "DT_VERSYM",
    0x6FFFFFF9: "DT_RELACOUNT", 0x6FFFFFFA: "DT_RELCOUNT",
}

BIND_NAMES = {0: "LOCAL", 1: "GLOBAL", 2: "WEAK"}
TYPE_NAMES = {0: "NOTYPE", 1: "OBJECT", 2: "FUNC", 3: "SECTION", 4: "FILE", 10: "IFUNC"}


class _Reader:
    def __init__(self, data: bytes):
        self.data = data

    def u8(self, off: int) -> int:
        return self.data[off]

    def u16(self, off: int, le: bool) -> int:
        return struct.unpack_from("<H" if le else ">H", self.data, off)[0]

    def u32(self, off: int, le: bool) -> int:
        return struct.unpack_from("<I" if le else ">I", self.data, off)[0]

    def u64(self, off: int, le: bool) -> int:
        return struct.unpack_from("<Q" if le else ">Q", self.data, off)[0]

    def bytes(self, off: int, n: int) -> bytes:
        return self.data[off : off + n]


def _read_cstr(r: _Reader, off: int, max_len: int = 4096) -> str:
    end = r.data.find(b"\x00", off, off + max_len)
    if end < 0:
        end = min(off + max_len, len(r.data))
    return r.data[off:end].decode("utf-8", "replace")


def parse_elf(path: str) -> dict:
    result: dict = {
        "ok": False, "kind": "ELF", "path": os.path.abspath(path),
        "warnings": [], "header": {}, "sections": [], "segments": [],
        "dynamic_deps": [], "dynamic_entries": [], "imports": [], "exports": [],
        "section_entropy": [], "notes": [], "build_id": None, "debug_link": None,
    }
    warnings = result["warnings"]

    size = os.path.getsize(path)
    if size < 52:
        warnings.append(f"File too small ({size} bytes) to be an ELF.")
        return result
    if size > 2 * 1024 * 1024 * 1024:
        warnings.append("File larger than 2 GiB; parsing first 2 GiB only.")
    try:
        with open(path, "rb") as fh:
            data = fh.read(2 * 1024 * 1024 * 1024)
    except OSError as exc:
        warnings.append(f"Read failed: {exc}")
        return result

    r = _Reader(data)
    if data[:4] != b"\x7fELF":
        warnings.append("Missing \\x7fELF magic.")
        return result

    ei_class = r.u8(4)
    ei_data = r.u8(5)
    if ei_class not in (1, 2):
        warnings.append(f"Invalid EI_CLASS {ei_class}.")
        return result
    if ei_data not in (1, 2):
        warnings.append(f"Invalid EI_DATA {ei_data}.")
        return result
    bits = 32 if ei_class == 1 else 64
    le = ei_data == 1
    result["header"] = {
        "bits": bits,
        "endianness": "little" if le else "big",
        "type": ET_NAMES.get(r.u16(16, le), str(r.u16(16, le))),
        "machine": MACHINES.get(r.u16(18, le), f"machine {r.u16(18, le)}"),
        "entry_point": hex(r.u64(24, le) if bits == 64 else r.u32(24, le)),
        "version": r.u8(6),
        "abi": r.u8(7),
    }

    def addr(fmt_off: int) -> int:
        return r.u64(fmt_off, le) if bits == 64 else r.u32(fmt_off, le)

    phoff = addr(32 if bits == 64 else 28)
    shoff = addr(40 if bits == 64 else 32)
    phentsize = r.u16(54 if bits == 64 else 42, le)
    phnum = r.u16(56 if bits == 64 else 44, le)
    shentsize = r.u16(58 if bits == 64 else 46, le)
    shnum = r.u16(60 if bits == 64 else 48, le)
    shstrndx = r.u16(62 if bits == 64 else 50, le)

    # ---- Program headers -------------------------------------------------
    if phnum and phentsize:
        if phoff + phnum * phentsize > len(data):
            warnings.append("Program header table extends beyond file; skipped.")
        else:
            for i in range(min(phnum, 512)):
                base = phoff + i * phentsize
                if bits == 64:
                    p_type = r.u32(base, le)
                    p_flags = r.u32(base + 4, le)
                    p_offset = r.u64(base + 8, le)
                    p_vaddr = r.u64(base + 16, le)
                    p_filesz = r.u64(base + 32, le)
                else:
                    p_type = r.u32(base, le)
                    p_offset = r.u32(base + 4, le)
                    p_vaddr = r.u32(base + 8, le)
                    p_filesz = r.u32(base + 16, le)
                    p_flags = r.u32(base + 24, le)
                result["segments"].append({
                    "type": PT_TYPES.get(p_type, hex(p_type)),
                    "offset": hex(p_offset),
                    "vaddr": hex(p_vaddr),
                    "filesz": p_filesz,
                    "flags": "".join([
                        "R" if p_flags & 4 else "-",
                        "W" if p_flags & 2 else "-",
                        "X" if p_flags & 1 else "-",
                    ]),
                })

    # ---- Section headers --------------------------------------------------
    shstrtab_off = 0
    shstrtab_size = 0
    raw_sections = []
    if shnum and shentsize:
        if shoff + shnum * shentsize > len(data):
            warnings.append("Section header table extends beyond file; truncated parse.")
            shnum = max(0, (len(data) - shoff) // shentsize)
        for i in range(min(shnum, 4096)):
            base = shoff + i * shentsize
            if bits == 64:
                (sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size,
                 sh_link, sh_info, sh_addralign, sh_entsize) = struct.unpack_from(
                    "<IIQQQQIIQQ" if le else ">IIQQQQIIQQ", data, base)
            else:
                (sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size,
                 sh_link, sh_info, sh_addralign, sh_entsize) = struct.unpack_from(
                    "<IIIIIIIIII" if le else ">IIIIIIIIII", data, base)
            raw_sections.append({
                "name_off": sh_name, "type": sh_type, "flags": sh_flags,
                "addr": sh_addr, "offset": sh_offset, "size": sh_size,
                "link": sh_link, "entsize": sh_entsize,
            })
        if 0 < shstrndx < len(raw_sections):
            s = raw_sections[shstrndx]
            if s["offset"] + s["size"] <= len(data):
                shstrtab_off, shstrtab_size = s["offset"], s["size"]
            else:
                warnings.append("Section-name string table out of range.")
        else:
            warnings.append("Invalid section-name string table index.")

        for s in raw_sections:
            if shstrtab_size and s["name_off"] < shstrtab_size:
                name = _read_cstr(r, shstrtab_off + s["name_off"], 256)
            else:
                name = f"section_{len(result['sections'])}"
            result["sections"].append({
                "name": name,
                "type": SHT_NAMES.get(s["type"], hex(s["type"])),
                "flags": "".join([
                    "W" if s["flags"] & 1 else "-",
                    "A" if s["flags"] & 2 else "-",
                    "X" if s["flags"] & 4 else "-",
                ]),
                "addr": hex(s["addr"]),
                "offset": hex(s["offset"]),
                "size": s["size"],
            })

    def section_by_name(name: str) -> dict | None:
        for idx, s in enumerate(raw_sections):
            if idx < len(result["sections"]) and result["sections"][idx].get("name") == name:
                return s
        return None

    # ---- Dynamic dependencies (DT_NEEDED) ---------------------------------
    dyn = section_by_name(".dynamic")
    dynstr = section_by_name(".dynstr")
    if dyn and dynstr and dynstr["offset"] + dynstr["size"] <= len(data):
        d_off, d_size, d_ent = dyn["offset"], dyn["size"], dyn["entsize"] or (16 if bits == 64 else 8)
        strtab_off, strtab_size = dynstr["offset"], dynstr["size"]
        for i in range(int(min(d_size // d_ent, 1024))):
            base = d_off + i * d_ent
            if base + d_ent > len(data):
                break
            if bits == 64:
                d_tag = r.u64(base, le)
                d_val = r.u64(base + 8, le)
            else:
                d_tag = r.u32(base, le)
                d_val = r.u32(base + 4, le)
            if d_tag == 0:
                break
            result["dynamic_entries"].append({
                "tag": DT_NAMES.get(d_tag, hex(d_tag)), "value": d_val,
            })
            if d_tag == 1 and d_val < strtab_size:
                result["dynamic_deps"].append(
                    _read_cstr(r, strtab_off + d_val, 1024))

    # ---- Symbols ------------------------------------------------------------
    def parse_symbols(sym_name: str, str_name: str) -> None:
        sym = section_by_name(sym_name)
        st = section_by_name(str_name)
        if not sym or not st:
            return
        if sym["offset"] + sym["size"] > len(data) or st["offset"] + st["size"] > len(data):
            warnings.append(f"{sym_name} or {str_name} out of range; skipped.")
            return
        ent = sym["entsize"] or (24 if bits == 64 else 16)
        count = sym["size"] // ent
        for i in range(min(count, 65536)):
            base = sym["offset"] + i * ent
            if bits == 64:
                st_name, st_info, _other, st_shndx = struct.unpack_from("<IBBH", data, base)
                st_value = r.u64(base + 8, le)
                st_size = r.u64(base + 16, le)
            else:
                st_name, st_value, st_size, st_info, _other, st_shndx = struct.unpack_from(
                    "<IIIBBH", data, base)
            bind = BIND_NAMES.get(st_info >> 4, str(st_info >> 4))
            typ = TYPE_NAMES.get(st_info & 0xF, str(st_info & 0xF))
            if st_name < st["size"]:
                name = _read_cstr(r, st["offset"] + st_name, 512)
            else:
                name = ""
            if not name:
                continue
            if st_shndx == 0 and st_value == 0 and bind in ("GLOBAL", "WEAK"):
                result["imports"].append({"name": name, "bind": bind, "type": typ})
            elif bind in ("GLOBAL", "WEAK") and st_shndx != 0:
                result["exports"].append({
                    "name": name, "bind": bind, "type": typ,
                    "value": hex(st_value), "size": st_size,
                })

    parse_symbols(".dynsym", ".dynstr")
    parse_symbols(".symtab", ".strtab")
    # de-duplicate imports/exports by name (symtab may repeat dynsym entries)
    seen_imports = set()
    uniq_imports = []
    for imp in result["imports"]:
        key = (imp["name"], imp["bind"])
        if key not in seen_imports:
            seen_imports.add(key)
            uniq_imports.append(imp)
    result["imports"] = uniq_imports
    seen_exports = set()
    uniq_exports = []
    for exp in result["exports"]:
        if exp["name"] not in seen_exports:
            seen_exports.add(exp["name"])
            uniq_exports.append(exp)
    result["exports"] = uniq_exports

    # ---- Section entropy ----------------------------------------------------
    for s, entry in zip(raw_sections, result["sections"]):
        if s["type"] in (8,):  # SHT_NOBITS has no file data
            continue
        if s["size"] == 0 or s["offset"] + s["size"] > len(data):
            continue
        blob = data[s["offset"] : s["offset"] + min(s["size"], READ_CHUNK * 4)]
        result["section_entropy"].append({
            "name": entry["name"], "size": s["size"],
            "entropy": shannon_entropy(blob),
        })

    # ---- Notes (.note.gnu.build-id etc.) + debug link ----------------------
    for idx, s in enumerate(raw_sections):
        if s["offset"] + s["size"] > len(data):
            continue
        sname = result["sections"][idx].get("name", "") if idx < len(result["sections"]) else ""
        if s["type"] == 7 or sname.startswith(".note"):  # SHT_NOTE
            blob = data[s["offset"]:s["offset"] + min(s["size"], 64 * 1024)]
            pos = 0
            while pos + 12 <= len(blob) and len(result["notes"]) < 64:
                namesz, descsz, ntype = struct.unpack_from("<III", blob, pos)
                pos += 12
                if namesz > 256 or descsz > 4096 or pos + namesz > len(blob):
                    break
                nname = blob[pos:pos + namesz].rstrip(b"\x00").decode(
                    "ascii", "replace")
                pos += (namesz + 3) & ~3
                desc = blob[pos:pos + descsz]
                pos += (descsz + 3) & ~3
                result["notes"].append({
                    "section": sname, "name": nname, "type": ntype,
                    "desc": desc[:256].hex(),
                })
                if nname == "GNU" and ntype == 3:  # NT_GNU_BUILD_ID
                    result["build_id"] = desc.hex()
        if sname == ".gnu_debuglink" and s["size"] >= 4:
            blob = data[s["offset"]:s["offset"] + min(s["size"], 4096)]
            nul = blob.find(b"\x00")
            if 0 < nul < 4096:
                crc_off = (nul + 1 + 3) & ~3
                crc = struct.unpack_from("<I", blob, crc_off)[0] \
                    if crc_off + 4 <= len(blob) else 0
                result["debug_link"] = {
                    "file": blob[:nul].decode("utf-8", "replace"),
                    "crc": f"{crc:#010x}",
                }

    result["ok"] = bool(result["header"]) and size >= 52
    result["file_size"] = size
    return result
