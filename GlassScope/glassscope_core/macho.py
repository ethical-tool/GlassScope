"""Apple Mach-O parser: magic/endianness/arch, load commands, symbol table,
linked dylibs, segments/sections, code signature presence and universal
(fat) binaries — pure standard library, fully defensive.

Also provides a light IPA triage (zip listing + Info.plist keys + Mach-O
payload detection) so iOS app packages can be inspected without extra tools.
"""

from __future__ import annotations

import plistlib
import struct
import zipfile

from .util import MAX_STREAM_READ

MH_MAGICS = {
    0xFEEDFACE: "Mach-O 32-bit big-endian",
    0xFEEDFACF: "Mach-O 64-bit big-endian",
    0xCEFAEDFE: "Mach-O 32-bit little-endian",
    0xCFFAEDFE: "Mach-O 64-bit little-endian",
    0xCAFEBABE: "universal (fat) binary",
    0xBEBAFECA: "universal (fat, byte-swapped)",
}
CPU_TYPES = {
    1: "x86 (i386)",
    7: "x86-64",
    6: "Motorola 680x0",
    0x01000007: "x86-64 (64-bit flag)",
    12: "ARM",
    0x0100000C: "ARM64 (AArch64)",
    13: "ARM64_32",
    14: "PowerPC",
    0x0100000E: "PowerPC 64",
    5: "MC680x0",
    18: "SPARC",
}


def _cpu_name(cpu: int) -> str:
    """Match with the 64-bit ABI flag masked off, then mark it."""
    if cpu in CPU_TYPES:
        return CPU_TYPES[cpu]
    base = cpu & 0x00FFFFFF
    if cpu & 0x01000000 and base in CPU_TYPES:
        return CPU_TYPES[base] + " (64-bit)"
    return f"unknown ({cpu:#010x})"
LC_NAMES = {
    0x1: "LC_SEGMENT", 0x19: "LC_SEGMENT_64", 0x2: "LC_SYMTAB",
    0xB: "LC_DYSYMTAB", 0xE: "LC_LOAD_DYLIB", 0x1D: "LC_ID_DYLIB",
    0xC: "LC_UUID", 0x1E: "LC_CODE_SIGNATURE", 0x22: "LC_DYLD_INFO",
    0x2A: "LC_VERSION_MIN_MACOSX", 0x25: "LC_BUILD_VERSION",
    0x2C: "LC_FUNCTION_STARTS", 0x26: "LC_MAIN", 0x28: "LC_DATA_IN_CODE",
    0x29: "LC_SOURCE_VERSION", 0x2F: "LC_SEGMENT_SPLIT_INFO",
    0x32: "LC_ENCRYPTION_INFO", 0x21: "LC_LOAD_WEAK_DYLIB",
    0x18: "LC_LOAD_DYLINKER", 0x1A: "LC_ID_DYLINKER",
    0x8000001C: "LC_RPATH",
}
MH_FILETYPES = {
    1: "object", 2: "executable", 3: "dylib (shared library)",
    4: "core dump", 5: "preload", 6: "bundle",
    7: "dynamic linker", 8: "dylib stub", 9: "DSYM companion",
    10: "kext", 11: "generic", 12: "debug map",
}
MH_FLAGS = {
    0x1: "NOUNDEFS", 0x2: "INCRLINK", 0x4: "DYLDLINK", 0x8: "BINDATLOAD",
    0x10: "PREBOUND", 0x20: "SPLIT_SEGS", 0x40: "TWOLEVEL",
    0x80: "PIE", 0x100: "NO_HEAP_EXECUTION", 0x200: "HAS_TLV_DESCRIPTORS",
    0x400: "NO_REEXPORTED_DYLIBS", 0x800: "PIE | bit",
    0x200000: "ALLOW_STACK_EXECUTION",
}


def _endian_fmt(le: bool) -> str:
    return "<" if le else ">"


def parse_macho(path: str) -> dict:
    """Parse a Mach-O file (thin or universal)."""
    out: dict = {"ok": False, "warnings": [], "errors": []}
    try:
        with open(path, "rb") as fh:
            data = fh.read(MAX_STREAM_READ)
    except OSError as exc:
        out["errors"].append(f"read failed: {exc}")
        return out
    if len(data) < 16:
        out["errors"].append("file too small")
        return out
    magic_le = struct.unpack_from("<I", data, 0)[0]
    if magic_le in (0xCAFEBABE, 0xBEBAFECA):
        return _parse_fat(data)
    if magic_le in MH_MAGICS and magic_le in (
            0xCEFAEDFE, 0xCFFAEDFE, 0xFEEDFACE, 0xFEEDFACF):
        sub = _parse_thin(data)
        out.update({k: v for k, v in sub.items()
                    if k not in ("ok", "warnings", "errors")})
        out["warnings"] = sub.get("warnings", [])
        out["errors"] = sub.get("errors", [])
        out["ok"] = sub.get("ok", False)
        return out
    out["errors"].append(f"not a Mach-O file (magic {magic_le:#010x})")
    return out


def _parse_fat(data: bytes) -> dict:
    """Universal binary: list arch slices and parse the first one."""
    out: dict = {"ok": False, "universal": True, "warnings": [],
                 "errors": []}
    magic = struct.unpack_from(">I", data, 0)[0]
    if magic == 0xBEBAFECA:  # swapped variant
        out["warnings"].append("byte-swapped fat header")
    nfat = struct.unpack_from(">I", data, 4)[0]
    slices = []
    pos = 8
    for _ in range(min(nfat, 32)):
        if pos + 20 > len(data):
            out["warnings"].append("fat table truncated")
            break
        cpu, sub, offset, size, align = struct.unpack_from(">IIIII", data, pos)
        slices.append({
            "cpu_type": _cpu_name(cpu),
            "cpu_subtype": f"{sub & 0x00FFFFFF:#x}",
            "offset": offset, "size": size, "align": 1 << align,
        })
        pos += 20
    out["slices"] = slices
    out["slice_count"] = len(slices)
    if slices:
        first = slices[0]
        end = min(first["offset"] + first["size"], len(data))
        if first["offset"] < len(data):
            sub = _parse_thin(data[first["offset"]:end])
            if sub.get("ok"):
                out["first_slice"] = {k: v for k, v in sub.items()
                                      if k not in ("ok", "warnings",
                                                   "errors")}
                out["warnings"] += sub.get("warnings", [])
            else:
                out["warnings"] += sub.get("errors", [])
        else:
            out["warnings"].append("first slice offset beyond file")
    out["ok"] = True
    return out


def _parse_thin(data: bytes) -> dict:
    """Parse a thin Mach-O blob (one architecture)."""
    out: dict = {"ok": False, "warnings": [], "errors": []}
    if len(data) < 32:
        out["errors"].append("too small for a Mach-O header")
        return out
    magic = struct.unpack_from("<I", data, 0)[0]
    le = magic in (0xCEFAEDFE, 0xCFFAEDFE)
    be = magic in (0xFEEDFACE, 0xFEEDFACF)
    if not le and not be:
        out["errors"].append(f"unknown magic {magic:#010x}")
        return out
    bits64 = magic in (0xCFFAEDFE, 0xFEEDFACF)
    fmt = _endian_fmt(le)
    (magic2, cpu_type, cpu_sub, filetype, ncmds, sizeofcmds,
     flags) = struct.unpack_from(fmt + "7I", data, 0)
    out["header"] = {
        "magic": MH_MAGICS.get(magic, f"{magic:#010x}"),
        "endianness": "little" if le else "big",
        "bits": 64 if bits64 else 32,
        "cpu_type": _cpu_name(cpu_type),
        "cpu_subtype": f"{cpu_sub:#x}",
        "filetype": MH_FILETYPES.get(filetype, f"unknown ({filetype})"),
        "ncmds": ncmds, "sizeofcmds": sizeofcmds,
        "flags": [v for bit, v in MH_FLAGS.items() if flags & bit],
        "pie": bool(flags & 0x80) or bool(flags & 0x200),
    }
    out["dylibs"] = []
    out["segments"] = []
    out["sections"] = []
    out["load_commands"] = []
    out["has_code_signature"] = False
    out["uuid"] = None
    out["minos"] = None
    out["sdk"] = None
    out["platform"] = None

    pos = 32 if bits64 else 28
    for _ in range(min(ncmds, 512)):
        if pos + 8 > len(data):
            out["warnings"].append("load-command table truncated")
            break
        cmd, cmdsize = struct.unpack_from(fmt + "II", data, pos)
        name = LC_NAMES.get(cmd, f"LC_{cmd:#010x}")
        if cmdsize < 8 or pos + cmdsize > len(data):
            out["warnings"].append(f"{name}: bad size {cmdsize}")
            break
        out["load_commands"].append(name)
        try:
            if cmd in (0x19, 0x1):  # LC_SEGMENT_64 / LC_SEGMENT
                wide = cmd == 0x19
                segname = data[pos + 8:pos + 24].rstrip(b"\x00").decode(
                    "ascii", "replace")
                if wide:
                    vals = struct.unpack_from(fmt + "QQQQiiII", data, pos + 24)
                    vmaddr, vmsize, fileoff, filesize, _maxp, initp, nsects, \
                        sflags = vals
                    sect_hdr = 72
                    sect_size = 80
                else:
                    vals = struct.unpack_from(fmt + "IIIIiiII", data, pos + 24)
                    vmaddr, vmsize, fileoff, filesize, _maxp, initp, nsects, \
                        sflags = vals
                    sect_hdr = 56
                    sect_size = 68
                prot = {1: "execute", 2: "write", 4: "read"}
                out["segments"].append({
                    "name": segname, "vmaddr": f"{vmaddr:#x}",
                    "vmsize": vmsize, "fileoff": fileoff,
                    "filesize": filesize,
                    "initprot": "+".join(v for b, v in prot.items()
                                         if initp & b) or "none",
                    "nsects": nsects, "flags": f"{sflags:#x}",
                })
                spos = pos + sect_hdr
                for _s in range(min(nsects, 128)):
                    if spos + sect_size > len(data):
                        break
                    sect = data[spos:spos + 16].rstrip(b"\x00").decode(
                        "ascii", "replace")
                    seg = data[spos + 16:spos + 32].rstrip(b"\x00").decode(
                        "ascii", "replace")
                    out["sections"].append({
                        "section": sect, "segment": seg,
                        "addr": f"{struct.unpack_from(fmt + 'Q', data, spos + 32)[0]:#x}"
                        if wide else
                        f"{struct.unpack_from(fmt + 'I', data, spos + 32)[0]:#x}",
                    })
                    spos += sect_size
            elif cmd in (0xE, 0x1D):  # LC_LOAD_DYLIB / LC_ID_DYLIB
                name_off = struct.unpack_from(fmt + "I", data, pos + 8)[0]
                dylib = data[pos + name_off:pos + cmdsize].split(b"\x00")[0]
                out["dylibs"].append(dylib.decode("utf-8", "replace"))
            elif cmd == 0xC:  # LC_UUID
                raw = data[pos + 8:pos + 24]
                if len(raw) == 16:
                    out["uuid"] = "-".join((
                        raw[:4].hex(), raw[4:6].hex(), raw[6:8].hex(),
                        raw[8:10].hex(), raw[10:].hex()))
            elif cmd == 0x1E:  # LC_CODE_SIGNATURE
                out["has_code_signature"] = True
            elif cmd == 0x2A:  # LC_VERSION_MIN_MACOSX
                vers = struct.unpack_from(fmt + "I", data, pos + 8)[0]
                out["minos"] = (f"{(vers >> 16) & 0xFF}."
                                f"{(vers >> 8) & 0xFF}.{vers & 0xFF}")
            elif cmd == 0x25:  # LC_BUILD_VERSION
                platform = struct.unpack_from(fmt + "I", data, pos + 8)[0]
                mins = struct.unpack_from(fmt + "I", data, pos + 12)[0]
                sdk = struct.unpack_from(fmt + "I", data, pos + 16)[0]
                out["sdk"] = (f"{(sdk >> 16) & 0xFF}."
                              f"{(sdk >> 8) & 0xFF}.{sdk & 0xFF}")
                out["minos"] = (f"{(mins >> 16) & 0xFF}."
                                f"{(mins >> 8) & 0xFF}.{mins & 0xFF}")
                out["platform"] = {1: "macOS", 2: "iOS", 3: "tvOS",
                                   4: "watchOS"}.get(platform,
                                                f"unknown ({platform})")
            elif cmd == 0x2:  # LC_SYMTAB
                symoff, nsyms, stroff, strsize = struct.unpack_from(
                    fmt + "IIII", data, pos + 8)
                out["symbol_table"] = {"symoff": symoff, "nsyms": nsyms,
                                       "stroff": stroff, "strsize": strsize}
                out["nsyms"] = nsyms
            elif cmd == 0x22:  # LC_DYLD_INFO
                out["has_dyld_info"] = True
            elif cmd == 0x32:  # LC_ENCRYPTION_INFO
                out["encrypted"] = bool(
                    struct.unpack_from(fmt + "I", data, pos + 16)[0])
        except (struct.error, ValueError) as exc:
            out["warnings"].append(f"load-command parse issue: {exc}")
        pos += cmdsize
    out["dylib_count"] = len(out["dylibs"])
    out["segment_count"] = len(out["segments"])
    out["section_count"] = len(out["sections"])
    if not out["segments"]:
        out["warnings"].append("no LC_SEGMENT load commands found")
    out["ok"] = True
    return out


def ipa_info(path: str) -> dict:
    """IPA triage: zip listing, Info.plist keys, Mach-O payloads."""
    out: dict = {"ok": False, "warnings": [], "errors": []}
    if not zipfile.is_zipfile(path):
        out["errors"].append("not a zip/ipa container")
        return out
    try:
        with zipfile.ZipFile(path) as zf:
            names = zf.namelist()
            out["entries"] = len(names)
            out["frameworks"] = sum(1 for n in names
                                    if n.endswith(".dylib")
                                    or "/Frameworks/" in n)
            out["has_extension"] = any("/PlugIns/" in n for n in names)
            out["has_watch_app"] = any("/Watch/" in n for n in names)
            plist_name = next((n for n in names if n.endswith(".app/Info.plist")),
                             None)
            if plist_name is None:
                plist_name = next((n for n in names
                                   if n.endswith("Info.plist")), None)
            if plist_name:
                try:
                    plist = plistlib.loads(zf.read(plist_name))
                    keep = ("CFBundleIdentifier", "CFBundleDisplayName",
                            "CFBundleShortVersionString", "CFBundleVersion",
                            "MinimumOSVersion", "CFBundleExecutable",
                            "DTPlatformName", "UIRequiresFullScreen")
                    out["info_plist"] = {k: str(v) for k, v in plist.items()
                                         if k in keep}
                except (plistlib.InvalidFileException, KeyError):
                    out["warnings"].append("Info.plist unreadable")
            macho_payloads = 0
            for n in names[:400]:
                try:
                    with zf.open(n) as fh:
                        head = fh.read(4)
                except (zipfile.BadZipFile, OSError, RuntimeError):
                    continue
                if head[:4] in (b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe",
                                b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf"):
                    macho_payloads += 1
            out["macho_payloads"] = macho_payloads
            out["provisioning"] = any(
                n.endswith("embedded.mobileprovision") for n in names)
            out["ok"] = True
    except (zipfile.BadZipFile, OSError) as exc:
        out["errors"].append(f"zip open failed: {exc}")
    return out
