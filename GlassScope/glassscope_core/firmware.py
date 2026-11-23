"""Firmware & embedded-format parsers (REA `firmware` domain parity).

Pure-stdlib, defensive parsers for: flattened devicetree (DTB/FIT), U-Boot
legacy images, Espressif/ESP flash images, Apple IPS bundles, Godot PCK,
Erlang BEAM files, Deno/Bun standalone binaries, .NET single-file bundles and
kernel hints (banner + embedded IKCONFIG). Every parser returns
{"ok", ..., "warnings", "errors"} and never raises.
"""

from __future__ import annotations

import gzip
import io
import os
import struct
import xml.etree.ElementTree as ET
import zipfile

from .util import MAX_STREAM_READ

FDT_MAGIC = 0xD00DFEED
UBOOT_MAGIC = 0x27051956
PCK_MAGIC = b"GDPC"
DENO_MAGIC = b"d3n0landndm0d1e5"
BUN_MAGIC = b"------Bun!------"
BUNDLE_SIGNATURE = b".NET Core bundle"
IKCONFIG_MAGIC = b"IKCFG_ST"
TFLITE_MAGIC = b"TFL3"

FDT_TOKENS = {1: "BEGIN_NODE", 2: "END_NODE", 3: "PROP", 4: "NOP", 9: "END"}
UBOOT_OS = {1: "openbsd", 2: "netbsd", 3: "freebsd", 4: "4.4bsd", 5: "linux",
            8: "vxworks", 16: "plan9", 21: "efi"}
UBOOT_TYPE = {1: "standalone", 2: "kernel", 3: "ramdisk", 4: "multi",
              5: "firmware", 6: "script", 7: "filesystem", 8: "flat_dt",
              9: "kwbimage"}
UBOOT_COMP = {0: "none", 1: "gzip", 2: "bzip2", 3: "lzma", 4: "lzo",
              5: "lz4", 6: "zstd"}
UBOOT_ARCH = {2: "arm", 3: "i386", 5: "mips", 8: "powerpc"}


def _head(path: str, limit: int = MAX_STREAM_READ) -> bytes | None:
    try:
        with open(path, "rb") as fh:
            return fh.read(min(os.path.getsize(path), limit))
    except OSError:
        return None


# --- devicetree (DTB) / FIT ------------------------------------------------
def parse_dtb_bytes(path: str) -> dict:
    """Read a DTB file and parse it (convenience wrapper for the GUI zoo)."""
    data = _head(path, 16 * 1024 * 1024)
    if data is None:
        return {"ok": False, "format": "devicetree", "warnings": [],
                "errors": ["unreadable"]}
    return parse_dtb(data)


def parse_dtb(data: bytes, max_nodes: int = 4000) -> dict:
    out: dict = {"ok": False, "format": "devicetree", "version": None,
                 "last_comp_version": None, "total_size": None,
                 "root_properties": {}, "top_nodes": [], "node_count": 0,
                 "prop_count": 0, "max_depth": 0, "tree": [],
                 "memory_reservations": 0, "warnings": [], "errors": []}
    if len(data) < 40:
        out["errors"].append("too small for FDT header")
        return out
    magic, totalsize, off_struct, off_strings, off_rsv, version, last_comp = \
        struct.unpack_from(">7I", data, 0)
    if magic != FDT_MAGIC:
        out["errors"].append("bad FDT magic")
        return out
    out["version"], out["last_comp_version"] = version, last_comp
    out["total_size"] = totalsize
    if totalsize > len(data):
        out["warnings"].append(
            f"header claims {totalsize} bytes but file holds {len(data)}")
    if off_struct >= len(data) or off_strings > len(data):
        out["errors"].append("structure/strings offsets out of range")
        return out

    # memory reservation block (list of u64 pairs, terminated by 0,0)
    pos = off_rsv
    while pos + 16 <= min(off_struct, len(data)):
        start, size = struct.unpack_from(">QQ", data, pos)
        pos += 16
        if start == 0 and size == 0:
            break
        out["memory_reservations"] += 1

    strings = data[off_strings:]
    pos = off_struct
    depth = 0
    path_stack: list[str] = []
    node_count = 0
    prop_count = 0
    max_depth = 0
    tree: list[str] = []
    for _ in range(200000):
        if pos + 4 > len(data):
            out["warnings"].append("structure block truncated")
            break
        token = struct.unpack_from(">I", data, pos)[0]
        pos += 4
        if token == 9:  # END
            out["ok"] = True
            break
        elif token == 1:  # BEGIN_NODE
            end = data.find(b"\x00", pos)
            if end < 0:
                break
            name = data[pos:end].decode("utf-8", "replace")
            pos = (end + 4) & ~3
            path_stack.append(name)
            depth += 1
            max_depth = max(max_depth, depth)
            node_count += 1
            if depth <= 3:
                tree.append("/" + "/".join(p for p in path_stack if p))
            if node_count == 1:
                out["top_nodes"].append(name or "/")
        elif token == 2:  # END_NODE
            if path_stack:
                path_stack.pop()
            depth = max(0, depth - 1)
        elif token == 3:  # PROP
            if pos + 8 > len(data):
                break
            plen, nameoff = struct.unpack_from(">II", data, pos)
            pos += 8
            nend = strings.find(b"\x00", nameoff)
            pname = strings[nameoff:nend].decode("utf-8", "replace") \
                if 0 <= nameoff < len(strings) else "?"
            pval = data[pos:pos + min(plen, 256)]
            pos += plen
            pos = (pos + 3) & ~3
            prop_count += 1
            if depth <= 1:
                shown = pval.decode("utf-8", "replace") if len(pval) < 64 \
                    else f"<{len(pval)} bytes>"
                out["root_properties"][pname] = shown
            if node_count <= max_nodes:
                continue
        elif token == 4:  # NOP
            continue
        else:
            out["warnings"].append(f"unknown token {token:#x} at {pos - 4:#x}")
            break
    out["node_count"], out["prop_count"], out["max_depth"] = \
        node_count, prop_count, max_depth
    out["tree"] = tree[:200]
    return out


def fit_image_info(path: str) -> dict:
    """U-Boot FIT images are flattened devicetrees with /images nodes."""
    data = _head(path)
    if data is None:
        return {"ok": False, "format": "fit", "errors": ["unreadable"],
                "warnings": [], "errors_list": True}
    base = parse_dtb(data)
    out = {"format": "fit", "ok": base.get("ok", False),
           "errors": base.get("errors", []), "warnings": base.get("warnings", [])}
    out["header"] = {k: base[k] for k in
                     ("version", "last_comp_version", "total_size",
                      "node_count", "prop_count", "max_depth")}
    # scan tree for image nodes + configurations
    images: list[str] = []
    configs: list[str] = []
    for entry in base.get("tree", []):
        if entry.startswith("/images/"):
            images.append(entry[len("/images/"):])
        if entry.startswith("/configurations/"):
            configs.append(entry[len("/configurations/"):])
    out["images"], out["configurations"] = images[:50], configs[:50]
    if not images:
        out["errors"].append("no /images node — a plain devicetree, not a FIT")
        return out
    out["ok"] = True
    return out


# --- U-Boot legacy image -----------------------------------------------------
def uboot_legacy_info(path: str) -> dict:
    out: dict = {"ok": False, "format": "uboot-legacy", "warnings": [],
                 "errors": []}
    data = _head(path, 4096)
    if data is None or len(data) < 64:
        out["errors"].append("unreadable or smaller than 64-byte header")
        return out
    magic = struct.unpack_from(">I", data, 0)[0]
    if magic != UBOOT_MAGIC:
        out["errors"].append(f"bad U-Boot magic {magic:#010x}")
        return out
    hcrc, ts, size, load, ep, dcrc = struct.unpack_from(">6I", data, 4)
    os_, arch, typ, comp = struct.unpack_from("4B", data, 28)
    name = data[32:64].split(b"\x00")[0].decode("utf-8", "replace")
    out.update({"header_crc": f"{hcrc:#010x}", "timestamp": ts,
                "image_size": size, "load_address": f"{load:#010x}",
                "entry_point": f"{ep:#010x}", "data_crc": f"{dcrc:#010x}",
                "os": UBOOT_OS.get(os_, str(os_)),
                "arch": UBOOT_ARCH.get(arch, str(arch)),
                "type": UBOOT_TYPE.get(typ, str(typ)),
                "compression": UBOOT_COMP.get(comp, str(comp)),
                "image_name": name})
    # verify header CRC with the crc field zeroed (U-Boot uses zlib CRC32)
    import zlib
    zeroed = data[:4] + b"\x00\x00\x00\x00" + data[8:64]
    out["header_crc_ok"] = (zlib.crc32(zeroed) & 0xFFFFFFFF) == hcrc
    if not out["header_crc_ok"]:
        out["warnings"].append("header CRC mismatch (corrupt or patched header)")
    out["ok"] = True
    return out


def _crc32_table_byte(crc: int, byte: int) -> int:
    crc ^= byte << 24
    for _ in range(8):
        crc = ((crc << 1) ^ 0x04C11DB7) & 0xFFFFFFFF if crc & 0x80000000 \
            else (crc << 1) & 0xFFFFFFFF
    return crc


# --- Espressif / ESP flash image --------------------------------------------
def esp_image_info(path: str) -> dict:
    out: dict = {"ok": False, "format": "esp-image", "segments": [],
                 "warnings": [], "errors": []}
    data = _head(path, 1 * 1024 * 1024)
    if data is None or len(data) < 8:
        out["errors"].append("unreadable or too small")
        return out
    if data[0] != 0xE9:
        out["errors"].append(f"bad ESP magic byte {data[0]:#04x}")
        return out
    entry_count = data[1]   # esp_image_header_t: magic, segment_count,
    out["entry_count"] = entry_count  # flash_mode, flash_size_freq, entry(4)
    out["flash_config"] = (f"mode={data[2]:#04x} "
                           f"size_freq={data[3]:#04x}")
    out["entry_address"] = f"{struct.unpack_from('<I', data, 4)[0]:#010x}"
    if entry_count > 16:
        out["errors"].append(f"implausible segment count {entry_count}")
        return out
    pos = 8 + 8 * entry_count
    if pos > len(data):
        out["warnings"].append("segment table runs past available bytes")
        out["ok"] = True
        return out
    for i in range(entry_count):
        load, length = struct.unpack_from("<II", data, 8 + 8 * i)
        out["segments"].append(
            {"index": i, "load": f"{load:#010x}", "length": length,
             "file_offset": 8 + 8 * entry_count
             + (sum(s["length"] for s in out["segments"]))})
    seg0_start = 8 + 8 * entry_count
    if entry_count and seg0_start + 0x24 <= len(data):
        app_magic = struct.unpack_from("<I", data, seg0_start + 0x20)[0]
        if app_magic == 0xABCD5432:
            out["app_descriptor"] = True
            ver, proj_id = struct.unpack_from("<II", data, seg0_start + 0x24)
            out["app_version"] = ver
    if entry_count == 3:
        out["warnings"].append("3 segments: typical bootloader layout")
    out["ok"] = True
    return out


# --- Apple IPS ---------------------------------------------------------------
def apple_ips_info(path: str) -> dict:
    out: dict = {"ok": False, "format": "apple-ips", "entries": [],
                 "manifest": {}, "warnings": [], "errors": []}
    try:
        with zipfile.ZipFile(path) as zf:
            names = zf.namelist()
            out["entries"] = names[:100]
            out["entry_count"] = len(names)
            if not any(n.endswith((".plist", ".ipsw", ".bbfw.dmg")) or
                       n == "manifest.plist" for n in names):
                out["errors"].append(
                    "zip lacks IPS markers (manifest.plist / .ipsw assets)")
                return out
            if "manifest.plist" not in names:
                out["warnings"].append("no manifest.plist entry")
            else:
                raw = zf.read("manifest.plist")
                if raw.startswith(b"bplist"):
                    out["warnings"].append("binary plist manifest not decoded")
                else:
                    root = ET.fromstring(raw)
                    for d in root.iter("dict"):
                        keys = [k.text for k in d.findall("key")]
                        vals = d.findall("string")
                        if len(vals) >= len(keys) and len(keys) >= 3:
                            for i, k in enumerate(keys):
                                if k in ("DeviceClass", "ProductType",
                                         "ProductVersion", "Build"):
                                    out["manifest"][k] = vals[i].text or ""
                            break
            total = sum(i.file_size for i in zf.infolist())
            out["uncompressed_total"] = total
            out["ok"] = True
            return out
    except zipfile.BadZipFile:
        out["errors"].append("not a ZIP container (IPS must be zip)")
        return out
    except (OSError, ET.ParseError, KeyError) as exc:
        out["errors"].append(f"parse failed: {exc}")
        return out


# --- Godot PCK ----------------------------------------------------------------
def godot_pck_info(path: str, embedded: bool = False) -> dict:
    out: dict = {"ok": False, "format": "godot-pck", "files": [],
                 "warnings": [], "errors": []}
    data = _head(path)
    if data is None:
        out["errors"].append("unreadable")
        return out
    idx = 0
    if embedded:
        idx = data.find(PCK_MAGIC)
        if idx < 0:
            out["errors"].append("no GDPC magic in first 8 MiB")
            return out
    elif not data.startswith(PCK_MAGIC):
        out["errors"].append("bad GDPC magic at offset 0")
        return out
    pos = idx + 4
    try:
        fmt_ver, godot_major, godot_minor, godot_patch = \
            struct.unpack_from("<4I", data, pos)
        pos += 16
        out.update({"pack_format_version": fmt_ver,
                    "godot_version": f"{godot_major}.{godot_minor}.{godot_patch}"})
        if fmt_ver >= 2:
            out["pack_flags"] = struct.unpack_from("<I", data, pos)[0]
            pos += 4
            out["file_base"] = struct.unpack_from("<Q", data, pos)[0]
            pos += 8
        pos += 16 * 4  # reserved
        count = struct.unpack_from("<I", data, pos)[0]
        pos += 4
        if count > 100000:
            out["errors"].append(f"implausible file count {count}")
            return out
        size = os.path.getsize(path)
        for _ in range(min(count, 2000)):
            plen = struct.unpack_from("<I", data, pos)[0]
            pos += 4
            if plen > 4096 or pos + plen > len(data):
                out["warnings"].append("entry table truncated")
                break
            fpath = data[pos:pos + plen].rstrip(b"\x00").decode("utf-8", "replace")
            pos += plen
            if fmt_ver >= 2:
                off, fsize = struct.unpack_from("<QQ", data, pos)
                pos += 16
            else:
                off, fsize = struct.unpack_from("<II", data, pos)
                pos += 8
            md5 = data[pos:pos + 16].hex()
            pos += 16
            if off > size or fsize > size:
                out["warnings"].append(f"entry {fpath} out of bounds")
            out["files"].append({"path": fpath, "offset": off,
                                 "size": fsize, "md5": md5})
        out["file_count"] = count
        out["ok"] = True
        return out
    except (struct.error, KeyError) as exc:
        out["errors"].append(f"parse failed: {exc}")
        return out


# --- Erlang BEAM ---------------------------------------------------------------
def beam_info(path: str) -> dict:
    out: dict = {"ok": False, "format": "erlang-beam", "chunks": [],
                 "warnings": [], "errors": []}
    data = _head(path, 4 * 1024 * 1024)
    if data is None or len(data) < 12:
        out["errors"].append("unreadable or too small")
        return out
    if data[:4] != b"FOR1" or data[8:12] != b"BEAM":
        out["errors"].append("bad FOR1/BEAM signature")
        return out
    out["declared_size"] = struct.unpack_from(">I", data, 4)[0]
    pos = 12
    while pos + 8 <= len(data) and len(out["chunks"]) < 64:
        cname = data[pos:pos + 4].decode("ascii", "replace")
        csize = struct.unpack_from(">I", data, pos + 4)[0]
        out["chunks"].append({"name": cname, "size": csize})
        pos += 8 + csize + (csize & 1)
        if csize > len(data):
            out["warnings"].append(f"chunk {cname} size overruns file")
            break
    names = {c["name"] for c in out["chunks"]}
    out["has_code"] = "Code" in names
    out["has_atoms"] = ("Atom" in names) or ("AtU8" in names)
    out["ok"] = True
    return out


# --- Deno / Bun standalone ------------------------------------------------------
def deno_bun_info(path: str) -> dict:
    out: dict = {"ok": False, "format": None, "warnings": [], "errors": []}
    try:
        size = os.path.getsize(path)
        with open(path, "rb") as fh:
            fh.seek(max(0, size - 4096))
            tail = fh.read()
    except OSError as exc:
        out["errors"].append(f"read failed: {exc}")
        return out
    di = tail.rfind(DENO_MAGIC)
    bi = tail.rfind(BUN_MAGIC)
    if di >= 0:
        out["format"] = "deno-standalone"
        after = tail[di + len(DENO_MAGIC): di + len(DENO_MAGIC) + 24]
        if len(after) >= 24:
            eszip_sz, meta_sz, npm_sz = struct.unpack_from("<QQQ", after, 0)
            out["eszip_size"], out["metadata_size"] = eszip_sz, meta_sz
            out["npm_snapshot_size"] = npm_sz
        out["ok"] = True
    if bi >= 0 and out["format"] is None:
        out["format"] = "bun-standalone"
        before = tail[max(0, bi - 16):bi]
        if len(before) == 16:
            a, b = struct.unpack_from("<QQ", before, 0)
            out["modules_offset"], out["modules_trailer"] = a, b
        out["ok"] = True
    if out["format"] is None:
        out["errors"].append("no Deno/Bun standalone trailer found in tail")
    return out


# --- .NET single-file bundle -----------------------------------------------------
def dotnet_bundle_info(path: str) -> dict:
    out: dict = {"ok": False, "format": "dotnet-bundle", "files": [],
                 "warnings": [], "errors": []}
    data = _head(path, 8 * 1024 * 1024)
    if data is None:
        out["errors"].append("unreadable (first 8 MiB)")
        return out
    idx = data.find(BUNDLE_SIGNATURE)
    if idx < 0:
        out["errors"].append("bundle signature not found")
        return out
    pos = idx + len(BUNDLE_SIGNATURE)
    try:
        major, minor = struct.unpack_from("<II", data, pos)
        pos += 8
        count = struct.unpack_from("<i", data, pos)[0]
        pos += 4
        if not (0 <= count <= 100000):
            out["errors"].append(f"implausible bundle file count {count}")
            return out
        out["bundle_version"] = f"{major}.{minor}"
        out["file_count"] = count
        size = os.path.getsize(path)
        for _ in range(min(count, 1000)):
            off, fsize = struct.unpack_from("<qq", data, pos)
            pos += 16
            ftype = data[pos] if pos < len(data) else -1
            pos += 1
            plen = struct.unpack_from("<i", data, pos)[0]
            pos += 4
            if plen < 0 or plen > 2048 or pos + plen > len(data):
                out["warnings"].append("bundle entry table truncated")
                break
            fpath = data[pos:pos + plen].decode("utf-8", "replace")
            pos += plen
            if not (0 <= off <= size and 0 <= fsize <= size):
                out["warnings"].append(f"entry {fpath} out of bounds")
            out["files"].append({"path": fpath, "offset": off,
                                 "size": fsize, "type": ftype})
        out["ok"] = True
        return out
    except struct.error as exc:
        out["errors"].append(f"parse failed: {exc}")
        return out


# --- kernel hints -----------------------------------------------------------------
def kernel_hints(path: str) -> dict:
    out: dict = {"ok": False, "format": "kernel-hints", "banner": None,
                 "embedded_config": False, "config_lines": 0,
                 "config_sample": [], "warnings": [], "errors": []}
    try:
        size = os.path.getsize(path)
        with open(path, "rb") as fh:
            head = fh.read(min(size, 256 * 1024))
            fh.seek(max(0, size - 64 * 1024))
            tail = fh.read()
    except OSError as exc:
        out["errors"].append(f"read failed: {exc}")
        return out
    for blob in (head, tail):
        idx = blob.find(b"Linux version ")
        if idx >= 0:
            end = blob.find(b"\x00", idx)
            out["banner"] = blob[idx: end if 0 <= end else idx + 160].decode(
                "utf-8", "replace")[:160]
            break
    blob = head if IKCONFIG_MAGIC in head else (tail if IKCONFIG_MAGIC in tail else None)
    if blob is not None:
        start = blob.find(IKCONFIG_MAGIC) + len(IKCONFIG_MAGIC)
        try:
            raw = gzip.decompress(blob[start:start + 4 * 1024 * 1024])
            text = raw[:256 * 1024].decode("utf-8", "replace")
            lines = [l for l in text.splitlines()
                     if l.startswith("CONFIG_") and "=" in l]
            out["embedded_config"] = True
            out["config_lines"] = len(lines)
            out["config_sample"] = lines[:40]
        except (OSError, ValueError) as exc:
            out["warnings"].append(f"IKCONFIG present but decompress failed: {exc}")
    out["ok"] = True
    return out
