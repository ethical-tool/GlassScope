"""Android & Java package analysis (REA `android` / `apkSignature` parity).

APK/JAR/AAB via zipfile: entry inventory, AndroidManifest.xml decoded from
Android binary XML (AXML) — package, version, SDK levels, permissions and
components — DEX header statistics, signature-file detection (v1 META-INF
plus the v2/v3 APK Signing Block) and Maven metadata hints. Pure stdlib,
defensive, bounded.
"""

from __future__ import annotations

import os
import struct
import zipfile

APK_SIG_BLOCK_MAGIC = b"APK Sig Block 42"
MAX_ZIP_READ = 64 * 1024 * 1024  # safety cap for a single entry read


# --- Android binary XML -------------------------------------------------------
def _parse_string_pool(data: bytes, off: int) -> tuple[list[str], int] | None:
    """Parse a ResStringPool at `off`; return (strings, next_offset)."""
    if off + 20 > len(data):
        return None
    ctype, hdr_size, size, str_count, style_count, flags, strs_start, _sty = \
        struct.unpack_from("<HHIIIIII", data, off)
    if ctype != 0x0001 or hdr_size < 28 or off + size > len(data):
        return None
    is_utf8 = bool(flags & 0x100)
    base = off + strs_start
    offsets = struct.unpack_from(f"<{str_count}I", data, off + hdr_size) \
        if str_count and off + hdr_size + 4 * str_count <= off + size else ()
    strings: list[str] = []
    for so in offsets:
        pos = base + so
        try:
            if is_utf8:
                if pos >= len(data):
                    strings.append("")
                    continue
                n = data[pos]
                pos += 1
                if n & 0x80:
                    n = ((n & 0x7F) << 8) | data[pos]
                    pos += 1
                raw = data[pos:pos + n]
                strings.append(raw.decode("utf-8", "replace"))
            else:
                if pos + 2 > len(data):
                    strings.append("")
                    continue
                n = struct.unpack_from("<H", data, pos)[0]
                pos += 2
                if n & 0x8000:
                    n2 = struct.unpack_from("<H", data, pos)[0]
                    pos += 2
                    n = ((n & 0x7FFF) << 16) | n2
                raw = data[pos:pos + 2 * n]
                strings.append(raw.decode("utf-16-le", "replace"))
        except (struct.error, UnicodeDecodeError):
            strings.append("")
    return strings, off + size


def _typed_value(data: bytes, pos: int) -> tuple[int, int, str]:
    """Return (data_type, data_value, raw_repr) of a Res_value."""
    size, _res0, dtype = struct.unpack_from("<HBB", data, pos)
    dval = struct.unpack_from("<I", data, pos + 4)[0]
    if size < 8:
        return 0, 0, ""
    return dtype, dval, ""


def parse_axml(data: bytes) -> dict:
    """Decode Android binary XML into a simple element tree summary."""
    out: dict = {"ok": False, "errors": [], "warnings": [], "strings": [],
                 "elements": []}
    if len(data) < 8:
        out["errors"].append("too small for AXML")
        return out
    ctype, hdr_size, size = struct.unpack_from("<HHI", data, 0)
    if ctype != 0x0003:
        out["errors"].append(f"not AXML (type {ctype:#06x})")
        return out
    if size > len(data):
        out["warnings"].append("declared size exceeds file")
        size = len(data)
    pos = hdr_size
    strings: list[str] = []
    depth = 0
    max_depth = 0
    aoff = pos  # keeps track of START_ELEMENT advance
    while pos + 8 <= size and len(out["elements"]) < 5000:
        ntype, _nh, _nsz, _line, _cmt = struct.unpack_from("<HHIII", data, pos)
        body = pos + 16
        if ntype == 0x0001:  # string pool
            parsed = _parse_string_pool(data, pos)
            if parsed is None:
                out["errors"].append("bad string pool")
                return out
            strings, pos = parsed
            out["strings"] = strings[:500]
            continue
        elif ntype == 0x0102 and body + 20 <= size:  # START_ELEMENT
            _ns, name, _astart, asize, acount, _id, _cls, _sty = \
                struct.unpack_from("<IIHHHHHH", data, body)
            tag = strings[name] if name < len(strings) else f"?{name}"
            attrs = []
            aoff = body + 20
            asize = max(20, asize if asize >= 20 else 20)
            for _ in range(min(acount, 64)):
                if aoff + 20 > size:
                    break
                _ans, aname, raw_i = struct.unpack_from("<III", data, aoff)
                dtype, dval = _typed_value(data, aoff + 12)[:2]
                raw = strings[raw_i] if 0 <= raw_i < len(strings) else ""
                an = strings[aname] if aname < len(strings) else f"?{aname}"
                if dtype == 0x03 and raw:          # STRING
                    val = raw
                elif dtype in (0x10, 0x11):        # INT_DEC / INT_HEX
                    val = str(dval)
                elif dtype == 0x12:                # INT_BOOL
                    val = "true" if dval else "false"
                elif dtype == 0x01:                # REFERENCE
                    val = f"@{dval:#010x}"
                else:
                    val = f"type={dtype:#x} data={dval:#x}"
                attrs.append({"name": an, "value": val})
                aoff += asize
            if depth == 0 or tag in ("uses-permission", "uses-sdk",
                                     "application", "instrumentation") or \
                    depth <= 2:
                out["elements"].append({"tag": tag, "attrs": attrs,
                                        "depth": depth})
            depth += 1
            max_depth = max(max_depth, depth)
            pos = aoff  # next chunk sits right after the attribute table
        elif ntype == 0x0103:  # END_ELEMENT
            depth = max(0, depth - 1)
            pos = body + 8  # node header + ns u32 + name u32
        elif ntype in (0x0100, 0x0101):  # START/END_NAMESPACE
            pos = body + 8
        elif ntype == 0x0104:  # CDATA
            pos = body + 4
        else:
            out["warnings"].append(f"unknown XML node type {ntype:#06x}; "
                                   "scan stopped early")
            break
    out["max_depth"] = max_depth
    out["ok"] = True
    return out


def _axml_element(axml: dict, tag: str) -> dict | None:
    for el in axml.get("elements", []):
        if el["tag"] == tag:
            return el
    return None


def _axml_children(axml: dict, tag: str) -> list[dict]:
    return [e for e in axml.get("elements", []) if e["tag"] == tag]


# --- APK / JAR ------------------------------------------------------------------
def apk_info(path: str) -> dict:
    out: dict = {"ok": False, "format": "apk", "kind": None, "entries": [],
                 "dex_files": [], "permissions": [], "components": [],
                 "signatures_v1": [], "signed_v2": None, "maven": [],
                 "manifest": {}, "warnings": [], "errors": []}
    try:
        with zipfile.ZipFile(path) as zf:
            names = zf.namelist()
            out["entry_count"] = len(names)
            out["entries"] = names[:300]
            out["uncompressed_total"] = sum(i.file_size for i in zf.infolist())
            out["dex_files"] = [n for n in names
                                if n == "classes.dex" or
                                (n.startswith("classes") and n.endswith(".dex"))]
            out["has_arsc"] = "resources.arsc" in names
            out["native_libs"] = [n for n in names if n.startswith("lib/")
                                  and n.endswith(".so")][:100]
            sig = [n for n in names if n.startswith("META-INF/") and
                   (n.endswith((".RSA", ".DSA", ".EC")) or
                    n == "META-INF/MANIFEST.MF")]
            out["signatures_v1"] = sig[:20]
            out["kind"] = "aab" if any(n.startswith(("base/", "split_"))
                                       for n in names) else "apk"
            # v2/v3 signing block: magic sits before the central directory
            try:
                size = os.path.getsize(path)
                with open(path, "rb") as fh:
                    fh.seek(max(0, size - 65536))
                    tail = fh.read()
                out["signed_v2"] = APK_SIG_BLOCK_MAGIC in tail
            except OSError:
                out["warnings"].append("could not scan tail for signing block")
            # manifest
            if "AndroidManifest.xml" in names:
                raw = zf.read("AndroidManifest.xml")
                axml = parse_axml(raw)
                if axml["ok"]:
                    man = _axml_element(axml, "manifest")
                    app = _axml_element(axml, "application")
                    sdk = _axml_element(axml, "uses-sdk")
                    attrmap = lambda el: {a["name"]: a["value"]
                                          for a in (el or {}).get("attrs", [])}
                    ma, aa = attrmap(man), attrmap(app)
                    out["manifest"] = {
                        "package": ma.get("package", ""),
                        "versionCode": ma.get("versionCode", ""),
                        "versionName": ma.get("versionName", ""),
                        "minSdk": attrmap(sdk).get("minSdkVersion", ""),
                        "targetSdk": attrmap(sdk).get("targetSdkVersion", ""),
                        "label": aa.get("label", ""),
                        "debuggable": aa.get("debuggable", "false"),
                        "allowBackup": aa.get("allowBackup", ""),
                    }
                    for p in _axml_children(axml, "uses-permission"):
                        pm = attrmap(p)
                        val = pm.get("android:name") or pm.get("name", "")
                        if val:
                            out["permissions"].append(val)
                    for tag in ("activity", "activity-alias", "service",
                                "receiver", "provider"):
                        for el in _axml_children(axml, tag):
                            cm = attrmap(el)
                            name = cm.get("android:name") or cm.get("name", "")
                            if name:
                                out["components"].append(
                                    {"type": tag, "name": name,
                                     "exported": cm.get("exported", "")})
                else:
                    out["errors"].extend(axml["errors"])
            # maven hints (REA inspect-maven-gradle-metadata parity)
            for n in names:
                if n.startswith("META-INF/maven/") and n.endswith("pom.properties"):
                    try:
                        for line in zf.read(n).decode("utf-8", "replace").splitlines():
                            k, _, v = line.partition("=")
                            if k in ("groupId", "artifactId", "version"):
                                out["maven"].append(f"{k}={v.strip()}")
                    except (OSError, KeyError):
                        continue
                    break
            out["ok"] = True
            return out
    except zipfile.BadZipFile:
        out["errors"].append("not a ZIP container")
        return out
    except (OSError, struct.error) as exc:
        out["errors"].append(f"parse failed: {exc}")
        return out


def dex_header(path: str, entry: str | None = None) -> dict:
    """DEX header stats, either a standalone .dex or an entry inside an APK."""
    out: dict = {"ok": False, "format": "dex", "warnings": [], "errors": []}
    try:
        if entry:
            with zipfile.ZipFile(path) as zf:
                data = zf.read(entry)
        else:
            with open(path, "rb") as fh:
                data = fh.read(112)
    except (OSError, zipfile.BadZipFile, KeyError) as exc:
        out["errors"].append(f"read failed: {exc}")
        return out
    if len(data) < 112 or data[:4] != b"dex\n":
        out["errors"].append("bad DEX magic")
        return out
    version = data[4:7].decode("ascii", "replace")
    (file_size, header_size, endian_tag, _link_size, _link_off, _map_off,
     string_ids, _string_off, type_ids, _type_off, proto_ids, _proto_off,
     field_ids, _field_off, method_ids, _method_off, class_defs, _class_off,
     data_size, _data_off) = struct.unpack_from("<20I", data, 32)
    out.update({"dex_version": version, "endian_tag": f"{endian_tag:#x}",
                "declared_size": file_size, "actual_entry_bytes": len(data),
                "string_ids": string_ids, "type_ids": type_ids,
                "proto_ids": proto_ids, "field_ids": field_ids,
                "method_ids": method_ids, "class_defs": class_defs,
                "data_size": data_size})
    if class_defs > 65535:
        out["warnings"].append(f"very high class count {class_defs}")
    out["ok"] = True
    return out


def jar_manifest(path: str) -> dict:
    out: dict = {"ok": False, "format": "jar", "main_class": None,
                 "attributes": {}, "signatures_v1": [], "warnings": [],
                 "errors": []}
    try:
        with zipfile.ZipFile(path) as zf:
            names = zf.namelist()
            if "META-INF/MANIFEST.MF" not in names:
                out["errors"].append("no META-INF/MANIFEST.MF (not a JAR?)")
                return out
            text = zf.read("META-INF/MANIFEST.MF").decode("utf-8", "replace")
            current: dict[str, str] = {}
            for line in text.splitlines():
                if line.startswith(" ") and current:
                    k = list(current)[-1]
                    current[k] += line[1:]
                    continue
                k, _, v = line.partition(":")
                if v:
                    current[k.strip()] = v.strip()
            out["main_class"] = current.get("Main-Class")
            out["attributes"] = {k: v for k, v in current.items()
                                 if k != "Main-Class"}
            out["signatures_v1"] = [n for n in names
                                    if n.startswith("META-INF/") and
                                    n.endswith((".SF", ".RSA", ".DSA", ".EC"))][:20]
            out["entry_count"] = len(names)
            out["ok"] = True
            return out
    except (OSError, zipfile.BadZipFile, KeyError) as exc:
        out["errors"].append(f"parse failed: {exc}")
        return out
