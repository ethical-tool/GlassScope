"""Java .class parser (JVM class-file format): constant pool with real
string values (so class/method/field names read like source), access flags,
fields, methods with descriptors, attributes (LineNumberTable, SourceFile,
InnerClasses, BootstrapMethods) and a fast decompile-style member listing.

Pairs with android.py (which covers APK/JAR containers) — this module goes
deep on one .class file, e.g. extracted by the carve engine.
"""

from __future__ import annotations

import struct

from .util import MAX_STREAM_READ

ACC_PUBLIC = 0x0001
ACC_CLASS_FLAGS = {
    0x0001: "public", 0x0010: "final", 0x0020: "super",
    0x0200: "interface", 0x0400: "abstract", 0x1000: "synthetic",
    0x2000: "annotation", 0x4000: "enum", 0x8000: "module",
}
ACC_MEMBER_FLAGS = {
    0x0001: "public", 0x0002: "private", 0x0004: "protected",
    0x0008: "static", 0x0010: "final", 0x0020: "synchronized",
    0x0040: "volatile|bridge", 0x0080: "transient|varargs",
    0x0100: "native", 0x0400: "abstract", 0x0800: "strictfp",
    0x1000: "synthetic",
}

_CONST_TAGS = {
    1: "Utf8", 3: "Integer", 4: "Float", 5: "Long", 6: "Double",
    7: "Class", 8: "String", 9: "Fieldref", 10: "Methodref",
    11: "InterfaceMethodref", 12: "NameAndType", 15: "MethodHandle",
    16: "MethodType", 17: "Dynamic", 18: "InvokeDynamic", 19: "Module",
    20: "Package",
}


class _ClsReader:
    def __init__(self, data: bytes):
        self.d = data
        self.pos = 0

    def u1(self) -> int | None:
        if self.pos + 1 > len(self.d):
            return None
        v = self.d[self.pos]
        self.pos += 1
        return v

    def u2(self) -> int | None:
        if self.pos + 2 > len(self.d):
            return None
        v = struct.unpack_from(">H", self.d, self.pos)[0]
        self.pos += 2
        return v

    def u4(self) -> int | None:
        if self.pos + 4 > len(self.d):
            return None
        v = struct.unpack_from(">I", self.d, self.pos)[0]
        self.pos += 4
        return v

    def bytes_(self, n: int) -> bytes | None:
        if self.pos + n > len(self.d):
            return None
        v = self.d[self.pos:self.pos + n]
        self.pos += n
        return v

    def cstr(self, n: int) -> str:
        raw = self.d[self.pos:self.pos + n]
        self.pos += n
        return raw.decode("utf-8", "replace")


def parse_class(path: str) -> dict:
    """Full .class parse. Returns header, fields, methods, attributes and a
    constant-pool sample with resolved names."""
    out: dict = {"ok": False, "warnings": [], "errors": []}
    try:
        with open(path, "rb") as fh:
            data = fh.read(MAX_STREAM_READ)
    except OSError as exc:
        out["errors"].append(f"read failed: {exc}")
        return out
    if len(data) < 10 or data[:4] != b"\xca\xfe\xba\xbe":
        out["errors"].append("not a Java class file (missing cafebabe magic)")
        return out
    r = _ClsReader(data)
    try:
        r.pos = 8  # skip magic + versions
        cpool_size = r.u2()
        # ---- constant pool --------------------------------------------------
        pool: dict[int, dict] = {}
        i = 1
        long_skip = False
        while i < cpool_size:
            if long_skip:
                long_skip = False
                i += 1
                continue
            tag = r.u1()
            if tag is None:
                out["warnings"].append("constant pool truncated")
                break
            entry: dict = {"tag": _CONST_TAGS.get(tag, f"tag{tag}")}
            if tag == 1:  # Utf8
                n = r.u2()
                if n is None:
                    break
                entry["value"] = r.cstr(n)
            elif tag in (3, 4):  # Integer/Float
                r.pos += 4
            elif tag in (5, 6):  # Long/Double — take two slots
                r.pos += 8
                long_skip = True
            elif tag == 7 or tag == 8 or tag == 19 or tag == 20:
                entry["index"] = r.u2()
            elif tag in (9, 10, 11):  # refs
                entry["class_index"] = r.u2()
                entry["nat_index"] = r.u2()
            elif tag == 12:  # NameAndType
                entry["name_index"] = r.u2()
                entry["desc_index"] = r.u2()
            elif tag == 15:  # MethodHandle
                r.pos += 3
            elif tag == 16:  # MethodType
                r.pos += 2
            elif tag in (17, 18):  # Dynamic / InvokeDynamic
                r.pos += 4
            else:
                out["warnings"].append(f"unknown constant tag {tag} at #{i}")
                break
            pool[i] = entry
            i += 1
        out["constant_pool_count"] = cpool_size

        def utf(idx: int) -> str:
            e = pool.get(idx, {})
            return e.get("value", "") if e.get("tag") == "Utf8" else ""

        def resolve_class(idx: int) -> str:
            e = pool.get(idx, {})
            if e.get("tag") == "Class":
                return utf(e.get("index", 0)).replace("/", ".").lstrip("[")
            return "?"

        # ---- access / this / super --------------------------------------
        access = r.u2() or 0
        this_idx = r.u2() or 0
        super_idx = r.u2() or 0
        out["class"] = {
            "name": resolve_class(this_idx),
            "super": resolve_class(super_idx),
            "flags": [v for bit, v in ACC_CLASS_FLAGS.items()
                      if access & bit],
            "raw_flags": f"{access:#06x}",
        }
        # ---- interfaces -----------------------------------------------------
        ifcount = r.u2() or 0
        out["interfaces"] = [resolve_class(r.u2() or 0)
                             for _ in range(min(ifcount, 64))]

        # ---- fields / methods -----------------------------------------------
        def members(kind: str) -> list[dict]:
            count = r.u2() or 0
            items = []
            for _ in range(min(count, 500)):
                f_access = r.u2() or 0
                f_name = utf(r.u2() or 0)
                f_desc = utf(r.u2() or 0)
                attr_count = r.u2() or 0
                attrs = []
                for _a in range(min(attr_count, 24)):
                    a_name = utf(r.u2() or 0)
                    a_len = r.u4() or 0
                    if a_name == "LineNumberTable" and a_len >= 2:
                        ln_count = struct.unpack_from(
                            ">H", r.d, r.pos)[0]
                        attrs.append({"name": a_name, "lines": ln_count})
                    else:
                        attrs.append({"name": a_name, "len": a_len})
                    r.pos += a_len
                items.append({
                    "kind": kind,
                    "flags": [v for bit, v in ACC_MEMBER_FLAGS.items()
                              if f_access & bit],
                    "name": f_name, "descriptor": f_desc,
                    "attributes": attrs,
                })
            return items

        out["fields"] = members("field")
        out["methods"] = members("method")
        out["field_count"] = len(out["fields"])
        out["method_count"] = len(out["methods"])

        # ---- class attributes ---------------------------------------------
        cattrs = []
        attr_count = r.u2() or 0
        for _ in range(min(attr_count, 32)):
            a_name = utf(r.u2() or 0)
            a_len = r.u4() or 0
            keep = None
            if a_name == "SourceFile" and a_len >= 2:
                keep = {"name": a_name,
                        "value": utf(struct.unpack_from(">H", r.d, r.pos)[0])}
            elif a_name == "InnerClasses" and a_len >= 2:
                inner_count = struct.unpack_from(">H", r.d, r.pos)[0]
                keep = {"name": a_name, "classes": inner_count}
            elif a_name == "BootstrapMethods" and a_len >= 2:
                bm_count = struct.unpack_from(">H", r.d, r.pos)[0]
                keep = {"name": a_name, "methods": bm_count}
            else:
                keep = {"name": a_name, "len": a_len}
            cattrs.append(keep)
            r.pos += a_len
        out["class_attributes"] = cattrs

        # ---- decompile-style signature ---------------------------------------
        flags_s = " ".join(out["class"]["flags"])
        out["signature"] = (f"{flags_s} class {out['class']['name']} "
                            f"extends {out['class']['super']}"
                            + (f" implements {', '.join(out['interfaces'])}"
                               if out.get("interfaces") else ""))
        out["ok"] = True
    except (struct.error, ValueError, IndexError) as exc:
        out["errors"].append(f"corrupt class structure: {exc}")
    return out
