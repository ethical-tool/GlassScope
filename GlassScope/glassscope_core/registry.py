"""Windows registry hive parser (REGF format): header, hive bins, key tree,
value types (SZ/DWORD/QWORD/BINARY) — the standard forensic triage for
persistence locations, run keys, MRUs and autoruns.

Read-only and bounded: no writes, no imports, values capped in size.
"""

from __future__ import annotations

import struct

from .util import MAX_STREAM_READ

_HIVE_FLAGS = {
    0x1: "HIVE_BIN_SIGNATURE issues", 0x2: "always-flush flag",
    0x4: "hive being compacted", 0x8: "marked dirty",
    0x10: "track dirty pages", 0x20: "no lazy flushing",
}

_VALUE_TYPES = {
    0: "REG_NONE", 1: "REG_SZ", 2: "REG_EXPAND_SZ", 3: "REG_BINARY",
    4: "REG_DWORD (LE)", 5: "REG_DWORD (BE)", 6: "REG_LINK",
    7: "REG_MULTI_SZ", 8: "REG_RESOURCE_LIST", 9: "REG_FULL_DESC",
    10: "REG_RESOURCE_REQ", 11: "REG_QWORD",
}

_SIG = b"hive"


def parse_registry(path: str, max_keys: int = 20000) -> dict:
    """Parse a REGF hive: header, root key with recursive child walk."""
    out: dict = {"ok": False, "warnings": [], "errors": []}
    try:
        with open(path, "rb") as fh:
            data = fh.read(MAX_STREAM_READ)
    except OSError as exc:
        out["errors"].append(f"read failed: {exc}")
        return out
    if len(data) < 512 or data[:4] != _SIG:
        out["errors"].append("not a registry hive (missing 'hive' signature)")
        return out
    try:
        (sig, seq1, seq2, ts_lo, ts_hi, _maj, _min, ftype, file_size,
         checksum, _name) = struct.unpack_from("<4sIIQHHIIIIs", data, 0)
        out["header"] = {
            "sequence_numbers": [seq1, seq2],
            "last_modified": _filetime_to_str(ts_lo, ts_hi),
            "format_version": f"{_maj}.{_min}",
            "file_type": ftype,
            "hive_size": file_size,
            "checksum_ok": checksum == _regf_checksum(data),
            "hive_flags": [v for bit, v in _HIVE_FLAGS.items() if ftype & bit],
        }
    except struct.error as exc:
        out["errors"].append(f"corrupt hive header: {exc}")
        return out
    # find the root cell from the first hbin
    root_off = 0x1000  # first hive bin starts right after the base block
    keys: list[dict] = []
    values_seen = 0
    key_count = _walk_cells(data, root_off, depth=0, path_components=[],
                            keys=keys, max_keys=max_keys,
                            values_seen_ref=[values_seen])
    out["keys"] = keys
    out["key_count"] = len(keys)
    out["value_count"] = values_seen_ref[0] if "values_seen_ref" in locals() \
        else 0
    out["ok"] = True
    if out["key_count"] >= max_keys:
        out["warnings"].append(f"key walk capped at {max_keys}")
    return out


def _filetime_to_str(lo: int, hi: int) -> str:
    if not lo and not hi:
        return "unset"
    ts = ((hi << 32) | lo) - 116444736000000000
    if ts <= 0:
        return "invalid"
    secs = ts / 10_000_000
    from datetime import datetime, timezone

    try:
        return datetime.fromtimestamp(secs, timezone.utc).strftime(
            "%Y-%m-%d %H:%M:%S UTC")
    except (OverflowError, ValueError, OSError):
        return "invalid"


def _regf_checksum(data: bytes) -> int:
    """XOR-fold of the first 127 dwords (excluding the checksum field)."""
    total = 0
    for i in range(0, 508, 4):
        (dw,) = struct.unpack_from("<I", data, i)
        total ^= dw
    return total & 0xFFFFFFFF


def _walk_cells(data: bytes, hbin_off: int, depth: int,
                path_components: list[str], keys: list[dict],
                max_keys: int, values_seen_ref: list[int]) -> int:
    """Walk hive-bin cells from the root node, collecting keys+values."""
    if depth > 32 or len(keys) >= max_keys:
        return len(keys)
    if hbin_off + 0x30 > len(data):
        return len(keys)
    # root cell: skip the hbin header (36 bytes), read the cell
    cell_off = hbin_off + 0x20
    (cell_size_signed,) = struct.unpack_from("<i", data, cell_off)
    cell_size = abs(cell_size_signed)
    sig = data[cell_off + 4:cell_off + 6]
    if sig != b"nk":
        # try the first cell right after hbin header variants
        cell_off = hbin_off + 0x24
        (cell_size_signed,) = struct.unpack_from("<i", data, cell_off)
        sig = data[cell_off + 4:cell_off + 6]
        if sig != b"nk":
            return len(keys)
    pos = cell_off
    return _walk_nk(data, pos, path_components, keys, max_keys,
                    values_seen_ref, depth)


def _read_str(data: bytes, off: int, length: int) -> str:
    raw = data[off:off + length]
    if len(raw) >= 2 and raw[0] == 0:
        return raw.decode("utf-16-le", "replace")
    return raw.decode("latin-1", "replace").rstrip("\x00")


def _walk_nk(data: bytes, nk_off: int, path_components: list[str],
             keys: list[dict], max_keys: int, values_seen_ref: list[int],
             depth: int) -> int:
    if len(keys) >= max_keys or depth > 40:
        return len(keys)
    try:
        (cell_size_signed,) = struct.unpack_from("<i", data, nk_off)
        if data[nk_off + 4:nk_off + 6] != b"nk":
            return len(keys)
        (sig, _sz, _ts_lo, _ts_hi) = struct.unpack_from(
            "<2sHI I", data, nk_off + 4) if False else \
            struct.unpack_from("<2sHII", data, nk_off + 4)
        # layout: [size i4][sig 2][flags 2][parent 4][subkeys 4][sk 4]
        # [num_sub 4]? offsets vary — use the classic layout:
        _flags, parent_off, subkey_off, num_subkeys = struct.unpack_from(
            "<HIII", data, nk_off + 6)
        num_values, vallist_off = struct.unpack_from("<II", data,
                                                     nk_off + 0x1C)
        name_len = data[nk_off + 0x50]
        # name may be ASCII or UTF-16 (compressed bit 0x20)
        name_off = nk_off + 0x54
        if _flags & 0x20:  # compressed name → ASCII
            name = data[name_off:name_off + name_len].decode(
                "latin-1", "replace")
        else:
            name = _read_str(data, name_off, min(name_len, 512))
        path = "\\".join(path_components + [name])
        values = _read_values(data, nk_off, vallist_off, num_values,
                              values_seen_ref)
        keys.append({
            "path": path, "name": name, "flags": f"{_flags:#06x}",
            "num_subkeys": num_subkeys, "subkey_list_offset": subkey_off,
            "num_values": num_values, "values": values,
        })
        # recurse into subkey list
        if subkey_off and num_subkeys:
            subk = 0x1000 + subkey_off
            if subk + 8 <= len(data) and \
                    data[subk:subk + 2] in (b"lf", b"ri", b"lh", b"li"):
                count = struct.unpack_from("<H", data, subk + 6)[0]
                for i in range(min(count, 256)):
                    entry = subk + 8 + i * 8
                    if entry + 8 > len(data):
                        break
                    child_off = 0x1000 + struct.unpack_from(
                        "<I", data, entry)[0]
                    _walk_nk(data, child_off,
                             path_components + [name], keys, max_keys,
                             values_seen_ref, depth + 1)
            elif subk + 8 <= len(data) and data[subk:subk + 2] == b"nk":
                _walk_nk(data, subk, path_components + [name], keys,
                         max_keys, values_seen_ref, depth + 1)
    except (struct.error, ValueError, IndexError):
        pass
    return len(keys)


def _read_values(data: bytes, nk_off: int, vallist_off: int,
                 num_values: int, values_seen_ref: list[int]) -> list[dict]:
    """Read the value list + VK cells of one key."""
    values: list[dict] = []
    if not vallist_off or not num_values:
        return values
    base = 0x1000 + vallist_off
    try:
        for i in range(min(num_values, 128)):
            entry = base + i * 2
            if entry + 2 > len(data):
                break
            vk_rel = struct.unpack_from("<H", data, entry)[0]
            vk_off = 0x1000 + vk_rel
            if vk_off + 0x18 > len(data) or data[vk_off + 4:vk_off + 6] != \
                    b"vk":
                break
            name_len = data[vk_off + 0x10]
            data_len = struct.unpack_from("<i", data, vk_off + 0x04)[0]
            vtype = struct.unpack_from("<H", data, vk_off + 0x10 + 2)[0]
            name_off = vk_off + 0x14
            vname = (_read_str(data, name_off, min(name_len, 256)) or
                     f"(default #{i})") if name_len else f"(default #{i})"
            entry: dict = {"name": vname,
                           "type": _VALUE_TYPES.get(vtype, f"type{vtype}")}
            if 0 < data_len < 0x80000000:  # inline data or offset given
                if data_len <= 4:
                    entry["value"] = f"<inline {data_len} bytes>"
                else:
                    data_off = 0x1000 + struct.unpack_from(
                        "<I", data, vk_off + 0x11)[0]
                    raw = data[data_off:data_off + min(data_len, 256)]
                    if vtype == 4:
                        entry["value"] = struct.unpack_from(
                            "<I", raw[:4])[0] if len(raw) >= 4 else raw.hex()
                    elif vtype == 11:
                        entry["value"] = struct.unpack_from(
                            "<Q", raw[:8])[0] if len(raw) >= 8 else raw.hex()
                    else:
                        entry["value"] = _read_str(data, data_off,
                                                  min(data_len, 256))[:128]
            elif data_len == 0:
                entry["value"] = "(empty)"
            values.append(entry)
            values_seen_ref[0] += 1
    except (struct.error, ValueError, IndexError):
        pass
    return values
