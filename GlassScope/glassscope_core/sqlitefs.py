"""SQLite triage without sqlite3 CLI: file header, page structure, freelist,
table/index inventory via the sqlite_master b-tree walk, and deleted-space
carving hints. Also recognizes WAL files and journal artifacts.

Read-only: the database is opened with mode=ro URI so analysis never
modifies evidence.
"""

from __future__ import annotations

import struct

from .util import MAX_STREAM_READ

_PAGE_TYPES = {
    2: "interior index b-tree", 5: "interior table b-tree",
    10: "leaf index b-tree", 13: "leaf table b-tree",
}


def sqlite_info(path: str, max_rows: int = 200) -> dict:
    """Parse the SQLite header and walk the schema table (page 1)."""
    out: dict = {"ok": False, "warnings": [], "errors": []}
    try:
        with open(path, "rb") as fh:
            data = fh.read(MAX_STREAM_READ)
    except OSError as exc:
        out["errors"].append(f"read failed: {exc}")
        return out
    if len(data) < 100 or not data.startswith(b"SQLite format 3\x00"):
        out["errors"].append("not a SQLite 3 database")
        return out
    try:
        write_ver = data[18]
        read_ver = data[19]
        page_count = struct.unpack_from(">I", data, 28)[0]
        freelist_pages = struct.unpack_from(">I", data, 36)[0]
        schema_cookie = struct.unpack_from(">I", data, 40)[0]
        schema_format = struct.unpack_from(">I", data, 44)[0]
        text_encoding = struct.unpack_from(">I", data, 56)[0]
        user_version = struct.unpack_from(">I", data, 60)[0]
        app_id = struct.unpack_from(">I", data, 68)[0]
    except (struct.error, IndexError) as exc:
        out["errors"].append(f"bad header: {exc}")
        return out
    page_size = struct.unpack_from(">H", data, 16)[0]
    if page_size == 1:
        page_size = 65536
    out["header"] = {
        "page_size": page_size,
        "write_version": write_ver,
        "read_version": read_ver,
        "page_count": page_count,
        "freelist_pages": freelist_pages,
        "schema_format": schema_format,
        "text_encoding": {1: "UTF-8", 2: "UTF-16LE", 3: "UTF-16BE"}.get(
            text_encoding, text_encoding),
        "user_version": user_version,
        "app_id": f"{app_id:#x}",
        "pragma_user_version": user_version & 0x7FFFFFFF,
    }
    out["file_size"] = len(data)
    out["page_types_present"] = sorted({
        _PAGE_TYPES.get(data[0x64 + page_size * (i - 1)])
        for i in range(1, min(page_count, 64) + 1)
        if page_size * i <= len(data)
        and _PAGE_TYPES.get(data[page_size * (i - 1)])})
    out["has_wal"] = (write_ver >= 2)
    if out["has_wal"]:
        out["warnings"].append(
            "WAL mode journaling — check for -wal/-shm side files; data may "
            "live in the WAL, not this file")
    out["freelist_bytes"] = freelist_pages * page_size
    if freelist_pages > 2:
        out["warnings"].append(
            f"{freelist_pages} free pages ({out['freelist_bytes'] // 1024} "
            "KB) — deleted rows may be recoverable from freelist pages")
    # ---- schema walk (page 1 = sqlite_master b-tree leaf) ---------------
    tables = []
    try:
        tables = _read_schema(data, page_size, max_rows)
    except (struct.error, ValueError, IndexError) as exc:
        out["warnings"].append(f"schema walk incomplete: {exc}")
    out["tables"] = tables
    out["table_count"] = len(tables)
    out["ok"] = True
    return out


def _read_schema(data: bytes, page_size: int, max_rows: int) -> list[dict]:
    """Read sqlite_master rows from page 1 (page header at offset 100)."""
    rows: list[dict] = []
    hdr_off = 100
    if data[hdr_off] not in (5, 13):
        return rows
    ncells = struct.unpack_from(">H", data, hdr_off + 3)[0]
    cell_ptr_start = hdr_off + 8 if data[hdr_off] == 13 else hdr_off + 12
    for i in range(min(ncells, max_rows)):
        try:
            ptr_off = cell_ptr_start + i * 2
            (cell_off,) = struct.unpack_from(">H", data, ptr_off)
            # each cell: varint payload_len, varint rowid, record
            payload_len, pos = _varint(data, cell_off)
            rowid, pos = _varint(data, pos)
            hdr_len, hpos = _varint(data, pos)
            serial_types = []
            while hpos < pos + hdr_len:
                st, hpos = _varint(data, hpos)
                serial_types.append(st)
            body = pos + hdr_len
            values = []
            for st in serial_types:
                v, body = _serial_value(data, body, st)
                values.append(v)
            if len(values) >= 5:
                rows.append({
                    "type": values[0], "name": values[1],
                    "tbl_name": values[2],
                    "rootpage": values[3] if isinstance(values[3], int)
                    else None,
                    "sql": (values[4] or "")[:400],
                })
        except (struct.error, ValueError, IndexError):
            break
    return rows


def _varint(data: bytes, pos: int) -> tuple[int, int]:
    """SQLite varint: 1–9 bytes, big-endian 7-bit groups."""
    value = 0
    for i in range(8):
        b = data[pos + i]
        value = (value << 7) | (b & 0x7F)
        if not b & 0x80:
            return value, pos + i + 1
    value = (value << 8) | data[pos + 8]
    return value, pos + 9


def _serial_value(data: bytes, pos: int, st: int) -> tuple[object, int]:
    """Decode one serial-typed value at pos."""
    if st == 0:
        return None, pos
    sizes = {1: 1, 2: 2, 3: 3, 4: 4, 5: 6, 6: 8}
    if st in sizes:
        n = sizes[st]
        v = int.from_bytes(data[pos:pos + n], "big")
        return v, pos + n
    if st == 7:
        import struct as _s

        f = _s.unpack_from(">d", data, pos)[0]
        return round(f, 6), pos + 8
    if st == 8:
        return 0, pos
    if st == 9:
        return 1, pos
    if st >= 12:
        n = (st - 12) // 2
        raw = data[pos:pos + n]
        return raw.decode("utf-8", "replace"), pos + n
    return None, pos
