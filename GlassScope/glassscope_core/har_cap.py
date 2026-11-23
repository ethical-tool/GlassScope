"""Network capture analysis: HAR files and pcap (REA `pcap`/captures parity).

HAR (HTTP Archive JSON) gets domain/status/timing/security analysis. Raw
pcap gets header, packet and IPv4 host enumeration (bounded, heuristic HTTP
Host extraction). Pure stdlib; both handlers are defensive.
"""

from __future__ import annotations

import json
import os
import struct
from collections import Counter

from .util import MAX_STREAM_READ

SECURITY_HEADERS = ["strict-transport-security", "content-security-policy",
                    "x-content-type-options", "x-frame-options"]


def har_info(path: str, max_entries: int = 5000) -> dict:
    out: dict = {"ok": False, "format": "har", "warnings": [], "errors": []}
    try:
        size = os.path.getsize(path)
        if size > 256 * 1024 * 1024:
            out["warnings"].append("HAR larger than 256 MiB; entries capped")
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            doc = json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        out["errors"].append(f"parse failed: {exc}")
        return out
    log = doc.get("log")
    if not isinstance(log, dict):
        out["errors"].append("missing log object")
        return out
    entries = log.get("entries") or []
    out["creator"] = str(log.get("creator", {}).get("name", "")) \
        if isinstance(log.get("creator"), dict) else ""
    out["entry_count"] = len(entries)
    domains: Counter = Counter()
    statuses: Counter = Counter()
    methods: Counter = Counter()
    mimes: Counter = Counter()
    missing_headers: Counter = Counter()
    slow = []
    cookie_events = 0
    insecure = 0
    for e in entries[:max_entries]:
        try:
            req = e.get("request", {})
            resp = e.get("response", {})
            url = str(req.get("url", ""))
            host = ""
            if "://" in url:
                try:
                    host = url.split("://", 1)[1].split("/", 1)[0]
                except (IndexError, ValueError):
                    host = ""
            domains[host] += 1
            methods[str(req.get("method", "?"))] += 1
            status = int(resp.get("status") or 0)
            statuses[str(status)] += 1
            if url.startswith("http://"):
                insecure += 1
            hdrs = {str(h.get("name", "")).lower(): str(h.get("value", ""))
                    for h in resp.get("headers", []) if isinstance(h, dict)}
            for hname in SECURITY_HEADERS:
                if hname not in hdrs:
                    missing_headers[hname] += 1
            cookie_events += int(bool(hdrs.get("set-cookie"))) + \
                int(any(str(h.get("name", "")).lower() == "cookie"
                        for h in req.get("headers", []) if isinstance(h, dict)))
            cm = (resp.get("content") or {})
            mimes[str(cm.get("mimeType", "?"))[:40]] += 1
            t = e.get("time")
            if isinstance(t, (int, float)):
                slow.append({"url": url[:160], "ms": round(t, 1),
                             "status": status})
        except (AttributeError, TypeError, ValueError):
            continue
    slow.sort(key=lambda x: -x["ms"])
    out.update({
        "domains": [{"host": h, "count": c} for h, c in domains.most_common(20)],
        "status_distribution": dict(statuses),
        "methods": dict(methods),
        "mime_types": [{"mime": m, "count": c} for m, c in mimes.most_common(12)],
        "missing_security_headers": dict(missing_headers),
        "cookie_events": cookie_events,
        "plain_http_entries": insecure,
        "slowest": slow[:10],
        "sampled": min(len(entries), max_entries),
    })
    out["ok"] = True
    return out


_LINKTYPES = {1: "Ethernet", 101: "Raw IP", 12: "Raw IP", 113: "Linux SLL",
              228: "IPv4", 229: "IPv6"}


def pcap_info(path: str, max_packets: int = 50000) -> dict:
    out: dict = {"ok": False, "format": "pcap", "hosts": [], "warnings": [],
                 "errors": []}
    try:
        size = os.path.getsize(path)
        with open(path, "rb") as fh:
            data = fh.read(min(size, MAX_STREAM_READ))
    except OSError as exc:
        out["errors"].append(f"read failed: {exc}")
        return out
    if len(data) < 24:
        out["errors"].append("too small for pcap global header")
        return out
    magic = data[:4]
    if magic == b"\x0a\x0d\x0d\x0a":
        out["format"] = "pcapng"
        out["ok"] = True
        out["warnings"].append("pcapng container: section-level stats only")
        out["packet_count"] = data.count(b"\x06\x00\x00\x00") // 1
        return out
    if magic in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4"):
        endian = "<" if magic == b"\xd4\xc3\xb2\xa1" else ">"
    elif magic in (b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d"):
        endian = "<" if magic == b"\x4d\x3c\xb2\xa1" else ">"
    else:
        out["errors"].append("bad pcap magic")
        return out
    vmaj, vmin, _tz, _sig, snaplen, linktype = struct.unpack_from(
        endian + "HHiIII", data, 4)
    out["version"] = f"{vmaj}.{vmin}"
    out["snaplen"], out["linktype"] = snaplen, linktype
    out["linktype_name"] = _LINKTYPES.get(linktype, str(linktype))
    hosts: Counter = Counter()
    http_hosts: Counter = Counter()
    count = 0
    truncated = False
    pos = 24
    eth = linktype == 1
    while pos + 16 <= len(data) and count < max_packets:
        ts_sec, ts_usec, incl, orig = struct.unpack_from(endian + "IIII",
                                                         data, pos)
        pos += 16
        if incl > 262144 or pos + incl > len(data):
            truncated = True
            break
        pkt = data[pos:pos + incl]
        pos += incl
        count += 1
        if eth and len(pkt) >= 34 and pkt[12:14] == b"\x08\x00":
            ihl = (pkt[14] & 0x0F) * 4
            if 20 <= ihl <= 60 and len(pkt) >= 14 + ihl:
                src = ".".join(str(b) for b in pkt[26:30])
                dst = ".".join(str(b) for b in pkt[30:34])
                hosts[src] += 1
                hosts[dst] += 1
                hidx = pkt.find(b"Host: ")
                if 0 < hidx < 200:
                    hend = pkt.find(b"\r\n", hidx)
                    if hend > hidx:
                        http_hosts[pkt[hidx + 6:hend].decode(
                            "ascii", "replace")[:80]] += 1
    out["packet_count"] = count
    out["hosts"] = [{"ip": h, "packets": c} for h, c in hosts.most_common(20)]
    out["http_hosts"] = [{"host": h, "count": c}
                         for h, c in http_hosts.most_common(20)]
    if truncated:
        out["warnings"].append("capture truncated at scan limit "
                               "(increase limit or export smaller pcap)")
    if count == 0:
        out["warnings"].append("no packets parsed")
    out["ok"] = True
    return out
