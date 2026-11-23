"""Document triage for reverse engineering: PDF, OLE (legacy .doc/.xls) and
OOXML (modern Office) — structure, metadata, embedded objects, JS macros,
launch actions, suspicious URI schemes and a risk verdict.

Static-only: nothing is rendered or executed; macros are listed, not run.
"""

from __future__ import annotations

import io
import re
import struct
import zipfile

from .util import MAX_STREAM_READ

_PDF_JS = re.compile(rb"/JavaScript|/JS\b|eval\(|this\.importDataObject|"
                     rb"app\.launchURL|Util\.printf")
_PDF_LAUNCH = re.compile(rb"/Launch|/OpenAction|/AA\b|/GoToR|/SubmitForm|"
                         rb"/URI\b")
_PDF_EMBED = re.compile(rb"/EmbeddedFile|/FileAttachment|/RichMedia|/XFA")
_URI_SCHEMES = re.compile(
    rb"(?i)\b(vbscript|javascript|file|resource|res|ms-msdt|search-ms|"
    rb"ms-officecmd|mhtml|hcp)\s*:")
_OLE_STG_NAMES = (
    b"WordDocument", b"Workbook", b"PowerPoint Document", b"VBA/",
    b"Macros/", b"_VBA_PROJECT", b"PROJECT", b"SummaryInformation",
    b"DocumentSummaryInformation", b"DigitalSignature",
)
_OLE_STG_PART = re.compile(rb"(?i)(vba|macro|module|thisdocument|"
                           rb"attribute\s+vb_name)")


def pdf_info(path: str) -> dict:
    """PDF structure triage: version, pages, xref state, JS/launch/embeds,
    metadata and a risk verdict."""
    out: dict = {"ok": False, "warnings": [], "errors": []}
    try:
        with open(path, "rb") as fh:
            data = fh.read(MAX_STREAM_READ)
    except OSError as exc:
        out["errors"].append(f"read failed: {exc}")
        return out
    if not data.startswith(b"%PDF-"):
        out["errors"].append("not a PDF")
        return out
    m = re.match(rb"%PDF-(\d\.\d)", data)
    out["pdf_version"] = m.group(1).decode() if m else "?"
    out["size"] = len(data)
    # count objects & streams
    out["objects"] = len(re.findall(rb"\d+ 0 obj", data))
    out["streams"] = len(re.findall(rb"\bstream\b", data))
    # page count via the /Type /Pages /Count entries
    counts = re.findall(rb"/Count\s+(\d+)", data)
    out["pages_hint"] = max(int(c) for c in counts) if counts else None
    # suspicious content
    js_hits = len(_PDF_JS.findall(data))
    launch_hits = len(_PDF_LAUNCH.findall(data))
    embed_hits = len(_PDF_EMBED.findall(data))
    out["javascript_hits"] = js_hits
    out["action_hits"] = launch_hits
    out["embedded_hits"] = embed_hits
    # URI schemes
    uri_hits = _URI_SCHEMES.findall(data)
    out["uri_scheme_hits"] = sorted({s.decode().lower() for s in uri_hits})
    # metadata
    for key in (b"/Title", b"/Author", b"/Producer", b"/Creator",
                b"/CreationDate", b"/ModDate"):
        m2 = re.search(re.escape(key) + rb"\s*\(([^)]{0,120})\)", data)
        if m2:
            out.setdefault("metadata", {})[key.decode()] = \
                m2.group(1).decode("utf-8", "replace")
    # xref / incremental updates
    out["startxref_count"] = len(re.findall(rb"startxref", data))
    out["eof_markers"] = len(re.findall(rb"%%EOF", data))
    if out["eof_markers"] > 1:
        out["warnings"].append(
            f"{out['eof_markers']} %%EOF markers — incremental updates or "
            "appended data (signature evasion trick)")
    if not data.rstrip().endswith(b"%%EOF"):
        out["warnings"].append("file does not end with %%EOF — trailing data")
    # encryption dictionary
    out["encrypted"] = bool(re.search(rb"/Encrypt\s+\d+\s+0\s+R", data))
    if out["encrypted"]:
        out["warnings"].append("encrypted PDF — content triage limited")
    # verdict
    risk = 0
    if js_hits:
        risk += 2
    if launch_hits:
        risk += 2
    if embed_hits:
        risk += 1
    if out.get("uri_scheme_hits"):
        risk += 1
    if out["startxref_count"] > 1:
        risk += 1
    out["risk_score"] = risk
    out["verdict"] = ("clean-looking" if risk == 0 else
                      "suspicious" if risk <= 2 else "high-risk")
    out["ok"] = True
    return out


def ole_info(path: str) -> dict:
    """OLE2 compound-document triage: streams, VBA macro presence,
    metadata and markers."""
    out: dict = {"ok": False, "warnings": [], "errors": []}
    try:
        with open(path, "rb") as fh:
            data = fh.read(MAX_STREAM_READ)
    except OSError as exc:
        out["errors"].append(f"read failed: {exc}")
        return out
    if len(data) < 512 or data[:8] != b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1":
        out["errors"].append("not an OLE2 compound document")
        return out
    sector_shift = struct.unpack_from("<H", data, 30)[0]
    mini_shift = struct.unpack_from("<H", data, 32)[0]
    out["sector_size"] = 1 << sector_shift
    out["mini_sector_size"] = 1 << mini_shift
    # fast name scan over the directory sector names area
    known = [n.decode() for n in _OLE_STG_NAMES
             if n in data]
    out["known_streams"] = known
    out["has_vba"] = any("VBA" in k or "Macro" in k or "PROJECT" == k
                         for k in known)
    macro_part_hits = len(_OLE_STG_PART.findall(data))
    out["vba_markers"] = macro_part_hits
    if out["has_vba"] or macro_part_hits:
        out["warnings"].append(
            "VBA/macro content detected — do not open in Office with "
            "macros enabled; extract with oletools for review")
    out["ok"] = True
    return out


def ooxml_info(path: str) -> dict:
    """OOXML (docx/xlsx/pptx) triage: zip parts, relationship targets,
    macro-enabled parts and external targets."""
    out: dict = {"ok": False, "warnings": [], "errors": []}
    if not zipfile.is_zipfile(path):
        out["errors"].append("not an OOXML (zip) container")
        return out
    try:
        with zipfile.ZipFile(path) as zf:
            names = zf.namelist()
            out["parts"] = len(names)
            out["content_types"] = "[Content_Types].xml" in names
            out["has_vba_project"] = any("vbaProject" in n for n in names)
            out["has_macros"] = any(
                n.endswith(("vbaData.xml", "vbaProject.bin",
                            "macroData.bin")) for n in names)
            media = [n for n in names if n.startswith("word/media/")
                     or n.startswith("xl/media/") or
                     n.startswith("ppt/media/")]
            out["media_files"] = len(media)
            out["embeddings"] = sum(
                1 for n in names if "embeddings/" in n)
            out["external_relationships"] = 0
            out["ole_objects"] = sum(1 for n in names
                                     if n.endswith((".bin", ".ole")))
            rels = [n for n in names if n.endswith(".rels")]
            for rel in rels[:40]:
                try:
                    content = zf.read(rel)
                except (zipfile.BadZipFile, RuntimeError):
                    continue
                if b"TargetMode=\"External\"" in content:
                    out["external_relationships"] += content.count(
                        b"TargetMode=\"External\"")
                out["ole_objects"] += content.count(
                    b"oleObject")
            if out["has_vba_project"] or out["has_macros"]:
                out["warnings"].append(
                    "macro-enabled OOXML document (vbaProject present)")
            if out["external_relationships"]:
                out["warnings"].append(
                    f"{out['external_relationships']} external relationship "
                    "targets (possible remote template/object injection)")
            out["ok"] = True
    except (zipfile.BadZipFile, OSError) as exc:
        out["errors"].append(f"zip open failed: {exc}")
    return out


def document_dispatch(path: str) -> dict:
    """Route a document by magic to the right triage parser."""
    try:
        with open(path, "rb") as fh:
            head = fh.read(8)
    except OSError as exc:
        return {"ok": False, "errors": [f"read failed: {exc}"]}
    if head.startswith(b"%PDF"):
        r = pdf_info(path)
        r["kind"] = "pdf"
    elif head == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1":
        r = ole_info(path)
        r["kind"] = "ole"
    else:
        r = ooxml_info(path)
        r["kind"] = "ooxml" if r.get("ok") else "unknown"
    return r
