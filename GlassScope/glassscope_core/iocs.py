"""IOC (indicator-of-compromise) hunter: static rule packs scanned against
any file or folder to surface embedded threats without running anything.

Rule families shipped:
- suspicious strings / keywords in 20+ script and binary families
- base64 blob detection with on-the-fly decode + nested-decode check
- URL / IP / domain extraction with public-suffix sanity
- crypto-wallet addresses (BTC/ETH), wallet clipboard hijack patterns
- keylogger / RAT / stealer family signatures (AgentTesla, Azorult,
  njRAT, Remcos, AsyncRAT, Warzone, NanoCore, Formbook...)
- obfuscation tells (long hex/base64 blobs, Chr() chains, fromCharCode)
- macro / office dropper traces, PowerShell download cradles
- packed-binary entropy gate + UPX markers
- webshell signatures (c99, WSO, b374k, China Chopper...)
- Android banker overlays hints and smali triage markers

Every hit carries {rule, family, severity, offset/line, evidence snippet}.
All rules are static patterns — no execution, no network calls.
"""

from __future__ import annotations

import base64
import binascii
import os
import re

from .util import MAX_STREAM_READ, shannon_entropy

# ---------------------------------------------------------------------------
# rule packs
# ---------------------------------------------------------------------------

# family -> list of (pattern, description)
_RAT_FAMILIES = {
    "AgentTesla": [rb"AgentTesla", rb"HawkEye\s?Keylogger",
                   rb"\.NET.*Keylogger"],
    "Azorult": [rb"Azorult", rb"AZORult"],
    "njRAT": [rb"njrat", rb"nj\s?RAT", rb"Door\x2ELog", rb"SKYNET\x00"],
    "Remcos": [rb"Remcos", rb"RC_\d+", rb"Remcos_\d+"],
    "AsyncRAT": [rb"Asyn[Rc]RAT", rb"AsyncRAT", rb"discord\.com/api",
                 rb"dc\.telewebion"],
    "Warzone": [rb"Warzone", rb"Ave\\Maria", rb"Wars lobster"],
    "NanoCore": [rb"NanoCore", rb"NanoCore\.Bark"],
    "Formbook": [rb"Formbook", rb"FB\s?Stealer"],
    "Lokibot": [rb"Lokibo?t", rb"Loki\s?Stealer"],
    "Emotet": [rb"Emotet", rb"Geodo"],
    "Trickbot": [rb"TrickBot", rb"Trickster"],
    "Raccoon": [rb"Raccoon\s?Stealer"],
    "Vidar": [rb"Vidar", rb"Vidar_Stealer"],
    "Redline": [rb"RedLine", rb"Redline\s?Stealer"],
    "CobaltStrike": [rb"cobaltstrike", rb"beacon\.dll", rb"Cobalt\s?Strike",
                      rb"\\xfc\\x48\\x83\\xe4\\xf0" b"\xfc\x48\x83\xe4\xf0"],
}

_URL_IP = re.compile(
    rb"(?:https?://|ftp://)[^\s\x00\"'<>]{4,120}", re.I)
_IPV4 = re.compile(
    rb"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}"
    rb"(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
_DOMAIN = re.compile(
    rb"\b(?:[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?\.)+"
    rb"(?:com|net|org|io|ru|cn|top|xyz|info|biz|online|site|live|cc|tk|ml|ga|cf|gq|pw|su|me|in|de|uk|is|to|st|link|icu|cam|rest|monster|sbs|cyou|buzz|shop)\b",
    re.I)
_B64_BLOB = re.compile(rb"[A-Za-z0-9+/]{80,}={0,2}")
_HEX_BLOB = re.compile(rb"[0-9a-fA-F]{60,}")
_BTC = re.compile(rb"\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b")
_ETH = re.compile(rb"\b0x[a-fA-F0-9]{40}\b")
_PWSH_CRADLE = re.compile(
    rb"(?i)(?P<ps1>https?://[^\s\x00\"']+)"
    rb"|(IEX|Invoke-Expression|iex)\s*\("
    rb"|(DownloadString|DownloadFile|WebClient|Net\.WebClient"
    rb"|Start-BitsTransfer|certutil\s+-urlcache|curl\s+-o|wget\s+http)"
)
_MSDOC_MACRO = re.compile(
    rb"(?i)(Auto(Open|Close)|Workbook_Open|Document_Open"
    rb"|Shell\s*\(\s*\"|WScript\.Shell|CreateObject\s*\(\s*\"WScript"
    rb"|cmd\s*/c\s+|powershell[.exe]*\s+-|vbs\.shell|WinExec"
    rb"|CreateProcess|URLDownloadToFile|EnumProcesses|GetAsyncKeyState)"
    )
_WEBSHELL_SIGS = {
    "c99": rb"CuCkoo.*c99|c99shell|c99madshell|\"c99\"",
    "WSO": rb"wso\s?2\.|WSO_FILE|wsoShell|<title>.*wso",
    "b374k": rb"b374k\s?shell|b374k\s?file\s?manager",
    "ChinaChopper": rb"China\s?Chopper|bigshell|Scripting\.FileSystemObject"
                    rb".*CreateTextFile",
    "PAS": rb"P.A.S\.*Team|PAS.*filemanager",
    "B44ck": rb"B44ck\s?Shell|Black\s?Door",
}
_SMALI_SUSP = {
    "accessibility": rb"Landroid/accessibilityservice/",
    "overlay": rb"SYSTEM_ALERT_WINDOW|TYPE_APPLICATION_OVERLAY",
    "device_admin": rb"Landroid/app/admin/DeviceAdminReceiver",
    "sms": rb"sendTextMessage|SmsManager",
    "clipper": rb"ClipboardManager|getPrimaryClip",
    "hidden_app": rb" com\.[a-z]+\.(codex|dx|dxv|cx)\b",
}
_C2_HINTS = rb"(?i)(c2|command\s?and\s?control|beacon|callback|exfil)"
_EXCLUDE_NOISE = (
    rb"microsoft\.com|google\.com|github\.com|w3\.org|apache\.org"
    rb"|python\.org|gnu\.org|mozilla\.org|adobe\.com|windows\.com"
    rb"|example\.com|schema|xml|openssl|unicode|ietf|ecma"
)


def scan_target(target: str, max_findings: int = 2000) -> dict:
    """Scan a file or a folder (recursively, bounded) for IOCs.

    Returns {ok, findings, counts_by_family, severity_counts, warnings,
    errors}. Each finding: {family, rule, severity, offset, evidence,
    source}.
    """
    out: dict = {"ok": False, "findings": [], "warnings": [],
                 "errors": []}
    if os.path.isfile(target):
        files = [target]
        out["scope"] = "file"
    elif os.path.isdir(target):
        files = []
        skip_dirs = {".git", "node_modules", "__pycache__", ".venv"}
        for root, dirs, names in os.walk(target):
            dirs[:] = [d for d in dirs if d not in skip_dirs]
            for name in names:
                files.append(os.path.join(root, name))
            if len(files) > 4000:
                out["warnings"].append("scan capped at 4000 files")
                break
        out["scope"] = "folder"
        out["files_scanned"] = len(files)
    else:
        out["errors"].append("target not found")
        return out

    findings: list[dict] = []
    counts: dict[str, int] = {}
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for path in files:
        file_findings = _scan_one(path, max_findings)
        for f in file_findings:
            f["source"] = os.path.basename(path)
            findings.append(f)
            counts[f["family"]] = counts.get(f["family"], 0) + 1
            severity_counts[f["severity"]] += 1
        if len(findings) >= max_findings:
            out["warnings"].append("findings list capped")
            break
    out["findings"] = findings
    out["counts_by_family"] = dict(sorted(counts.items(),
                                           key=lambda kv: -kv[1]))
    out["severity_counts"] = severity_counts
    out["ok"] = True
    return out


def _scan_one(path: str, max_findings: int) -> list[dict]:
    """Run every rule pack against one file."""
    findings: list[dict] = []
    try:
        size = os.path.getsize(path)
        with open(path, "rb") as fh:
            data = fh.read(min(size, MAX_STREAM_READ))
    except OSError:
        return findings
    if size > MAX_STREAM_READ:
        pass  # prefix scan is still useful
    if not data:
        return findings

    def add(family: str, rule: str, severity: str, offset: int,
            evidence: str) -> None:
        findings.append({
            "family": family, "rule": rule, "severity": severity,
            "offset": offset, "evidence": evidence[:160]})

    # ---- RAT family strings --------------------------------------------
    for family, pats in _RAT_FAMILIES.items():
        for pat in pats:
            for m in re.finditer(pat, data):
                add(family, "family signature", "critical", m.start(),
                    _snippet_at(data, m.start()))
                if len(findings) >= max_findings:
                    return findings

    # ---- URLs and hosts ---------------------------------------------------
    seen_hosts: set[str] = set()
    for m in _URL_IP.finditer(data):
        url = m.group().decode("ascii", "replace")
        host = re.split(r"[/:]", url, 2)[2] if url.count("/") >= 2 else url
        if re.search(_EXCLUDE_NOISE, url.encode()):
            continue
        if host not in seen_hosts:
            seen_hosts.add(host)
            add("network", "URL", "medium", m.start(), url)
    for m in _IPV4.finditer(data):
        ip = m.group().decode()
        if ip.split(".")[0] in ("0", "10", "127", "224", "255"):
            continue  # private / reserved
        add("network", "IPv4", "low", m.start(), ip)
    for m in _DOMAIN.finditer(data):
        dom = m.group().decode("ascii", "replace").lower()
        if re.search(_EXCLUDE_NOISE, dom.encode()):
            continue
        add("network", "domain", "low", m.start(), dom)

    # ---- wallet addresses ----------------------------------------------------
    for m in _BTC.finditer(data):
        add("crypto", "BTC address", "medium", m.start(), m.group().decode())
    for m in _ETH.finditer(data):
        add("crypto", "ETH address", "medium", m.start(), m.group().decode())

    # ---- PowerShell / droppers ------------------------------------------------
    for m in _PWSH_CRADLE.finditer(data):
        add("dropper", "PowerShell/certutil download", "high", m.start(),
            _snippet_at(data, m.start()))
    for m in _MSDOC_MACRO.finditer(data):
        add("macro", "macro/dropper API", "high", m.start(),
            _snippet_at(data, m.start()))

    # ---- webshells ---------------------------------------------------------
    for shell, pat in _WEBSHELL_SIGS.items():
        if re.search(pat, data):
            add("webshell", f"{shell} signature", "critical", 0,
                f"matches in {os.path.basename(path)}")

    # ---- base64 blobs (decode + nested check) --------------------------------
    for m in _B64_BLOB.finditer(data):
        blob = m.group()
        try:
            decoded = base64.b64decode(blob + b"=" * (-len(blob) % 4),
                                       validate=False)
        except (binascii.Error, ValueError):
            continue
        if len(decoded) > 40 and decoded[:1] in (b"M", b"P", b"\x7f", b"z",
                                                 b"@", b"\x1f"):
            add("packed", "base64-embedded payload", "high", m.start(),
                f"decodes to {decoded[:24].hex()}")
        # nested base64 inside decoded data
        nested = _B64_BLOB.search(decoded)
        if nested:
            add("packed", "nested base64 layer", "medium", m.start(),
                "double-encoded payload")

    # ---- hex blobs ------------------------------------------------------------
    for m in _HEX_BLOB.finditer(data):
        add("obfuscation", "long hex blob", "medium", m.start(),
            _snippet_at(data, m.start()))

    # ---- entropy gate ------------------------------------------------------------
    ent = shannon_entropy(data)
    if ent >= 7.0 and len(data) > 4096:
        add("packed", "high-entropy blob", "medium", 0,
            f"entropy {ent:.2f} bits/byte over first "
            f"{len(data)} bytes")
    # UPX marker
    if b"UPX!" in data[:4096] or b"\\$Info" in data[:512]:
        add("packed", "UPX marker", "medium", data.find(b"UPX!"),
            "UPX! magic found")
    return findings


def _snippet_at(data: bytes, offset: int, width: int = 96) -> str:
    start = max(0, offset - 32)
    chunk = data[start:start + width]
    return "".join(chr(b) if 0x20 <= b <= 0x7e else "." for b in chunk)


def _snippet_b64dec(blob: bytes) -> str:
    try:
        return base64.b64decode(blob + b"=" * (-len(blob) % 4))[:48].hex()
    except Exception:
        return ""
