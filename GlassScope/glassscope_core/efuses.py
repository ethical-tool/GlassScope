"""Electron fuse wire parsing (REA `electron` fuses parity).

Electron binaries embed a fuse-wire sentinel followed by one status byte per
known fuse (0x00 disabled, 0x01 enabled, 0xFF removed). Reading those states
tells you whether hardening features (ASAR integrity, cookie encryption,
inspect-argument gating) were compiled in — key evidence when judging an
Electron app's security posture.
"""

from __future__ import annotations

import os

SENTINEL = b"dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX"
SCAN_LIMIT = 64 * 1024 * 1024

# fuse order after the sentinel's version byte (Electron fuse wire v1+)
FUSE_NAMES = [
    "RunAsNode",
    "EnableCookieEncryption",
    "EnableNodeOptionsEnvironmentVariable",
    "EnableNodeCliInspectArguments",
    "EnableEmbeddedAsarIntegrityValidation",
    "GrantFileProtocolExtraPrivileges",
]
STATE_NAMES = {0x00: "disabled", 0x01: "enabled", 0xFF: "removed"}


def fuse_wire_info(path: str) -> dict:
    out: dict = {"ok": False, "format": "electron-fuses", "fuses": [],
                 "warnings": [], "errors": []}
    try:
        size = os.path.getsize(path)
        with open(path, "rb") as fh:
            data = fh.read(min(size, SCAN_LIMIT))
    except OSError as exc:
        out["errors"].append(f"read failed: {exc}")
        return out
    idx = data.find(SENTINEL)
    if idx < 0:
        out["errors"].append("fuse wire sentinel not found "
                             "(not an Electron binary, or fuses stripped)")
        return out
    out["sentinel_offset"] = idx
    ver_pos = idx + len(SENTINEL)
    if ver_pos + 1 > len(data):
        out["errors"].append("sentinel at end of file; no version byte")
        return out
    out["fuse_version"] = data[ver_pos]
    states: list[dict] = []
    for i, name in enumerate(FUSE_NAMES):
        pos = ver_pos + 1 + i
        if pos >= len(data):
            out["warnings"].append(f"fuse {name}: wire ends early")
            break
        raw = data[pos]
        states.append({"fuse": name, "raw": f"{raw:#04x}",
                       "state": STATE_NAMES.get(raw, "unknown")})
    out["fuses"] = states
    # security verdicts (evidence-based hints, not moralising)
    verdicts: list[str] = []
    for s in states:
        if s["fuse"] == "RunAsNode" and s["state"] == "enabled":
            verdicts.append("RunAsNode enabled: ELECTRON_RUN_AS_NODE allows "
                            "spawning Node mode from a parent process")
        if s["fuse"] == "EnableNodeCliInspectArguments" and \
                s["state"] == "enabled":
            verdicts.append("inspect arguments enabled: --inspect exposes a "
                            "debugger port at runtime")
        if s["fuse"] == "EnableEmbeddedAsarIntegrityValidation" and \
                s["state"] == "disabled":
            verdicts.append("ASAR integrity validation disabled: modified "
                            "ASAR archives load without complaint")
        if s["fuse"] == "EnableCookieEncryption" and s["state"] == "disabled":
            verdicts.append("cookie encryption disabled: cookies stored in "
                            "plaintext on disk")
    out["verdicts"] = verdicts
    out["ok"] = True
    return out
