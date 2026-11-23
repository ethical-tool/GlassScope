"""Bridge to Kali Linux CLI tools — fixed argument recipes only.

The GUI never passes user-controlled strings as tool flags; the target path
is passed positionally (and only when it exists), which keeps the bridge
injection-safe. Output is captured with a timeout and a size cap.
"""

from __future__ import annotations

import os
import shutil
import subprocess

MAX_OUTPUT = 1 * 1024 * 1024
TIMEOUT = 60

# tool key -> {binary, description, recipes}
RECIPES: dict[str, dict] = {
    "file": {
        "binary": "file",
        "description": "File type identification",
        "runs": [("Identify type", ["file", "-L", "{target}"])],
    },
    "strings": {
        "binary": "strings",
        "description": "Extract printable strings",
        "runs": [("Strings (min 8)", ["strings", "-n", "8", "{target}"]),
                 ("Strings (min 16, offsets)", ["strings", "-t", "x", "-n", "16", "{target}"])],
    },
    "readelf": {
        "binary": "readelf",
        "description": "ELF header / sections / dynamic info",
        "runs": [("All headers", ["readelf", "-h", "{target}"]),
                 ("Sections", ["readelf", "-S", "{target}"]),
                 ("Dynamic section", ["readelf", "-d", "{target}"]),
                 ("Symbols", ["readelf", "-sW", "{target}"]),
                 ("Notes & relocations", ["readelf", "-n", "-r", "{target}"])],
    },
    "objdump": {
        "binary": "objdump",
        "description": "Disassembly and symbol tables",
        "runs": [("File summary", ["objdump", "-f", "{target}"]),
                 ("Symbols", ["objdump", "-t", "{target}"]),
                 ("Disassemble (Intel)", ["objdump", "-d", "-M", "intel", "{target}"])],
    },
    "nm": {
        "binary": "nm",
        "description": "Symbol table listing",
        "runs": [("Symbols (demangled)", ["nm", "-C", "{target}"]),
                 ("Dynamic symbols", ["nm", "-D", "{target}"])],
    },
    "ldd": {
        "binary": "ldd",
        "description": "Shared library dependencies",
        "runs": [("Dependencies", ["ldd", "{target}"])],
    },
    "binwalk": {
        "binary": "binwalk",
        "description": "Firmware / embedded file signature scan",
        "runs": [("Signature scan", ["binwalk", "{target}"]),
                 ("Entropy analysis", ["binwalk", "-E", "{target}"])],
    },
    "exiftool": {
        "binary": "exiftool",
        "description": "Metadata extraction",
        "runs": [("All metadata", ["exiftool", "{target}"])],
    },
    "checksec": {
        "binary": "checksec",
        "description": "Binary security mitigations",
        "runs": [("Mitigations", ["checksec", "--file={target}"])],
    },
    "rabin2": {
        "binary": "rabin2",
        "description": "radare2 binary info",
        "runs": [("Info", ["rabin2", "-I", "{target}"]),
                 ("Entrypoints", ["rabin2", "-e", "{target}"]),
                 ("Imports", ["rabin2", "-i", "{target}"]),
                 ("Libraries", ["rabin2", "-l", "{target}"])],
    },
    "upx": {
        "binary": "upx",
        "description": "UPX packed executable test",
        "runs": [("Test packing", ["upx", "-t", "{target}"])],
    },
    "apktool": {
        "binary": "apktool",
        "description": "Android APK resource & manifest decoding",
        "runs": [("Decode resources", ["apktool", "d", "-f", "-o",
                                       "/tmp/glassscope-apktool", "{target}"]),
                 ("Badging info", ["apktool", "badging", "{target}"])],
    },
    "jadx": {
        "binary": "jadx",
        "description": "DEX to Java decompiler",
        "runs": [("Show class list", ["jadx", "--list-classes", "{target}"])],
    },
    "aapt2": {
        "binary": "aapt2",
        "description": "Android asset packaging tool (badging)",
        "runs": [("Badging", ["aapt2", "dump", "badging", "{target}"]),
                 ("Permissions", ["aapt2", "dump", "permissions", "{target}"])],
    },
    "strace": {
        "binary": "strace",
        "description": "Runtime syscall tracing (runs a quick probe)",
        "runs": [("Trace file opens", ["strace", "-f", "-e", "trace=openat",
                                       "-o", "/tmp/glassscope-strace.log",
                                       "true"])],
    },
    "ltrace": {
        "binary": "ltrace",
        "description": "Runtime library call tracing",
        "runs": [("Trace calls", ["ltrace", "-o", "/tmp/glassscope-ltrace.log",
                                  "ls", "/"])],
    },
    "ghidra": {
        "binary": "analyzeHeadless",
        "description": "Ghidra headless analysis (decompiler parity)",
        "runs": [("Import & analyze", ["analyzeHeadless", "/tmp/glassscope-ghidra",
                                       "GlassScopeProj", "-import", "{target}",
                                       "-analysisTimeoutPerFile", "300"])],
    },
}

AVAILABLE: dict[str, str | None] = {}


def tool_available(key: str) -> str | None:
    """Return the resolved binary path for a tool key, or None."""
    if key in AVAILABLE:
        return AVAILABLE[key]
    spec = RECIPES.get(key)
    if not spec:
        return None
    found = shutil.which(spec["binary"])
    AVAILABLE[key] = found
    return found


def list_tools() -> list[dict]:
    out = []
    for key, spec in RECIPES.items():
        bin_path = tool_available(key)
        out.append({
            "key": key,
            "binary": spec["binary"],
            "description": spec["description"],
            "available": bool(bin_path),
            "path": bin_path or "",
            "recipes": [label for label, _ in spec["runs"]],
        })
    return out


def run_recipe(key: str, recipe_index: int, target: str) -> dict:
    """Run a fixed recipe against an existing target file."""
    spec = RECIPES.get(key)
    if not spec:
        return {"ok": False, "error": f"Unknown tool: {key}"}
    if recipe_index < 0 or recipe_index >= len(spec["runs"]):
        return {"ok": False, "error": "Invalid recipe selection"}
    bin_path = tool_available(key)
    if not bin_path:
        return {"ok": False, "error": f"'{spec['binary']}' is not installed — "
                f"run: sudo apt install {spec['binary']} (or the matching Kali package)"}
    if not os.path.exists(target):
        return {"ok": False, "error": f"Target does not exist: {target}"}
    label, template = spec["runs"][recipe_index]
    argv = [arg.replace("{target}", target) for arg in template]
    # never pass anything before the binary path we resolved ourselves
    argv[0] = bin_path
    try:
        proc = subprocess.run(
            argv, capture_output=True, timeout=TIMEOUT,
            text=True, errors="replace", shell=False)
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": f"{spec['binary']} timed out after {TIMEOUT}s"}
    except OSError as exc:
        return {"ok": False, "error": f"Failed to launch {spec['binary']}: {exc}"}
    out = (proc.stdout or "")[:MAX_OUTPUT]
    err = (proc.stderr or "")[:64 * 1024]
    truncated = len(proc.stdout or "") > MAX_OUTPUT
    return {
        "ok": proc.returncode == 0 or bool(out),
        "tool": spec["binary"], "recipe": label, "argv": argv[1:],
        "returncode": proc.returncode,
        "stdout": out, "stderr": err, "truncated": truncated,
    }
