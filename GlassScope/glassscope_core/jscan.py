"""Static JavaScript / Electron application scanner.

Walks a directory (or a single .js/.mjs/.cjs file) and reports:
- module inventory (files, lines, size, minified heuristic)
- require/import graph summary (internal vs external packages)
- Electron security boundaries (nodeIntegration, contextIsolation, sandbox,
  webSecurity, remote module) with file+line evidence
- risky API usage (eval, new Function, child_process, shell.openExternal, ...)
- package.json metadata and postinstall-script warnings
- high-signal secret patterns (AWS keys, GitHub tokens, private key blocks...)

Designed for evidence-first output: every finding carries file, line number
and a trimmed snippet.
"""

from __future__ import annotations

import json
import os
import re

from .util import MAX_SNIPPET_READ, human_size, sanitize_rel_path

JS_EXTENSIONS = {".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".mts", ".cts"}
SKIP_DIRS = {".git", "node_modules", ".cache", "__pycache__", "dist-e2e"}
MAX_FILES = 8000
MAX_BYTES_TOTAL = 512 * 1024 * 1024

IMPORT_RE = re.compile(
    r"""(?:
        \brequire\s*\(\s*['"]([^'"]+)['"]\s*\)          # require('x')
      | \bimport\s+(?:[\w{}\s,*$]+\s+from\s+)?['"]([^'"]+)['"]  # import ... from 'x' / import 'x'
      | \bexport\s+[\w{}\s,*$]+\s+from\s+['"]([^'"]+)['"]      # export ... from 'x'
      | \bimport\s*\(\s*['"]([^'"]+)['"]\s*\)          # dynamic import('x')
    )""",
    re.VERBOSE,
)

# rule id, regex, severity, title, description
ELECTRON_RULES: list[tuple[str, str, str, str]] = [
    ("nodeIntegrationOn", r"nodeIntegration\s*:\s*true", "high",
     "nodeIntegration enabled in a webPreferences block"),
    ("contextIsolationOff", r"contextIsolation\s*:\s*false", "high",
     "contextIsolation disabled — renderer can reach preload APIs directly"),
    ("sandboxOff", r"sandbox\s*:\s*false", "medium",
     "sandbox disabled for a renderer process"),
    ("webSecurityOff", r"webSecurity\s*:\s*false", "high",
     "webSecurity disabled — same-origin policy off"),
    ("remoteModule", r"enableRemoteModule\s*:\s*true|require\(\s*['\"]@electron/remote['\"]\s*\)|require\(\s*['\"]electron-remote['\"]\s*\)", "medium",
     "Electron remote module usage"),
    ("evalUse", r"\beval\s*\(", "medium", "eval() usage"),
    ("newFunction", r"new\s+Function\s*\(", "medium", "new Function() dynamic code"),
    ("childProcess", r"require\(\s*['\"]child_process['\"]\s*\)|from\s+['\"]child_process['\"]", "medium",
     "child_process usage (shell command execution)"),
    ("execCall", r"\bexec(?:Sync)?\s*\(", "low", "exec()/execSync() call"),
    ("shellOpenExternal", r"shell\.openExternal\s*\(", "medium",
     "shell.openExternal() — opens URLs/paths in the OS"),
    ("ipcRenderer", r"\bipcRenderer\.(?:send|sendSync|invoke|on)\b", "low",
     "ipcRenderer message channel"),
    ("ipcMain", r"\bipcMain\.(?:handle|on)\b", "low", "ipcMain channel handler"),
    ("allowFileAccessFromFileUrls", r"allowFileAccessFromFileURLs\s*:\s*true", "high",
     "allowFileAccessFromFileURLs enabled"),
    ("webviewDisablewebsecurity", r"disablewebsecurity", "high",
     "webview with disablewebsecurity"),
    ("httpProtocolLoad", r"loadURL\s*\(\s*['\"]http://", "medium",
     "loads a remote page over plain HTTP"),
]

SECRET_RULES: list[tuple[str, str, str]] = [
    ("awsAccessKey", r"AKIA[0-9A-Z]{16}", "critical", "AWS access key ID"),
    ("githubToken", r"\bgh[pousr]_[A-Za-z0-9]{36,255}\b", "critical", "GitHub token"),
    ("slackToken", r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b", "critical", "Slack token"),
    ("slackWebhook", r"hooks\.slack\.com/services/T[A-Za-z0-9_/]{8,}", "critical", "Slack webhook URL"),
    ("googleApiKey", r"\bAIza[0-9A-Za-z_\-]{35}\b", "critical", "Google API key"),
    ("privateKeyBlock", r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----", "critical",
     "embedded private key"),
    ("jwt", r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b", "high",
     "JSON Web Token literal"),
    ("genericBearer", r"(?:api[_-]?key|apikey|secret|token|password)\s*[:=]\s*['\"][A-Za-z0-9_\-]{16,}['\"]",
     "medium", "hardcoded credential-looking assignment"),
]


def _snippet(text: str, line_no: int, width: int = 160) -> str:
    lines = text.splitlines()
    if 1 <= line_no <= len(lines):
        return lines[line_no - 1].strip()[:width]
    return ""


def scan_javascript_app(root: str, on_progress=None) -> dict:
    result: dict = {
        "ok": False, "kind": "JavaScriptApp", "path": os.path.abspath(root),
        "warnings": [], "files": [], "imports": [], "findings": [],
        "package_json": {}, "summary": {},
    }
    warnings = result["warnings"]
    findings = result["findings"]
    imports = result["imports"]
    files = result["files"]

    if os.path.isfile(root):
        target_files = [(os.path.dirname(root) or ".", [root])]
    elif os.path.isdir(root):
        try:
            walker = list(os.walk(root))
        except OSError as exc:
            warnings.append(f"Cannot walk {root}: {exc}")
            return result
        target_files = []
        for dirpath, dirnames, filenames in walker:
            dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
            js = [os.path.join(dirpath, f) for f in sorted(filenames)
                  if os.path.splitext(f)[1].lower() in JS_EXTENSIONS]
            if js:
                target_files.append((dirpath, js))
    else:
        warnings.append(f"Path does not exist: {root}")
        return result

    flat: list[str] = [p for _, lst in target_files for p in lst]
    if len(flat) > MAX_FILES:
        warnings.append(f"Too many JS files ({len(flat)}); scanning first {MAX_FILES}.")
        flat = flat[:MAX_FILES]

    total_bytes = 0
    minified_count = 0
    scanned = 0

    # package.json metadata (only at root level, closest to the target)
    pkg_candidates = [os.path.join(root, "package.json")] if os.path.isdir(root) else []
    for cand in pkg_candidates:
        if os.path.isfile(cand):
            try:
                with open(cand, "r", encoding="utf-8", errors="replace") as fh:
                    pkg = json.load(fh)
                result["package_json"] = {
                    "name": pkg.get("name", ""),
                    "version": pkg.get("version", ""),
                    "main": pkg.get("main", ""),
                    "scripts": pkg.get("scripts", {}),
                    "dependencies": sorted((pkg.get("dependencies") or {}).keys()),
                    "devDependencies": sorted((pkg.get("devDependencies") or {}).keys()),
                }
                for name in sorted((pkg.get("scripts") or {}).keys()):
                    if re.search(r"(postinstall|preinstall|prepare)$", name):
                        findings.append({
                            "rule": "installScript", "severity": "medium",
                            "file": cand, "line": 0, "snippet": f"\"{name}\": {pkg['scripts'][name][:120]}",
                            "title": f"package.json install script: {name}",
                        })
            except (json.JSONDecodeError, OSError) as exc:
                warnings.append(f"package.json unreadable: {exc}")
            break

    for path in flat:
        if total_bytes > MAX_BYTES_TOTAL:
            warnings.append("Total scan budget reached; stopping early.")
            break
        try:
            fsize = os.path.getsize(path)
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                text = fh.read(MAX_SNIPPET_READ)
        except OSError as exc:
            warnings.append(f"Could not read {path}: {exc}")
            continue
        total_bytes += fsize
        scanned += 1
        lines = text.splitlines()
        rel = os.path.relpath(path, result["path"]) if os.path.isdir(root) else os.path.basename(path)
        entry = {"file": rel, "size": fsize, "lines": len(lines)}
        nonblank = sum(1 for ln in lines if ln.strip())
        avg_len = (len(text) / max(nonblank, 1)) if nonblank else 0
        entry["minified"] = bool(len(lines) < 12 and len(text) > 4096) or avg_len > 400
        minified_count += 1 if entry["minified"] else 0
        files.append(entry)

        seen_imports: set[str] = set()
        for lineno, line in enumerate(lines, 1):
            for m in IMPORT_RE.finditer(line):
                spec = next((g for g in m.groups() if g), None)
                if spec and spec not in seen_imports:
                    seen_imports.add(spec)
                    if spec.startswith(".") or spec.startswith("/"):
                        imports.append({"source": rel, "target": spec, "kind": "internal"})
                    else:
                        pkg_name = spec.split("/")[0] if not spec.startswith("@") else "/".join(spec.split("/")[:2])
                        imports.append({"source": rel, "target": pkg_name, "kind": "package"})
            for rule_id, pattern, severity, title in ELECTRON_RULES:
                if re.search(pattern, line):
                    findings.append({
                        "rule": rule_id, "severity": severity, "file": rel,
                        "line": lineno, "snippet": line.strip()[:160], "title": title,
                    })
            for rule_id, pattern, severity, title in SECRET_RULES:
                for m in re.finditer(pattern, line, re.IGNORECASE):
                    findings.append({
                        "rule": rule_id, "severity": severity, "file": rel,
                        "line": lineno, "snippet": m.group(0)[:160], "title": f"Possible {title}",
                    })
        if on_progress and scanned % 25 == 0:
            on_progress(scanned, len(flat))

    ext_pkgs = sorted({i["target"] for i in imports if i["kind"] == "package"})
    pkg_deps = set(result["package_json"].get("dependencies") or [])
    all_packages = sorted(set(ext_pkgs) | pkg_deps)
    internal_edges = sum(1 for i in imports if i["kind"] == "internal")
    sev_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    findings.sort(key=lambda f: (sev_rank.get(f["severity"], 9), f["file"], f["line"]))
    result["summary"] = {
        "jsFiles": len(files),
        "totalSize": total_bytes,
        "totalSizeHuman": human_size(total_bytes),
        "minifiedFiles": minified_count,
        "externalPackages": all_packages,
        "importedPackages": ext_pkgs,
        "externalPackageCount": len(all_packages),
        "internalImports": internal_edges,
        "findingCount": len(findings),
        "criticalOrHigh": sum(1 for f in findings if f["severity"] in ("critical", "high")),
    }
    result["ok"] = scanned > 0
    return result
