"""GlassScope pages: Overview, Binary, Bytes, ASAR, Android, Managed,
Firmware, JavaScript, Website, Toolbox, Evidence, About."""

from __future__ import annotations

import json
import os
import shutil
import tempfile
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from glassscope_core import asar as asar_mod
from glassscope_core import android, dotnet, efuses, elf, formats
from glassscope_core import bytescan, firmware, har_cap, jscan, toolbridge, util
from glassscope_core import webscan as webscan_mod

from . import theme, widgets

# GlassScopeApp is only referenced in (lazily-evaluated) type annotations;
# importing it here would create a circular import with glassscope_gui.app.


class PageBase:
    def __init__(self, app: GlassScopeApp, parent: ttk.Frame):
        self.app = app
        self.frame = parent
        self.last_result = None
        self.build()

    def build(self) -> None:  # pragma: no cover - overridden
        raise NotImplementedError

    def refresh(self) -> None:
        pass


# ---------------------------------------------------------------------------
class OverviewPage(PageBase):
    def build(self) -> None:
        widgets.page_header(
            self.frame, "Overview",
            "Pick a target — a binary, an app folder, an archive, a "
            "document or a URL — and GlassScope detects what it is, then "
            "takes you to the right scanner. 22 scanners in the Power "
            "Edition.")
        self.entry = widgets.target_bar(self.frame, self.app, self.on_detect,
                                        run_label="Detect target")
        if self.app.current_target:
            self.entry.insert(0, self.app.current_target)

        self.detect_card = widgets.card(self.frame)
        self.jump = ttk.Frame(self.frame, style="Page.TFrame")
        self.jump.pack(fill="x", padx=20, pady=(0, 10))
        self.empty = tk.Label(
            self.frame,
            text="No target loaded yet.\n\n"
                 "Supported targets: ELF binaries & shared objects · Electron/ASAR "
                 "archives · JavaScript/TypeScript app folders · HTML pages & URLs",
            bg=theme.BG, fg=theme.MUTED, font=self.app.f["base"], justify="center")
        self.empty.pack(expand=True)

    def set_target(self, path: str) -> None:
        self.entry.delete(0, "end")
        self.entry.insert(0, path)
        self.on_detect()

    def on_detect(self) -> None:
        target = self.entry.get().strip()
        if not target:
            messagebox.showinfo("No target", "Choose a file, folder or URL first.")
            return
        self.app.current_target = target
        exists = os.path.exists(target)
        card = self.detect_card
        for w in card.winfo_children():
            w.destroy()
        facts = [
            ("Path", target),
            ("Exists", "yes" if exists else "no (URL or missing path)"),
        ]
        if exists and os.path.isfile(target):
            kind = util.magic_sniff(target)
            facts += [
                ("Detected type", kind),
                ("Size", util.human_size(os.path.getsize(target))),
                ("Entropy (head)", f'{util.entropy_of_file(target):.2f} / 8.00 bits per byte'),
            ]
        elif exists and os.path.isdir(target):
            js_count = 0
            for root, dirs, files in os.walk(target):
                dirs[:] = [d for d in dirs if d not in (".git", "node_modules")]
                js_count += sum(1 for f in files
                                if os.path.splitext(f)[1].lower() in
                                (".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx"))
                if js_count > 5000:
                    break
            facts += [("Detected type", "directory"), ("JS/TS files", str(js_count))]

        for i, (label, value) in enumerate(facts):
            widgets.card_row(card, label, value, 0, i)
        card.columnconfigure(1, weight=1)

        # routing suggestions
        for w in self.jump.winfo_children():
            w.destroy()
        suggestions: list[tuple[str, str]] = []
        if exists and os.path.isfile(target):
            det = formats.detect_format(target)
            kind = det.get("kind")
            route = {
                "elf": [("Open in Binary Inspector", "binary"),
                        ("Disassemble (.text)", "disasm")],
                "pe": [("Open in PE Inspector", "pe"),
                       ("Open in .NET & Managed", "managed"),
                       ("Disassemble", "disasm")],
                "macho": [("Open in Mach-O & iOS", "macho"),
                          ("Open in Bytes & Strings", "bytes")],
                "dex": [("Open in Android & Java", "android")],
                "zip": [("Open in Android & Java", "android"),
                        ("Inspect in Firmware & Formats", "firmware")],
                "sqlite": [("Open in Data Stores", "stores")],
                "wasm": [("Inspect in Firmware & Formats", "firmware")],
                "dtb": [("Inspect in Firmware & Formats", "firmware")],
                "pck": [("Inspect in Firmware & Formats", "firmware")],
                "beam": [("Inspect in Firmware & Formats", "firmware")],
                "deno": [("Inspect in Firmware & Formats", "firmware")],
                "bun": [("Inspect in Firmware & Formats", "firmware")],
                "dart": [("Inspect in Firmware & Formats", "firmware")],
                "go": [("Inspect in Firmware & Formats", "firmware")],
                "il2cpp-meta": [("Open in .NET & Managed", "managed")],
                "dotnet-meta": [("Open in .NET & Managed", "managed")],
                "kernel": [("Inspect in Firmware & Formats", "firmware")],
                "tflite": [("Inspect in Firmware & Formats", "firmware")],
                "json": [("Analyze as HAR capture", "website"),
                         ("Inspect in Firmware & Formats", "firmware")],
                "Electron ASAR archive": [],
            }
            if kind == "asar":
                suggestions = [("Open in ASAR & Electron", "asar")]
            elif kind == "html" or kind == "pdf":
                suggestions = [("Open in Document Triage", "docs"),
                               ("Open in Website Scan", "website")]
            elif kind in route:
                suggestions = list(route[kind])
            else:
                suggestions = [
                    ("Open in Bytes & Strings", "bytes"),
                    ("Inspect in Firmware & Formats", "firmware"),
                    ("Hunt IOCs", "iocs"),
                ]
            if not any(k == "bytes" for _, k in suggestions):
                suggestions.append(("Open in Bytes & Strings", "bytes"))
        elif exists:
            suggestions = [("Scan as JavaScript app", "js"),
                           ("Scan an APK folder", "android"),
                           ("Open in Binary Inspector", "binary")]
        else:
            suggestions = [("Scan as website/URL", "website")]
        for label, page_key in suggestions:
            btn = ttk.Button(self.jump, text=label, style="Soft.TButton",
                             command=lambda k=page_key: self._goto(k))
            btn.pack(side="left", padx=(0, 8))
        self.empty.pack_forget()
        self.app.set_status(f"Detected: {target}")

    def _goto(self, key: str) -> None:
        page = self.app.pages[key]
        entry = getattr(page, "entry", None)
        if entry is not None:
            entry.delete(0, "end")
            entry.insert(0, self.entry.get().strip())
        self.app.show_page(key)


def theme_bg() -> str:
    return theme.BG


# (kept for backwards compatibility with external callers)


# ---------------------------------------------------------------------------
class BinaryPage(PageBase):
    def build(self) -> None:
        widgets.page_header(
            self.frame, "Binary Inspector",
            "Pure-Python ELF analysis: header, sections, segments, dynamic "
            "dependencies, symbols and per-section entropy — no external "
            "tools required.")
        self.entry = widgets.target_bar(self.frame, self.app, self.on_run)
        self.area = widgets.results_area(self.frame, tree_mode="tree")
        widgets.export_bar(self.frame, [
            ("Export JSON...", self.export_json),
        ])

    def on_run(self) -> None:
        target = self.entry.get().strip()
        if not target or not os.path.isfile(target):
            messagebox.showinfo("Target needed", "Choose an ELF file first.")
            return
        self.app.current_target = target

        def work(cb):
            return elf.parse_elf(target)

        self.app.start_scan("elf", work, self.on_done)

    def on_done(self, result: dict) -> None:
        self.last_result = result
        tree = self.area["tree"]
        widgets.clear_tree(tree)
        self.area["detail_data"] = {}
        if not result.get("ok"):
            widgets.set_text(self.area["text"],
                             "Not an ELF file.\n\nWarnings:\n" +
                             "\n".join(result.get("warnings", [])))
            return
        h = result["header"]
        root = tree.insert("", "end", text=f"ELF {h['bits']}-bit {h['machine']}")
        self.area["detail_data"][root] = json.dumps(
            {"header": h, "file_size": result.get("file_size")},
            indent=2, ensure_ascii=False)

        sec_parent = tree.insert("", "end",
                                 text=f"Sections ({len(result['sections'])})")
        for s in result["sections"][:400]:
            iid = tree.insert(sec_parent, "end",
                              text=f"{s['name']}  ·  {s['type']}  ·  {s['size']} B",
                              tags=("muted",))
            self.area["detail_data"][iid] = json.dumps(s, indent=2)

        seg_parent = tree.insert("", "end",
                                 text=f"Program segments ({len(result['segments'])})")
        for s in result["segments"][:100]:
            iid = tree.insert(seg_parent, "end",
                              text=f"{s['type']}  ·  {s['flags']}  ·  vaddr {s['vaddr']}")
            self.area["detail_data"][iid] = json.dumps(s, indent=2)

        dep_parent = tree.insert(
            "", "end", text=f"Dynamic dependencies ({len(result['dynamic_deps'])})")
        for d in result["dynamic_deps"]:
            iid = tree.insert(dep_parent, "end", text=d, tags=("ok",))
            self.area["detail_data"][iid] = f"DT_NEEDED library: {d}"

        imp_parent = tree.insert(
            "", "end", text=f"Imported symbols ({len(result['imports'])})")
        for imp in result["imports"][:600]:
            iid = tree.insert(imp_parent, "end",
                              text=f"{imp['name']}  ({imp['type']}, {imp['bind']})",
                              tags=("muted",))
            self.area["detail_data"][iid] = json.dumps(imp, indent=2)
        if not result["imports"]:
            tree.insert(imp_parent, "end", text="(none — static binary?)",
                        tags=("muted",))

        exp_parent = tree.insert(
            "", "end", text=f"Exported symbols ({len(result['exports'])})")
        for exp in result["exports"][:600]:
            iid = tree.insert(exp_parent, "end",
                              text=f"{exp['name']}  @ {exp['value']}  ({exp['size']} B)")
            self.area["detail_data"][iid] = json.dumps(exp, indent=2)

        ent_parent = tree.insert(
            "", "end", text=f"Section entropy ({len(result['section_entropy'])})")
        for e in result["section_entropy"][:100]:
            flag = "warn" if e["entropy"] > 7.3 else ("muted" if e["entropy"] < 1.0 else "")
            iid = tree.insert(ent_parent, "end",
                              text=f"{e['name']:<24} entropy {e['entropy']:5.2f}  ({e['size']} B)",
                              tags=(flag,))
            self.area["detail_data"][iid] = (
                f"{e['name']}\n\nEntropy {e['entropy']} bits/byte over the first "
                f"{min(e['size'], 4 * 1024 * 1024)} bytes.\nHigh entropy (> 7.3) often "
                "means compression or packing (UPX etc.). Near-zero means padding.")

        # Notes / build-id / debug link / Electron fuse wire
        notes_parent = tree.insert(
            "", "end", text=f"Notes ({len(result.get('notes', []))})")
        for n in result.get("notes", [])[:64]:
            iid = tree.insert(notes_parent, "end",
                              text=f"{n['section']}  ·  {n['name']} type {n['type']}",
                              tags=("muted",))
            self.area["detail_data"][iid] = json.dumps(n, indent=2)
        if result.get("build_id"):
            iid = tree.insert(notes_parent, "end",
                              text=f"GNU build-id: {result['build_id']}",
                              tags=("ok",))
            self.area["detail_data"][iid] = (
                "NT_GNU_BUILD_ID — matches debug symbol files "
                "(.debug or /usr/lib/debug paths).")
        if result.get("debug_link"):
            d = result["debug_link"]
            iid = tree.insert(notes_parent, "end",
                              text=f"debug link: {d['file']} (crc {d['crc']})",
                              tags=("ok",))
            self.area["detail_data"][iid] = (
                ".gnu_debuglink points to a separate debug symbols file — "
                f"load {d['file']} next to the binary for symbolicated analysis.")

        target = self.app.current_target or ""
        if os.path.isfile(target):
            fuse_res = efuses.fuse_wire_info(target)
            if fuse_res.get("ok"):
                fparent = tree.insert("", "end", text="Electron fuse wire")
                for fu in fuse_res.get("fuses", []):
                    tag = "ok" if fu["state"] == "enabled" else (
                        "warn" if fu["state"] == "removed" else "muted")
                    iid = tree.insert(fparent, "end",
                                      text=f"{fu['fuse']}: {fu['state']}",
                                      tags=(tag,))
                    self.area["detail_data"][iid] = json.dumps(fu, indent=2)
                for v in fuse_res.get("verdicts", []):
                    iid = tree.insert(fparent, "end", text=v, tags=("warn",))
                    self.area["detail_data"][iid] = v

        warnings = result.get("warnings", [])
        widgets.set_text(
            self.area["text"],
            "Open a node on the left to inspect its details.\n\n"
            + (f"{len(warnings)} warning(s):\n" + "\n".join(warnings) if warnings else "No warnings."))

    def export_json(self) -> None:
        if not self.last_result:
            messagebox.showinfo("Nothing to export", "Run an analysis first.")
            return
        widgets.ask_save_json(self.app, "glassscope-binary.json", self.last_result)


# ---------------------------------------------------------------------------
class AsarPage(PageBase):
    def build(self) -> None:
        widgets.page_header(
            self.frame, "ASAR & Electron",
            "Parse Electron ASAR archives with full extent validation, list "
            "entries, extract safely (path-traversal protected), and run a "
            "deep Electron security scan on the contents.")
        self.entry = widgets.target_bar(self.frame, self.app, self.on_run)
        self.stats_card = widgets.card(self.frame)
        self.area = widgets.results_area(self.frame, tree_mode="tree")
        deep_bar = ttk.Frame(self.frame, style="Page.TFrame")
        deep_bar.pack(fill="x", padx=20, pady=(0, 8))
        ttk.Button(deep_bar, text="Deep Electron security scan",
                   style="Soft.TButton", command=self.on_deep_scan).pack(side="left")
        tk.Label(deep_bar, text="Extracts the archive to a temporary folder and runs "
                 "the JavaScript security scanner on every module inside.",
                 bg=theme.BG, fg=theme.MUTED, font=self.app.f["small"]
                 ).pack(side="left", padx=(10, 0))
        self.findings = widgets.results_area(
            self.frame, tree_mode="table",
            columns=("severity", "rule", "file", "title"),
            headers=("Severity", "Rule", "File", "Finding"), height=6)
        widgets.export_bar(self.frame, [
            ("Extract all...", self.on_extract),
            ("Export entries JSON...", self.export_entries),
            ("Export findings JSON...", self.export_findings),
        ])
        self._temp_dir: str | None = None
        self._extract_errors = 0
        self._findings_data: list[dict] = []

    def _clear_temp(self) -> None:
        if self._temp_dir:
            shutil.rmtree(self._temp_dir, ignore_errors=True)
            self._temp_dir = None

    def on_run(self) -> None:
        target = self.entry.get().strip()
        if not target or not os.path.isfile(target):
            messagebox.showinfo("Target needed", "Choose an .asar archive first.")
            return
        self.app.current_target = target

        def work(cb):
            parsed = asar_mod.parse_asar(target)
            if not parsed.get("ok"):
                raise ValueError("; ".join(parsed.get("warnings", ["invalid ASAR"])))
            return parsed

        self.app.start_scan("asar", work, self.on_done)

    def on_done(self, parsed: dict) -> None:
        self.last_result = parsed
        self._clear_temp()
        tree = self.area["tree"]
        widgets.clear_tree(tree)
        self.area["detail_data"] = {}
        stats = parsed["stats"]
        card = self.stats_card
        for w in card.winfo_children():
            w.destroy()
        widgets.card_row(card, "Archive", parsed["path"], 0, 0)
        widgets.card_row(card, "Entries",
                         f"{stats['files']} files · {stats['directories']} dirs · "
                         f"{util.human_size(stats['total_file_bytes'])} payload", 0, 1)
        widgets.card_row(card, "Unpacked entries", str(stats["unpacked_entries"]), 0, 2)
        card.columnconfigure(1, weight=1)

        def add_dir(parent_iid: str, node: dict, prefix: str) -> None:
            files = node.get("files") or {}
            for name, meta in sorted(files.items()):
                child_path = f"{prefix}/{name}" if prefix else name
                if isinstance(meta, dict) and "files" in meta:
                    iid = tree.insert(parent_iid, "end", text=name, open=False)
                    self.area["detail_data"][iid] = f"directory: {child_path}"
                    add_dir(iid, meta, child_path)
                else:
                    label = (f"{name}  ·  {util.human_size(meta.get('size', 0))}"
                             + ("  · unpacked" if meta.get("unpacked") else ""))
                    iid = tree.insert(parent_iid, "end", text=label, tags=("muted",))
                    self.area["detail_data"][iid] = json.dumps(
                        {"path": child_path, **meta}, indent=2, ensure_ascii=False)

        add_dir("", parsed.get("header", {}), "")
        widgets.set_text(self.area["text"], "Archive parsed. Select any entry "
                         "to see its metadata; use the buttons below to extract "
                         "or deep-scan.")

    def _ensure_extracted(self, archive_path: str) -> str:
        """Extract to a temp dir (thread-safe: no Tk calls in here)."""
        if self._temp_dir and os.path.isdir(self._temp_dir):
            return self._temp_dir
        self._temp_dir = tempfile.mkdtemp(prefix="glassscope-asar-")
        res = asar_mod.extract_asar(archive_path, self._temp_dir,
                                    self.last_result)
        if res["errors"]:
            self._extract_errors = len(res["errors"])
        return self._temp_dir

    def on_extract(self) -> None:
        if not self.last_result:
            messagebox.showinfo("Nothing to extract", "Parse an ASAR archive first.")
            return
        dest_dir = filedialog.askdirectory(
            title="Choose destination folder")
        if not dest_dir:
            return
        try:
            res = asar_mod.extract_asar(self.entry.get().strip(), dest_dir,
                                        self.last_result)
        except (ValueError, OSError, asar_mod.AsarError) as exc:
            messagebox.showerror("Extraction failed", str(exc))
            return
        msg = f"Extracted {res['extracted']} files ({res['skipped']} skipped)."
        if res["errors"]:
            preview = "\n".join(res["errors"][:10])
            messagebox.showwarning("Extracted with warnings", f"{msg}\n\n{preview}")
        else:
            messagebox.showinfo("Extracted", msg)

    def on_deep_scan(self) -> None:
        if not self.last_result:
            messagebox.showinfo("Nothing to scan", "Parse an ASAR archive first.")
            return
        src = self.entry.get().strip()  # read the widget on the main thread

        def work(cb):
            tmp = self._ensure_extracted(src)
            result = jscan.scan_javascript_app(tmp, on_progress=cb)
            result["source_archive"] = src
            return result

        self.app.start_scan("asar-deep", work, self.on_deep_done)

    def on_deep_done(self, result: dict) -> None:
        self._fill_findings(result)
        total = result["summary"]["findingCount"]
        skipped = f" ({self._extract_errors} entries skipped during extraction)" \
            if self._extract_errors else ""
        self.app.set_status(f"Deep scan done: {total} findings{skipped}")

    def _fill_findings(self, result: dict) -> None:
        self._findings_data = result.get("findings", [])
        tree = self.findings["tree"]
        widgets.clear_tree(tree)
        self.findings["detail_data"] = {}
        for f in self._findings_data:
            iid = tree.insert(
                "", "end", tags=(f"sev-{f['severity']}",),
                values=(f["severity"], f["rule"], f"{f['file']}:{f['line']}",
                        f["title"]))
            self.findings["detail_data"][iid] = (
                f"Rule: {f['rule']}\nSeverity: {f['severity']}\n"
                f"File: {f['file']} (line {f['line']})\n\nSnippet:\n{f['snippet']}")
        if not self._findings_data:
            tree.insert("", "end", values=("—", "no findings", "—", "clean"), tags=("ok",))

    def export_entries(self) -> None:
        if not self.last_result:
            messagebox.showinfo("Nothing to export", "Parse an ASAR archive first.")
            return
        widgets.ask_save_json(self.app, "glassscope-asar-entries.json", {
            "stats": self.last_result["stats"],
            "entries": self.last_result["entries"],
            "warnings": self.last_result.get("warnings", []),
        })

    def export_findings(self) -> None:
        if not self._findings_data:
            messagebox.showinfo("Nothing to export", "Run the deep scan first "
                                "(button below the findings table).")
            return
        widgets.ask_save_json(self.app, "glassscope-asar-findings.json",
                              self._findings_data)


# ---------------------------------------------------------------------------
# pages part 2: JavaScript Scan, Website Scan, Toolbox, Evidence Log, About
# ---------------------------------------------------------------------------



class JsPage(PageBase):
    def build(self) -> None:
        widgets.page_header(
            self.frame, "JavaScript Scan",
            "Static analysis of JavaScript/TypeScript apps and Electron "
            "projects: module inventory, dependency overview, Electron "
            "security boundaries, risky APIs and possible secrets — with "
            "file-and-line evidence for every finding.")
        self.entry = widgets.target_bar(self.frame, self.app, self.on_run)
        self.summary_card = widgets.card(self.frame)
        self.area = widgets.results_area(
            self.frame, tree_mode="table",
            columns=("severity", "rule", "file", "title"),
            headers=("Severity", "Rule", "File", "Finding"))
        widgets.export_bar(self.frame, [
            ("Export JSON...", self.export_json),
            ("Export Markdown...", self.export_md),
        ])

    def on_run(self) -> None:
        target = self.entry.get().strip()
        if not target or not os.path.exists(target):
            messagebox.showinfo("Target needed", "Choose an app folder or a JS file first.")
            return
        self.app.current_target = target

        def work(cb):
            return jscan.scan_javascript_app(target, on_progress=cb)

        self.app.start_scan("js", work, self.on_done)

    def on_done(self, result: dict) -> None:
        self.last_result = result
        summary = result["summary"]
        card = self.summary_card
        for w in card.winfo_children():
            w.destroy()
        widgets.card_row(card, "Target", result["path"], 0, 0)
        widgets.card_row(card, "Scope",
                         f"{summary['jsFiles']} JS/TS files · "
                         f"{summary['totalSizeHuman']} · {summary['minifiedFiles']} minified",
                         0, 1)
        widgets.card_row(card, "Packages",
                         f"{summary['externalPackageCount']} external "
                         f"({', '.join(summary['externalPackages'][:8])}"
                         f"{'...' if summary['externalPackageCount'] > 8 else ''})",
                         0, 2)
        widgets.card_row(card, "Findings",
                         f"{summary['findingCount']} total · "
                         f"{summary['criticalOrHigh']} critical/high",
                         0, 3)
        card.columnconfigure(1, weight=1)

        tree = self.area["tree"]
        widgets.clear_tree(tree)
        self.area["detail_data"] = {}
        for f in result["findings"]:
            iid = tree.insert("", "end", tags=(f"sev-{f['severity']}",),
                              values=(f["severity"], f["rule"],
                                      f"{f['file']}:{f['line']}", f["title"]))
            self.area["detail_data"][iid] = (
                f"Rule: {f['rule']}\nSeverity: {f['severity']}\n"
                f"File: {f['file']}  (line {f['line']})\n\nSnippet:\n    {f['snippet']}")
        if not result["findings"]:
            tree.insert("", "end", values=("—", "clean", "—", "no findings"),
                        tags=("ok",))
        if result.get("warnings"):
            for warn in result["warnings"]:
                iid = tree.insert("", "end", tags=("muted",),
                                  values=("info", "warning", "—", warn))
                self.area["detail_data"][iid] = warn
        widgets.set_text(self.area["text"],
                         "Select a finding on the left to see its evidence "
                         "(rule, file, line, snippet).")

    def export_json(self) -> None:
        if not self.last_result:
            messagebox.showinfo("Nothing to export", "Run a scan first.")
            return
        widgets.ask_save_json(self.app, "glassscope-js-scan.json", self.last_result)

    def export_md(self) -> None:
        if not self.last_result:
            messagebox.showinfo("Nothing to export", "Run a scan first.")
            return
        r = self.last_result
        lines = [
            "# GlassScope — JavaScript scan report", "",
            f"- Target: `{r['path']}`",
            f"- Files: {r['summary']['jsFiles']}  ({r['summary']['totalSizeHuman']})",
            f"- Findings: {r['summary']['findingCount']} "
            f"({r['summary']['criticalOrHigh']} critical/high)", "", "## Findings", "",
        ]
        for f in r["findings"]:
            lines.append(f"- **{f['severity']}** · `{f['rule']}` · {f['file']}:{f['line']}")
            lines.append(f"  {f['title']} — `{f['snippet'][:100]}`")
        for w in r.get("warnings", []):
            lines.append(f"- warning: {w}")
        widgets.ask_save_text(self.app, "glassscope-js-report.md", "\n".join(lines))


# ---------------------------------------------------------------------------
class WebsitePage(PageBase):
    def build(self) -> None:
        widgets.page_header(
            self.frame, "Website Scan",
            "Analyze a URL or a local HTML file: response & TLS details, "
            "security headers, cookies, scripts, iframes, forms, external "
            "hosts and mixed-content findings.")
        self.entry = widgets.target_bar(self.frame, self.app, self.on_run,
                                        run_label="Fetch & analyze",
                                        allow_url=True)
        self.robots_var = tk.BooleanVar(value=False)
        opts = ttk.Frame(self.frame, style="Page.TFrame")
        opts.pack(fill="x", padx=20, pady=(0, 8))
        ttk.Checkbutton(opts, text="Also fetch /robots.txt and /sitemap.xml discovery",
                        variable=self.robots_var).pack(side="left")
        self.area = widgets.results_area(self.frame, tree_mode="tree")
        self.findings = widgets.results_area(
            self.frame, tree_mode="table",
            columns=("severity", "rule", "detail"),
            headers=("Severity", "Rule", "Finding"), height=5)
        widgets.export_bar(self.frame, [("Export JSON...", self.export_json)])

    def on_run(self) -> None:
        target = self.entry.get().strip()
        if not target:
            messagebox.showinfo("Target needed", "Enter a URL or HTML file path first.")
            return
        self.app.current_target = target
        robots = self.robots_var.get()
        lower = target.lower()

        # Capture mode: HAR / pcap files are analyzed locally (REA
        # inspect-web-network-capture parity) instead of being fetched.
        if os.path.isfile(target) and lower.endswith((".har", ".pcap",
                                                      ".pcapng", ".cap")):
            mode = "har" if lower.endswith(".har") else "pcap"

            def capwork(cb):
                if mode == "har":
                    return har_cap.har_info(target)
                return har_cap.pcap_info(target)

            self.app.start_scan(f"capture-{mode}", capwork, self.on_capture)
            return

        def work(cb):
            return webscan_mod.scan_website(target, fetch_robots=robots, on_progress=cb)

        self.app.start_scan("web", work, self.on_done)

    def on_capture(self, result: dict) -> None:
        """Render HAR / pcap analysis into the same results tree."""
        self.last_result = result
        tree = self.area["tree"]
        widgets.clear_tree(tree)
        self.area["detail_data"] = {}
        find_tree = self.findings["tree"]
        widgets.clear_tree(find_tree)
        self.findings["detail_data"] = {}
        if not result.get("ok"):
            widgets.set_text(self.area["text"], "\n".join(result.get("errors", [])))
            return
        fmt = result.get("format")
        if fmt == "har":
            root = tree.insert("", "end",
                               text=f"HAR capture — {result['entry_count']} entries"
                                    f" (creator: {result.get('creator') or '?'})")
            dom = tree.insert(root, "end", text="Top domains")
            for d in result.get("domains", []):
                iid = tree.insert(dom, "end", text=f"{d['host']} — {d['count']} requests",
                                  tags=("muted",))
                self.area["detail_data"][iid] = json.dumps(d, indent=2)
            st = tree.insert(root, "end",
                             text=f"Status codes: {result.get('status_distribution')}")
            self.area["detail_data"][st] = json.dumps(
                result.get("status_distribution"), indent=2)
            sec = tree.insert(root, "end", text="Missing security headers")
            for h, c in (result.get("missing_security_headers") or {}).items():
                iid = tree.insert(sec, "end",
                                  text=f"{h} — missing on {c} response(s)",
                                  tags=("warn",))
                self.area["detail_data"][iid] = (
                    f"{h} was absent on {c} of {result['entry_count']} responses. "
                    "Missing hardening headers are a common web-app finding.")
            slow = tree.insert(root, "end", text="Slowest requests")
            for s in result.get("slowest", []):
                iid = tree.insert(slow, "end",
                                  text=f"{s['ms']} ms — {s['status']} — {s['url'][:70]}",
                                  tags=("muted",))
                self.area["detail_data"][iid] = json.dumps(s, indent=2)
            if result.get("plain_http_entries"):
                iid = find_tree.insert("", "end", values=(
                    "medium", "plain-http", f"{result['plain_http_entries']} "
                    "request(s) went over plain HTTP"), tags=("sev-medium",))
                self.findings["detail_data"][iid] = (
                    "Plain HTTP requests expose URL paths and query strings "
                    "to anyone on the network.")
            for h, c in (result.get("missing_security_headers") or {}).items():
                find_tree.insert("", "end", values=(
                    "low", "missing-header", f"{h} missing on {c} response(s)"),
                    tags=("sev-low",))
        else:
            root = tree.insert("", "end",
                               text=f"{fmt} — {result['packet_count']} packets, "
                                    f"linktype {result.get('linktype_name')}")
            hosts = tree.insert(root, "end", text="Top IPv4 hosts")
            for h in result.get("hosts", []):
                iid = tree.insert(hosts, "end",
                                  text=f"{h['ip']} — {h['packets']} packets",
                                  tags=("muted",))
                self.area["detail_data"][iid] = json.dumps(h, indent=2)
            hh = tree.insert(root, "end", text="HTTP Host headers")
            for h in result.get("http_hosts", []):
                tree.insert(hh, "end", text=f"{h['host']} — {h['count']} packets",
                            tags=("ok",))
        for w in result.get("warnings", []):
            tree.insert("", "end", text=f"warning: {w}", tags=("warn",))
        widgets.set_text(self.area["text"],
                         "Capture analysis complete. Select a node for details.")

    def on_done(self, result: dict) -> None:
        self.last_result = result
        tree = self.area["tree"]
        widgets.clear_tree(tree)
        self.area["detail_data"] = {}
        resp = result.get("response", {})
        root = tree.insert("", "end", text=f"Response — {resp.get('status', 'unknown')}")
        self.area["detail_data"][root] = json.dumps(resp, indent=2, ensure_ascii=False)
        for k, v in resp.items():
            if k == "headers":
                h_iid = tree.insert(root, "end", text=f"headers ({len(v)})", tags=("muted",))
                self.area["detail_data"][h_iid] = "\n".join(f"{a}: {b}" for a, b in v.items())
            else:
                iid = tree.insert(root, "end", text=f"{k}: {v}", tags=("muted",))
                self.area["detail_data"][iid] = str(v)

        tls = result.get("tls") or {}
        if tls:
            t_iid = tree.insert("", "end", text="TLS certificate")
            self.area["detail_data"][t_iid] = json.dumps(tls, indent=2)
            for k, v in tls.items():
                iid = tree.insert(t_iid, "end", text=f"{k}: {v}", tags=("ok",))
                self.area["detail_data"][iid] = str(v)

        html = result.get("html", {})
        h_root = tree.insert("", "end", text=f"HTML — {html.get('title', '(no title)')}")
        self.area["detail_data"][h_root] = json.dumps(html, indent=2, ensure_ascii=False)
        for key, label in (("inline_scripts", "inline scripts"),
                           ("external_scripts", "external scripts"),
                           ("iframes", "iframes"), ("forms", "forms"),
                           ("external_links", "external links"),
                           ("stylesheets", "stylesheets"), ("images", "images")):
            v = html.get(key, 0)
            iid = tree.insert(h_root, "end", text=f"{label}: {v}", tags=("muted",))
            self.area["detail_data"][iid] = json.dumps(html.get(key), indent=2, default=str)
        hosts_iid = tree.insert(h_root, "end",
                                text=f"external hosts: {len(html.get('external_hosts', []))}")
        for host in html.get("external_hosts", []):
            tree.insert(hosts_iid, "end", text=host, tags=("warn",))
        cookies = resp.get("cookies")
        if cookies:
            c_iid = tree.insert(root, "end", text=f"cookies: {len(cookies)}", tags=("warn",))
            self.area["detail_data"][c_iid] = "\n".join(cookies)
        if result.get("robots"):
            r_iid = tree.insert("", "end", text="robots.txt")
            self.area["detail_data"][r_iid] = json.dumps(result["robots"], indent=2)

        ftree = self.findings["tree"]
        widgets.clear_tree(ftree)
        self.findings["detail_data"] = {}
        for f in result.get("findings", []):
            iid = ftree.insert("", "end", tags=(f"sev-{f['severity']}",),
                               values=(f["severity"], f["rule"], f["title"][:80]))
            self.findings["detail_data"][iid] = f"{f['title']}\n\n{f.get('evidence', '')}"
        if not result.get("findings"):
            ftree.insert("", "end", values=("—", "clean", "no findings"), tags=("ok",))

        widgets.set_text(self.area["text"],
                         "Select any node for details. Findings are listed below.")
        if result.get("warnings"):
            widgets.set_text(self.area["text"],
                             "Warnings:\n" + "\n".join(result["warnings"]))

    def export_json(self) -> None:
        if not self.last_result:
            messagebox.showinfo("Nothing to export", "Run a scan first.")
            return
        widgets.ask_save_json(self.app, "glassscope-website.json", self.last_result)


# ---------------------------------------------------------------------------
class ToolboxPage(PageBase):
    TOOLS_ORDER = ["file", "strings", "readelf", "objdump", "nm", "ldd",
                   "binwalk", "exiftool", "checksec", "rabin2", "upx",
                   "apktool", "jadx", "aapt2", "strace", "ltrace", "ghidra"]

    def build(self) -> None:
        widgets.page_header(
            self.frame, "Toolbox",
            "Run Kali's own tools against the loaded target through fixed, "
            "injection-safe recipes. Tools missing on this system show an "
            "install hint instead of failing.")
        self.area = widgets.results_area(
            self.frame, tree_mode="table",
            columns=("tool", "status", "description"),
            headers=("Tool", "Status", "What it does"), detail=False)
        mid = ttk.Frame(self.frame, style="Card.TFrame", padding=(12, 10))
        mid.pack(fill="x", padx=20, pady=(0, 10))
        tk.Label(mid, text="Recipe:", bg=theme.PANEL, fg=theme.MUTED,
                 font=self.app.f["small"]).pack(side="left")
        self.recipe_var = tk.StringVar()
        self.recipe_box = ttk.Combobox(mid, textvariable=self.recipe_var,
                                       state="readonly", width=42)
        self.recipe_box.pack(side="left", padx=(8, 10))
        ttk.Button(mid, text="Run on target", style="Accent.TButton",
                   command=self.on_run).pack(side="left")
        self.target_label = tk.Label(mid, text="target: none", bg=theme.PANEL,
                                     fg=theme.MUTED, font=self.app.f["small"])
        self.target_label.pack(side="left", padx=(12, 0))
        self.area["tree"].bind("<<TreeviewSelect>>", self.on_tool_select)
        self.out_text = tk.Text(self.frame, height=12, bg=theme.PANEL,
                                fg=theme.TEXT, relief="flat",
                                font=self.app.f["mono"], padx=10, pady=8,
                                state="disabled")
        self.out_text.pack(fill="both", expand=True, padx=20, pady=(0, 10))
        self.refresh()

    def refresh(self) -> None:
        self.tools = {t["key"]: t for t in toolbridge.list_tools()}
        tree = self.area["tree"]
        widgets.clear_tree(tree)
        for key in self.TOOLS_ORDER:
            t = self.tools[key]
            tree.insert("", "end", iid=key,
                        values=(t["binary"], "available" if t["available"] else "not installed",
                                t["description"]),
                        tags=("ok",) if t["available"] else ("muted",))
        self.target = (self.app.current_target
                       if self.app.current_target and os.path.exists(self.app.current_target)
                       else None)
        self.target_label.config(
            text=f"target: {self.target or 'none — load one on the Overview page'}")
        if not self.area["tree"].selection() and tree.get_children():
            tree.selection_set(tree.get_children()[0])
        self.on_tool_select()

    def on_tool_select(self, _event=None) -> None:
        sel = self.area["tree"].selection()
        if not sel:
            return
        key = sel[0]
        self.recipe_box["values"] = self.tools[key]["recipes"]
        if self.tools[key]["recipes"]:
            self.recipe_box.current(0)

    def on_run(self) -> None:
        sel = self.area["tree"].selection()
        if not sel:
            messagebox.showinfo("Pick a tool", "Select a tool in the table first.")
            return
        key = sel[0]
        if not self.target or not os.path.exists(self.target):
            messagebox.showinfo("Target needed",
                                "Load a target file on the Overview page first.")
            return
        recipe = self.recipe_box.current()
        if recipe < 0:
            messagebox.showinfo("Pick a recipe", "Choose a recipe for this tool.")
            return

        def work(cb):
            return toolbridge.run_recipe(key, recipe, self.target)

        self.app.start_scan("tool", work, self.on_done)

    def on_done(self, result: dict) -> None:
        if not result.get("ok"):
            hint = result.get("error", "unknown error")
            widgets.set_text(self.out_text, f"[error] {hint}")
            self.out_text.tag_config("err", foreground=theme.DANGER)
            self.out_text.tag_add("err", "1.0", "1.end")
            return
        header = (f"$ {' '.join([result['tool']] + result['argv'])}\n"
                  f"# exit code {result['returncode']}"
                  + (" (output truncated)" if result.get("truncated") else "")
                  + "\n\n")
        widgets.set_text(self.out_text, header + result["stdout"]
                         + ("\n[stderr]\n" + result["stderr"] if result["stderr"] else ""))


# ---------------------------------------------------------------------------
class EvidencePage(PageBase):
    def build(self) -> None:
        widgets.page_header(
            self.frame, "Evidence Log",
            "Every analysis lands here automatically. Review results and "
            "export them as JSON or Markdown for your reports.")
        self.area = widgets.results_area(
            self.frame, tree_mode="table",
            columns=("time", "module", "target"),
            headers=("Time", "Module", "Target"), detail=False)
        self.detail = tk.Text(self.frame, height=12, bg=theme.PANEL, fg=theme.TEXT,
                              relief="flat", font=self.app.f["mono"], padx=10,
                              pady=8, state="disabled")
        self.detail.pack(fill="both", expand=True, padx=20, pady=(0, 10))
        self.area["tree"].bind("<<TreeviewSelect>>", self.on_select)
        widgets.export_bar(self.frame, [
            ("Export all (JSON)...", lambda: self.export("json")),
            ("Export all (Markdown)...", lambda: self.export("md")),
            ("Clear log", self.clear),
        ])

    def refresh(self) -> None:
        tree = self.area["tree"]
        widgets.clear_tree(tree)
        for entry in self.app.evidence.entries():
            tree.insert("", "end", iid=entry["id"],
                        values=(entry["time"], entry["module"],
                                entry["target"]))
        if not self.app.evidence.entries():
            tree.insert("", "end", values=("—", "empty", "run an analysis first"),
                        tags=("muted",))
        if tree.get_children():
            tree.selection_set(tree.get_children()[0])
        self.on_select()

    def on_select(self, _event=None) -> None:
        sel = self.area["tree"].selection()
        if not sel:
            return
        entry = self.app.evidence.get(sel[0])
        if entry:
            widgets.set_text(self.detail, json.dumps(entry, indent=2,
                                                     ensure_ascii=False,
                                                     default=str))

    def export(self, fmt: str) -> None:
        entries = self.app.evidence.entries()
        if not entries:
            messagebox.showinfo("Empty", "No evidence recorded yet.")
            return
        if fmt == "json":
            widgets.ask_save_json(self.app, "glassscope-evidence.json",
                                  self.app.evidence.entries())
        else:
            lines = ["# GlassScope Studio — evidence log", ""]
            for e in entries:
                lines.append(widgets_entry_md(e))
            widgets.ask_save_text(self.app, "glassscope-evidence.md", "\n".join(lines))

    def clear(self) -> None:
        if messagebox.askyesno("Clear log", "Delete all recorded evidence?"):
            self.app.evidence.clear()
            self.refresh()


def widgets_entry_md(entry: dict) -> str:
    import io
    buf = io.StringIO()
    buf.write(f"## {entry['module']} — {entry['target']}\n\n")
    buf.write(f"- id: `{entry['id']}`\n- time: {entry['time']}\n\n")
    for k, v in (entry.get("summary") or {}).items():
        buf.write(f"- {k}: {v}\n")
    buf.write("\n```json\n")
    buf.write(json.dumps(entry.get("data", {}), indent=1, default=str)[:4000])
    buf.write("\n```\n\n")
    return buf.getvalue()


# ---------------------------------------------------------------------------
class AboutPage(PageBase):
    def build(self) -> None:
        widgets.page_header(self.frame, "About", "")
        card = ttk.Frame(self.frame, style="Card.TFrame", padding=(24, 20))
        card.pack(fill="both", expand=True, padx=20, pady=(0, 12))
        if self.app.logo_img:
            tk.Label(card, image=self.app.logo_img, bg=theme.PANEL).pack(anchor="w")
        from glassscope_core import APP_NAME, APP_TAGLINE, __version__
        tk.Label(card, text=f"{APP_NAME}  v{__version__}", bg=theme.PANEL,
                 fg=theme.TEXT, font=self.app.f["h1"]).pack(anchor="w", pady=(8, 2))
        tk.Label(card, text=APP_TAGLINE, bg=theme.PANEL, fg=theme.MUTED,
                 font=self.app.f["base"]).pack(anchor="w")
        body = (
            "GlassScope Studio v1.1 Power Edition is a light, frosted-glass "
            "reverse engineering studio for Kali Linux. It covers the "
            "everyday static-analysis surface of REA (Reverse Engineer "
            "Anything, morluto/rea) as a native GUI — plus the Power "
            "Edition engines: a pure-Python x86/x64 + ARM64 disassembler "
            "(98% mnemonic match with objdump), a full Windows PE parser "
            "(sections, imports/exports, checksec mitigations, Rich "
            "header), Apple Mach-O/universal binaries and IPA triage, a "
            "hash lab (every stdlib digest + ssdeep-style fuzzy hashing + "
            "imphash), binary diff with patch lists, a 10-family IOC "
            "hunter (RAT signatures, C2 URLs, wallets, droppers, "
            "webshells), a crypto lab (XOR brute force, key-length "
            "scoring, recursive base64 decoding, embedded-key scans), "
            "JVM .class deep inspection, document triage (PDF/OLE/OOXML "
            "macro and launch-action review) and data stores (Windows "
            "registry hives, SQLite schemas).\n\n"
            "Every scan runs on pure Python with zero external "
            "dependencies and records evidence automatically. The "
            "Toolbox still drives the Kali tools you already have "
            "(file, strings, readelf, objdump, nm, ldd, binwalk, "
            "exiftool, checksec, rabin2, upx, apktool, jadx, aapt2, "
            "strace, ltrace, Ghidra headless) through fixed "
            "injection-safe recipes, and a headless CLI mode "
            "(glassscope --scan <module> <target>) runs any of the 33 "
            "scanners as JSON for pipelines. Dynamic work (live "
            "decompilation in Ghidra/IDA/Hopper, Frida/GDB runtime "
            "tracing) stays with those tools; GlassScope focuses on "
            "instant, local, evidence-first static analysis.\n\n"
            "Lineage: rebuilt from the REA codebase. Four verified "
            "upstream CLI bugs are documented in BUGFIXES.md and shipped "
            "as a patch (patches/rea-bugfixes.patch).\n\n"
            "Use responsibly: analyze only software you own or are "
            "explicitly authorized to examine. GlassScope performs "
            "local, static analysis and sends nothing anywhere.")
        tk.Label(card, text=body, bg=theme.PANEL, fg=theme.TEXT,
                 font=self.app.f["base"], justify="left", wraplength=760).pack(
            anchor="w", pady=(14, 0))



# ---------------------------------------------------------------------------
class BytesPage(PageBase):
    """Strings extraction + hexdump + entropy strip (REA byte inspection)."""

    HEX_WINDOW = 320  # bytes per hexdump view

    def build(self) -> None:
        widgets.page_header(
            self.frame, "Bytes & Strings",
            "Strings extraction with regex filtering and byte offsets, a "
            "navigable hexdump, and a sliding-window entropy map for packing "
            "and obfuscation detection — the low-level lens of the studio.")
        self.entry = widgets.target_bar(self.frame, self.app, self.on_run,
                                        run_label="Analyze bytes")
        opts = ttk.Frame(self.frame, style="Page.TFrame")
        opts.pack(fill="x", padx=20, pady=(0, 8))
        tk.Label(opts, text="min length:", bg=theme.BG, fg=theme.MUTED,
                 font=self.app.f["small"]).pack(side="left")
        self.minlen = ttk.Combobox(opts, width=4, state="readonly",
                                   values=("4", "6", "8", "12"))
        self.minlen.current(0)
        self.minlen.pack(side="left", padx=(6, 14))
        self.utf16_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(opts, text="UTF-16 mode", variable=self.utf16_var
                        ).pack(side="left", padx=(0, 14))
        tk.Label(opts, text="regex filter:", bg=theme.BG, fg=theme.MUTED,
                 font=self.app.f["small"]).pack(side="left")
        self.filter_entry = ttk.Entry(opts, width=26)
        self.filter_entry.pack(side="left", padx=(6, 0))
        self.strings_area = widgets.results_area(
            self.frame, tree_mode="table",
            columns=("offset", "enc", "string"),
            headers=("Offset", "Enc", "String"), height=7, detail=False)
        # hexdump viewer with navigation
        hexwrap = ttk.Frame(self.frame, style="Card.TFrame", padding=(12, 10))
        hexwrap.pack(fill="x", padx=20, pady=(0, 10))
        nav = ttk.Frame(hexwrap, style="Card.TFrame")
        nav.pack(fill="x")
        ttk.Button(nav, text="◀ -1 page", style="Soft.TButton",
                   command=lambda: self.hex_jump(-self.HEX_WINDOW)
                   ).pack(side="left")
        ttk.Button(nav, text="Start", style="Soft.TButton",
                   command=lambda: self.hex_jump(None)).pack(side="left", padx=6)
        ttk.Button(nav, text="+1 page ▶", style="Soft.TButton",
                   command=lambda: self.hex_jump(self.HEX_WINDOW)
                   ).pack(side="left")
        self.hex_label = tk.Label(nav, text="offset: 0", bg=theme.PANEL,
                                  fg=theme.MUTED, font=self.app.f["small"])
        self.hex_label.pack(side="left", padx=(14, 0))
        self.hex_text = tk.Text(hexwrap, height=12, bg=theme.PANEL,
                                fg=theme.TEXT, relief="flat",
                                font=self.app.f["mono"], padx=10, pady=8,
                                state="disabled")
        self.hex_text.pack(fill="both", expand=True, pady=(8, 0))
        # entropy strip
        ent = ttk.Frame(self.frame, style="Card.TFrame", padding=(12, 8))
        ent.pack(fill="x", padx=20, pady=(0, 10))
        self.ent_label = tk.Label(ent, text="entropy map:", bg=theme.PANEL,
                                  fg=theme.MUTED, font=self.app.f["small"])
        self.ent_label.pack(anchor="w")
        self.ent_canvas = tk.Canvas(ent, height=56, bg=theme.PANEL,
                                    highlightthickness=0)
        self.ent_canvas.pack(fill="both", expand=True, pady=(4, 0))
        widgets.export_bar(self.frame, [("Export strings (JSON)...",
                                         self.export_strings)])
        self._hex_offset = 0

    def on_run(self) -> None:
        target = self.entry.get().strip()
        if not target or not os.path.isfile(target):
            messagebox.showinfo("Target needed", "Choose a file first.")
            return
        self.app.current_target = target
        flt = self.filter_entry.get().strip()
        minlen = int(self.minlen.get())
        utf16 = self.utf16_var.get()

        def work(cb):
            res = bytescan.extract_strings(target, min_length=minlen,
                                           utf16=utf16, pattern=flt)
            res["entropy"] = bytescan.entropy_map(target)
            return res

        self.app.start_scan("bytes", work, self.on_done)
        self._hex_offset = 0
        self._render_hex(target)

    def _render_hex(self, target: str) -> None:
        res = bytescan.hexdump(target, self._hex_offset, self.HEX_WINDOW)
        if not res["ok"]:
            widgets.set_text(self.hex_text, "\n".join(res["errors"]))
            return
        self._hex_offset = res["offset"]
        rows = [f"{r['offset']:08x}  {r['hex']:<47}  |{r['ascii']}|"
                for r in res["rows"]]
        if res["has_before"]:
            rows.insert(0, "… (use ◀ to scroll up)")
        if res["has_after"]:
            rows.append("… (use ▶ to scroll down)")
        widgets.set_text(self.hex_text, "\n".join(rows))
        self.hex_label.config(text=f"offset: {self._hex_offset:#x} / "
                              f"{res['file_size']:#x}")

    def hex_jump(self, delta) -> None:
        target = self.entry.get().strip()
        if not target or not os.path.isfile(target):
            return
        if delta is None:
            self._hex_offset = 0
        else:
            self._hex_offset = max(0, self._hex_offset + delta)
        self._render_hex(target)

    def on_done(self, result: dict) -> None:
        self.last_result = {k: v for k, v in result.items() if k != "entropy"}
        tree = self.strings_area["tree"]
        widgets.clear_tree(tree)
        if not result.get("ok"):
            messagebox.showerror("Scan failed", "\n".join(result["errors"]))
            return
        for s in result.get("strings", [])[:5000]:
            tree.insert("", "end", values=(f"{s['offset']:#x}", s["encoding"],
                                           s["text"][:200]), tags=("muted",))
        if result.get("truncated"):
            tree.insert("", "end", values=("", "", "… list truncated"),)
        ent = result.get("entropy") or {}
        self._draw_entropy(ent)

    def _draw_entropy(self, ent: dict) -> None:
        canvas = self.ent_canvas
        canvas.delete("all")
        if not ent.get("ok") or not ent.get("points"):
            self.ent_label.config(text="entropy map: no data")
            return
        pts = ent["points"]
        w = max(canvas.winfo_width(), 400)
        h = max(canvas.winfo_height(), 40)
        bw = max(1, w // len(pts))
        for i, v in enumerate(pts):
            bh = int((v / 8.0) * h)
            color = theme.ACCENT if v < 7.0 else theme.WARN
            canvas.create_rectangle(i * bw, h - bh, (i + 1) * bw, h,
                                    fill=color, width=0)
        self.ent_label.config(
            text=f"entropy map: avg {ent['avg']} · max {ent['max']} · "
                 f"high-entropy windows {(ent['high_ratio'] * 100):.0f}%"
                 f"{'  — looks packed/compressed' if ent['high_ratio'] > 0.6 else ''}")

    def export_strings(self) -> None:
        if not self.last_result:
            messagebox.showinfo("Nothing to export", "Run a scan first.")
            return
        widgets.ask_save_json(self.app, "glassscope-strings.json",
                              self.last_result)


# ---------------------------------------------------------------------------
class AndroidPage(PageBase):
    """APK / JAR / DEX analysis (REA inspect-android-package parity)."""

    def build(self) -> None:
        widgets.page_header(
            self.frame, "Android & Java",
            "APK, AAB and JAR packages: AndroidManifest.xml decoded straight "
            "from Android binary XML (package, SDK levels, permissions, "
            "components), DEX header statistics, signature files (v1 META-INF "
            "and the v2/v3 signing block) and Maven metadata hints.")
        self.entry = widgets.target_bar(self.frame, self.app, self.on_run)
        self.area = widgets.results_area(self.frame, tree_mode="tree")
        widgets.export_bar(self.frame, [("Export JSON...", self.export_json)])

    def on_run(self) -> None:
        target = self.entry.get().strip()
        if not target or not os.path.isfile(target):
            messagebox.showinfo("Target needed",
                                "Choose an APK/AAB/JAR file first.")
            return
        self.app.current_target = target

        def work(cb):
            lower = target.lower()
            if lower.endswith((".apk", ".aab", ".apks", ".xapk")):
                res = android.apk_info(target)
                if res["ok"] and res["dex_files"]:
                    dexres = android.dex_header(target, res["dex_files"][0])
                    if dexres["ok"]:
                        res["dex_header"] = dexres
            elif lower.endswith((".jar", ".war")):
                res = android.jar_manifest(target)
            elif lower.endswith((".dex",)):
                res = android.dex_header(target)
                res["format"] = "dex-standalone"
            else:
                res = {"ok": False, "errors": [
                    "unsupported: pick an .apk/.aab/.jar/.war/.dex file"]}
            return res

        self.app.start_scan("android", work, self.on_done)

    def on_done(self, result: dict) -> None:
        self.last_result = result
        tree = self.area["tree"]
        widgets.clear_tree(tree)
        self.area["detail_data"] = {}
        if not result.get("ok"):
            widgets.set_text(self.area["text"],
                             "Could not parse the package.\n\n" +
                             "\n".join(result.get("errors", [])))
            return
        fmt = result.get("format")
        if fmt == "jar":
            root = tree.insert("", "end", text=f"JAR — Main-Class: "
                               f"{result.get('main_class') or '(none)'}")
            for k, v in (result.get("attributes") or {}).items():
                tree.insert(root, "end", text=f"{k}: {v}", tags=("muted",))
            sig = tree.insert(root, "end", text="v1 signatures")
            for s in result.get("signatures_v1", []):
                tree.insert(sig, "end", text=s, tags=("ok",))
        elif fmt == "dex-standalone":
            root = tree.insert("", "end", text="Standalone DEX")
            self._dex_nodes(tree, root, result)
        else:
            man = result.get("manifest", {})
            root = tree.insert("", "end",
                               text=f"{fmt.upper()} — {man.get('package', '?')} "
                                    f"v{man.get('versionName', '?')} "
                                    f"(code {man.get('versionCode', '?')})")
            sdk = tree.insert(root, "end", text="SDK levels")
            tree.insert(sdk, "end", text=f"minSdk: {man.get('minSdk', '?')}")
            tree.insert(sdk, "end", text=f"targetSdk: {man.get('targetSdk', '?')}")
            flags = tree.insert(root, "end", text="App flags")
            tree.insert(flags, "end",
                        text=f"debuggable: {man.get('debuggable', '?')}",
                        tags=("warn",) if man.get("debuggable") == "true"
                        else ("ok",))
            tree.insert(flags, "end",
                        text=f"allowBackup: {man.get('allowBackup', '(unset)')}")
            perm = tree.insert(root, "end",
                               text=f"Permissions ({len(result['permissions'])})")
            for p in result["permissions"][:200]:
                tree.insert(perm, "end", text=p, tags=("muted",))
            comp = tree.insert(root, "end",
                               text=f"Components ({len(result['components'])})")
            for c in result["components"][:200]:
                exp = c.get("exported", "")
                tag = "warn" if exp == "true" else "muted"
                iid = tree.insert(comp, "end",
                                  text=f"{c['type']}: {c['name']}"
                                       f"{'  (exported)' if exp == 'true' else ''}",
                                  tags=(tag,))
                self.area["detail_data"][iid] = json.dumps(c, indent=2)
            sig = tree.insert(root, "end", text="Signing")
            v2 = result.get("signed_v2")
            tree.insert(sig, "end", text="v2/v3 APK Signing Block: "
                        + ("present" if v2 else "not found"),
                        tags=("ok",) if v2 else ("warn",))
            for s in result.get("signatures_v1", [])[:10]:
                tree.insert(sig, "end", text=f"v1: {s}", tags=("ok",))
            dex = tree.insert(root, "end",
                              text=f"DEX files ({len(result['dex_files'])})")
            for d in result["dex_files"][:20]:
                tree.insert(dex, "end", text=d, tags=("muted",))
            dh = result.get("dex_header")
            if dh:
                dn = tree.insert(dex, "end",
                                 text=f"{dh['dex_files'][0] if dh.get('dex_files') else 'classes.dex'} header")
                self._dex_nodes(tree, dn, dh)
            if result.get("native_libs"):
                lib = tree.insert(root, "end",
                                  text=f"Native libs ({len(result['native_libs'])})")
                for l in result["native_libs"][:50]:
                    tree.insert(lib, "end", text=l, tags=("muted",))
            if result.get("maven"):
                mv = tree.insert(root, "end", text="Maven metadata")
                for m in result["maven"]:
                    tree.insert(mv, "end", text=m, tags=("ok",))
        widgets.set_text(self.area["text"],
                         "Select a node for details. Exported components "
                         "without permission guards are worth reviewing first.")

    def _dex_nodes(self, tree, parent, dh: dict) -> None:
        for label, key in (("strings", "string_ids"), ("types", "type_ids"),
                           ("protos", "proto_ids"), ("fields", "field_ids"),
                           ("methods", "method_ids"), ("classes", "class_defs")):
            tree.insert(parent, "end", text=f"{label}: {dh.get(key, '?')}",
                        tags=("muted",))

    def export_json(self) -> None:
        if not self.last_result:
            messagebox.showinfo("Nothing to export", "Run an analysis first.")
            return
        widgets.ask_save_json(self.app, "glassscope-android.json",
                              self.last_result)


# ---------------------------------------------------------------------------
class ManagedPage(PageBase):
    """.NET assemblies, il2cpp metadata (REA dotnet / inspect-il parity)."""

    def build(self) -> None:
        widgets.page_header(
            self.frame, ".NET & Managed",
            "PE/CLR inspection for .NET assemblies: runtime version, IL-only "
            "and strong-name flags, metadata streams and table row counts — "
            "plus Unity il2cpp global-metadata detection.")
        self.entry = widgets.target_bar(self.frame, self.app, self.on_run)
        self.area = widgets.results_area(self.frame, tree_mode="tree")
        widgets.export_bar(self.frame, [("Export JSON...", self.export_json)])

    def on_run(self) -> None:
        target = self.entry.get().strip()
        if not target or not os.path.isfile(target):
            messagebox.showinfo("Target needed",
                                "Choose a .NET assembly or global-metadata.dat.")
            return
        self.app.current_target = target
        lower = target.lower()

        def work(cb):
            if os.path.basename(lower) == "global-metadata.dat":
                return dotnet.global_metadata_info(target)
            return dotnet.dotnet_info(target)

        self.app.start_scan("dotnet", work, self.on_done)

    def on_done(self, result: dict) -> None:
        self.last_result = result
        tree = self.area["tree"]
        widgets.clear_tree(tree)
        self.area["detail_data"] = {}
        if not result.get("ok"):
            widgets.set_text(self.area["text"],
                             "Could not parse as .NET/managed.\n\n" +
                             "\n".join(result.get("errors", [])) +
                             "\n\nFor il2cpp metadata, name the file "
                             "global-metadata.dat or pick it directly.")
            return
        if result.get("format") == "il2cpp-metadata":
            root = tree.insert("", "end",
                               text=f"il2cpp global-metadata — version "
                                    f"{result['metadata_version']}")
            tree.insert(root, "end", text="Unity il2cpp metadata blob "
                        "detected (magic 0xFAB11BAF)", tags=("ok",))
        else:
            root = tree.insert("", "end",
                               text=f".NET assembly — {result.get('machine')} "
                                    f"({result.get('pe_format')})")
            rt = tree.insert(root, "end", text="Runtime")
            tree.insert(rt, "end", text=f"runtime version: "
                        f"{result.get('runtime_version')}")
            tree.insert(rt, "end", text=f"IL-only: {result.get('il_only')}")
            tree.insert(rt, "end", text=f"strong-name signed: "
                        f"{result.get('strong_name_signed')}")
            md = tree.insert(root, "end",
                             text=f"Metadata ({result.get('metadata_version')})")
            streams = tree.insert(md, "end",
                                  text=f"Streams ({len(result.get('streams', []))})")
            for s in result.get("streams", []):
                iid = tree.insert(streams, "end",
                                  text=f"{s['name']} — {s['size']} B",
                                  tags=("muted",))
                self.area["detail_data"][iid] = json.dumps(s, indent=2)
            tables = tree.insert(md, "end", text="Table row counts")
            for t in result.get("tables", []):
                tree.insert(tables, "end",
                            text=f"{t['table']}: {t['rows']} rows",
                            tags=("ok",))
            secs = tree.insert(root, "end",
                               text=f"Sections ({len(result.get('sections', []))})")
            for s in result.get("sections", []):
                tree.insert(secs, "end", text=s, tags=("muted",))
        for w in result.get("warnings", []):
            tree.insert("", "end", text=f"warning: {w}", tags=("warn",))
        widgets.set_text(self.area["text"],
                         "Tip: high TypeDef/MethodDef counts with no "
                         "AssemblyRef rows can indicate statically-linked "
                         "or AOT-compiled payloads.")

    def export_json(self) -> None:
        if not self.last_result:
            messagebox.showinfo("Nothing to export", "Run an analysis first.")
            return
        widgets.ask_save_json(self.app, "glassscope-dotnet.json",
                              self.last_result)


# ---------------------------------------------------------------------------
class FirmwarePage(PageBase):
    """Firmware & format zoo (REA firmware domain + generic artifacts)."""

    def build(self) -> None:
        widgets.page_header(
            self.frame, "Firmware & Formats",
            "One button, the whole zoo: devicetrees (DTB/FIT), U-Boot legacy "
            "images, ESP flash images, Apple IPS, Godot PCK, Erlang BEAM, "
            "Deno/Bun standalone binaries, .NET single-file bundles, kernel "
            "hints, WASM, Go buildinfo, Dart snapshots, EVM, ML models — plus "
            "embedded-file carving for anything else.")
        self.entry = widgets.target_bar(self.frame, self.app, self.on_run,
                                        run_label="Inspect format")
        self.area = widgets.results_area(self.frame, tree_mode="tree")
        widgets.export_bar(self.frame, [("Export JSON...", self.export_json)])

    def on_run(self) -> None:
        target = self.entry.get().strip()
        if not target or not os.path.isfile(target):
            messagebox.showinfo("Target needed", "Choose a file first.")
            return
        self.app.current_target = target

        def work(cb):
            cb("dispatching…")
            res = formats.detect_format(target)
            res["carve"] = formats.carve_signatures(target)
            parsers = [
                ("android", android.apk_info, (target,)),
                ("dotnet", dotnet.dotnet_info, (target,)),
                ("dtb", firmware.parse_dtb_bytes, (target,)),
                ("fit", firmware.fit_image_info, (target,)),
                ("uboot", firmware.uboot_legacy_info, (target,)),
                ("esp", firmware.esp_image_info, (target,)),
                ("ips", firmware.apple_ips_info, (target,)),
                ("pck", firmware.godot_pck_info, (target,)),
                ("beam", firmware.beam_info, (target,)),
                ("deno_bun", firmware.deno_bun_info, (target,)),
                ("bundle", firmware.dotnet_bundle_info, (target,)),
                ("kernel", firmware.kernel_hints, (target,)),
                ("wasm", formats.wasm_info, (target,)),
                ("go", formats.go_buildinfo, (target,)),
                ("dart", formats.dart_snapshot_info, (target,)),
                ("evm", formats.evm_hints, (target,)),
                ("model", formats.model_info, (target,)),
            ]
            results = {}
            for name, fn, args in parsers:
                try:
                    r = fn(*args)
                    if r.get("ok"):
                        results[name] = r
                except Exception as exc:  # never kill the zoo on one parser
                    results[name] = {"ok": False,
                                     "errors": [f"{type(exc).__name__}: {exc}"]}
                cb(name)
            res["parsers"] = results
            return res

        self.app.start_scan("firmware", work, self.on_done)

    def on_done(self, result: dict) -> None:
        self.last_result = result
        tree = self.area["tree"]
        widgets.clear_tree(tree)
        self.area["detail_data"] = {}
        det = result.get("detect", result)
        label = det.get("label", "unknown")
        root = tree.insert("", "end",
                           text=f"Detected: {label} ({det.get('size', 0)} bytes)")
        self.area["detail_data"][root] = json.dumps(
            {k: v for k, v in det.items() if k != "parsers"}, indent=2)
        for name, r in (result.get("parsers") or {}).items():
            if not r.get("ok"):
                continue
            node = tree.insert("", "end", text=f"{name}: {r.get('format', '')}")
            self._flat(tree, node, r)
        carve = result.get("carve") or {}
        cnode = tree.insert("", "end",
                            text=f"Embedded signatures ({carve.get('hit_count', 0)})")
        for h in carve.get("hits", [])[:200]:
            iid = tree.insert(cnode, "end",
                              text=f"{h['signature']} @ {h['offset']:#x}",
                              tags=("ok",))
            self.area["detail_data"][iid] = json.dumps(h, indent=2)
        widgets.set_text(self.area["text"],
                         "Every parser that matched the file is listed; "
                         "embedded-file hits show where child files start.")

    def _flat(self, tree, parent, r: dict, depth: int = 0) -> None:
        if depth > 2:
            return
        for k, v in r.items():
            if k in ("ok", "warnings", "errors", "format"):
                continue
            if isinstance(v, dict):
                sub = tree.insert(parent, "end", text=str(k), tags=("muted",))
                self._flat(tree, sub, v, depth + 1)
            elif isinstance(v, list):
                if not v:
                    continue
                sub = tree.insert(parent, "end",
                                  text=f"{k} ({len(v)})", tags=("muted",))
                for item in v[:60]:
                    if isinstance(item, dict):
                        iid = tree.insert(sub, "end", text=self._one(item))
                        self.area["detail_data"][iid] = json.dumps(item, indent=2)
                    else:
                        tree.insert(sub, "end", text=str(item)[:120])
            else:
                tree.insert(parent, "end", text=f"{k}: {v}")

    def _one(self, item: dict) -> str:
        for key in ("path", "name", "fuse", "ip", "signature", "host", "index"):
            if key in item:
                extra = item.get("state") or item.get("count") or \
                    item.get("size") or ""
                return f"{item[key]}{'  ' + str(extra) if extra else ''}"
        return next(iter(item.values()) if item else ["?"])

    def export_json(self) -> None:
        if not self.last_result:
            messagebox.showinfo("Nothing to export", "Run an analysis first.")
            return
        widgets.ask_save_json(self.app, "glassscope-firmware.json",
                              self.last_result)
