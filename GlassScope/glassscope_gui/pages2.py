"""GlassScope Power Edition pages: PE Inspector, Mach-O & iOS, Disassembler,
Hash Lab, Binary Diff, IOC Hunter, Crypto Lab, Java Classes, Documents,
Data Stores (registry/SQLite) and Toolbox extensions.

Each page follows the v1 contract: PageBase + build() + on_run/on_done via
app.start_scan, so scans stay threaded and evidence lands in the log.
"""

from __future__ import annotations

import json
import os
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from glassscope_core import (cryptolab, diffmod, disasm, documents, hashing,
                             iocs, jclass, macho, pe, registry, sqlitefs)
from glassscope_core import util as gsutil

from . import theme, widgets
from .pages import PageBase


# ---------------------------------------------------------------------------
class PEPage(PageBase):
    """Windows PE Inspector — the .NET page's native sibling."""

    def build(self) -> None:
        widgets.page_header(
            self.frame, "PE Inspector",
            "Native Windows binaries: COFF header, sections, imports, "
            "exports, resources, checksec-style mitigations, Rich header "
            "and version info — pure Python, no external tools.")
        self.entry = widgets.target_bar(self.frame, self.app, self.on_run,
                                        run_label="Analyze PE")
        self.area = widgets.results_area(self.frame, tree_mode="tree")
        widgets.export_bar(self.frame, [("Export JSON...", self.export_json)])

    def on_run(self) -> None:
        target = self.entry.get().strip()
        if not target or not os.path.isfile(target):
            messagebox.showinfo("Target needed", "Choose a PE file first.")
            return
        self.app.current_target = target

        def work(cb):
            return pe.parse_pe(target)

        self.app.start_scan("pe", work, self.on_done)

    def on_done(self, result: dict) -> None:
        self.last_result = result
        tree = self.area["tree"]
        widgets.clear_tree(tree)
        self.area["detail_data"] = {}
        if not result.get("ok"):
            widgets.set_text(self.area["text"],
                             "Not a PE file.\n" +
                             "\n".join(result.get("errors", [])))
            return
        h = result["header"]
        root = tree.insert("", "end",
                           text=f"PE {h['machine']} — "
                                f"{h['timestamp_human']}")
        self._leaf(tree, root, "Header", result.get("optional_header", {}))
        self._leaf(tree, root, "Characteristics", h.get("characteristics"))
        secs = tree.insert(root, "end",
                           text=f"Sections ({len(result.get('sections', []))})")
        for s in result.get("sections", []):
            n = tree.insert(secs, "end", text=f"{s['name']}  {s['virtual_address']}")
            self.area["detail_data"][n] = json.dumps(s, indent=2)
        imps = tree.insert(root, "end",
                           text=f"Imports ({result.get('import_count', 0)})")
        for d in result.get("imports", []):
            n = tree.insert(imps, "end",
                            text=f"{d['dll']} ({d['count']})")
            self.area["detail_data"][n] = json.dumps(d, indent=2)
        exps = result.get("exports") or {}
        enode = tree.insert(root, "end",
                            text=f"Exports ({len(exps.get('functions', []))})")
        if exps.get("name"):
            tree.insert(enode, "end", text=f"module: {exps['name']}")
        for f in exps.get("functions", [])[:200]:
            tree.insert(enode, "end", text=f.get("name", "?"))
        mit = tree.insert(root, "end", text="Mitigations (checksec)")
        for k, v in (result.get("mitigations") or {}).items():
            tag = "ok" if v else "muted"
            tree.insert(mit, "end", text=f"{k}: {'yes' if v else 'no'}",
                        tags=(tag,))
        if result.get("version_info"):
            vn = tree.insert(root, "end", text="Version info")
            for k, v in result["version_info"].items():
                tree.insert(vn, "end", text=f"{k}: {v}")
        if result.get("rich_header"):
            rh = tree.insert(root, "end", text="Rich header (MSVC)")
            for e in result["rich_header"].get("entries", [])[:24]:
                tree.insert(rh, "end", text=f"tool id {e['id']} build "
                            f"{e['build']} × {e['count']}")
        for w in result.get("warnings", []):
            tree.insert(root, "end", text=f"⚠ {w}", tags=("warn",))
        widgets.set_text(self.area["text"],
                         "Select a node for details. Mitigations: "
                         "NX/ASLR/CFG/ForceIntegrity flags from the "
                         "optional header + load config.")

    def _leaf(self, tree, parent, label, payload) -> None:
        n = tree.insert(parent, "end", text=label)
        self.area["detail_data"][n] = json.dumps(payload, indent=2,
                                                 default=str)

    def export_json(self) -> None:
        if not self.last_result:
            messagebox.showinfo("Nothing to export", "Run a scan first.")
            return
        widgets.ask_save_json(self.app, "glassscope-pe.json",
                              self.last_result)


# ---------------------------------------------------------------------------
class MachOPage(PageBase):
    """Apple Mach-O + universal binaries + IPA triage."""

    def build(self) -> None:
        widgets.page_header(
            self.frame, "Mach-O & iOS",
            "Apple binaries: thin and universal (fat) Mach-O headers, "
            "segments, sections, linked dylibs, code signature presence, "
            "plus IPA package triage (Info.plist, frameworks).")
        self.entry = widgets.target_bar(self.frame, self.app, self.on_run,
                                        run_label="Analyze Mach-O")
        self.area = widgets.results_area(self.frame, tree_mode="tree")
        widgets.export_bar(self.frame, [("Export JSON...", self.export_json)])

    def on_run(self) -> None:
        target = self.entry.get().strip()
        if not target or not os.path.isfile(target):
            messagebox.showinfo("Target needed",
                                "Choose a Mach-O / IPA file first.")
            return
        self.app.current_target = target

        def work(cb):
            res = macho.parse_macho(target)
            if target.lower().endswith(".ipa"):
                res["ipa"] = macho.ipa_info(target)
            return res

        self.app.start_scan("macho", work, self.on_done)

    def on_done(self, result: dict) -> None:
        self.last_result = result
        tree = self.area["tree"]
        widgets.clear_tree(tree)
        self.area["detail_data"] = {}
        if not result.get("ok"):
            widgets.set_text(self.area["text"],
                             "Not a Mach-O file.\n" +
                             "\n".join(result.get("errors", [])))
            return
        if result.get("universal"):
            root = tree.insert("", "end",
                               text=f"Universal Mach-O — "
                                    f"{result.get('slice_count', 0)} slices")
            for s in result.get("slices", []):
                n = tree.insert(root, "end",
                                text=f"{s['cpu_type']} @ {s['offset']:#x} "
                                     f"({s['size']} bytes)")
                self.area["detail_data"][n] = json.dumps(s, indent=2)
            first = result.get("first_slice") or {}
            if first:
                self._render_thin(tree, root, first, label="First slice: ")
        else:
            self._render_thin(tree, "", result)
        ipa = result.get("ipa")
        if ipa and ipa.get("ok"):
            inode = tree.insert("", "end", text="IPA package")
            for k, v in (ipa.get("info_plist") or {}).items():
                tree.insert(inode, "end", text=f"{k}: {v}")
            tree.insert(inode, "end",
                        text=f"entries: {ipa.get('entries')}")
            tree.insert(inode, "end",
                        text=f"macho payloads: {ipa.get('macho_payloads')}")
            if ipa.get("provisioning"):
                tree.insert(inode, "end", text="embedded.mobileprovision "
                            "present", tags=("ok",))
        for w in result.get("warnings", []):
            tree.insert("", "end", text=f"⚠ {w}", tags=("warn",))

    def _render_thin(self, tree, parent, res: dict, label: str = "") -> None:
        h = res.get("header", {})
        root = tree.insert(parent, "end",
                           text=f"{label}{h.get('magic', 'Mach-O')} — "
                                f"{h.get('cpu_type')}")
        n = tree.insert(root, "end", text="Header")
        self.area["detail_data"][n] = json.dumps(h, indent=2)
        segs = tree.insert(root, "end",
                           text=f"Segments ({res.get('segment_count', 0)})")
        for s in res.get("segments", []):
            n = tree.insert(segs, "end", text=f"{s['name']}  {s['vmaddr']}")
            self.area["detail_data"][n] = json.dumps(s, indent=2)
        libs = tree.insert(root, "end",
                           text=f"Linked dylibs "
                                f"({res.get('dylib_count', 0)})")
        for d in res.get("dylibs", [])[:100]:
            tree.insert(libs, "end", text=d, tags=("muted",))
        tree.insert(root, "end",
                    text="code signature: " + ("present" if res.get(
                        "has_code_signature") else "absent"),
                    tags=("ok",) if res.get("has_code_signature")
                    else ("muted",))
        if res.get("uuid"):
            tree.insert(root, "end", text=f"UUID: {res['uuid']}")
        if res.get("platform"):
            tree.insert(root, "end", text=f"platform: {res['platform']} "
                        f"min {res.get('minos')} SDK {res.get('sdk')}")

    def export_json(self) -> None:
        if not self.last_result:
            messagebox.showinfo("Nothing to export", "Run a scan first.")
            return
        widgets.ask_save_json(self.app, "glassscope-macho.json",
                              self.last_result)


# ---------------------------------------------------------------------------
class DisasmPage(PageBase):
    """Pure-Python disassembler front-end (x86/x64 + ARM64)."""

    WINDOW = 256  # instructions per page

    def build(self) -> None:
        widgets.page_header(
            self.frame, "Disassembler",
            "Decode raw code regions with the built-in x86/x64 and ARM64 "
            "engines (98% mnemonic match with objdump on real binaries). "
            "Pick a file, offset and length; targets with an ELF/PE/Mach-O "
            "magic are auto-routed to the right architecture.")
        self.entry = widgets.target_bar(self.frame, self.app, self.on_run,
                                        run_label="Disassemble")
        opts = ttk.Frame(self.frame, style="Page.TFrame")
        opts.pack(fill="x", padx=20, pady=(0, 8))
        tk.Label(opts, text="arch:", bg=theme.BG, fg=theme.MUTED,
                 font=self.app.f["small"]).pack(side="left")
        self.arch_box = ttk.Combobox(
            opts, width=10, state="readonly",
            values=("auto", "x86", "x64", "arm64"))
        self.arch_box.current(0)
        self.arch_box.pack(side="left", padx=(6, 14))
        tk.Label(opts, text="offset (hex):", bg=theme.BG, fg=theme.MUTED,
                 font=self.app.f["small"]).pack(side="left")
        self.offset_entry = ttk.Entry(opts, width=10)
        self.offset_entry.insert(0, "0")
        self.offset_entry.pack(side="left", padx=(6, 14))
        tk.Label(opts, text="bytes:", bg=theme.BG, fg=theme.MUTED,
                 font=self.app.f["small"]).pack(side="left")
        self.len_box = ttk.Combobox(opts, width=8, state="readonly",
                                    values=("256", "512", "1024", "4096"))
        self.len_box.current(1)
        self.len_box.pack(side="left", padx=(6, 0))
        self.area = widgets.results_area(
            self.frame, tree_mode="table",
            columns=("offset", "instruction"),
            headers=("Offset", "Instruction"), height=10, detail=False)
        self.mono = tk.Text(self.frame, height=4, bg=theme.PANEL,
                            fg=theme.TEXT, relief="flat",
                            font=self.app.f["mono"], padx=10, pady=8,
                            state="disabled")
        self.mono.pack(fill="x", padx=20, pady=(0, 10))
        widgets.export_bar(self.frame, [("Export JSON...", self.export_json)])

    def on_run(self) -> None:
        target = self.entry.get().strip()
        if not target or not os.path.isfile(target):
            messagebox.showinfo("Target needed", "Choose a code file first.")
            return
        self.app.current_target = target
        try:
            off = int(self.offset_entry.get(), 0)
        except ValueError:
            off = 0
        nbytes = int(self.len_box.get())
        arch = self.arch_box.get()

        def work(cb):
            with open(target, "rb") as fh:
                fh.seek(off)
                data = fh.read(nbytes)
            if arch == "auto":
                a = disasm.detect_arch(gsutil.safe_read_head(target, 16))
                if a in ("arm64be",):
                    a = "arm64"
                elif a == "unknown":
                    a = "x64"
            else:
                a = arch
            rows = disasm.disassemble(data, a, base=off, limit=4096)
            return {"ok": True, "arch": a, "rows": rows[:2048],
                    "summary": disasm.summarize_code(rows)}

        self.app.start_scan("disasm", work, self.on_done)

    def on_done(self, result: dict) -> None:
        self.last_result = result
        tree = self.area["tree"]
        widgets.clear_tree(tree)
        if not result.get("ok"):
            return
        for r in result.get("rows", []):
            tree.insert("", "end", values=(f"{r['offset']:#x}", r["text"]),
                        tags=("muted",))
        s = result.get("summary", {})
        top = list(s.get("mnemonics", {}).items())[:8]
        text = (f"arch: {result.get('arch')}  ·  "
                f"instructions: {s.get('instruction_count')}\n"
                f"top mnemonics: " +
                ", ".join(f"{m}×{c}" for m, c in top))
        widgets.set_text(self.mono, text)

    def export_json(self) -> None:
        if not self.last_result:
            messagebox.showinfo("Nothing to export", "Run a scan first.")
            return
        widgets.ask_save_json(self.app, "glassscope-disasm.json",
                              self.last_result)


# ---------------------------------------------------------------------------
class HashPage(PageBase):
    """Hash lab: digests, fuzzy similarity, imphash, symhash."""

    def build(self) -> None:
        widgets.page_header(
            self.frame, "Hash Lab",
            "Every stdlib digest (MD5→BLAKE2s), CRC32, ssdeep-style fuzzy "
            "hashing with similarity scoring, PE imphash and ELF symbol "
            "hash — for clustering and version correlation.")
        self.entry = widgets.target_bar(self.frame, self.app, self.on_run,
                                        run_label="Hash target")
        self.entry2 = widgets.target_bar(self.frame, self.app, self.on_run2,
                                         run_label="Fuzzy-compare A↔B")
        self.area = widgets.results_area(self.frame, tree_mode="table",
                                         columns=("algorithm", "value"),
                                         headers=("Algorithm", "Value"),
                                         height=8, detail=False)
        self.sim_text = tk.Text(self.frame, height=3, bg=theme.PANEL,
                                fg=theme.TEXT, relief="flat",
                                font=self.app.f["mono"], padx=10, pady=8,
                                state="disabled")
        self.sim_text.pack(fill="x", padx=20, pady=(0, 10))
        widgets.export_bar(self.frame, [("Export JSON...", self.export_json)])

    def on_run(self) -> None:
        target = self.entry.get().strip()
        if not target or not os.path.isfile(target):
            messagebox.showinfo("Target needed", "Choose a file first.")
            return
        self.app.current_target = target

        def work(cb):
            res = hashing.hashes(target)
            res["fuzzy"] = hashing.fuzzy_hash(target)
            head = gsutil.safe_read_head(target, 64)
            if head.startswith(b"MZ"):
                res["imphash"] = hashing.imphash(target)
            if head.startswith(b"\x7fELF"):
                res["symhash"] = hashing.elf_symhash(target)
            return res

        self.app.start_scan("hash", work, self.on_done)

    def on_run2(self) -> None:
        a = self.entry.get().strip()
        b = self.entry2.get().strip()
        if not (a and b and os.path.isfile(a) and os.path.isfile(b)):
            messagebox.showinfo("Two files needed",
                                 "Fill both target bars with files.")
            return

        def work(cb):
            return diffmod.fuzzy_files(a, b) if False else \
                hashing.fuzzy_files(a, b)

        self.app.start_scan("fuzzy", work, self.on_done2)

    def on_done(self, result: dict) -> None:
        self.last_result = result
        tree = self.area["tree"]
        widgets.clear_tree(tree)
        if not result.get("ok"):
            return
        for algo in ("md5", "sha1", "sha256", "sha384", "sha512",
                     "sha3_256", "sha3_512", "blake2b", "blake2s",
                     "crc32"):
            if result.get(algo):
                tree.insert("", "end", values=(algo, result[algo]),
                             tags=("muted",))
        fz = result.get("fuzzy") or {}
        if fz.get("ok"):
            tree.insert("", "end", values=(
                "fuzzy (ssdeep-style)",
                f"{fz.get('signature', '')}::{fz.get('signature2', '')}"))
        if result.get("imphash", {}).get("imphash"):
            tree.insert("", "end", values=(
                "imphash", result["imphash"]["imphash"]))
        if result.get("symhash", {}).get("symhash"):
            tree.insert("", "end", values=(
                "elf symhash", result["symhash"]["symhash"]))

    def on_done2(self, result: dict) -> None:
        if result.get("ok"):
            widgets.set_text(self.sim_text,
                             f"similarity: {result['similarity']}% "
                             f"(sig1 {result['similarity_signature1']}% / "
                             f"sig2 {result['similarity_signature2']}%)")
        else:
            widgets.set_text(self.sim_text, "comparison failed")

    def export_json(self) -> None:
        if not self.last_result:
            messagebox.showinfo("Nothing to export", "Run a scan first.")
            return
        widgets.ask_save_json(self.app, "glassscope-hashes.json",
                              self.last_result)


# ---------------------------------------------------------------------------
class DiffPage(PageBase):
    """Binary diff: block map, patch list, similarity."""

    def build(self) -> None:
        widgets.page_header(
            self.frame, "Binary Diff",
            "Byte-level comparison with equal/differing block ranges, a "
            "patch list and entropy deltas — malware versioning and patch "
            "auditing without external tools.")
        self.entry = widgets.target_bar(self.frame, self.app, self.on_run,
                                        run_label="Diff A")
        self.entry2 = widgets.target_bar(self.frame, self.app, self.on_run2,
                                         run_label="Diff B")
        self.area = widgets.results_area(self.frame, tree_mode="table",
                                          columns=("offset", "a", "b"),
                                          headers=("Offset", "A", "B"),
                                          height=10, detail=False)
        self.stats_text = tk.Text(self.frame, height=6, bg=theme.PANEL,
                                  fg=theme.TEXT, relief="flat",
                                  font=self.app.f["mono"], padx=10, pady=8,
                                  state="disabled")
        self.stats_text.pack(fill="x", padx=20, pady=(0, 10))
        widgets.export_bar(self.frame, [("Export JSON...", self.export_json)])

    def on_run(self) -> None:
        a = self.entry.get().strip()
        b = self.entry2.get().strip()
        if not (a and b and os.path.isfile(a) and os.path.isfile(b)):
            messagebox.showinfo("Two files needed",
                                "Fill both bars with files to diff.")
            return
        self.app.current_target = a

        def work(cb):
            res = diffmod.diff_files(a, b)
            res["patches"] = diffmod.patch_bytes(a, b)
            return res

        self.app.start_scan("bindiff", work, self.on_done)

    on_run2 = on_run

    def on_done(self, result: dict) -> None:
        self.last_result = {k: v for k, v in result.items()
                            if k != "patches"}
        tree = self.area["tree"]
        widgets.clear_tree(tree)
        if not result.get("ok"):
            return
        for p in (result.get("patches", {}) or {}).get("patches", [])[:500]:
            tree.insert("", "end",
                        values=(f"{p['offset']:#x}", f"0x{p['a']}",
                                f"0x{p['b']}"), tags=("muted",))
        stats = {k: result.get(k) for k in (
            "size_a_human", "size_b_human", "compared_bytes",
            "identical_bytes", "differing_bytes", "identical_ratio",
            "first_diff", "last_diff", "ranges_equal", "ranges_diff")}
        lines = [f"{k.replace('_', ' ')}: {v}"
                 for k, v in stats.items() if v is not None]
        for w in result.get("warnings", []):
            lines.append(f"⚠ {w}")
        widgets.set_text(self.stats_text, "\n".join(lines))

    def export_json(self) -> None:
        if not self.last_result:
            messagebox.showinfo("Nothing to export", "Run a scan first.")
            return
        widgets.ask_save_json(self.app, "glassscope-diff.json",
                              self.last_result)


# ---------------------------------------------------------------------------
class IOCPage(PageBase):
    """IOC hunter: rule-pack scan with severity tree."""

    def build(self) -> None:
        widgets.page_header(
            self.frame, "IOC Hunter",
            "Static threat hunting: RAT/stealer family signatures, C2 "
            "URLs and IPs, wallet addresses, dropper cradles, webshell "
            "markers, packed/high-entropy blobs and base64 payloads — "
            "file or folder, nothing executed.")
        self.entry = widgets.target_bar(self.frame, self.app, self.on_run,
                                        run_label="Hunt IOCs")
        self.area = widgets.results_area(self.frame, tree_mode="table",
                                         columns=("severity", "family",
                                                  "rule", "offset",
                                                  "evidence"),
                                         headers=("Severity", "Family",
                                                  "Rule", "Offset",
                                                  "Evidence"), height=10,
                                         detail=False)
        self.sum_text = tk.Text(self.frame, height=4, bg=theme.PANEL,
                                fg=theme.TEXT, relief="flat",
                                font=self.app.f["mono"], padx=10, pady=8,
                                state="disabled")
        self.sum_text.pack(fill="x", padx=20, pady=(0, 10))
        widgets.export_bar(self.frame, [("Export JSON...", self.export_json)])

    def on_run(self) -> None:
        target = self.entry.get().strip()
        if not target or not os.path.exists(target):
            messagebox.showinfo("Target needed",
                                "Choose a file or folder first.")
            return
        self.app.current_target = target

        def work(cb):
            return iocs.scan_target(target)

        self.app.start_scan("iocs", work, self.on_done)

    def on_done(self, result: dict) -> None:
        self.last_result = result
        tree = self.area["tree"]
        widgets.clear_tree(tree)
        if not result.get("ok"):
            return
        sevs = {"critical": "sev-critical", "high": "sev-high",
                "medium": "sev-medium", "low": "sev-low"}
        for f in result.get("findings", [])[:800]:
            tree.insert("", "end", values=(
                f["severity"], f["family"], f["rule"],
                f"{f['offset']:#x}" if isinstance(f.get("offset"), int)
                else "-", f["evidence"][:80]), tags=(sevs.get(
                    f["severity"], "muted"),))
        counts = result.get("counts_by_family", {})
        lines = [f"{fam}: {n}" for fam, n in list(counts.items())[:12]]
        widgets.set_text(self.sum_text,
                         "Family counts:\n" + "\n".join(lines)
                         if lines else "No IOCs found.")

    def export_json(self) -> None:
        if not self.last_result:
            messagebox.showinfo("Nothing to export", "Run a scan first.")
            return
        widgets.ask_save_json(self.app, "glassscope-iocs.json",
                              self.last_result)


# ---------------------------------------------------------------------------
class CryptoPage(PageBase):
    """Crypto lab page: markers, XOR analysis, embedded keys, decoders."""

    def build(self) -> None:
        widgets.page_header(
            self.frame, "Crypto Lab",
            "Cipher/container identification (PEM, LUKS, TrueCrypt, "
            "password-hash formats), single-byte and repeating-key XOR "
            "brute force with index-of-coincidence key-length scoring, "
            "recursive base64/hex/base32 decoding and embedded-key scans.")
        self.entry = widgets.target_bar(self.frame, self.app, self.on_run,
                                        run_label="Analyze crypto")
        self.area = widgets.results_area(self.frame, tree_mode="tree")
        widgets.export_bar(self.frame, [("Export JSON...", self.export_json)])

    def on_run(self) -> None:
        target = self.entry.get().strip()
        if not target or not os.path.isfile(target):
            messagebox.showinfo("Target needed", "Choose a file first.")
            return
        self.app.current_target = target

        def work(cb):
            res = cryptolab.identify_crypto(target)
            res["xor"] = cryptolab.xor_analysis(target)
            res["keys"] = cryptolab.find_embedded_keys(target)
            return res

        self.app.start_scan("crypto", work, self.on_done)

    def on_done(self, result: dict) -> None:
        self.last_result = result
        tree = self.area["tree"]
        widgets.clear_tree(tree)
        self.area["detail_data"] = {}
        if not result.get("ok"):
            return
        root = tree.insert("", "end", text="Crypto markers")
        for m in result.get("markers", []):
            tree.insert(root, "end",
                        text=f"{m['marker']} @ {m['offset']}",
                        tags=("muted",))
        xr = result.get("xor") or {}
        xroot = tree.insert("", "end", text="XOR analysis")
        tree.insert(xroot, "end", text=xr.get("verdict", "?"))
        for c in xr.get("single_byte_candidates", [])[:6]:
            tree.insert(xroot, "end", text=f"key {c['key']} "
                        f"({c['printable_ratio']} printable) → "
                        f"{c['preview'][:40]}")
        for kl in xr.get("likely_key_lengths", [])[:3]:
            tree.insert(xroot, "end", text=f"key length {kl['key_length']} "
                        f"IoC {kl['ioc']}")
        kr = result.get("keys") or {}
        kroot = tree.insert("", "end", text="Embedded keys")
        for k in kr.get("findings", [])[:40]:
            tree.insert(kroot, "end", text=f"{k['kind']} @ {k['offset']}")
        if not (result.get("markers") or (kr.get("findings"))):
            widgets.set_text(self.area["text"], "No crypto markers found.")

    def export_json(self) -> None:
        if not self.last_result:
            messagebox.showinfo("Nothing to export", "Run a scan first.")
            return
        widgets.ask_save_json(self.app, "glassscope-crypto.json",
                              self.last_result)


# ---------------------------------------------------------------------------
class JavaClassPage(PageBase):
    """JVM class deep-dive (constant-pool resolved names)."""

    def build(self) -> None:
        widgets.page_header(
            self.frame, "Java Classes",
            "JVM .class deep inspection: constant pool with resolved "
            "strings, access flags, fields, method descriptors, "
            "attributes and a decompile-style class signature.")
        self.entry = widgets.target_bar(self.frame, self.app, self.on_run,
                                        run_label="Parse class")
        self.area = widgets.results_area(self.frame, tree_mode="tree")
        widgets.export_bar(self.frame, [("Export JSON...", self.export_json)])

    def on_run(self) -> None:
        target = self.entry.get().strip()
        if not target or not os.path.isfile(target):
            messagebox.showinfo("Target needed", "Choose a .class file.")
            return
        self.app.current_target = target

        def work(cb):
            return jclass.parse_class(target)

        self.app.start_scan("jclass", work, self.on_done)

    def on_done(self, result: dict) -> None:
        self.last_result = result
        tree = self.area["tree"]
        widgets.clear_tree(tree)
        self.area["detail_data"] = {}
        if not result.get("ok"):
            widgets.set_text(self.area["text"],
                             "Not a Java class.\n" +
                             "\n".join(result.get("errors", [])))
            return
        cls = result.get("class", {})
        root = tree.insert("", "end", text=result.get("signature",
                                                     cls.get("name", "?")))
        n = tree.insert(root, "end", text="Class")
        self.area["detail_data"][n] = json.dumps(cls, indent=2)
        flds = tree.insert(root, "end",
                           text=f"Fields ({result.get('field_count', 0)})")
        for f in result.get("fields", []):
            n = tree.insert(flds, "end", text=f"{f.get('name')} "
                            f"{f.get('descriptor')}")
            self.area["detail_data"][n] = json.dumps(f, indent=2)
        mths = tree.insert(root, "end",
                           text=f"Methods ({result.get('method_count', 0)})")
        for m in result.get("methods", []):
            n = tree.insert(mths, "end", text=f"{m.get('name')} "
                            f"{m.get('descriptor')}")
            self.area["detail_data"][n] = json.dumps(m, indent=2)
        attrs = tree.insert(root, "end", text="Attributes")
        for a in result.get("class_attributes", []):
            tree.insert(attrs, "end", text=str(a), tags=("muted",))

    def export_json(self) -> None:
        if not self.last_result:
            messagebox.showinfo("Nothing to export", "Run a scan first.")
            return
        widgets.ask_save_json(self.app, "glassscope-class.json",
                              self.last_result)


# ---------------------------------------------------------------------------
class DocsPage(PageBase):
    """Document triage: PDF / OLE / OOXML risk review."""

    def build(self) -> None:
        widgets.page_header(
            self.frame, "Document Triage",
            "PDF, OLE2 and OOXML risk triage: JavaScript and launch "
            "actions, embedded files, suspicious URI schemes, VBA macro "
            "presence and external relationships — nothing rendered or "
            "executed.")
        self.entry = widgets.target_bar(self.frame, self.app, self.on_run,
                                        run_label="Triage document")
        self.area = widgets.results_area(self.frame, tree_mode="tree")
        widgets.export_bar(self.frame, [("Export JSON...", self.export_json)])

    def on_run(self) -> None:
        target = self.entry.get().strip()
        if not target or not os.path.isfile(target):
            messagebox.showinfo("Target needed", "Choose a document first.")
            return
        self.app.current_target = target

        def work(cb):
            return documents.document_dispatch(target)

        self.app.start_scan("docs", work, self.on_done)

    def on_done(self, result: dict) -> None:
        self.last_result = result
        tree = self.area["tree"]
        widgets.clear_tree(tree)
        self.area["detail_data"] = {}
        if not result.get("ok"):
            widgets.set_text(self.area["text"],
                             "Could not triage.\n" +
                             "\n".join(result.get("errors", [])))
            return
        kind = result.get("kind")
        root = tree.insert("", "end", text=f"{kind.upper()} triage")
        for k in ("pdf_version", "pages_hint", "objects", "streams",
                  "javascript_hits", "action_hits", "embedded_hits",
                  "uri_scheme_hits", "startxref_count", "eof_markers",
                  "encrypted", "known_streams", "has_vba", "vba_markers",
                  "parts", "media_files", "embeddings",
                  "external_relationships", "ole_objects"):
            if result.get(k) not in (None, 0, []):
                n = tree.insert(root, "end", text=f"{k}: {result[k]}")
                if k in ("javascript_hits", "action_hits", "has_vba",
                         "external_relationships"):
                    n and tree.item(n, tags=("warn",))
        meta = result.get("metadata") or result.get("info_plist") or {}
        for k, v in meta.items():
            tree.insert(root, "end", text=f"{k}: {v}")
        verdict = result.get("verdict")
        if verdict:
            tag = ("sev-high",) if verdict == "high-risk" else (
                ("sev-medium",) if verdict == "suspicious" else ("ok",))
            tree.insert("", "end", text=f"Verdict: {verdict} "
                        f"(risk {result.get('risk_score')})", tags=tag)
        for w in result.get("warnings", []):
            tree.insert("", "end", text=f"⚠ {w}", tags=("warn",))

    def export_json(self) -> None:
        if not self.last_result:
            messagebox.showinfo("Nothing to export", "Run a scan first.")
            return
        widgets.ask_save_json(self.app, "glassscope-document.json",
                              self.last_result)


# ---------------------------------------------------------------------------
class DataStoresPage(PageBase):
    """Registry hives + SQLite databases in one forensic page."""

    def build(self) -> None:
        widgets.page_header(
            self.frame, "Data Stores",
            "Windows registry hives (REGF) and SQLite databases: header, "
            "key tree with values, page/freelist structure and schema "
            "inventory — read-only forensic triage.")
        self.entry = widgets.target_bar(self.frame, self.app, self.on_run,
                                        run_label="Open store")
        self.area = widgets.results_area(self.frame, tree_mode="tree")
        widgets.export_bar(self.frame, [("Export JSON...", self.export_json)])

    def on_run(self) -> None:
        target = self.entry.get().strip()
        if not target or not os.path.isfile(target):
            messagebox.showinfo("Target needed",
                                "Choose a hive (.dat) or database file.")
            return
        self.app.current_target = target
        with open(target, "rb") as fh:
            magic = fh.read(16)

        def work(cb):
            if magic.startswith(b"regf") or magic.startswith(b"hive"):
                return registry.parse_registry(target)
            return sqlitefs.sqlite_info(target)

        self.app.start_scan("stores", work, self.on_done)

    def on_done(self, result: dict) -> None:
        self.last_result = result
        tree = self.area["tree"]
        widgets.clear_tree(tree)
        self.area["detail_data"] = {}
        if not result.get("ok"):
            widgets.set_text(self.area["text"],
                             "Not a registry hive or SQLite db.\n" +
                             "\n".join(result.get("errors", [])))
            return
        if "keys" in result:  # registry
            hdr = result.get("header", {})
            root = tree.insert("", "end",
                               text=f"Registry hive — {hdr.get('last_modified')}")
            n = tree.insert(root, "end", text="Header")
            self.area["detail_data"][n] = json.dumps(hdr, indent=2)
            tree.insert(root, "end", text=f"keys: {result.get('key_count')}")
            for k in result.get("keys", [])[:400]:
                kn = tree.insert(root, "end", text=k["path"],
                                 open=False)
                self.area["detail_data"][kn] = json.dumps(
                    {"values": k.get("values")}, indent=2)
        else:  # sqlite
            hdr = result.get("header", {})
            root = tree.insert("", "end", text="SQLite database")
            n = tree.insert(root, "end", text="Header")
            self.area["detail_data"][n] = json.dumps(hdr, indent=2)
            for t in result.get("tables", [])[:100]:
                tn = tree.insert(root, "end",
                                 text=f"{t['name']} ({t['type']})")
                self.area["detail_data"][tn] = json.dumps(t, indent=2)
            if result.get("freelist_bytes"):
                tree.insert(root, "end",
                            text=f"freelist: {result['freelist_bytes']} bytes",
                            tags=("warn",))

    def export_json(self) -> None:
        if not self.last_result:
            messagebox.showinfo("Nothing to export", "Run a scan first.")
            return
        widgets.ask_save_json(self.app, "glassscope-store.json",
                              self.last_result)
