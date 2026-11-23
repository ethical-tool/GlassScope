"""Reusable light-theme widgets shared by all GlassScope pages."""

from __future__ import annotations

import json
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from . import theme


def page_header(parent: ttk.Frame, title: str, subtitle: str) -> None:
    tk.Label(parent, text=title, bg=theme.BG, fg=theme.TEXT,
             font=theme.fonts()["h2"]).pack(anchor="w", padx=20, pady=(4, 0))
    tk.Label(parent, text=subtitle, bg=theme.BG, fg=theme.MUTED,
             font=theme.fonts()["small"], wraplength=940,
             justify="left").pack(anchor="w", padx=20, pady=(0, 8))


def target_bar(parent: ttk.Frame, app, on_run: callable, run_label: str = "Analyze",
               allow_url: bool = False) -> ttk.Frame:
    """Row: target entry + browse buttons + run + cancel."""
    bar = ttk.Frame(parent, style="Card.TFrame", padding=(12, 10))
    bar.pack(fill="x", padx=20, pady=(0, 10))
    entry = ttk.Entry(bar)
    entry.grid(row=0, column=0, sticky="ew")
    bar.columnconfigure(0, weight=1)

    if allow_url:
        ttk.Button(bar, text="Paste URL", style="Ghost.TButton",
                   command=lambda: _paste_from_clipboard(entry)).grid(
            row=0, column=1, padx=(8, 0))
    else:
        def _pick_file() -> None:
            path = filedialog.askopenfilename(title="Choose target file")
            if path:
                entry.delete(0, "end")
                entry.insert(0, path)

        def _pick_dir() -> None:
            path = filedialog.askdirectory(title="Choose target folder")
            if path:
                entry.delete(0, "end")
                entry.insert(0, path)

        ttk.Button(bar, text="File...", style="Ghost.TButton",
                   command=_pick_file).grid(row=0, column=1, padx=(8, 0))
        ttk.Button(bar, text="Folder...", style="Ghost.TButton",
                   command=_pick_dir).grid(row=0, column=2, padx=(8, 0))

    run_btn = ttk.Button(bar, text=run_label, style="Accent.TButton",
                         command=lambda: on_run())
    run_btn.grid(row=0, column=3, padx=(10, 0))
    cancel_btn = ttk.Button(bar, text="Cancel", style="Soft.TButton",
                            command=app.cancel_scan)
    cancel_btn.grid(row=0, column=4, padx=(8, 0))

    progress = ttk.Progressbar(bar, style="Light.Horizontal.TProgressbar",
                               mode="indeterminate", length=140)
    # grid it once, then remove: grid_remove remembers the layout, so
    # app._set_progress() can restore it with a bare .grid() during a scan
    progress.grid(row=0, column=5, padx=(10, 0))
    progress.grid_remove()
    if not hasattr(app, "progress_bars"):
        app.progress_bars = []
    app.progress_bars.append(progress)
    return entry


def _paste_from_clipboard(entry: ttk.Entry) -> None:
    try:
        text = entry.clipboard_get()
        entry.delete(0, "end")
        entry.insert(0, text.strip())
    except tk.TclError:
        pass


def results_area(parent: ttk.Frame, tree_mode: str, columns: tuple[str, ...] = (),
                 headers: tuple[str, ...] = (),
                 detail: bool = True, height: int = 8) -> dict:
    """Left: Treeview (tree or table) — right: optional detail text pane."""
    wrap = ttk.Frame(parent, style="Card.TFrame")
    wrap.pack(fill="both", expand=True, padx=20, pady=(0, 10))

    body = ttk.Frame(wrap, style="Card.TFrame")
    body.pack(fill="both", expand=True)
    body.rowconfigure(0, weight=1)
    body.columnconfigure(0, weight=1)
    if detail:
        body.columnconfigure(1, weight=1)

    if tree_mode == "tree":
        tree = ttk.Treeview(body, show="tree", selectmode="browse")
    else:
        tree = ttk.Treeview(body, show="headings", selectmode="browse",
                            columns=columns)
        for col, head in zip(columns, headers):
            tree.heading(col, text=head)
            tree.column(col, anchor="w", stretch=True)
    tree.grid(row=0, column=0, sticky="nsew", padx=(10, 8), pady=10)
    tree.tag_configure("sev-critical", foreground=theme.CRITICAL)
    tree.tag_configure("sev-high", foreground=theme.HIGH)
    tree.tag_configure("sev-medium", foreground=theme.MEDIUM)
    tree.tag_configure("sev-low", foreground=theme.LOW)
    tree.tag_configure("muted", foreground=theme.MUTED)
    tree.tag_configure("ok", foreground=theme.SUCCESS)
    tree.tag_configure("warn", foreground=theme.WARN)
    tree.tag_configure("err", foreground=theme.DANGER)

    vsb = ttk.Scrollbar(body, orient="vertical", command=tree.yview)
    tree.configure(yscrollcommand=vsb.set)
    vsb.grid(row=0, column=0, sticky="ens", pady=10)

    out = {"tree": tree, "wrap": wrap}
    if detail:
        pane = ttk.Frame(body, style="Card.TFrame")
        pane.grid(row=0, column=1, sticky="nsew", padx=(0, 10), pady=10)
        text = tk.Text(pane, width=42, height=height, wrap="word",
                       bg=theme.PANEL, fg=theme.TEXT, relief="flat",
                       font=theme.fonts()["mono"], padx=10, pady=8,
                       state="disabled")
        text.pack(fill="both", expand=True)
        tvsb = ttk.Scrollbar(pane, orient="vertical", command=text.yview)
        text.configure(yscrollcommand=tvsb.set)
        tvsb.pack(side="right", fill="y")
        out["text"] = text

    def on_select(_event=None):
        if not detail:
            return
        sel = tree.selection()
        if not sel:
            return
        payload = out["detail_data"].get(sel[0], "")  # set by callers
        set_text(out["text"], payload if isinstance(payload, str)
                 else json.dumps(payload, indent=2, ensure_ascii=False, default=str))

    out["detail_data"] = {}
    tree.bind("<<TreeviewSelect>>", on_select)
    return out


def set_text(widget: tk.Text, content: str) -> None:
    widget.config(state="normal")
    widget.delete("1.0", "end")
    widget.insert("1.0", content)
    widget.config(state="disabled")


def clear_tree(tree: ttk.Treeview) -> None:
    for item in tree.get_children():
        tree.delete(item)


def card(parent: ttk.Frame) -> ttk.Frame:
    c = ttk.Frame(parent, style="Card.TFrame", padding=(12, 10))
    c.pack(fill="x", padx=20, pady=(0, 10))
    return c


def card_row(c: ttk.Frame, label: str, value: str, col: int, row: int,
             span: int = 1) -> None:
    tk.Label(c, text=label, bg=theme.PANEL, fg=theme.MUTED,
             font=theme.fonts()["small"]).grid(
        column=col, row=row, sticky="w", padx=(0, 6), pady=1)
    tk.Label(c, text=value, bg=theme.PANEL, fg=theme.TEXT,
             font=theme.fonts()["bold"], wraplength=420, justify="left").grid(
        column=col + 1, row=row, sticky="w", columnspan=span, pady=1)


def export_bar(parent: ttk.Frame, callbacks: list[tuple[str, callable]]) -> ttk.Frame:
    bar = ttk.Frame(parent, style="Page.TFrame")
    bar.pack(fill="x", padx=20, pady=(0, 12))
    for label, cb in callbacks:
        ttk.Button(bar, text=label, style="Soft.TButton", command=cb).pack(
            side="left", padx=(0, 8))
    return bar


def ask_save_json(app, default_name: str, data) -> bool:
    path = filedialog.asksaveasfilename(
        title="Save evidence as JSON", defaultextension=".json",
        initialfile=default_name, filetypes=[("JSON", "*.json")])
    if not path:
        return False
    try:
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2, ensure_ascii=False, default=str)
        app.set_status(f"Saved: {path}")
        messagebox.showinfo("Saved", f"Evidence saved to:\n{path}")
        return True
    except OSError as exc:
        messagebox.showerror("Save failed", str(exc))
        return False


def ask_save_text(app, default_name: str, content: str) -> bool:
    path = filedialog.asksaveasfilename(
        title="Save report", defaultextension=".md", initialfile=default_name,
        filetypes=[("Markdown", "*.md"), ("Text", "*.txt"), ("All files", "*")])
    if not path:
        return False
    try:
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(content)
        app.set_status(f"Saved: {path}")
        messagebox.showinfo("Saved", f"Report saved to:\n{path}")
        return True
    except OSError as exc:
        messagebox.showerror("Save failed", str(exc))
        return False
