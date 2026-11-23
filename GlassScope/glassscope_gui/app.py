"""GlassScope Studio main application shell (v2 look).

Layout: white header band (logo + title), icy pill navigation bar across the
top, stacked pages, bottom status bar. All scans run in worker threads;
results come back through a queue and are marshalled onto the Tk main loop
with after().
"""

from __future__ import annotations

import os
import queue
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from glassscope_core import APP_NAME, APP_TAGLINE, __version__
from glassscope_core.report import EvidenceLog

from . import theme
from .pages import (
    AboutPage, AndroidPage, AsarPage, BinaryPage, BytesPage, EvidencePage,
    FirmwarePage, JsPage, ManagedPage, OverviewPage, ToolboxPage, WebsitePage,
)
from .pages2 import (
    CryptoPage, DataStoresPage, DiffPage, DisasmPage, DocsPage, HashPage,
    IOCPage, JavaClassPage, MachOPage, PEPage,
)


class ScanCancelled(Exception):
    pass


class ScanThread(threading.Thread):
    """Run one scan in the background; post status/result into a queue."""

    def __init__(self, name: str, fn, out_q: queue.Queue, cancel: threading.Event):
        super().__init__(daemon=True, name=f"scan-{name}")
        self.fn = fn
        self.out_q = out_q
        self.cancel = cancel

    def run(self) -> None:
        def progress_cb(done, total=None):
            if self.cancel.is_set():
                raise ScanCancelled()
            if total:
                self.out_q.put(("status", f"{done}/{total}"))
            else:
                self.out_q.put(("status", str(done)))

        try:
            self.out_q.put(("status", "running..."))
            result = self.fn(progress_cb)
            self.out_q.put(("done", result))
        except ScanCancelled:
            self.out_q.put(("cancelled", None))
        except Exception as exc:  # never let a scan kill the GUI
            self.out_q.put(("error", f"{type(exc).__name__}: {exc}"))


class GlassScopeApp:
    # Power Edition: 22 scanner pages in two nav rows of 11 pills each.
    PAGES = [
        ("overview", "Overview"),
        ("binary", "Binary"),
        ("bytes", "Bytes"),
        ("disasm", "Disasm"),
        ("pe", "PE"),
        ("macho", "Mach-O"),
        ("asar", "ASAR"),
        ("android", "Android"),
        ("jclass", "Java"),
        ("managed", ".NET"),
        ("firmware", "Firmware"),
        ("hash", "Hash"),
        ("diff", "Diff"),
        ("iocs", "IOC"),
        ("crypto", "Crypto"),
        ("docs", "Docs"),
        ("stores", "Stores"),
        ("js", "JavaScript"),
        ("website", "Website"),
        ("toolbox", "Toolbox"),
        ("evidence", "Evidence"),
        ("about", "About"),
    ]
    PAGE_TITLES = {
        "overview": "Overview",
        "binary": "Binary Inspector",
        "bytes": "Bytes & Strings",
        "disasm": "Disassembler",
        "pe": "PE Inspector",
        "macho": "Mach-O & iOS",
        "asar": "ASAR & Electron",
        "android": "Android & Java",
        "jclass": "Java Classes",
        "managed": ".NET & Managed",
        "firmware": "Firmware & Formats",
        "hash": "Hash Lab",
        "diff": "Binary Diff",
        "iocs": "IOC Hunter",
        "crypto": "Crypto Lab",
        "docs": "Document Triage",
        "stores": "Data Stores",
        "js": "JavaScript Scan",
        "website": "Website Scan",
        "toolbox": "Toolbox",
        "evidence": "Evidence Log",
        "about": "About",
    }

    def __init__(self, root: tk.Tk):
        self.root = root
        self.f = theme.fonts(root)
        theme.apply(root, self.f)
        self.out_q: queue.Queue = queue.Queue()
        self.current_thread: ScanThread | None = None
        self.cancel_event = threading.Event()
        self.evidence = EvidenceLog()
        self.current_target: str | None = None
        self.logo_img: tk.PhotoImage | None = None
        self.nav_active: str | None = None

        root.title(f"{APP_NAME} {__version__}")
        root.geometry("1200x760")
        root.minsize(980, 620)
        root.configure(bg=theme.BG)
        self._load_logo()
        self._build_menu()
        self._build_layout()
        self._poll_queue()
        self.show_page("overview")

    # ------------------------------------------------------------------
    def _load_logo(self) -> None:
        candidates = [
            os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                         "assets", "logo_64.ppm"),
            "/usr/share/pixmaps/glassscope.ppm",
            "/opt/glassscope/assets/logo_64.ppm",
        ]
        for path in candidates:
            if os.path.isfile(path):
                try:
                    img = tk.PhotoImage(file=path)
                    # scale to ~44px header height
                    h = max(1, int(img.height()))
                    target = 44
                    if h > target:
                        img = img.subsample(max(1, h // target))
                    self.logo_img = img
                    return
                except tk.TclError:
                    continue

    def _build_menu(self) -> None:
        menubar = tk.Menu(self.root, bg=theme.PANEL, fg=theme.TEXT,
                          activebackground=theme.ACCENT_SOFT,
                          activeforeground=theme.ACCENT_TEXT)
        file_menu = tk.Menu(menubar, tearoff=0, bg=theme.PANEL, fg=theme.TEXT,
                            activebackground=theme.ACCENT_SOFT)
        file_menu.add_command(label="Open target file...", command=self.browse_file)
        file_menu.add_command(label="Open target folder...", command=self.browse_dir)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.root.destroy)
        menubar.add_cascade(label="File", menu=file_menu)
        help_menu = tk.Menu(menubar, tearoff=0, bg=theme.PANEL, fg=theme.TEXT,
                            activebackground=theme.ACCENT_SOFT)
        help_menu.add_command(label="About", command=lambda: self.show_page("about"))
        menubar.add_cascade(label="Help", menu=help_menu)
        self.root.config(menu=menubar)

    # ------------------------------------------------------------------
    def _build_layout(self) -> None:
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(2, weight=1)

        # Header band: logo, name, tagline, version chip
        header = ttk.Frame(self.root, style="Header.TFrame", padding=(20, 14))
        header.grid(row=0, column=0, sticky="ew")
        header.columnconfigure(2, weight=1)
        if self.logo_img:
            tk.Label(header, image=self.logo_img, bg=theme.PANEL).grid(
                row=0, column=0, rowspan=2, padx=(0, 14))
        tk.Label(header, text=APP_NAME, bg=theme.PANEL, fg=theme.TEXT,
                 font=self.f["h1"]).grid(row=0, column=1, sticky="w")
        tk.Label(header, text=f"{APP_TAGLINE}  ·  Kali Linux edition",
                 bg=theme.PANEL, fg=theme.MUTED,
                 font=self.f["small"]).grid(row=1, column=1, sticky="w")
        tk.Label(header, text=f"v{__version__}", bg=theme.ACCENT_SOFT,
                 fg=theme.ACCENT_TEXT, font=self.f["small"], padx=10, pady=3
                 ).grid(row=0, column=2, sticky="e", rowspan=2, padx=6)

        # Pill navigation strip across the top — wraps into two rows for
        # the 22 Power Edition scanners
        navbar = ttk.Frame(self.root, style="Nav.TFrame", padding=(20, 8))
        navbar.grid(row=1, column=0, sticky="ew")
        self.nav_buttons: dict[str, tk.Label] = {}
        row = 0
        col = 0
        max_per_row = 11
        nav_grid = ttk.Frame(navbar, style="Nav.TFrame")
        nav_grid.pack(fill="x")
        for idx, (key, label) in enumerate(self.PAGES):
            if idx == max_per_row:
                row, col = 1, 0
            pill = self._nav_pill(nav_grid, key, label)
            pill.grid(row=row, column=col, padx=(0, 8) if col < 10 else 0,
                      pady=2, sticky="w")
            col += 1
            self.nav_buttons[key] = pill

        # Content pages
        self.pages_container = ttk.Frame(self.root, style="Page.TFrame")
        self.pages_container.grid(row=2, column=0, sticky="nsew")
        self.pages_container.rowconfigure(0, weight=1)
        self.pages_container.columnconfigure(0, weight=1)

        pages_cls = {
            "overview": OverviewPage, "binary": BinaryPage, "bytes": BytesPage,
            "disasm": DisasmPage, "pe": PEPage, "macho": MachOPage,
            "asar": AsarPage, "android": AndroidPage, "jclass": JavaClassPage,
            "managed": ManagedPage, "firmware": FirmwarePage,
            "hash": HashPage, "diff": DiffPage, "iocs": IOCPage,
            "crypto": CryptoPage, "docs": DocsPage, "stores": DataStoresPage,
            "js": JsPage, "website": WebsitePage, "toolbox": ToolboxPage,
            "evidence": EvidencePage, "about": AboutPage,
        }
        self.pages: dict[str, object] = {}
        for key, _label in self.PAGES:
            frame = ttk.Frame(self.pages_container, style="Page.TFrame")
            frame.grid(row=0, column=0, sticky="nsew")
            self.pages[key] = pages_cls[key](self, frame)

        # Status bar
        status = ttk.Frame(self.root, style="Header.TFrame", padding=(20, 6))
        status.grid(row=3, column=0, sticky="ew")
        status.columnconfigure(0, weight=1)
        self.status_var = tk.StringVar(value="Ready. Pick a target on the Overview page.")
        tk.Label(status, textvariable=self.status_var, bg=theme.PANEL,
                 fg=theme.MUTED, font=self.f["small"], anchor="w").grid(
            row=0, column=0, sticky="w")

    def _nav_pill(self, parent: ttk.Frame, key: str, label: str) -> tk.Label:
        pill = tk.Label(parent, text=label, bg=theme.NAV_PILL, fg=theme.MUTED,
                        font=self.f["bold"], anchor="center", padx=16, pady=7,
                        cursor="hand2")
        pill.bind("<Enter>", lambda e: pill.config(bg=theme.NAV_HOVER)
                  if self.nav_active != key else None)
        pill.bind("<Leave>", lambda e: pill.config(bg=theme.NAV_PILL)
                  if self.nav_active != key else None)
        pill.bind("<Button-1>", lambda e: self.show_page(key))
        return pill

    def show_page(self, key: str) -> None:
        self.nav_active = key
        for k, pill in self.nav_buttons.items():
            if k == key:
                pill.config(bg=theme.ACCENT, fg="#FFFFFF")
            else:
                pill.config(bg=theme.NAV_PILL, fg=theme.MUTED)
        page = self.pages[key]
        if hasattr(page, "refresh"):
            page.refresh()
        page.frame.tkraise()
        self.set_status(self.PAGE_TITLES[key])

    # ------------------------------------------------------------------
    def set_status(self, text: str) -> None:
        self.status_var.set(text)

    def browse_file(self) -> None:
        path = filedialog.askopenfilename(title="Choose a target file")
        if path:
            self.set_target(path)

    def browse_dir(self) -> None:
        path = filedialog.askdirectory(title="Choose a target folder")
        if path:
            self.set_target(path)

    def set_target(self, path: str) -> None:
        self.current_target = path
        self.pages["overview"].set_target(path)
        self.set_status(f"Target: {path}")

    # ------------------------------------------------------------------
    def start_scan(self, name: str, fn, on_done) -> None:
        if self.current_thread and self.current_thread.is_alive():
            messagebox.showinfo(
                "Busy", "A scan is already running. Please wait or cancel it.")
            return
        self.cancel_event = threading.Event()
        self.current_thread = ScanThread(name, fn, self.out_q, self.cancel_event)

        def wrapped_done(payload) -> None:
            try:
                summary = dict(payload.get("summary") or payload.get("stats") or {})
                warnings = payload.get("warnings") if isinstance(payload, dict) else None
                if warnings:
                    summary["warnings"] = len(warnings)
                self.evidence.add(module=name,
                                  target=self.current_target or "",
                                  summary=summary,
                                  data=payload)
            except (TypeError, ValueError, AttributeError):
                pass  # evidence logging must never break a scan result
            on_done(payload)

        self.current_thread.on_done = wrapped_done  # type: ignore[attr-defined]
        self.current_thread.start()
        self._set_progress(True)

    def _set_progress(self, running: bool) -> None:
        for bar in getattr(self, "progress_bars", []):
            try:
                if running:
                    bar.grid()
                    bar.start(12)
                else:
                    bar.stop()
                    bar.grid_remove()
            except tk.TclError:
                continue

    def cancel_scan(self) -> None:
        self.cancel_event.set()

    def _poll_queue(self) -> None:
        try:
            while True:
                kind, payload = self.out_q.get_nowait()
                thread = self.current_thread
                if kind == "status":
                    self.set_status(f"Working... {payload}" if payload else "Working...")
                elif kind in ("done", "error", "cancelled"):
                    self._set_progress(False)
                    if kind == "done":
                        self.set_status("Done.")
                        if thread is not None and hasattr(thread, "on_done"):
                            thread.on_done(payload)  # type: ignore[attr-defined]
                    elif kind == "error":
                        self.set_status("Scan failed.")
                        messagebox.showerror("Scan failed", str(payload))
                    else:
                        self.set_status("Scan cancelled.")
                    self.current_thread = None
        except queue.Empty:
            pass
        self.root.after(90, self._poll_queue)


# (launching lives in glassscope.py at the project root)


def run(allow_any_os: bool = False) -> int:
    """Convenience programmatic launcher (kept for tests and embedding)."""
    root = tk.Tk()
    GlassScopeApp(root)
    root.mainloop()
    return 0
