"""GlassScope light theme — icy frosted-glass palette, enforced everywhere.

Dark themes are intentionally NOT provided (product requirement): this module
is the single source of truth for all colors, fonts and ttk widget styles.
The v2 look is an icy cyan-teal glass design with pill navigation; no code
outside this module may hardcode a color.
"""

from __future__ import annotations

import tkinter as tk
import tkinter.font as tkfont

# --- palette (icy glass: pale cyan whites, deep teal accent) ---------------
BG = "#F1F6F8"          # window background (icy pale cyan-white)
PANEL = "#FFFFFF"       # cards / results
NAV_BG = "#E7F0F4"      # navigation strip behind the pill bar
NAV_PILL = "#FFFFFF"    # idle pill background
NAV_HOVER = "#D8EDF2"   # hover pill background
BORDER = "#D3E2E8"
TEXT = "#15252E"
MUTED = "#5A707C"
ACCENT = "#0E8FA8"      # primary icy teal
ACCENT_HOVER = "#0C7C91"
ACCENT_SOFT = "#D8EDF2"
ACCENT_TEXT = "#0B6F85"
GLASS_TINT = "#EAF5F7"  # subtle tinted panel variant
SUCCESS = "#0E9F6E"
WARN = "#B25E09"
DANGER = "#C0392B"
CRITICAL = "#B42318"
HIGH = "#DC6803"
MEDIUM = "#9A6700"
LOW = "#1E7FA8"

SEVERITY_COLORS = {
    "critical": CRITICAL,
    "high": HIGH,
    "medium": MEDIUM,
    "low": LOW,
}

FONT_FAMILY = "DejaVu Sans"


def _pick_family(root: tk.Misc, candidates: list[str], fallback: str) -> str:
    """First installed family from candidates (Tk has no fallback chains)."""
    try:
        available = set(tkfont.families(root))
    except tk.TclError:
        return fallback
    for name in candidates:
        if name in available:
            return name
    return fallback


_FONT_CACHE: dict[str, tkfont.Font] | None = None


def fonts(root: tk.Misc | None = None) -> dict[str, tkfont.Font]:
    """Build (once) and return the font set, choosing families that actually
    exist on this system (Kali ships DejaVu Sans via Xft; minimal X builds
    fall back to Nimbus Sans / fixed bitmap fonts)."""
    global _FONT_CACHE
    if _FONT_CACHE is not None:
        return _FONT_CACHE
    sans = _pick_family(
        root,
        ["DejaVu Sans", "Noto Sans", "Nimbus Sans", "Nimbus Sans L",
         "Helvetica", "Arial"],
        "fixed")
    mono = _pick_family(
        root,
        ["DejaVu Sans Mono", "Noto Sans Mono", "Nimbus Mono PS",
         "Liberation Mono", "Courier 10 Pitch", "Courier"],
        "fixed")
    _FONT_CACHE = {
        "base": tkfont.Font(root=root, family=sans, size=10),
        "small": tkfont.Font(root=root, family=sans, size=9),
        "bold": tkfont.Font(root=root, family=sans, size=10, weight="bold"),
        "h1": tkfont.Font(root=root, family=sans, size=17, weight="bold"),
        "h2": tkfont.Font(root=root, family=sans, size=12, weight="bold"),
        "mono": tkfont.Font(root=root, family=mono, size=9),
    }
    return _FONT_CACHE


def apply(root: tk.Tk, f: dict[str, tkfont.Font]) -> None:
    """Configure ttk styles + base option database for the light theme."""
    import tkinter.ttk as ttk

    root.option_add("*Font", f["base"])
    root.option_add("*foreground", TEXT)
    root.option_add("*background", BG)
    root.option_add("*Entry.background", PANEL)
    root.option_add("*Entry.foreground", TEXT)
    root.option_add("*Text.background", PANEL)
    root.option_add("*Text.foreground", TEXT)

    style = ttk.Style(root)
    try:
        style.theme_use("clam")
    except tk.TclError:
        pass

    style.configure(".", background=BG, foreground=TEXT, borderwidth=0,
                    focuscolor=ACCENT)

    # Frames
    style.configure("Card.TFrame", background=PANEL, relief="flat")
    style.configure("Page.TFrame", background=BG)
    style.configure("Header.TFrame", background=PANEL)
    style.configure("Nav.TFrame", background=NAV_BG)
    style.configure("Glass.TFrame", background=GLASS_TINT)

    # Labels
    style.configure("Card.TLabel", background=PANEL, foreground=TEXT)
    style.configure("Muted.TLabel", background=PANEL, foreground=MUTED,
                    font=f["small"])
    style.configure("H2.TLabel", background=PANEL, foreground=TEXT, font=f["h2"])
    style.configure("PageTitle.TLabel", background=BG, foreground=TEXT, font=f["h2"])
    style.configure("Chip.TLabel", background=ACCENT_SOFT, foreground=ACCENT_TEXT,
                    font=f["small"], padding=(8, 2))

    # Buttons — flat, generous padding, light hover
    style.configure("Accent.TButton", background=ACCENT, foreground="#FFFFFF",
                    padding=(16, 7), borderwidth=0, font=f["bold"])
    style.map("Accent.TButton",
              background=[("active", ACCENT_HOVER), ("pressed", "#0A6B7E"),
                          ("disabled", "#A5CDD6")],
              foreground=[("disabled", "#EDF6F8")])
    style.configure("Soft.TButton", background=PANEL, foreground=ACCENT_TEXT,
                    padding=(12, 6), borderwidth=1,
                    lightcolor=PANEL, darkcolor=BORDER)
    style.map("Soft.TButton",
              background=[("active", ACCENT_SOFT)],
              bordercolor=[("!active", BORDER), ("active", ACCENT)])
    style.configure("Ghost.TButton", background=BG, foreground=TEXT,
                    padding=(10, 6), borderwidth=0)
    style.map("Ghost.TButton", background=[("active", "#E2EEF2")])

    # Entry / Combobox
    style.configure("TEntry", fieldbackground=PANEL, foreground=TEXT,
                    lightcolor=PANEL, darkcolor=BORDER,
                    borderwidth=1, padding=5)
    style.map("TEntry",
              lightcolor=[("focus", ACCENT)], darkcolor=[("focus", ACCENT)])
    style.configure("TCombobox", fieldbackground=PANEL, foreground=TEXT,
                    background=PANEL, lightcolor=PANEL, darkcolor=BORDER,
                    borderwidth=1, padding=4)
    style.map("TCombobox", fieldbackground=[("readonly", PANEL)],
              foreground=[("readonly", TEXT)])

    # Checkbutton
    style.configure("TCheckbutton", background=PANEL, foreground=TEXT)
    style.configure("Page.TCheckbutton", background=BG, foreground=TEXT)

    # Treeview — airy rows on white
    style.configure("Treeview", background=PANEL, fieldbackground=PANEL,
                    foreground=TEXT, rowheight=26, borderwidth=0, font=f["base"])
    style.configure("Treeview.Heading", background="#E7F0F4", foreground=TEXT,
                    font=f["bold"], padding=(8, 6), borderwidth=0)
    style.map("Treeview", background=[("selected", ACCENT_SOFT)],
              foreground=[("selected", ACCENT_TEXT)])
    style.map("Treeview.Heading", background=[("active", "#DAE9EE")])

    # Progressbar
    style.configure("Light.Horizontal.TProgressbar", background=ACCENT,
                    troughcolor="#DFEBEF", borderwidth=0, thickness=8)

    # Scrollbars — slim and light
    style.configure("Vertical.TScrollbar", background="#D8E6EC",
                    troughcolor=BG, borderwidth=0, arrowsize=12)
    style.configure("Horizontal.TScrollbar", background="#D8E6EC",
                    troughcolor=BG, borderwidth=0, arrowsize=12)


def severity_tag(color: str) -> str:
    return color
