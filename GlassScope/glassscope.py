#!/usr/bin/env python3
"""GlassScope Studio launcher (Power Edition).

- Enforces the Kali Linux only requirement (see README.md).
- Optional developer escape hatch: --allow-any-os (for testing on other
  systems; the packaged app does not advertise it).
- Headless mode: `glassscope --scan <module> <target>` runs any scanner
  without a display and prints JSON to stdout (--out <file> to save).
- Optional --version, a positional target for the GUI, and --list-scans.
"""

from __future__ import annotations

import argparse
import json
import os
import sys

# make the package importable when launched from any working directory
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from glassscope_core import APP_NAME, __version__, util  # noqa: E402


def _firmware_auto(target: str) -> dict:
    """Format zoo auto-dispatch (mirrors the Firmware page logic)."""
    from glassscope_core import (android, dotnet, firmware, formats)

    res = formats.detect_format(target)
    res["carve"] = formats.carve_signatures(target)
    parsers = [
        ("android", android.apk_info),
        ("dotnet", dotnet.dotnet_info),
        ("dtb", firmware.parse_dtb_bytes),
        ("fit", firmware.fit_image_info),
        ("uboot", firmware.uboot_legacy_info),
        ("esp", firmware.esp_image_info),
        ("ips", firmware.apple_ips_info),
        ("pck", firmware.godot_pck_info),
        ("beam", firmware.beam_info),
        ("deno_bun", firmware.deno_bun_info),
        ("bundle", firmware.dotnet_bundle_info),
        ("kernel", firmware.kernel_hints),
        ("wasm", formats.wasm_info),
        ("go", formats.go_buildinfo),
        ("dart", formats.dart_snapshot_info),
        ("evm", formats.evm_hints),
        ("model", formats.model_info),
    ]
    results = {}
    for name, fn in parsers:
        try:
            r = fn(target)
            if r.get("ok"):
                results[name] = r
        except Exception as exc:  # never kill the zoo on one parser
            results[name] = {"ok": False,
                             "errors": [f"{type(exc).__name__}: {exc}"]}
    res["parsers"] = results
    return res


def _scan_registry() -> dict[str, callable]:
    """Map module names to one-argument scan callables."""
    from glassscope_core import (android, asar, bytescan, cryptolab,
                                 disasm, documents, dotnet, elf, formats,
                                 hashing, iocs, jclass, macho, pe, registry,
                                 sqlitefs)

    def _disasm_auto(target: str) -> dict:
        head = util.safe_read_head(target, 16)
        arch = disasm.detect_arch(head)
        if arch in ("arm64be",):
            arch = "arm64"
        elif arch == "unknown":
            arch = "x64"
        with open(target, "rb") as fh:
            data = fh.read(4096)
        rows = disasm.disassemble(data, arch, base=0, limit=1024)
        return {"ok": True, "arch": arch,
                "instructions": [r["text"] for r in rows[:1024]],
                "summary": disasm.summarize_code(rows)}

    reg = {
        "elf": elf.parse_elf,
        "pe": pe.parse_pe,
        "macho": macho.parse_macho,
        "ipa": macho.ipa_info,
        "asar": asar.parse_asar,
        "apk": android.apk_info,
        "dex": android.dex_header,
        "jar": android.jar_manifest,
        "dotnet": dotnet.dotnet_info,
        "il2cpp": dotnet.global_metadata_info,
        "class": jclass.parse_class,
        "firmware": _firmware_auto,
        "formats": formats.detect_format,
        "carve": formats.carve_signatures,
        "wasm": formats.wasm_info,
        "gobuild": formats.go_buildinfo,
        "strings": bytescan.extract_strings,
        "hexdump": bytescan.hexdump,
        "entropy": bytescan.entropy_map,
        "disasm": _disasm_auto,
        "hashes": hashing.hashes,
        "fuzzy": hashing.fuzzy_hash,
        "imphash": hashing.imphash,
        "symhash": hashing.elf_symhash,
        "iocs": iocs.scan_target,
        "crypto": cryptolab.identify_crypto,
        "xor": cryptolab.xor_analysis,
        "keys": cryptolab.find_embedded_keys,
        "pdf": documents.pdf_info,
        "ole": documents.ole_info,
        "ooxml": documents.ooxml_info,
        "registry": registry.parse_registry,
        "sqlite": sqlitefs.sqlite_info,
    }
    return reg


def run_headless(module: str, target: str, out_file: str | None) -> int:
    """Run one scanner headlessly; print/save JSON."""
    reg = _scan_registry()
    fn = reg.get(module)
    if fn is None:
        print(f"unknown scan module: {module}", file=sys.stderr)
        print("run with --list-scans for available modules", file=sys.stderr)
        return 2
    if not os.path.exists(target):
        print(f"target does not exist: {target}", file=sys.stderr)
        return 2
    try:
        result = fn(target)
    except Exception as exc:  # headless must never traceback at the user
        print(f"scan failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1
    payload = json.dumps(result, indent=2, ensure_ascii=False, default=str)
    if out_file:
        with open(out_file, "w", encoding="utf-8") as fh:
            fh.write(payload + "\n")
        print(f"wrote {out_file}")
    else:
        print(payload)
    ok = result.get("ok") if isinstance(result, dict) else None
    return 0 if (ok is None or ok) else 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="glassscope",
        description=f"{APP_NAME} — light-themed reverse engineering studio "
        "for Kali Linux, with a headless scan mode.",
        epilog="For lawful analysis of software you own or are authorized "
        "to examine.")
    parser.add_argument("target", nargs="?", default=None,
                        help="optional target to preload (file, folder or URL)")
    parser.add_argument("--version", "-v", action="version",
                        version=f"{APP_NAME} {__version__}")
    parser.add_argument("--allow-any-os", action="store_true",
                        help=argparse.SUPPRESS)  # developer escape hatch
    parser.add_argument("--scan", metavar="MODULE",
                        help="headless: run MODULE on TARGET, print JSON")
    parser.add_argument("--out", metavar="FILE",
                        help="with --scan: write JSON to FILE instead of "
                        "stdout")
    parser.add_argument("--list-scans", action="store_true",
                        help="list the available headless scan modules")
    args = parser.parse_args(argv)

    if args.list_scans:
        mods = sorted(_scan_registry())
        print(f"{APP_NAME} headless scan modules ({len(mods)}):")
        print("  " + "  ".join(mods))
        return 0

    if args.scan:
        if not args.target:
            print("--scan needs a TARGET argument", file=sys.stderr)
            return 2
        return run_headless(args.scan, args.target, args.out)

    if not args.allow_any_os and not util.is_kali_linux():
        # import tkinter lazily so the refusal works even without a toolkit
        print(f"{APP_NAME}: this tool runs on Kali Linux only.", file=sys.stderr)
        print(f"Detected operating system: {util.os_release_pretty()}", file=sys.stderr)
        print("Install GlassScope on Kali Linux, or run with --allow-any-os if "
              "you are a developer testing the app.", file=sys.stderr)
        return 2

    try:
        import tkinter  # noqa: F401
    except ImportError:
        print("python3-tk is required for the GUI: sudo apt install python3-tk",
              file=sys.stderr)
        return 3

    from glassscope_gui.app import GlassScopeApp

    import tkinter as tk
    try:
        root = tk.Tk()
    except tk.TclError as exc:
        if "no display" in str(exc).lower() or "can't connect" in str(exc).lower():
            print(f"{APP_NAME} needs a graphical session (X11/Wayland). "
                  "Run it from the desktop, or check DISPLAY.", file=sys.stderr)
            return 4
        raise
    app = GlassScopeApp(root)
    if args.target:
        app.set_target(args.target)
    try:
        root.mainloop()
    except KeyboardInterrupt:
        return 130
    return 0


if __name__ == "__main__":
    sys.exit(main())
