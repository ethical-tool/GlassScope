"""Evidence report store: every scan lands here; export as JSON or Markdown."""

from __future__ import annotations

import json
import os
import threading
from datetime import datetime


class EvidenceLog:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._entries: list[dict] = []

    def add(self, module: str, target: str, summary: dict, data: dict) -> str:
        with self._lock:
            entry = {
                "id": f"{datetime.now().strftime('%Y%m%d-%H%M%S')}-{len(self._entries)+1:03d}",
                "time": datetime.now().isoformat(timespec="seconds"),
                "module": module,
                "target": target,
                "summary": summary,
                "data": data,
            }
            self._entries.insert(0, entry)  # newest first
            return entry["id"]

    def entries(self) -> list[dict]:
        with self._lock:
            return list(self._entries)

    def get(self, entry_id: str) -> dict | None:
        with self._lock:
            for e in self._entries:
                if e["id"] == entry_id:
                    return e
        return None

    def clear(self) -> None:
        with self._lock:
            self._entries.clear()

    # -- exports -----------------------------------------------------------
    def export_json(self, path: str, entry_id: str | None = None) -> int:
        entries = self.entries()
        if entry_id:
            one = self.get(entry_id)
            entries = [one] if one else []
        os.makedirs(os.path.dirname(os.path.abspath(path)) or ".", exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(entries, fh, indent=2, ensure_ascii=False, default=str)
        return len(entries)

    @staticmethod
    def _entry_markdown(entry: dict) -> str:
        lines = [
            f"## {entry['module']} — {os.path.basename(str(entry['target'])) or entry['target']}",
            "",
            f"- **Evidence ID**: `{entry['id']}`",
            f"- **Time**: {entry['time']}",
            f"- **Target**: `{entry['target']}`",
            "",
        ]
        for key, value in (entry.get("summary") or {}).items():
            lines.append(f"- **{key}**: {value}")
        warnings = entry.get("data", {}).get("warnings") or []
        if warnings:
            lines += ["", "### Warnings", ""]
            lines += [f"- {w}" for w in warnings[:20]]
        lines.append("")
        return "\n".join(lines)

    def export_markdown(self, path: str, entry_id: str | None = None) -> int:
        entries = self.entries()
        if entry_id:
            one = self.get(entry_id)
            entries = [one] if one else []
        os.makedirs(os.path.dirname(os.path.abspath(path)) or ".", exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("# GlassScope Studio — Analysis Evidence\n\n")
            for e in entries:
                fh.write(self._entry_markdown(e))
        return len(entries)
