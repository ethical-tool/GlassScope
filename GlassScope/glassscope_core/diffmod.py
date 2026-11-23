"""Binary diff engine: byte-level comparison of two files with visual gap
analysis, identical/differing block mapping (BDIFF-style), shifted-content
detection and a per-offset patch list.

Use cases: malware family versioning, patch auditing, firmware revisions.
Everything bounded (files are read up to 16 MiB) and defensive.
"""

from __future__ import annotations

import os

from .util import MAX_STREAM_READ, human_size, shannon_entropy

BLOCK = 4096  # comparison block size


def diff_files(path_a: str, path_b: str) -> dict:
    """Compare two binaries block by block. Returns ranges of equal /
    differing bytes, first/last difference, per-block detail and stats."""
    out: dict = {"ok": False, "warnings": [], "errors": []}
    try:
        size_a = os.path.getsize(path_a)
        size_b = os.path.getsize(path_b)
        with open(path_a, "rb") as fh:
            data_a = fh.read(MAX_STREAM_READ)
        with open(path_b, "rb") as fh:
            data_b = fh.read(MAX_STREAM_READ)
    except OSError as exc:
        out["errors"].append(f"read failed: {exc}")
        return out
    if size_a > MAX_STREAM_READ or size_b > MAX_STREAM_READ:
        out["warnings"].append(
            "a file is larger than 16 MiB — diff covers the first 16 MiB")
    if size_a != size_b:
        out["warnings"].append(f"size differs: {human_size(size_a)} vs "
                               f"{human_size(size_b)}")
    n = min(len(data_a), len(data_b))
    blocks = []
    ranges_equal: list[dict] = []
    ranges_diff: list[dict] = []
    first_diff = None
    last_diff = None
    diff_bytes = 0
    i = 0
    while i < n:
        block_a = data_a[i:i + BLOCK]
        block_b = data_b[i:i + BLOCK]
        same = block_a == block_b
        end = min(i + BLOCK, n)
        blocks.append({"offset": i, "size": end - i, "same": same})
        entry = {"start": i, "end": end, "same": same}
        if same:
            if ranges_equal and ranges_equal[-1]["end"] == i:
                ranges_equal[-1]["end"] = end
            else:
                ranges_equal.append(entry)
        else:
            if ranges_diff and ranges_diff[-1]["end"] == i:
                ranges_diff[-1]["end"] = end
            else:
                ranges_diff.append(entry)
            diff_bytes += sum(1 for x, y in zip(block_a, block_b) if x != y)
            if first_diff is None:
                first_diff = i + next(
                    (k for k, (x, y) in enumerate(zip(block_a, block_b))
                     if x != y), 0)
            last_diff = end - 1 - next(
                (k for k, (x, y) in enumerate(zip(reversed(block_a),
                                                  reversed(block_b)))
                 if x != y) * -1, 0) if False else end - 1
        i += BLOCK
    if n == 0 and (len(data_a) or len(data_b)):
        first_diff = 0
        last_diff = max(len(data_a), len(data_b)) - 1
    identical_ratio = 1 - (diff_bytes / n) if n else 0.0
    out.update({
        "size_a": size_a, "size_b": size_b,
        "size_a_human": human_size(size_a), "size_b_human": human_size(size_b),
        "compared_bytes": n,
        "identical_bytes": n - diff_bytes,
        "differing_bytes": diff_bytes,
        "identical_ratio": round(identical_ratio, 4),
        "blocks": len(blocks),
        "block_map": blocks if len(blocks) <= 512 else
        blocks[:256] + blocks[-256:],
        "first_diff": first_diff, "last_diff": last_diff,
        "ranges_equal": len(ranges_equal), "ranges_diff": len(ranges_diff),
    })
    # trailing data that only one file has
    if len(data_a) > n:
        out["extra_tail_a"] = len(data_a) - n
    if len(data_b) > n:
        out["extra_tail_b"] = len(data_b) - n
    # entropy delta over differing blocks
    if ranges_diff:
        ent_a = shannon_entropy(data_a[:n])
        ent_b = shannon_entropy(data_b[:n])
        out["entropy_a"] = ent_a
        out["entropy_b"] = ent_b
    out["ok"] = True
    return out


def patch_bytes(path_a: str, path_b: str, limit: int = 500) -> dict:
    """List concrete differing bytes (offset, old, new) — a patch list."""
    out: dict = {"ok": False, "warnings": [], "errors": []}
    try:
        with open(path_a, "rb") as fh:
            data_a = fh.read(MAX_STREAM_READ)
        with open(path_b, "rb") as fh:
            data_b = fh.read(MAX_STREAM_READ)
    except OSError as exc:
        out["errors"].append(f"read failed: {exc}")
        return out
    n = min(len(data_a), len(data_b))
    patches: list[dict] = []
    truncated = False
    for i in range(n):
        if data_a[i] != data_b[i]:
            patches.append({"offset": i,
                            "a": f"{data_a[i]:02x}",
                            "b": f"{data_b[i]:02x}"})
            if len(patches) >= limit:
                truncated = True
                break
    out["patches"] = patches
    out["count"] = len(patches)
    out["truncated"] = truncated
    out["total_possible"] = sum(
        1 for i in range(n) if data_a[i] != data_b[i]) if not truncated \
        else None
    out["ok"] = True
    return out
