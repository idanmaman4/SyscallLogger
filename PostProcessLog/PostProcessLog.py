#!/usr/bin/env python3


from __future__ import annotations

import logging
import os
import sys
from collections import Counter, defaultdict
from typing import Dict, List, Tuple

from log_parser import parse_log
from module_registry import ModuleRegistry
from symbol_resolver import CACHE_DIR, dll_name_from_pdb

logging.basicConfig(format="%(levelname)-8s %(message)s", level=logging.INFO)



def write_traces(records: List[dict], registry: ModuleRegistry, out):
    for rec in records:
        if rec["type"] != "Syscall" or not rec["frames"]:
            continue
        for fi, fr in enumerate(rec["frames"]):
            out.write(registry.format_frame(
                rec["time"], rec["tid"], fi,
                fr["module_base"], fr["rva"]) + "\n")
        out.write("\n")


def write_summary(records: List[dict], skipped: int,
                  registry: ModuleRegistry, log_path: str, out):
    def w(s: str = ""):
        out.write(s + "\n")

    counts = Counter(r["type"] for r in records)

    w("=" * 70)
    w("SYSCALLLOGGER TRACE REPORT")
    w("=" * 70)
    w(f"  Source   : {os.path.abspath(log_path)}")
    w(f"  Records  : {len(records)}  ({skipped} bytes skipped)")
    for k, v in sorted(counts.items()):
        w(f"    {k:<20} {v}")
    w(f"  {registry.summary()}")
    w()

    seen_modules: Dict[str, dict] = {}
    for m in records:
        if m["type"] == "NewModule":
            seen_modules.setdefault(m["guid"], m)

    w(f"-- LOADED MODULES ({len(seen_modules)}) " + "-" * 38)
    for m in seen_modules.values():
        tag = "[symbols OK]" if "_symtable" in m else "[no symbols]"
        w(f"  {tag}  {dll_name_from_pdb(m['pdb'])}  ({m['pdb']})")
        w(f"            GUID: {m['guid']}  base: 0x{m.get('base', 0):x}")
    w()

    syscalls    = [r for r in records if r["type"] == "Syscall"]
    with_frames = [s for s in syscalls if s["frames"]]

    w(f"-- SYSCALL EVENTS ({len(syscalls)}) " + "-" * 38)
    w(f"  With stack frames : {len(with_frames)}")
    w(f"  No frames         : {len(syscalls) - len(with_frames)}")
    w()

    if not with_frames:
        w("  No stack frame data in this log.")
        return

    w("-- UNIQUE CALL SITES (sorted by hit count) " + "-" * 23)
    site_hits: Dict[Tuple[int, int], int] = defaultdict(int)
    for sc in syscalls:
        for fr in sc["frames"]:
            site_hits[(fr["module_base"], fr["rva"])] += 1

    sorted_sites = sorted(site_hits.items(), key=lambda x: (-x[1], x[0]))
    w(f"  {'Symbol':<65}  {'Hits':>6}")
    w(f"  {'-'*65}  {'-'*6}")
    for (base, rva), hits in sorted_sites:
        frame_str = registry.format_frame(0, 0, 0, base, rva)
        symbol_part = frame_str.split("] ", 1)[-1]
        w(f"  {symbol_part:<65}  {hits:>6}")
    w()


# ── main ──────────────────────────────────────────────────────────────

def main():
    if len(sys.argv) < 2:
        print(f"Usage: python {os.path.basename(sys.argv[0])} <trace.log>")
        print(f"  Cache dir: {CACHE_DIR}")
        sys.exit(1)

    log_path = sys.argv[1]

    with open(log_path, "rb") as f:
        data = f.read()

    print(f"File  : {log_path}  ({len(data):,} bytes)")
    print(f"Cache : {CACHE_DIR}\n")

    records, skipped = parse_log(data)

    registry = ModuleRegistry()
    for rec in records:
        if rec["type"] == "NewModule":
            registry.register_module(rec)

    registry.resolve_all()

    log_stem     = os.path.splitext(os.path.basename(log_path))[0]
    traces_path  = os.path.join(CACHE_DIR, log_stem + "_traces.txt")
    summary_path = os.path.join(CACHE_DIR, log_stem + "_summary.txt")

    with open(traces_path, "w", encoding="utf-8") as f:
        write_traces(records, registry, f)

    with open(summary_path, "w", encoding="utf-8") as f:
        write_summary(records, skipped, registry, log_path, f)

    write_summary(records, skipped, registry, log_path, sys.stdout)

    print(f"Traces  saved : {traces_path}")
    print(f"Summary saved : {summary_path}")


if __name__ == "__main__":
    main()
