#!/usr/bin/env python3

from __future__ import annotations

import bisect
import json
import logging
import os
import struct
import sys
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional, Set, Tuple
from urllib import request as urllib_request

logging.basicConfig(format="%(levelname)-8s %(message)s", level=logging.INFO)
logger = logging.getLogger("syscall_log_parser")

CACHE_DIR          = os.path.join(os.path.dirname(os.path.abspath(__file__)), "SysLogger")
FAILURE_CACHE_PATH = os.path.join(CACHE_DIR, "failed_resolutions.json")

HEADER_FMT   = "<QIB"
HEADER_SIZE  = struct.calcsize(HEADER_FMT)
GUID_FMT     = "<IHH8s"
GUID_SIZE    = struct.calcsize(GUID_FMT)
PDB_LEN      = 256
MODULE_SIZE  = HEADER_SIZE + PDB_LEN + GUID_SIZE
FRAME_FMT    = "<QI"
FRAME_SIZE   = struct.calcsize(FRAME_FMT)
PROCESS_SIZE = HEADER_SIZE + 4

LOGTYPE_NEW_MODULE  = 0x01
LOGTYPE_SYSCALL     = 0x33
LOGTYPE_NEW_THREAD  = 0x03
LOGTYPE_NEW_PROCESS = 0x04

PDB_TO_DLL = {
    "ntdll":                "ntdll.dll",
    "kernel32":             "KERNEL32.DLL",
    "kernelbase":           "KERNELBASE.dll",
    "ucrtbase":             "ucrtbase.dll",
    "ucrtbased":            "ucrtbased.dll",
    "msvcp140":             "MSVCP140.dll",
    "msvcp140d":            "MSVCP140D.dll",
    "msvcp_win":            "msvcp_win.dll",
    "vcruntime140":         "vcruntime140.dll",
    "vcruntime140d":        "vcruntime140d.dll",
    "vcruntime140_1":       "vcruntime140_1.dll",
    "vcruntime140_1d":      "vcruntime140_1d.dll",
    "shell32":              "SHELL32.dll",
    "user32":               "USER32.dll",
    "win32u":               "win32u.dll",
    "gdi32":                "GDI32.dll",
    "gdi32full":            "gdi32full.dll",
    "wintypes":             "WinTypes.dll",
    "combase":              "combase.dll",
    "rpcrt4":               "RPCRT4.dll",
    "concrt140":            "CONCRT140.dll",
    "imm32":                "IMM32.dll",
    "windows.storage":      "Windows.Storage.dll",
    "advapi32":             "ADVAPI32.dll",
    "msvcrt":               "msvcrt.dll",
    "sechost":              "sechost.dll",
    "shcore":               "SHCore.dll",
    "shlwapi":              "SHLWAPI.dll",
    "ws2_32":               "WS2_32.dll",
    "ntoskrnl":             "ntoskrnl.exe",
    "win32k":               "win32k.sys",
}


EXE_STEMS = {"syscalllogger", "syscallrecorder"}


def dll_name_from_pdb(pdb_path: str) -> str:
    stem       = os.path.basename(pdb_path).replace(".pdb", "")
    stem_lower = stem.lower()

    if stem_lower in PDB_TO_DLL:
        return PDB_TO_DLL[stem_lower]

    if stem_lower.endswith(".amd64"):
        clean = stem[:-6]
        if clean.lower() in PDB_TO_DLL:
            return PDB_TO_DLL[clean.lower()]
        return clean + ".dll"

    for key, val in PDB_TO_DLL.items():
        if stem_lower.startswith(key):
            return val

    if "." in stem:
        return stem

    if stem_lower in EXE_STEMS:
        return stem + ".exe"

    path_lower = pdb_path.lower().replace("\\", "/")
    if any(hint in path_lower for hint in ("/release/", "/debug/", "/x64/", "/x86/")):
        return stem + ".exe"

    return stem + ".dll"


def _parse_guid(raw: bytes) -> str:
    d1, d2, d3, d4 = struct.unpack_from(GUID_FMT, raw)
    return f"{d1:08X}-{d2:04X}-{d3:04X}-{d4[:2].hex().upper()}-{d4[2:].hex().upper()}"


def _parse_pdb_name(raw: bytes) -> str:
    return raw.split(b"\x00")[0].decode("utf-8", errors="replace")


def _parse_new_module(data: bytes, pos: int) -> Optional[dict]:
    if pos + MODULE_SIZE > len(data):
        return None
    t, tid, _ = struct.unpack_from(HEADER_FMT, data, pos)
    pdb  = _parse_pdb_name(data[pos + HEADER_SIZE : pos + HEADER_SIZE + PDB_LEN])
    guid = _parse_guid(data[pos + HEADER_SIZE + PDB_LEN : pos + MODULE_SIZE])
    return {"type": "NewModule", "pos": pos, "time": t, "tid": tid,
            "pdb": pdb, "guid": guid, "size": MODULE_SIZE}


def _parse_syscall(data: bytes, pos: int) -> Optional[dict]:
    if pos + HEADER_SIZE + 4 > len(data):
        return None
    t, tid, _ = struct.unpack_from(HEADER_FMT, data, pos)
    fc, = struct.unpack_from("<I", data, pos + HEADER_SIZE)
    total = HEADER_SIZE + 4 + fc * FRAME_SIZE
    if pos + total > len(data):
        return None
    frames = []
    for i in range(fc):
        mb, rva = struct.unpack_from(FRAME_FMT, data, pos + HEADER_SIZE + 4 + i * FRAME_SIZE)
        frames.append({"module_base": mb, "rva": rva})
    return {"type": "Syscall", "pos": pos, "time": t, "tid": tid,
            "frames": frames, "size": total}


def _parse_new_thread(data: bytes, pos: int) -> Optional[dict]:
    if pos + HEADER_SIZE > len(data):
        return None
    t, tid, _ = struct.unpack_from(HEADER_FMT, data, pos)
    return {"type": "NewThread", "pos": pos, "time": t, "tid": tid, "size": HEADER_SIZE}


def _parse_new_process(data: bytes, pos: int) -> Optional[dict]:
    if pos + PROCESS_SIZE > len(data):
        return None
    t, tid, _ = struct.unpack_from(HEADER_FMT, data, pos)
    pid, = struct.unpack_from("<I", data, pos + HEADER_SIZE)
    return {"type": "NewProcess", "pos": pos, "time": t, "tid": tid,
            "pid": pid, "size": PROCESS_SIZE}


_PARSERS = {
    LOGTYPE_NEW_MODULE:  _parse_new_module,
    LOGTYPE_SYSCALL:     _parse_syscall,
    LOGTYPE_NEW_THREAD:  _parse_new_thread,
    LOGTYPE_NEW_PROCESS: _parse_new_process,
}


def parse_log(data: bytes) -> Tuple[List[dict], int]:
    records, skipped, pos = [], 0, 0
    while pos < len(data) - HEADER_SIZE:
        lt = data[pos + 12]
        parser = _PARSERS.get(lt)
        if parser is None:
            pos += 1
            skipped += 1
            continue
        rec = parser(data, pos)
        if rec is None:
            break
        records.append(rec)
        pos += rec["size"]
    return records, skipped


def isf_path_for(pdb_basename: str) -> str:
    return os.path.join(CACHE_DIR, pdb_basename.replace(".pdb", "") + ".json")


def pdb_path_for(pdb_basename: str) -> str:
    return os.path.join(CACHE_DIR, pdb_basename)


def load_failure_cache() -> Set[str]:
    if os.path.isfile(FAILURE_CACHE_PATH):
        try:
            with open(FAILURE_CACHE_PATH) as f:
                return set(json.load(f))
        except Exception:
            pass
    return set()


def save_failure_cache(failed: Set[str]):
    with open(FAILURE_CACHE_PATH, "w") as f:
        json.dump(sorted(failed), f, indent=2)


def download_pdb(guid: str, pdb_basename: str) -> Optional[str]:
    dest = pdb_path_for(pdb_basename)
    if os.path.isfile(dest):
        logger.info("  Cache hit   %-35s  GUID: %s", pdb_basename, guid)
        return dest

    guid_no_dashes = guid.replace("-", "").upper()
    for age in range(1, 10):
        guid_age = guid_no_dashes + str(age)
        url_base = f"http://msdl.microsoft.com/download/symbols/{pdb_basename}/{guid_age}/"
        for suffix in [pdb_basename[:-1] + "_", pdb_basename]:
            try:
                tmp, _ = urllib_request.urlretrieve(url_base + suffix)
                os.replace(tmp, dest)
                logger.info("  Downloaded  %-35s  GUID: %s", pdb_basename, guid)
                return dest
            except Exception:
                pass

    logger.warning("  Not found   %-35s  GUID: %s", pdb_basename, guid)
    return None


def pdb_to_isf(pdb_path: str) -> Optional[dict]:
    try:
        import pdbparse
        import pdbparse.undecorate
    except ImportError:
        logger.error("pdbparse is not installed. Run: pip install pdbparse")
        return None

    try:
        pdb = pdbparse.parse(pdb_path)
        try:
            sects = pdb.STREAM_SECT_HDR_ORIG.sections
            omap  = pdb.STREAM_OMAP_FROM_SRC
        except AttributeError:
            sects = pdb.STREAM_SECT_HDR.sections
            omap  = None

        symbols = {}
        for sym in pdb.STREAM_GSYM.globals:
            if not hasattr(sym, "offset"):
                continue
            try:
                virt_base = sects[sym.segment - 1].VirtualAddress
            except IndexError:
                continue
            name, _, _ = pdbparse.undecorate.undecorate(sym.name)
            rva = sym.offset + virt_base
            if omap:
                rva = omap.remap(rva)
            symbols[name] = rva

        return {"symbols": {n: {"address": a} for n, a in symbols.items()}}

    except Exception as exc:
        logger.warning("  Parse error  %s: %s", os.path.basename(pdb_path), exc)
        return None


def resolve_one(rec: dict, failed_cache: Set[str]) -> Tuple[dict, Optional[dict], Optional[str]]:
    pdb_basename = os.path.basename(rec["pdb"])
    isf_file     = isf_path_for(pdb_basename)
    cache_key    = f"{pdb_basename}:{rec['guid']}"

    if os.path.isfile(isf_file):
        logger.info("  ISF cached  %-35s  GUID: %s", pdb_basename, rec["guid"])
        with open(isf_file) as f:
            return rec, json.load(f), None

    if cache_key in failed_cache:
        logger.info("  Skipped     %-35s  GUID: %s  (known failure)", pdb_basename, rec["guid"])
        return rec, None, None

    local = download_pdb(rec["guid"], pdb_basename)
    if not local:
        return rec, None, cache_key

    isf = pdb_to_isf(local)
    if isf:
        with open(isf_file, "w") as f:
            json.dump(isf, f)
        logger.info("  ISF saved   %-35s  GUID: %s", pdb_basename, rec["guid"])
        return rec, isf, None

    return rec, None, cache_key


class SymbolTable:

    def __init__(self, module_name: str, isf: dict):
        self.module_name = module_name
        pairs = sorted(
            (info["address"], name)
            for name, info in isf.get("symbols", {}).items()
            if isinstance(info, dict) and "address" in info
        )
        self._addrs: List[int] = [p[0] for p in pairs]
        self._names: List[str] = [p[1] for p in pairs]

    def nearest(self, rva: int) -> Tuple[Optional[str], int]:
        if not self._addrs:
            return None, rva
        idx = bisect.bisect_right(self._addrs, rva) - 1
        if idx < 0:
            return None, rva
        return self._names[idx], rva - self._addrs[idx]

    def __len__(self) -> int:
        return len(self._addrs)


class ModuleRegistry:

    def __init__(self):
        self._load_order:   List[dict]             = []
        self._guid_index:   Dict[str, dict]        = {}
        self._seen_bases:   Dict[int, int]         = {}
        self._base_to_sym:  Dict[int, SymbolTable] = {}
        self._base_to_dll:  Dict[int, str]         = {}

    def register_module(self, rec: dict):
        if rec["guid"] not in self._guid_index:
            self._guid_index[rec["guid"]] = rec
            self._load_order.append(rec)

    def register_base(self, base: int):
        if base and base not in self._seen_bases:
            self._seen_bases[base] = len(self._seen_bases)

    def resolve_all(self, workers: int = 8):
        os.makedirs(CACHE_DIR, exist_ok=True)

        failed_cache  = load_failure_cache()
        pending       = [rec for rec in self._load_order if "_symtable" not in rec]
        newly_failed: Set[str] = set()

        if pending:
            logger.info("Resolving %d modules with %d threads...", len(pending), workers)
            with ThreadPoolExecutor(max_workers=workers) as pool:
                futures = {pool.submit(resolve_one, rec, failed_cache): rec for rec in pending}
                for future in as_completed(futures):
                    rec, isf, fail_key = future.result()
                    if isf:
                        name = os.path.basename(rec["pdb"]).replace(".pdb", "")
                        rec["_symtable"] = SymbolTable(name, isf)
                    if fail_key:
                        newly_failed.add(fail_key)

            if newly_failed:
                save_failure_cache(failed_cache | newly_failed)

        self._save_modules_status()

        ordered_bases = sorted(self._seen_bases, key=lambda b: self._seen_bases[b])
        for base in ordered_bases:
            if base in self._base_to_dll:
                continue
            idx = self._seen_bases[base]
            if idx < len(self._load_order):
                rec = self._load_order[idx]
                self._base_to_dll[base] = dll_name_from_pdb(rec["pdb"])
                if "_symtable" in rec:
                    self._base_to_sym[base] = rec["_symtable"]

    def _save_modules_status(self):
        entries = []
        for rec in self._load_order:
            pdb_basename = os.path.basename(rec["pdb"])
            resolved     = "_symtable" in rec
            entries.append({
                "pdb":          pdb_basename,
                "pdb_path":     rec["pdb"],
                "guid":         rec["guid"],
                "dll_name":     dll_name_from_pdb(rec["pdb"]),
                "resolved":     resolved,
                "isf_file":     isf_path_for(pdb_basename) if resolved else None,
                "symbol_count": len(rec["_symtable"]) if resolved else 0,
            })
        status_path = os.path.join(CACHE_DIR, "modules_status.json")
        with open(status_path, "w") as f:
            json.dump(entries, f, indent=2)
        logger.info("Module status: %s", status_path)

    def format_frame(self, time: int, tid: int, frame_idx: int,
                     module_base: int, rva: int) -> str:
        dll = self._base_to_dll.get(module_base, f"0x{module_base:016x}")
        st  = self._base_to_sym.get(module_base)

        if st:
            sym_name, delta = st.nearest(rva)
            if sym_name:
                return f"#{time}::{{{tid}}}[{frame_idx}] {dll}!{sym_name}(+{delta:x})"

        return f"#{time}::{{{tid}}}[{frame_idx}] {dll}!(+{rva:x})"

    def summary(self) -> str:
        n = sum(1 for r in self._load_order if "_symtable" in r)
        return f"{len(self._load_order)} modules, {n} resolved, {len(self._seen_bases)} runtime bases"


def write_traces(records: List[dict], registry: ModuleRegistry, out):
    syscalls    = [r for r in records if r["type"] == "Syscall"]
    with_frames = [s for s in syscalls if s["frames"]]

    for sc in with_frames:
        for fi, fr in enumerate(sc["frames"]):
            out.write(registry.format_frame(sc["time"], sc["tid"], fi,
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
        w(f"            GUID: {m['guid']}")
    w()

    syscalls    = [r for r in records if r["type"] == "Syscall"]
    with_frames = [s for s in syscalls if s["frames"]]

    w(f"-- SYSCALL EVENTS ({len(syscalls)}) " + "-" * 38)
    w(f"  With stack frames : {len(with_frames)}")
    w(f"  No frames         : {len(syscalls) - len(with_frames)}")
    w()

    if not with_frames:
        w("  No stack frame data in this log.")
        w("  Fix: add ++i inside the loop in release_work() in SyscallRecorder.cpp")
        return

    w(f"-- UNIQUE CALL SITES (sorted by hit count) " + "-" * 23)
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
        elif rec["type"] == "Syscall":
            for fr in rec["frames"]:
                registry.register_base(fr["module_base"])

    registry.resolve_all()

    log_stem      = os.path.splitext(os.path.basename(log_path))[0]
    traces_path   = os.path.join(CACHE_DIR, log_stem + "_traces.txt")
    summary_path  = os.path.join(CACHE_DIR, log_stem + "_summary.txt")

    with open(traces_path, "w", encoding="utf-8") as f:
        write_traces(records, registry, f)

    with open(summary_path, "w", encoding="utf-8") as f:
        write_summary(records, skipped, registry, log_path, f)

    write_summary(records, skipped, registry, log_path, sys.stdout)

    print(f"Traces  saved : {traces_path}")
    print(f"Summary saved : {summary_path}")


if __name__ == "__main__":
    main()