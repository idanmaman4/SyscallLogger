"""PDB download from Microsoft symbol server + symbol table extraction."""

from __future__ import annotations

import bisect
import json
import logging
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional, Set, Tuple
from urllib import request as urllib_request

logger = logging.getLogger("syscall_log_parser")

CACHE_DIR          = os.path.join(os.path.dirname(os.path.abspath(__file__)), "SysLogger")
FAILURE_CACHE_PATH = os.path.join(CACHE_DIR, "failed_resolutions.json")


def isf_path_for(pdb_basename: str) -> str:
    return os.path.join(CACHE_DIR, pdb_basename.replace(".pdb", "") + ".json")


def pdb_path_for(pdb_basename: str) -> str:
    return os.path.join(CACHE_DIR, pdb_basename)


# ── dll name from pdb ─────────────────────────────────────────────────

def dll_name_from_pdb(pdb_path: str) -> str:
    """Derive a display name from the pdb path.  ntdll.pdb -> ntdll.dll"""
    stem = os.path.basename(pdb_path).replace(".pdb", "")

    if stem.lower().endswith(".amd64"):
        stem = stem[:-6]

    if "." in stem:
        return stem

    return stem + ".dll"


# ── failure cache ─────────────────────────────────────────────────────

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


# ── PDB download ─────────────────────────────────────────────────────

def download_pdb(guid: str, pdb_basename: str) -> Optional[str]:
    dest = pdb_path_for(pdb_basename)
    if os.path.isfile(dest):
        logger.info("  Cache hit   %-35s  GUID: %s", pdb_basename, guid)
        return dest

    guid_no_dashes = guid.replace("-", "").upper()
    for age in range(1, 10):
        guid_age = guid_no_dashes + str(age)
        url_base = (f"http://msdl.microsoft.com/download/symbols/"
                    f"{pdb_basename}/{guid_age}/")
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


# ── PDB -> symbol map ────────────────────────────────────────────────

def pdb_to_isf(pdb_path: str) -> Optional[dict]:
    try:
        import pdbparse
        import pdbparse.undecorate
    except ImportError:
        logger.error("pdbparse is not installed.  Run: pip install pdbparse")
        return None

    try:
        pdb = pdbparse.parse(pdb_path)
        try:
            sects = pdb.STREAM_SECT_HDR_ORIG.sections
            omap  = pdb.STREAM_OMAP_FROM_SRC
        except AttributeError:
            sects = pdb.STREAM_SECT_HDR.sections
            omap  = None

        symbols: Dict[str, int] = {}
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


# ── resolve one module record ─────────────────────────────────────────

def resolve_one(
    rec: dict, failed_cache: Set[str]
) -> Tuple[dict, Optional[dict], Optional[str]]:
    pdb_basename = os.path.basename(rec["pdb"])
    isf_file     = isf_path_for(pdb_basename)
    cache_key    = f"{pdb_basename}:{rec['guid']}"

    if os.path.isfile(isf_file):
        logger.info("  ISF cached  %-35s  GUID: %s", pdb_basename, rec["guid"])
        with open(isf_file) as f:
            return rec, json.load(f), None

    if cache_key in failed_cache:
        logger.info("  Skipped     %-35s  GUID: %s  (known failure)",
                    pdb_basename, rec["guid"])
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


# ── symbol table (sorted addresses for bisect lookup) ─────────────────

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


# ── bulk resolve ──────────────────────────────────────────────────────

def resolve_modules(
    load_order: List[dict], workers: int = 8
) -> None:
    """Download PDBs + build SymbolTables for every module record in-place."""
    os.makedirs(CACHE_DIR, exist_ok=True)

    failed_cache = load_failure_cache()
    pending      = [r for r in load_order if "_symtable" not in r]
    newly_failed: Set[str] = set()

    if not pending:
        return

    logger.info("Resolving %d modules with %d threads ...", len(pending), workers)
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(resolve_one, rec, failed_cache): rec
                   for rec in pending}
        for future in as_completed(futures):
            rec, isf, fail_key = future.result()
            if isf:
                name = os.path.basename(rec["pdb"]).replace(".pdb", "")
                rec["_symtable"] = SymbolTable(name, isf)
            if fail_key:
                newly_failed.add(fail_key)

    if newly_failed:
        save_failure_cache(failed_cache | newly_failed)
