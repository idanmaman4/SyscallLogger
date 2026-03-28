"""Maps runtime module base addresses to PDB symbols."""

from __future__ import annotations

import json
import logging
import os
from typing import Dict, List, Optional, Tuple

from symbol_resolver import (
    CACHE_DIR,
    SymbolTable,
    dll_name_from_pdb,
    isf_path_for,
    resolve_modules,
)

logger = logging.getLogger("syscall_log_parser")


class ModuleRegistry:

    def __init__(self):
        self._load_order:  List[dict]             = []
        self._guid_index:  Dict[str, dict]        = {}
        self._base_to_rec: Dict[int, dict]        = {}
        self._base_to_sym: Dict[int, SymbolTable] = {}
        self._base_to_dll: Dict[int, str]         = {}

    # ── registration ──────────────────────────────────────────────────

    def register_module(self, rec: dict):
        if rec["guid"] not in self._guid_index:
            self._guid_index[rec["guid"]] = rec
            self._load_order.append(rec)
        base = rec.get("base", 0)
        if base:
            self._base_to_rec[base] = rec

    # ── resolve all registered modules ────────────────────────────────

    def resolve_all(self, workers: int = 8):
        resolve_modules(self._load_order, workers)
        self._save_modules_status()

        for base, rec in self._base_to_rec.items():
            self._base_to_dll[base] = dll_name_from_pdb(rec["pdb"])
            if "_symtable" in rec:
                self._base_to_sym[base] = rec["_symtable"]

    # ── formatting ────────────────────────────────────────────────────

    def format_frame(self, time: int, tid: int, frame_idx: int,
                     module_base: int, rva: int) -> str:
        """
        Produce a line matching the debug-mode format:
            #<time>::{<tid>}[<depth>] <module>!<function>(+<rva_hex>)
        """
        dll = self._base_to_dll.get(module_base, f"0x{module_base:016x}")
        st  = self._base_to_sym.get(module_base)

        if st:
            sym_name, _ = st.nearest(rva)
            if sym_name:
                return f"#{time}::{{{tid}}}[{frame_idx}] {dll}!{sym_name}(+{rva:x})"

        return f"#{time}::{{{tid}}}[{frame_idx}] {dll}!(+{rva:x})"

    def summary(self) -> str:
        n = sum(1 for r in self._load_order if "_symtable" in r)
        return (f"{len(self._load_order)} modules, {n} resolved, "
                f"{len(self._base_to_rec)} runtime bases")

    # ── internal ──────────────────────────────────────────────────────

    def _save_modules_status(self):
        entries = []
        for rec in self._load_order:
            pdb_basename = os.path.basename(rec["pdb"])
            resolved     = "_symtable" in rec
            entries.append({
                "pdb":          pdb_basename,
                "pdb_path":     rec["pdb"],
                "guid":         rec["guid"],
                "base":         hex(rec.get("base", 0)),
                "dll_name":     dll_name_from_pdb(rec["pdb"]),
                "resolved":     resolved,
                "isf_file":     isf_path_for(pdb_basename) if resolved else None,
                "symbol_count": len(rec["_symtable"]) if resolved else 0,
            })
        status_path = os.path.join(CACHE_DIR, "modules_status.json")
        with open(status_path, "w") as f:
            json.dump(entries, f, indent=2)
        logger.info("Module status: %s", status_path)
