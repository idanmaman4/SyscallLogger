"""Binary log parser — matches the #pragma pack(push,1) structs in LogInfo.h."""

from __future__ import annotations

import struct
from typing import List, Optional, Tuple

# ── binary layout constants ────────────────────────────────────────────
# LogHeader = uint64 m_time + uint32 m_tid + uint8 logtype
HEADER_FMT  = "<QIB"
HEADER_SIZE = struct.calcsize(HEADER_FMT)           # 13

# GUID = uint32 + uint16 + uint16 + 8 bytes
GUID_FMT  = "<IHH8s"
GUID_SIZE = struct.calcsize(GUID_FMT)               # 16

PDB_LEN  = 256
BASE_SIZE = 8                                        # uintptr_t m_base

MODULE_SIZE = HEADER_SIZE + BASE_SIZE + PDB_LEN + GUID_SIZE   # 293

# SyscallFrameInfo = uintptr_t module_base + uint32 stack_trace_offsets
FRAME_FMT  = "<QI"
FRAME_SIZE = struct.calcsize(FRAME_FMT)              # 12

PROCESS_SIZE    = HEADER_SIZE + 4
MAX_FRAME_COUNT = 20

# LogType enum values
LOGTYPE_NEW_MODULE  = 0x01
LOGTYPE_SYSCALL     = 0x33
LOGTYPE_NEW_THREAD  = 0x03
LOGTYPE_NEW_PROCESS = 0x04


# ── helpers ────────────────────────────────────────────────────────────

def parse_guid(raw: bytes) -> str:
    d1, d2, d3, d4 = struct.unpack_from(GUID_FMT, raw)
    return (f"{d1:08X}-{d2:04X}-{d3:04X}-"
            f"{d4[:2].hex().upper()}-{d4[2:].hex().upper()}")


def parse_pdb_name(raw: bytes) -> str:
    return raw.split(b"\x00")[0].decode("utf-8", errors="replace")


# ── record parsers ─────────────────────────────────────────────────────

def _parse_new_module(data: bytes, pos: int) -> Optional[dict]:
    if pos + MODULE_SIZE > len(data):
        return None
    t, tid, _ = struct.unpack_from(HEADER_FMT, data, pos)
    base,     = struct.unpack_from("<Q", data, pos + HEADER_SIZE)
    pdb_off   = pos + HEADER_SIZE + BASE_SIZE
    pdb       = parse_pdb_name(data[pdb_off : pdb_off + PDB_LEN])
    guid      = parse_guid(data[pdb_off + PDB_LEN : pos + MODULE_SIZE])
    return {"type": "NewModule", "pos": pos, "time": t, "tid": tid,
            "base": base, "pdb": pdb, "guid": guid, "size": MODULE_SIZE}


def _parse_syscall(data: bytes, pos: int) -> Optional[dict]:
    if pos + HEADER_SIZE + 4 > len(data):
        return None
    t, tid, _ = struct.unpack_from(HEADER_FMT, data, pos)
    fc,       = struct.unpack_from("<I", data, pos + HEADER_SIZE)
    if fc > MAX_FRAME_COUNT:
        return None
    total = HEADER_SIZE + 4 + fc * FRAME_SIZE
    if pos + total > len(data):
        return None
    frames = []
    off = pos + HEADER_SIZE + 4
    for i in range(fc):
        mb, rva = struct.unpack_from(FRAME_FMT, data, off + i * FRAME_SIZE)
        frames.append({"module_base": mb, "rva": rva})
    return {"type": "Syscall", "pos": pos, "time": t, "tid": tid,
            "frames": frames, "size": total}


def _parse_new_thread(data: bytes, pos: int) -> Optional[dict]:
    if pos + HEADER_SIZE > len(data):
        return None
    t, tid, _ = struct.unpack_from(HEADER_FMT, data, pos)
    return {"type": "NewThread", "pos": pos, "time": t, "tid": tid,
            "size": HEADER_SIZE}


def _parse_new_process(data: bytes, pos: int) -> Optional[dict]:
    if pos + PROCESS_SIZE > len(data):
        return None
    t, tid, _ = struct.unpack_from(HEADER_FMT, data, pos)
    pid,      = struct.unpack_from("<I", data, pos + HEADER_SIZE)
    return {"type": "NewProcess", "pos": pos, "time": t, "tid": tid,
            "pid": pid, "size": PROCESS_SIZE}


_PARSERS = {
    LOGTYPE_NEW_MODULE:  _parse_new_module,
    LOGTYPE_SYSCALL:     _parse_syscall,
    LOGTYPE_NEW_THREAD:  _parse_new_thread,
    LOGTYPE_NEW_PROCESS: _parse_new_process,
}


# ── main entry point ──────────────────────────────────────────────────

def parse_log(data: bytes) -> Tuple[List[dict], int]:
    records: List[dict] = []
    skipped = 0
    pos = 0
    while pos < len(data) - HEADER_SIZE:
        lt = data[pos + 12]
        parser = _PARSERS.get(lt)
        if parser is None:
            pos += 1
            skipped += 1
            continue
        rec = parser(data, pos)
        if rec is None:
            pos += 1
            skipped += 1
            continue
        records.append(rec)
        pos += rec["size"]
    return records, skipped
