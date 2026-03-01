#pragma once
#include <ctype.h>
#include "structres.h"
#include "Windows.h"
#include "cstring"
#include <cinttypes>

static constexpr size_t MAX_COUNT = 20 ; 

enum class LogType : byte {
	NewModule = 1, 
	SyscallCreated = 2,
	NewThread = 3,
	NewProcess = 4,
};

#pragma pack(push, 1)
struct LogHeader {
	uint64_t  m_time;
	DWORD m_tid;
	LogType logtype;
	LogHeader(LogType type, uint64_t time, DWORD tid ) : logtype(type), m_time(time), m_tid(tid) {
	}
};

struct LogInfoNewModule
{
	LogHeader m_header;
	char m_pdb_name[256] = { 0 };
	_GUID m_guid;
	LogInfoNewModule(const char* pdb, const _GUID& g, uint64_t time, DWORD tid) : m_guid(g), m_header(LogType::NewModule, time, tid)
	{
		strncpy_s(m_pdb_name, pdb, sizeof(m_pdb_name) - 1);
	}
};

struct SyscallFrameInfo {
	uintptr_t module_base;
	uint32_t  stack_trace_offsets;
};

struct LogInfoNewSyscall {
	LogHeader m_header;
	SyscallFrameInfo frames[MAX_COUNT] = {0};
	LogInfoNewSyscall(DWORD tid, uint64_t time) :m_header(LogType::SyscallCreated, time, tid) {
	
	}
	
};
 
struct LogInfoNewThread {
	LogHeader m_header;
	LogInfoNewThread(DWORD tid, uint64_t time) :  m_header(LogType::NewThread, time, tid)
	{
	}
};

struct LogInfoNewProcess {
	LogHeader m_header;
	DWORD m_process_id;
	LogInfoNewProcess(DWORD process_id, DWORD tid, uint64_t time) :m_process_id(process_id), m_header(LogType::NewProcess, time, tid)
	{
	}
};

#pragma pack(pop)