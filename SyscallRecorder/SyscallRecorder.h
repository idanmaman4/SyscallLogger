// The following ifdef block is the standard way of creating macros which make exporting
// from a DLL simpler. All files within this DLL are compiled with the SYSCALLRECORDER_EXPORTS
// symbol defined on the command line. This symbol should not be defined on any project
// that uses this DLL. This way any other project whose source files include this file see
// SYSCALLRECORDER_API functions as being imported from a DLL, whereas this DLL sees symbols
// defined with this macro as being exported.
#ifdef SYSCALLRECORDER_EXPORTS
#define SYSCALLRECORDER_API __declspec(dllexport)
#else
#define SYSCALLRECORDER_API __declspec(dllimport)
#endif


#include "concurrent_queue.h"



// This class is exported from the dll
class SYSCALLRECORDER_API CSyscallRecorder {
public:
	CSyscallRecorder(void);
	// TODO: add your methods here.
};

using addr_t = LPVOID;


using nt_set_information_process_t = NTSTATUS(NTAPI*)(HANDLE,
	PROCESS_INFORMATION_CLASS,
	PVOID, ULONG);

using bridge_function_t = void (*)();


#pragma pack(push, 1)
struct FunctionInfoPack {
	wchar_t module_name[256]{ 0 };
	char function_name[256]{ 0 };
	size_t function_offset_in_module{ 0 };
};
#pragma pack(pop)

#pragma pack(push, 1)
struct LogEntry {
   FunctionInfoPack current_function;
	FunctionInfoPack previous_function;
	uint64_t return_value;
};
#pragma pack(pop)

extern SYSCALLRECORDER_API int nSyscallRecorder;

SYSCALLRECORDER_API int fnSyscallRecorder(void);
bool register_instrumentation_callback();
extern "C" void InstrumentationCallback(CONTEXT* context);
extern "C" void InstrumentationCallbackThunk();

extern "C" Concurrency::concurrent_queue<LogEntry> log_queue;