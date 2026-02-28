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


bool register_instrumentation_callback();
extern "C" void InstrumentationCallback(CONTEXT* context);
extern "C" void InstrumentationCallbackThunk();

extern "C" Concurrency::concurrent_queue<LogEntry> log_queue;