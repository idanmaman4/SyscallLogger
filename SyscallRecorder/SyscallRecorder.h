#ifdef SYSCALLRECORDER_EXPORTS
#define SYSCALLRECORDER_API __declspec(dllexport)
#else
#define SYSCALLRECORDER_API __declspec(dllimport)
#endif

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


bool register_instrumentation_callback();
extern "C" void InstrumentationCallback(CONTEXT* context);
extern "C" void InstrumentationCallbackThunk();
