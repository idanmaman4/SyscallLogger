#include "pch.h"
#include "framework.h"
#include "SyscallRecorder.h"
#include "structres.h"
#include "debug_utils.hpp"
#include "StackUnwindIterator.hpp"

#include <filesystem>
#include <cstdint>
#include <iostream>
#include <fstream>
#include <format>
#include <ranges>

Concurrency::concurrent_queue<LogEntry> log_queue;

static constexpr size_t MAX_COUNT = 5 ; 

static std::wofstream g_log_file;

struct process_instrumentation_callback_info_t {
    uint32_t          version;
    uint32_t          reserved;
    bridge_function_t callback;
};



std::wstring build_log_filename()
{
    wchar_t exe_path[MAX_PATH] = {};
    GetModuleFileNameW(nullptr, exe_path, MAX_PATH);

    std::wstring stem = std::filesystem::path(exe_path).stem().wstring();

    DWORD pid = GetCurrentProcessId();

    SYSTEMTIME st = {};
    GetLocalTime(&st);

    wchar_t filename[MAX_PATH] = {};
    swprintf_s(filename, MAX_PATH,
        L"%s_%u_%04u%02u%02u_%02u%02u%02u.log",
        stem.c_str(), pid,
        st.wYear, st.wMonth, st.wDay,
        st.wHour, st.wMinute, st.wSecond);

    return std::wstring(filename);
}

void InstrumentationCallback(CONTEXT* context)
{
    _TEB64* teb = reinterpret_cast<_TEB64*>(NtCurrentTeb());
    context->Rip = teb->InstrumentationCallbackPreviousPc;
    context->Rsp = teb->InstrumentationCallbackPreviousSp;
    context->Rcx = context->R10;

    if (!teb->InstrumentationCallbackDisabled)
    {
        teb->InstrumentationCallbackDisabled = TRUE;
        try {

            int depth = 0;
            std::wstringstream stream;
            for (const StackFrame& frame : StackUnwindRange{ context->Rip, context->Rsp } | std::views::take(MAX_COUNT))
            {
                if (depth == 0)
                {
                    stream << L"  [" << depth << L"] " << frame.module_name << L"!"
                        << frame.function_name << L"(+"
                        << std::hex << frame.function_offset << L")"
                        << L" rax=" << context->Rax << L"\n";
                }
                else
                {
                    stream << L"  [" << depth << L"] "
                        << frame.module_name << L"!"
                        << frame.function_name << L"(+"
                        << std::hex << frame.function_offset << L")\n";
                }
                std::wstring_view module_name = frame.module_name;
                if (module_name.ends_with(L".exe")) {
                    break;
                }
                ++depth;
            }
            g_log_file << stream.str();
            g_log_file << L"\n";
            g_log_file.flush();
        }
        catch (...) {}
        teb->InstrumentationCallbackDisabled = FALSE;
    }

    RtlRestoreContext(context, NULL);
}

bool register_instrumentation_callback()
{

    std::wstring filename = build_log_filename();

    if (debugging_utils::is_debug)
        g_log_file.set_rdbuf(std::wcout.rdbuf());
    else {
        g_log_file.open(filename, std::ios::out | std::ios::trunc);
    }

    HMODULE nt_dll = GetModuleHandleA("ntdll.dll");
    auto nt_set_information_process = reinterpret_cast<nt_set_information_process_t>(
        GetProcAddress(nt_dll, "NtSetInformationProcess"));

    if (nt_set_information_process == nullptr)
        return false;

    process_instrumentation_callback_info_t info;
    info.version  = 0;
    info.reserved = 0;
    info.callback = reinterpret_cast<bridge_function_t>(InstrumentationCallbackThunk);

    nt_set_information_process(GetCurrentProcess(),
        static_cast<PROCESS_INFORMATION_CLASS>(0x28),
        &info, sizeof(info));

    return true;
}