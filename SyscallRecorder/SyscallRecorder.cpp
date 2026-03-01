#include "pch.h"
#include "framework.h"
#include "SyscallRecorder.h"
#include "structres.h"
#include "debug_utils.hpp"
#include "StackUnwindIterator.hpp"
#include <ShlObj.h>
#include <wrl/client.h>
#include <filesystem>
#include <cstdint>
#include <iostream>
#include <fstream>
#include <format>
#include <ranges>
#include <bitset>
#include "LogInfo.h"
#include "ModuleManager.h"
#include "InstrumentaionCallbackProtection.h"
#include "FastInformationUtils.h"

Concurrency::concurrent_queue<LogEntry> log_queue;

static std::ofstream g_log_file;
static ModuleManager module_manager(g_log_file);

struct process_instrumentation_callback_info_t {
    uint32_t          version;
    uint32_t          reserved;
    bridge_function_t callback;
};



static constexpr size_t POOL_BUFFER_WCHARS = 2048;
static constexpr size_t POOL_COUNT         = 2048;

enum class BufferState : uint32_t
{
    Free     = 0,
    Writing  = 1,
    Ready    = 2,
    Printing = 3,
};

struct alignas(64) PoolBuffer
{
    wchar_t                  data[POOL_BUFFER_WCHARS];
    size_t                   length = 0;
    std::atomic<BufferState> state  { BufferState::Free };
};

static PoolBuffer g_pool[POOL_COUNT];

[[nodiscard]] static PoolBuffer* pool_acquire() noexcept
{
    for (size_t i = 0; i < POOL_COUNT; ++i) {
        BufferState expected = BufferState::Free;
        if (g_pool[i].state.compare_exchange_weak(
                expected, BufferState::Writing,
                std::memory_order_acquire,
                std::memory_order_relaxed))
        {
            g_pool[i].length = 0;
            return &g_pool[i];
        }
    }
    return nullptr;
}

static void pool_mark_ready(PoolBuffer* buf) noexcept
{
    if (buf)
        buf->state.store(BufferState::Ready, std::memory_order_release);
}

static void pool_release(PoolBuffer* buf) noexcept
{
    if (buf)
        buf->state.store(BufferState::Free, std::memory_order_release);
}



static HANDLE            g_printer_thread    = nullptr;
static DWORD             g_printer_thread_id = 0;
static std::atomic<bool> g_stop              { false };

static DWORD WINAPI printer_thread_proc(LPVOID) noexcept
{
    InstrumentaionCallbackProtection protection;
    const HANDLE hout = GetStdHandle(STD_OUTPUT_HANDLE);

    while (!g_stop.load(std::memory_order_acquire)) {

        bool found = false;

        for (size_t i = 0; i < POOL_COUNT; ++i) {
            BufferState expected = BufferState::Ready;
            if (!g_pool[i].state.compare_exchange_weak(
                    expected, BufferState::Printing,
                    std::memory_order_acquire,
                    std::memory_order_relaxed))
                continue;

            PoolBuffer* buf = &g_pool[i];
            if (buf->length > 0) {
                DWORD written = 0;
                WriteConsoleW(hout,
                              buf->data,
                              static_cast<DWORD>(buf->length),
                              &written,
                              nullptr);
            }

            pool_release(buf);
            found = true;
        }

        if (!found)
            SwitchToThread();
    }


    for (size_t i = 0; i < POOL_COUNT; ++i) {
        BufferState expected = BufferState::Ready;
        if (!g_pool[i].state.compare_exchange_weak(
                expected, BufferState::Printing,
                std::memory_order_acquire,
                std::memory_order_relaxed))
            continue;

        PoolBuffer* buf = &g_pool[i];
        if (buf->length > 0) {
            DWORD written = 0;
            WriteConsoleW(GetStdHandle(STD_OUTPUT_HANDLE),
                          buf->data,
                          static_cast<DWORD>(buf->length),
                          &written,
                          nullptr);
        }
        pool_release(buf);
    }

    return 0;
}

static bool start_printer_thread() noexcept
{
    g_printer_thread = CreateThread(
        nullptr, 0,
        printer_thread_proc,
        nullptr,
        0,
        &g_printer_thread_id);

    return g_printer_thread != nullptr;
}


static void stop_printer_thread() noexcept
{
    if (!g_printer_thread) return;
    g_stop.store(true, std::memory_order_release);
    WaitForSingleObject(g_printer_thread, 3000);
    CloseHandle(g_printer_thread);
    g_printer_thread = nullptr;
}


static size_t append_string_stream(const StackFrame& frame, size_t depth,
                                    wchar_t* buf, size_t remaining) noexcept
{
    if (remaining == 0) return 0;

    int written = swprintf_s(buf, remaining,
        L"#%zu::{%lu}[%zu] %s!%s(+%llx)\n",
        FastInformationUtils::get_time(),
        FastInformationUtils::get_tid(),
        depth,
        frame.module_name,
        frame.function_name,
        static_cast<unsigned long long>(frame.function_offset));

    return (written > 0) ? static_cast<size_t>(written) : 0;
}
void debug_work(CONTEXT* context)
{
    PoolBuffer* buf = pool_acquire();
    if (!buf) return;

    wchar_t* cursor    = buf->data;
    size_t   remaining = POOL_BUFFER_WCHARS;

    size_t depth = 0;
    for (const StackFrame& frame :
         StackUnwindRange{ context->Rip, context->Rsp }
             | std::views::take(MAX_COUNT))
    {
        size_t written = append_string_stream(frame, depth,
                                               cursor, remaining);
        if (written == 0) break;

        cursor    += written;
        remaining -= written;
        ++depth;
    }

    if (remaining >= 2) {
        *cursor++ = L'\n';
        *cursor   = L'\0';
        --remaining;
    }

    buf->length = POOL_BUFFER_WCHARS - remaining;
    pool_mark_ready(buf);
}


void release_work(CONTEXT* context)
{
   
    for (const StackFrame& frame :
         StackUnwindRange{ context->Rip, context->Rsp }
             | std::views::take(MAX_COUNT))
    {
       
    }
    g_log_file.flush();
}


void check_for_function_hook(uintptr_t rip) {
    // doing hook stuff...(TO DO : make smart logic);

}


void InstrumentationCallback(CONTEXT* context)
{
    _TEB64* teb = reinterpret_cast<_TEB64*>(NtCurrentTeb());
    context->Rip = teb->InstrumentationCallbackPreviousPc;
    context->Rsp = teb->InstrumentationCallbackPreviousSp;
    context->Rcx = context->R10;

    if (!teb->InstrumentationCallbackDisabled
        && GetCurrentThreadId() != g_printer_thread_id)
    {
        teb->InstrumentationCallbackDisabled = TRUE;
        __try {
            if (debugging_utils::is_debug)
                debug_work(context);
            else
                release_work(context);
        }
        __except(EXCEPTION_EXECUTE_HANDLER) {}
        teb->InstrumentationCallbackDisabled = FALSE;
    }

    RtlRestoreContext(context, NULL);
}


std::wstring build_log_filename()
{
    wchar_t documents_path[MAX_PATH] = {};
    if (FAILED(SHGetKnownFolderPath(FOLDERID_Documents, 0, nullptr,
                reinterpret_cast<PWSTR*>(&documents_path))))
        GetCurrentDirectoryW(MAX_PATH, documents_path);

    wchar_t exe_path[MAX_PATH] = {};
    GetModuleFileNameW(nullptr, exe_path, MAX_PATH);
    std::wstring stem = std::filesystem::path(exe_path).stem().wstring();

    DWORD      pid = GetCurrentProcessId();
    SYSTEMTIME st  = {};
    GetLocalTime(&st);

    wchar_t filename[MAX_PATH] = {};
    swprintf_s(filename, MAX_PATH,
        L"%s_%u_%04u%02u%02u_%02u%02u%02u.log",
        stem.c_str(), pid,
        st.wYear, st.wMonth, st.wDay,
        st.wHour, st.wMinute, st.wSecond);

    return (std::filesystem::path(documents_path) / filename).wstring();
}


bool register_instrumentation_callback()
{
    if (debugging_utils::is_debug) {
        if (!start_printer_thread())
            return false;
        g_log_file.set_rdbuf(std::cout.rdbuf());
    }
    else {
        std::wstring filename = build_log_filename();
        g_log_file.open(filename,
            std::ios::out | std::ios::trunc | std::ios::binary);
        if (!g_log_file.is_open())
            return false;
    }

    module_manager.start_managing();

    HMODULE nt_dll = GetModuleHandleA("ntdll.dll");
    auto nt_set_information_process =
        reinterpret_cast<nt_set_information_process_t>(
            GetProcAddress(nt_dll, "NtSetInformationProcess"));

    if (!nt_set_information_process)
        return false;

    process_instrumentation_callback_info_t info;
    info.version  = 0;
    info.reserved = 0;
    info.callback = reinterpret_cast<bridge_function_t>(InstrumentationCallbackThunk);

    nt_set_information_process(
        GetCurrentProcess(),
        static_cast<PROCESS_INFORMATION_CLASS>(0x28),
        &info, sizeof(info));

    return true;
}