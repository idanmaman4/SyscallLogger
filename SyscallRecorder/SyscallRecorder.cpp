#include "pch.h"
#include "framework.h"
#include "SyscallRecorder.h"
#include "structres.h"

#include <filesystem>
#include <cstdint>
#include <iostream>
#include <fstream>
#include <format>

Concurrency::concurrent_queue<LogEntry> log_queue;

static std::wofstream g_log_file;

struct ModuleInformation {
	addr_t base_address;
};

struct FunctionInformation {
	addr_t function_address;
	ModuleInformation module_info;
};

struct process_instrumentation_callback_info_t {
	uint32_t version;
	uint32_t reserved;
	bridge_function_t callback;
};

SYSCALLRECORDER_API int nSyscallRecorder = 0;

SYSCALLRECORDER_API int fnSyscallRecorder(void)
{
	return 0;
}

CSyscallRecorder::CSyscallRecorder()
{
	return;
}

struct RUNTIME_FUNCTION_MANUAL {
	DWORD BeginAddress;
	DWORD EndAddress;
	DWORD UnwindInfoAddress;
};

struct UNWIND_INFO_MANUAL {
	BYTE Version : 3;
	BYTE Flags : 5;
	BYTE SizeOfProlog;
	BYTE CountOfCodes;
	BYTE FrameRegister : 4;
	BYTE FrameOffset : 4;
};

struct UNWIND_CODE {
	BYTE CodeOffset;
	BYTE UnwindOp : 4;
	BYTE OpInfo : 4;
};

bool GetPDataSection(HMODULE module, RUNTIME_FUNCTION_MANUAL*& pdata, size_t& count)
{
	auto dosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(module);
	if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
		return false;

	IMAGE_NT_HEADERS* ntHeaders = reinterpret_cast<IMAGE_NT_HEADERS64*>(reinterpret_cast<BYTE*>(module) + dosHeader->e_lfanew);
	if (ntHeaders->Signature != IMAGE_NT_SIGNATURE)
		return false;

	auto& dataDir = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
	if (dataDir.VirtualAddress == 0)
		return false;

	pdata = reinterpret_cast<RUNTIME_FUNCTION_MANUAL*>(reinterpret_cast<BYTE*>(module) + dataDir.VirtualAddress);
	count = dataDir.Size / sizeof(RUNTIME_FUNCTION_MANUAL);
	return true;
}

RUNTIME_FUNCTION_MANUAL* LookupFunction(HMODULE module, void* address)
{
	RUNTIME_FUNCTION_MANUAL* pdata;
	size_t count;
	if (!GetPDataSection(module, pdata, count))
		return nullptr;

	uintptr_t addr = reinterpret_cast<uintptr_t>(address) - reinterpret_cast<uintptr_t>(module);

	for (size_t i = 0; i < count; i++) {
		if (addr >= pdata[i].BeginAddress && addr <= pdata[i].EndAddress)
			return &pdata[i];
	}
	return nullptr;
}

void symbol_search(addr_t address, HMODULE module, char name[sizeof(FunctionInfoPack::function_name)])
{
	if (module == NULL || address == NULL)
		return;

	PBYTE pmodule = reinterpret_cast<PBYTE>(module);
	IMAGE_DOS_HEADER* dos_header = reinterpret_cast<IMAGE_DOS_HEADER*>(pmodule);
	if (dos_header->e_magic != IMAGE_DOS_SIGNATURE)
		return;

	IMAGE_NT_HEADERS* nt_headers = reinterpret_cast<IMAGE_NT_HEADERS64*>(pmodule + dos_header->e_lfanew);
	if (nt_headers->Signature != IMAGE_NT_SIGNATURE)
		return;

	IMAGE_DATA_DIRECTORY export_directory = nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
	if (export_directory.VirtualAddress == 0)
		return;

	PIMAGE_EXPORT_DIRECTORY export_table = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(pmodule + export_directory.VirtualAddress);
	if (export_table->AddressOfFunctions == 0)
		return;

	char* function_name = nullptr;
	for (size_t i = 0; i < export_table->NumberOfNames; i++) {
		auto ordinal = ((WORD*)(export_table->AddressOfNameOrdinals + pmodule))[i];
		auto func_addaress = ((DWORD*)(export_table->AddressOfFunctions + pmodule))[ordinal] + pmodule;
		if (func_addaress == address) {
			function_name = (char*)pmodule + *((DWORD*)(pmodule + export_table->AddressOfNames + (i * sizeof(DWORD))));
			break;
		}
	}

	if (function_name != NULL)
		strncpy_s(name, sizeof(FunctionInfoPack::function_name) - 1, function_name, sizeof(FunctionInfoPack::function_name) - 1);
}

addr_t get_module_base_and_name(addr_t func_addaress, FunctionInfoPack& log)
{
	auto peb = (_PEB64_2*)__readgsqword(0x60);
	auto ldr = (_PEB_LDR_DATA_2*)peb->Ldr;

	for (LIST_ENTRY* i = ldr->InLoadOrderModuleList.Flink; i != NULL; i = i->Flink) {
		auto current_address = CONTAINING_RECORD(i, _LDR_DATA_TABLE_ENTRY_2, InLoadOrderLinks);
		if (current_address->DllBase <= func_addaress &&
			(reinterpret_cast<BYTE*>(current_address->DllBase) + current_address->SizeOfImage) > func_addaress)
		{
			lstrcpynW(
				log.module_name,
				current_address->FullDllName.Buffer,
				min(current_address->FullDllName.Length / sizeof(WCHAR), sizeof(log.module_name) / sizeof(WCHAR) - 1)
			);
			return current_address->DllBase;
		}
	}

	ZeroMemory(&log.module_name, sizeof(log.module_name));
	return nullptr;
}

void get_function_info_pack(addr_t address, FunctionInformation& info, FunctionInfoPack& log)
{
	addr_t module = get_module_base_and_name(address, log);
	if (module == nullptr)
		return;

	RUNTIME_FUNCTION_MANUAL* runtime_info = LookupFunction((HMODULE)module, (void*)address);
	if (runtime_info != nullptr)
		symbol_search(reinterpret_cast<BYTE*>(module) + runtime_info->BeginAddress, (HMODULE)module, log.function_name);

	log.function_offset_in_module = (size_t)address - (size_t)module;
}

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
		stem.c_str(),
		pid,
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
	addr_t previous_function = NULL;

	if (!teb->InstrumentationCallbackDisabled) {
		teb->InstrumentationCallbackDisabled = TRUE;

		LogEntry log_entry;

		FunctionInformation current_function_info;
		get_function_info_pack(reinterpret_cast<addr_t>(context->Rip),
			current_function_info, log_entry.current_function);

		if (context->Rsp != 0 && context->Rsp != (DWORD64)-1)
			previous_function = *reinterpret_cast<addr_t*>(context->Rsp);

		if (previous_function != 0 && previous_function != (addr_t)-1) {
			FunctionInformation prev_function_info;
			get_function_info_pack(reinterpret_cast<addr_t>(previous_function),
				prev_function_info, log_entry.previous_function);
		}

		log_entry.return_value = context->Rax;

		g_log_file << L"Current Function : " << log_entry.current_function.module_name << L"!"
			<< log_entry.current_function.function_name
			<< L"(" << std::hex << log_entry.current_function.function_offset_in_module << L") \n";

		g_log_file << L"Previous Function : " << log_entry.previous_function.module_name << L"!"
			<< log_entry.previous_function.function_name
			<< L"(" << std::hex << log_entry.previous_function.function_offset_in_module << L") | "
			<< log_entry.return_value << L"\n\n";

		g_log_file.flush();

		teb->InstrumentationCallbackDisabled = FALSE;
	}
	RtlRestoreContext(context, NULL);
}

bool register_instrumentation_callback()
{
	std::wstring filename = build_log_filename();
	g_log_file.open(filename, std::ios::out | std::ios::trunc);
	if (!g_log_file.is_open())
		return false;

	HMODULE nt_dll = GetModuleHandleA("ntdll.dll");
	auto nt_set_information_process = reinterpret_cast<nt_set_information_process_t>(
		GetProcAddress(nt_dll, "NtSetInformationProcess"));
	if (nt_set_information_process == nullptr)
		return false;

	process_instrumentation_callback_info_t info;
	info.version = 0;
	info.reserved = 0;
	info.callback = reinterpret_cast<bridge_function_t>(InstrumentationCallbackThunk);

	nt_set_information_process(GetCurrentProcess(),
		static_cast<PROCESS_INFORMATION_CLASS>(0x28),
		&info, sizeof(info));

	return true;
}