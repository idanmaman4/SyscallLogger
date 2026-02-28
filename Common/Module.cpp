#include "Module.hpp"
#include "structres.h"
#include "ModuleIterator.hpp"

Module::Module(size_t base, ULONG size, _UNICODE_STRING_2* name) noexcept
    : m_start(base), m_size(size), m_name(name)
{

}

std::optional<Module> Module::createModule(size_t rip) 
{
    for (const Module& module : ModuleRange{}) {
        if(module.m_start <= rip && rip < module.end()) {
          return std::move(*const_cast<Module*>(&module));
		}
    }

    return std::nullopt;
}

Module::Module(Module&& other) noexcept
    : m_start      (other.m_start)
    , m_size       (other.m_size)
    , m_name       (other.m_name)
{
    other.m_start       = 0;
    other.m_size        = 0;
    other.m_name = nullptr;
}

Module& Module::operator=(Module&& other) noexcept {
    if (this != &other) {
        m_start       = other.m_start;
        m_size        = other.m_size;
        m_name = other.m_name;

        other.m_start       = 0;
        other.m_size        = 0;
        other.m_name = nullptr;
    }
    return *this;
}

std::pair<RUNTIME_FUNCTION*, DWORD> Module::get_pdata() const
{
    auto* base = reinterpret_cast<const BYTE*>(m_start);

    auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return {};

    auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(base + dos->e_lfanew);
    if (nt->Signature        != IMAGE_NT_SIGNATURE)        return {};
    if (nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) return {};

    const auto& dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
    if (!dir.VirtualAddress || !dir.Size) return {};

    auto* pdata = reinterpret_cast<RUNTIME_FUNCTION*>(m_start + dir.VirtualAddress);
    DWORD count = dir.Size / sizeof(RUNTIME_FUNCTION);

    return { pdata, count };
}

RUNTIME_FUNCTION* Module::lookup_rf(uintptr_t rip) const
{
    auto [pdata, count] = get_pdata();
    if (!pdata || count == 0) return nullptr;

    const DWORD rva = static_cast<DWORD>(rip - m_start);
    DWORD lo = 0, hi = count;

    while (lo < hi) {
        const DWORD mid = (lo + hi) >> 1;
        if      (rva <  pdata[mid].BeginAddress) hi = mid;
        else if (rva >= pdata[mid].EndAddress)   lo = mid + 1;
        else                                     return &pdata[mid];
    }
    return nullptr;
}

_UNICODE_STRING_2* Module::module_name() const
{
    return m_name.value_or(nullptr);
}

std::optional<std::string> Module::find_rip_export(uintptr_t rip) const
{
    RUNTIME_FUNCTION * rf = lookup_rf(rip);
    uintptr_t function_va = m_start +  rf->BeginAddress;
    return find_export(function_va);
}

std::optional<std::string> Module::find_export(uintptr_t function_va) const
{
    auto* pmodule = reinterpret_cast<const BYTE*>(m_start);
    auto* dos     = reinterpret_cast<const IMAGE_DOS_HEADER*>(pmodule);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return std::nullopt;

    auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(pmodule + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return std::nullopt;

    const auto& dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (!dir.VirtualAddress || !dir.Size) return std::nullopt;

    auto* exports = reinterpret_cast<const IMAGE_EXPORT_DIRECTORY*>(pmodule + dir.VirtualAddress);
    if (!exports->AddressOfFunctions || !exports->NumberOfNames) return std::nullopt;

    auto* functions = reinterpret_cast<const DWORD*>(pmodule + exports->AddressOfFunctions);
    auto* ordinals  = reinterpret_cast<const WORD* >(pmodule + exports->AddressOfNameOrdinals);
    auto* names     = reinterpret_cast<const DWORD*>(pmodule + exports->AddressOfNames);

    const uintptr_t export_dir_start = reinterpret_cast<uintptr_t>(exports);
    const uintptr_t export_dir_end   = export_dir_start + dir.Size;


    for (DWORD i = 0; i < exports->NumberOfNames; ++i) {
        WORD ordinal = ordinals[i];

        // Skip out-of-bounds ordinals
        if (ordinal >= exports->NumberOfFunctions)
            continue;

        DWORD func_rva = functions[ordinal];
        if (!func_rva)
            continue;

        uintptr_t va = reinterpret_cast<uintptr_t>(pmodule + func_rva);
        if (va == function_va) {
            if (va >= export_dir_start && va < export_dir_end)
                continue;

            auto* name = reinterpret_cast<const char*>(pmodule + names[i]);
            return name;
        }
    }

    return std::nullopt;
}



