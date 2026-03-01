#include "Module.hpp"
#include "structres.h"
#include "ModuleIterator.hpp"

Module::Module(size_t base, ULONG size, _LDR_DATA_TABLE_ENTRY_2* ldr_entry) noexcept
    : protection(ldr_entry), m_start(base), m_size(size)
{
    if (ldr_entry) {
        for (size_t i = 0; i < ARRAYSIZE(m_name) && i < ldr_entry->BaseDllName.Length / sizeof(wchar_t); ++i)
            m_name[i] = ldr_entry->BaseDllName.Buffer[i];
    }
}

std::optional<Module> Module::createModule(size_t rip) 
{
    for (Module module : ModuleRange{}) {
        if (module.m_start <= rip && rip < module.end())
            return std::move(module);       // moves protection cleanly
    }
    return std::nullopt;
}

Module::Module(Module&& other) noexcept
    : protection (std::move(other.protection)) ,
     m_start      (other.m_start)
    , m_size       (other.m_size)
{
    std::memcpy(m_name, other.m_name, sizeof(other.m_name));
    std::memset(other.m_name, 0, sizeof(other.m_name));
    other.m_start       = 0;
    other.m_size        = 0;
}

Module& Module::operator=(Module&& other) noexcept {
    if (this != &other) {
        protection    = std::move(other.protection);
        m_start       = other.m_start;
        m_size        = other.m_size;
        std::memcpy(m_name, other.m_name, sizeof(other.m_name));

        other.m_start       = 0;
        other.m_size        = 0;
        std::memset(other.m_name, 0, sizeof(other.m_name));
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


bool Module::find_rip_export(uintptr_t rip, wchar_t* string, size_t string_size) const
{
    RUNTIME_FUNCTION * rf = lookup_rf(rip);
    if (rf) {
        uintptr_t function_va = m_start + rf->BeginAddress;
        return find_export(function_va, string, string_size);
    }
    return false;
}

bool Module::find_export(uintptr_t function_va, wchar_t* string, size_t string_size) const
{
    auto* pmodule = reinterpret_cast<const BYTE*>(m_start);
    auto* dos     = reinterpret_cast<const IMAGE_DOS_HEADER*>(pmodule);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;

    auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(pmodule + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return false;

    const auto& dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (!dir.VirtualAddress || !dir.Size) return false;

    auto* exports = reinterpret_cast<const IMAGE_EXPORT_DIRECTORY*>(pmodule + dir.VirtualAddress);
    if (!exports->AddressOfFunctions || !exports->NumberOfNames) return false;

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
            for(size_t i=0 ; i < string_size - 1 && name[i] != '\0'; ++i)
				string[i] = static_cast<wchar_t>(name[i]);
            string[string_size - 1] = '\0';
            return true;
        }
    }

    return false;
}

std::optional<Module::PdbInfo> Module::get_pdb_info(uintptr_t module_base)
{
    std::optional<PdbInfo> result = std::nullopt;

    __try {
        auto* base = reinterpret_cast<const BYTE*>(module_base);

        auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) return std::nullopt;

        auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE) return std::nullopt;

        IMAGE_DATA_DIRECTORY debug_dir{};
        if (nt->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
            debug_dir = reinterpret_cast<const IMAGE_NT_HEADERS64*>(nt)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG];
        else if (nt->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
            debug_dir = reinterpret_cast<const IMAGE_NT_HEADERS32*>(nt)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG];
        else
            return std::nullopt;

        if (!debug_dir.VirtualAddress || !debug_dir.Size) return std::nullopt;

        auto*  entries     = reinterpret_cast<const IMAGE_DEBUG_DIRECTORY*>(
            base + debug_dir.VirtualAddress);
        size_t entry_count = debug_dir.Size / sizeof(IMAGE_DEBUG_DIRECTORY);

        for (size_t i = 0; i < entry_count; ++i) {
            const auto& e = entries[i];

            if (e.Type != IMAGE_DEBUG_TYPE_CODEVIEW) continue;
            if (e.SizeOfData < sizeof(DWORD))        continue;

            auto* cv = reinterpret_cast<const DWORD*>(base + e.AddressOfRawData);

            if (*cv == CV_SIGNATURE_RSDS) {
                auto* info = reinterpret_cast<const CV_INFO_PDB70*>(cv);
                if (e.SizeOfData < offsetof(CV_INFO_PDB70, PdbFileName)) continue;

                PdbInfo out;
                out.guid     = info->Signature;
                out.pdb_name = reinterpret_cast<const char*>(info->PdbFileName);
                return out;
            }
        }
    }
    __except(EXCEPTION_EXECUTE_HANDLER) {}

    return result;
}

