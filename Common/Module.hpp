#pragma once
#include <Windows.h>
#include <string>
#include <optional>
#include <vector>
#include "structres.h"
#include "LdrRefrenceProtection.hpp"
#include <unordered_map>




class Module {
public:

    struct PdbInfo
    {
        _GUID       guid;
        const char* pdb_name = nullptr;
    };

    size_t       m_start    = 0;
    size_t       m_size     = 0;
    wchar_t m_name[32] = {0};

    Module() = delete;
    Module(size_t base, ULONG size, _LDR_DATA_TABLE_ENTRY_2* ldr_table_entry = nullptr) noexcept;
    static std::optional<Module> createModule(size_t rip);


    Module(Module&& other) noexcept;
    Module& operator=(Module&& other) noexcept;

    Module(const Module&)            = delete;
    Module& operator=(const Module&) = delete;

    [[nodiscard]] std::pair<RUNTIME_FUNCTION*, DWORD> get_pdata() const;

    [[nodiscard]] inline size_t end() const noexcept { return m_start + m_size; }

    [[nodiscard]] RUNTIME_FUNCTION* lookup_rf(uintptr_t rip) const;

    [[nodiscard]]bool find_rip_export(uintptr_t rip, wchar_t* string, size_t string_size) const;

    [[nodiscard]]bool find_export(uintptr_t function_va, wchar_t* string, size_t string_size) const;

    [[nodiscard]] static std::optional<PdbInfo> get_pdb_info(uintptr_t module_base);
   

private: 
    LdrRefrenceProtection protection;
};