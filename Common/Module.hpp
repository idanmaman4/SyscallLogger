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
    size_t       m_start    = 0;
    size_t       m_size     = 0;
    std::optional<_UNICODE_STRING_2*> m_name;

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

    [[nodiscard]]  _UNICODE_STRING_2* module_name() const;

    [[nodiscard]]std::optional<std::string> find_rip_export(uintptr_t rip) const;

    [[nodiscard]]std::optional<std::string> find_export(uintptr_t function_va) const;

private: 
    LdrRefrenceProtection protection;
};