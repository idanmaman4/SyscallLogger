#pragma once
#pragma once
#include <Windows.h>
#include <cstdint>
#include <vector>
#include "Module.hpp"

struct SymbolInformation
{
    uintptr_t address         = 0;   // the original pointer
    uintptr_t module_base     = 0;   // base of the containing module
    uintptr_t function_offset = 0;   // address - module_base
    WCHAR     module_name[MAX_PATH] = {};
    char      function_name[128]    = {};

    [[nodiscard]] bool valid() const noexcept
    {
        return address != 0 && address != static_cast<uintptr_t>(-1);
    }

    
    [[nodiscard]] static SymbolInformation from_address(uintptr_t address) noexcept
    {
        SymbolInformation info{};
        info.address = address;

        if (!address || address == static_cast<uintptr_t>(-1))
            return info;

        try {
            std::vector<Module> modules = Module::snapshot_loaded_modules();

            const Module* owner = nullptr;
            for (const Module& m : modules) {
                if (address >= m.m_start && address < m.end()) {
                    owner = &m;
                    break;
                }
            }

            if (!owner)
                return info;

            info.module_base     = owner->m_start;
            info.function_offset = address - owner->m_start;

            if (!owner->m_name.empty()) {
                lstrcpynW(info.module_name,
                          owner->m_name.c_str(),
                          static_cast<int>(
                              min(owner->m_name.size() + 1,
                                  static_cast<size_t>(MAX_PATH - 1))));
            }

  
            RUNTIME_FUNCTION* rf = owner->lookup_rf(address);
            if (rf) {
                uintptr_t fn_start = owner->m_start + rf->BeginAddress;
                if (const char* name = owner->find_export(fn_start)->c_str())
                    strncpy_s(info.function_name, sizeof(info.function_name),
                              name, sizeof(info.function_name) - 1);
            }
        }
        catch (...) {}

        return info;
    }

    [[nodiscard]] static SymbolInformation from_address(const void* ptr) noexcept
    {
        return from_address(reinterpret_cast<uintptr_t>(ptr));
    }
};