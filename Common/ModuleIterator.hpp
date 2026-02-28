#pragma once
#include <Windows.h>
#include <cstdint>
#include <iterator>
#include "Module.hpp"
#include "structres.h"

class ModuleIterator
{
public:
    using iterator_category = std::input_iterator_tag;
    using value_type        = const Module;
    using difference_type   = std::ptrdiff_t;
    using pointer           = const Module*;
    using reference         = const Module&;

    ModuleIterator() noexcept = default;

    explicit ModuleIterator(LIST_ENTRY* head) noexcept
        : m_head(head)
        , m_current(head ? head->Flink : nullptr)
    {
        skip_invalid();
        build_current();
    }

    [[nodiscard]] reference operator*()  const noexcept { return m_module;  }
    [[nodiscard]] pointer   operator->() const noexcept { return &m_module; }

    ModuleIterator& operator++() noexcept
    {
        advance();
        return *this;
    }

    [[nodiscard]] bool operator==(const ModuleIterator& rhs) const noexcept
    {
        // Both end sentinels, or same list position
        if (is_end() && rhs.is_end()) return true;
        if (is_end() != rhs.is_end()) return false;
        return m_current == rhs.m_current;
    }

private:
    LIST_ENTRY* m_head    = nullptr; 
    LIST_ENTRY* m_current = nullptr; 
    Module      m_module;            

    [[nodiscard]] bool is_end() const noexcept
    {
        return !m_current || m_current == m_head;
    }

    void skip_invalid() noexcept
    {
        while (m_current && m_current != m_head) {
            auto* entry = CONTAINING_RECORD(
                m_current, _LDR_DATA_TABLE_ENTRY_2, InLoadOrderLinks);
            if (entry->DllBase)
                break;
            m_current = m_current->Flink;
        }
    }

    void advance() noexcept
    {
        if (is_end()) return;
        m_current = m_current->Flink;
        skip_invalid();
        build_current();
    }

    void build_current() noexcept
    {
        if (is_end()) return;

        try {
            auto* entry = CONTAINING_RECORD(
                m_current, _LDR_DATA_TABLE_ENTRY_2, InLoadOrderLinks);

            auto base = reinterpret_cast<uintptr_t>(entry->DllBase);
            auto size = static_cast<ULONG>(entry->SizeOfImage);

            m_module = Module(base, size,&entry->FullDllName);
        }
        catch (...) {
            m_current = m_head;
        }
    }
};


struct ModuleRange
{
    [[nodiscard]] ModuleIterator begin() const noexcept
    {
        try {
            auto* peb  = reinterpret_cast<_PEB64_2*>(__readgsqword(0x60));
            auto* ldr  = reinterpret_cast<_PEB_LDR_DATA_2*>(peb->Ldr);
            auto* head = &ldr->InLoadOrderModuleList;
            return ModuleIterator{ head };
        }
        catch (...) {
            return ModuleIterator{};
        }
    }

    [[nodiscard]] static ModuleIterator end() noexcept
    {
        return ModuleIterator{};
    }
};

