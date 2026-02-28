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
    using value_type        = Module;
    using difference_type   = std::ptrdiff_t;
    using pointer           = Module*;
    using reference         = Module&;

    // End sentinel
    ModuleIterator() noexcept = default;

    explicit ModuleIterator(LIST_ENTRY* head) noexcept
        : m_head   (head)
        , m_current(head ? head->Flink : nullptr)
    {
        skip_invalid();
    }

    [[nodiscard]] Module operator*() const noexcept
    {
        auto* entry = CONTAINING_RECORD(
            m_current, _LDR_DATA_TABLE_ENTRY_2, InLoadOrderLinks);

        return Module(
            reinterpret_cast<uintptr_t>(entry->DllBase),
            static_cast<ULONG>(entry->SizeOfImage),
            entry);
    }

    ModuleIterator& operator++() noexcept
    {
        if (!is_end()) {
            m_current = m_current->Flink;
            skip_invalid();
        }
        return *this;
    }

    [[nodiscard]] bool operator==(const ModuleIterator& rhs) const noexcept
    {
        if (is_end() && rhs.is_end()) return true;
        if (is_end() != rhs.is_end()) return false;
        return m_current == rhs.m_current;
    }

private:
    LIST_ENTRY* m_head    = nullptr;
    LIST_ENTRY* m_current = nullptr;

    [[nodiscard]] bool is_end() const noexcept
    {
        return !m_current || m_current == m_head;
    }

    void skip_invalid() noexcept
    {
        while (!is_end()) {
            auto* entry = CONTAINING_RECORD(
                m_current, _LDR_DATA_TABLE_ENTRY_2, InLoadOrderLinks);
            if (entry->DllBase) break;
            m_current = m_current->Flink;
        }
    }
};

struct ModuleRange
{
    [[nodiscard]] ModuleIterator begin() const noexcept
    {
        ModuleIterator result{};
        __try {
            auto* peb  = reinterpret_cast<_PEB64_2*>(__readgsqword(0x60));
            auto* ldr  = reinterpret_cast<_PEB_LDR_DATA_2*>(peb->Ldr);
            result     = ModuleIterator{ &ldr->InLoadOrderModuleList };
        }
        __except(EXCEPTION_EXECUTE_HANDLER) {}
        return result;
    }

    [[nodiscard]] static ModuleIterator end() noexcept
    {
        return ModuleIterator{};
    }
};

