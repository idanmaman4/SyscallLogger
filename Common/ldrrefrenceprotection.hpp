#pragma once
#include "structres.h"
#include "Windows.h"

class LdrRefrenceProtection {
public:
    _LDR_DATA_TABLE_ENTRY_2 *m_entry = nullptr;
    LdrRefrenceProtection(_LDR_DATA_TABLE_ENTRY_2 *entry) noexcept : m_entry(entry) {
		if (m_entry) {
			InterlockedIncrement(&m_entry->ReferenceCount);
		}
	}
    ~LdrRefrenceProtection() noexcept {
        if (m_entry) {
            InterlockedDecrement(&m_entry->ReferenceCount);
        }
    }
    LdrRefrenceProtection(LdrRefrenceProtection&& other) noexcept
        : m_entry(other.m_entry)
    {
        other.m_entry = nullptr;
    }

    LdrRefrenceProtection& operator=(LdrRefrenceProtection&& other) noexcept
    {
        if (this != &other) {
            if (m_entry)
                InterlockedDecrement(&m_entry->ReferenceCount);
            m_entry       = other.m_entry;
            other.m_entry = nullptr;
        }
        return *this;
    }

    LdrRefrenceProtection(const LdrRefrenceProtection&)            = delete;
    LdrRefrenceProtection& operator=(const LdrRefrenceProtection&) = delete;

};