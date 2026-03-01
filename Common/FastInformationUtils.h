#pragma once
#include <cinttypes>
#include <Windows.h>
#include "structres.h"

namespace FastInformationUtils {
	static inline const volatile KUSER_SHARED_DATA* const g_kuser_shared_data = reinterpret_cast<const volatile KUSER_SHARED_DATA*>(0x7FFE0000);	
	static constexpr uint64_t  EPOCH_DIFF_100NS  = 11644473600ULL * 10000000ULL; // in 100-ns units

	inline uint64_t get_time() {
		uint64_t filetime = (static_cast<uint64_t>(g_kuser_shared_data->SystemTime.High1Time) << 32) | g_kuser_shared_data->SystemTime.LowPart; 
		return filetime - EPOCH_DIFF_100NS; // Convert to Unix epoch time in 100-ns units
	}

	inline DWORD get_tid() {
		 _TEB64* teb = reinterpret_cast<_TEB64*>(NtCurrentTeb());
		 return teb->client_id.UniqueThread; 
	
	}

	inline DWORD get_pid() {
		 _TEB64* teb = reinterpret_cast<_TEB64*>(NtCurrentTeb());
		 return teb->client_id.UniqueProcess;
	
	}
}