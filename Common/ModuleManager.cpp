#include "ModuleManager.h"
#include "LogInfo.h"
#include "Module.hpp"
#include "FastInformationUtils.h"
#include "ModuleIterator.hpp"
#include <iostream>
#include <debug_utils.hpp>
#include "InstrumentaionCallbackProtection.h"

void ModuleManager::log_module_info_record(std::ofstream& stream, uintptr_t modulebase) {
	std::optional<Module::PdbInfo> pdb_info = Module::get_pdb_info(modulebase);
	if (pdb_info.has_value()) {
		{
			LogInfoNewModule loginfo(pdb_info.value().pdb_name,
				pdb_info.value().guid,
				FastInformationUtils::get_time(),
				FastInformationUtils::get_tid());
			stream.write(reinterpret_cast<const char*>(&loginfo), sizeof(loginfo));
		}
	}
}

void ModuleManager::log_module_info_debug(std::ofstream& stream, uintptr_t modulebase)
{
	std::optional<Module::PdbInfo> pdb_info = Module::get_pdb_info(modulebase);
	if (pdb_info.has_value()) {
		stream << "Loaded: " << pdb_info.value().pdb_name << std::endl;
	}
}

void ModuleManager::log_module_info_debug_unload(std::ofstream& stream, uintptr_t modulebase)
{
	std::optional<Module::PdbInfo> pdb_info = Module::get_pdb_info(modulebase);
	if (pdb_info.has_value()) {
		stream << "Unloaded: " << pdb_info.value().pdb_name << std::endl;
	}

}


ModuleManager::ModuleManager(std::ofstream& output_file) : m_output_file(output_file)
{
	
}

void ModuleManager::start_managing()
{auto ntdll   = GetModuleHandleA("ntdll.dll");
	auto proc    = GetProcAddress(ntdll, "LdrRegisterDllNotification");
	auto ldr_reg = reinterpret_cast<LdrRegisterDllNotification_t*>(proc);



	ldr_reg(0,
			reinterpret_cast<LdrDllNotification_t*>(caching_update_handler),
			this,
			&m_cookie);

	for (const Module& module : ModuleRange{}) {
		if (debugging_utils::is_debug) {
			log_module_info_debug(m_output_file, module.m_start);
		}
		else {
			log_module_info_record(m_output_file, module.m_start);
		}
	}
}


ModuleManager::~ModuleManager() {
	if (m_cookie) {
		auto ntdll      = GetModuleHandleA("ntdll.dll");
		auto proc       = GetProcAddress(ntdll, "LdrUnregisterDllNotification");
		using Unreg_t   = NTSTATUS(NTAPI)(PVOID);
		auto ldr_unreg  = reinterpret_cast<Unreg_t*>(proc);
		if (ldr_unreg)
			ldr_unreg(m_cookie);
	}
}


void ModuleManager::caching_update_handler(ULONG NotificationReason, LDR_DLL_NOTIFICATION_DATA* NotificationData, ModuleManager* Context)
{
	InstrumentaionCallbackProtection protection();

	switch (NotificationReason) {

	case static_cast<ULONG>(LdrLoadReason::LDR_DLL_NOTIFICATION_REASON_LOADED):
			if (debugging_utils::is_debug) {
				log_module_info_debug(Context->m_output_file, reinterpret_cast<uintptr_t>(NotificationData->Loaded.DllBase));	
			}
			else {
				log_module_info_record(Context->m_output_file, reinterpret_cast<uintptr_t>(NotificationData->Loaded.DllBase));			
			}
			break;
		case static_cast<ULONG>(LdrLoadReason::LDR_DLL_NOTIFICATION_REASON_UNLOADED):
			if (debugging_utils::is_debug) {
				log_module_info_debug_unload(Context->m_output_file, reinterpret_cast<uintptr_t>(NotificationData->Unloaded.DllBase));	

			}
			break;
	}
}

