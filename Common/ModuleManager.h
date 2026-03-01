#pragma once
#include <Windows.h>
#include "structres.h"
#include <fstream>

class ModuleManager
{
public:
	ModuleManager(std::ofstream& output_file);
    
    void start_managing();

    ~ModuleManager();
    
    static void CALLBACK caching_update_handler(
        _In_     ULONG                      NotificationReason,
        _In_     LDR_DLL_NOTIFICATION_DATA* NotificationData,
        _In_opt_ ModuleManager*               Context);

private:
	PVOID m_cookie;
    std::ofstream& m_output_file;
    static void log_module_info_record(std::ofstream& stream,  uintptr_t);
    static void log_module_info_debug(std::ofstream& stream, uintptr_t modulebase);
    static void log_module_info_debug_unload(std::ofstream& stream, uintptr_t modulebase);

};



