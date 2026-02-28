

#include <iostream>
#include <Windows.h>

int main()
{
    HMODULE self_delete_library = LoadLibraryA("SyscallRecorder.dll");
    for(size_t i=0; ;i++){
        FreeLibrary(LoadLibraryA("advapi32.dll"));
        FreeLibrary(LoadLibraryA("sechost.dll"));
        FreeLibrary(LoadLibraryA("ws2_32.dll"));

        CreateThread(NULL,
                     0,
                     reinterpret_cast<LPTHREAD_START_ROUTINE>(DeleteFileA),
                     const_cast<LPSTR>("C:\\Windows\\System32\\ntoskrnl.exe"),
                     0,
                     NULL);
        std::cout << i  << ".) Elapsed time: " << i *500 << " seconds\r" << std::endl;
            Sleep(500);
    }

    return 0;
}

