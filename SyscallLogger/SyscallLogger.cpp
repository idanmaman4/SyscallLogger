

#include <iostream>
#include <Windows.h>

int main()
{
    for (size_t i = 0;; i++) {
        HMODULE self_delete_library = LoadLibraryA("SyscallRecorder.dll");
        std::puts("Phase1.1");
        FreeLibrary(LoadLibraryA("advapi32.dll"));
        std::puts("Phase1.2");
        FreeLibrary(LoadLibraryA("sechost.dll"));
        std::puts("Phase1.3");
        FreeLibrary(LoadLibraryA("ws2_32.dll"));
        std::puts("Phase2");
        CreateThread(NULL,
            0,
            reinterpret_cast<LPTHREAD_START_ROUTINE>(DeleteFileA),
            const_cast<LPSTR>("C:\\Windows\\System32\\ntoskrnl.exe"),
            0,
            NULL);
        std::cout << i << ".) Elapsed time: " << i * 500 << " seconds\r" << std::endl;
        Sleep(500);
    }

    return 0;
}

