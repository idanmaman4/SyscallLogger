

#include <iostream>
#include <Windows.h>

int main()
{
    HMODULE self_delete_library = LoadLibraryA("SyscallRecorder.dll");
    Sleep(1000);
}

