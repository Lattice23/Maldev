#pragma once

namespace HASH {

  using OpenProcess = HANDLE(*)(
   DWORD dwDesiredAccess,
   BOOL  bInheritHandle,
   DWORD dwProcessId
   );
  
  using VirtualAllocEx = PVOID(*)(
     HANDLE hProcess,
     LPVOID lpAddress,
     SIZE_T dwSize,
     DWORD  flAllocationType,
     DWORD  flProtect
    );

  using WriteProcessMemory = BOOL(*)(
     HANDLE  hProcess,
     LPVOID  lpBaseAddress,
     LPCVOID lpBuffer,
     SIZE_T  nSize,
     SIZE_T  *lpNumberOfBytesWritten
  );
  

  using CreateRemoteThread = HANDLE(*)(
    HANDLE                 hProcess,
    LPSECURITY_ATTRIBUTES  lpThreadAttributes,
    SIZE_T                 dwStackSize,
    LPTHREAD_START_ROUTINE lpStartAddress,
    LPVOID                 lpParameter,
    DWORD                  dwCreationFlags,
    LPDWORD                lpThreadId
  );

}
