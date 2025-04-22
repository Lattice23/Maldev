#pragma once
#include <iostream>
#include <windows.h>

// idek why i made this file
#define good L"[+]" 
#define bad  L"[-]"
#define info L"[i]"
namespace lattice
{

	LPVOID AllocateWriteMemory(const HANDLE hProcess, const SIZE_T& size, LPVOID buf)
	{
		LPVOID pAlloc = VirtualAllocEx(hProcess, NULL, size, (MEM_COMMIT | MEM_RESERVE), PAGE_EXECUTE_READWRITE);
		if (pAlloc == NULL)
		{
			std::wprintf(L"%s Problem Allocating memory: %lu\n", bad, GetLastError());
			std::exit(1);
		}
		std::wprintf(L"%s Successfully Allocated memory\n", good);

		SIZE_T bytesWritten;
		if (!WriteProcessMemory(hProcess, pAlloc, buf, size, &bytesWritten))
		{
			std::wprintf(L" Problem Writing process memory 0x%lu bytes written : %lu\n",bytesWritten, GetLastError());
			std::exit(1);
		}
		std::wprintf(L"%s Wrote 0x%lu bytes of memory\n", good,bytesWritten);

		return pAlloc;
	}

	void MakeThread(const HANDLE hProcess, const auto& start, LPVOID lparameter = NULL)
	{

		DWORD tid;
		HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, static_cast<LPTHREAD_START_ROUTINE>(start), lparameter, 0, &tid);
		if (hThread == NULL)
		{
			std::wprintf(L"%s Problem creating remote thread to the proccess %lu\n", bad, GetLastError());
			std::exit(0);
		}
		std::wprintf(L"%s Creating thread TID=%d\n", good, tid);
		WaitForSingleObject(hThread, 3000);
		CloseHandle(hThread);

	}

	LPVOID GetAddress(const HMODULE& dll, const auto& function)
	{
		LPVOID address = GetProcAddress(dll, function);
		if (address == NULL)
		{
			std::wprintf(L"%s Problem getting address to the kernel32.dll function %lu\n", bad, GetLastError());
			std::exit(1);
		}
		std::wprintf(L"%s Successfully got the address to LoadLibraryW in kernel32\n", good);

		return address;
	}

	void Free(LPVOID Alloc, const SIZE_T& dwsize)
	{
		VirtualFree(Alloc, dwsize, MEM_RELEASE);
	}
}
