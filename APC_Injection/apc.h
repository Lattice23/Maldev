#pragma once
#include <iostream>
#include <windows.h>
#include <vector>
#include <TlHelp32.h>

std::vector<DWORD>  findThreads(const HANDLE hSnapshot, THREADENTRY32* Tentry, DWORD pid);
HANDLE snapshotThread  ();
HANDLE snapshotProcess ();
DWORD  findProcesses   (const HANDLE hSnapshot, PROCESSENTRY32W* entry, const std::wstring& ProccessName);
void   ApcInject	     (const std::vector<DWORD>& ThreadIds, LPVOID buffer);
