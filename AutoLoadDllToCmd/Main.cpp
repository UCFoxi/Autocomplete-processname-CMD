#include <Windows.h>
#include <iostream>
#include <TlHelp32.h>

DWORD GetProcessIdByName(std::wstring ProcSubname)
{
	DWORD ResultPid{};
	DWORD highestThreadCount = 0;

	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	PROCESSENTRY32W pe;
	pe.dwSize = sizeof(PROCESSENTRY32);
	Process32FirstW(hSnap, &pe);

	int Skipped = 0;
	while (Process32NextW(hSnap, &pe))
	{
		if (std::wstring(pe.szExeFile)._Equal(ProcSubname) && (pe.cntThreads > highestThreadCount))
		{
			highestThreadCount = pe.cntThreads;
			ResultPid = pe.th32ProcessID;
		}
	}
	CloseHandle(hSnap);
	return ResultPid;
}

UINT64 GetModuleBaseAddress(DWORD ProcId, std::wstring ModuleName)
{
	UINT64 moduleBaseAddress = 0;
	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, ProcId);

	if (hSnap != INVALID_HANDLE_VALUE)
	{
		MODULEENTRY32 moduleEntry;
		moduleEntry.dwSize = sizeof(moduleEntry);
		if (Module32FirstW(hSnap, &moduleEntry))
		{
			do
			{
				if (_wcsicmp(moduleEntry.szModule, ModuleName.c_str()) == 0)
				{
					moduleBaseAddress = (UINT64)moduleEntry.modBaseAddr;
					break;
				}
			} while (Module32NextW(hSnap, &moduleEntry));
		}
	}
	CloseHandle(hSnap);
	return moduleBaseAddress;
}

int __stdcall WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nShowCmd)
{
	const std::string DllPath = "C:\\Windows\\System32\\CmdProcessNameAutoComplete.dll";
	DWORD LastCmdPid = 0;
	while (true)
	{
		Sleep(500);

		DWORD CmdPid = GetProcessIdByName(L"cmd.exe");
		if (CmdPid && CmdPid != LastCmdPid)
		{
			auto local_kernel32 = LoadLibraryA("Kernel32.dll");
			if (!local_kernel32)
				continue;

			DWORD loadliba_offset = INT64(GetProcAddress(local_kernel32, "LoadLibraryA")) - INT64(local_kernel32);
			if (!loadliba_offset)
				continue;

			auto kernel32 = GetModuleBaseAddress(CmdPid, L"Kernel32.dll");
			if (!kernel32)
				continue;
			
			auto hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, CmdPid);
			if (hProc == INVALID_HANDLE_VALUE)
				continue;

			auto StrAlloc = VirtualAllocEx(hProc, 0, DllPath.size() + 1, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
			if (!StrAlloc)
			{
				CloseHandle(hProc);
				continue;
			}

			if(!WriteProcessMemory(hProc, StrAlloc, DllPath.data(), DllPath.size(), 0))
			{
				CloseHandle(hProc);
				continue;
			}

			auto hthread = CreateRemoteThread(hProc, 0, 0, LPTHREAD_START_ROUTINE(loadliba_offset + kernel32), StrAlloc, 0, 0);
			CloseHandle(hthread);
			CloseHandle(hProc);
			LastCmdPid = CmdPid;
		}
	}
	return 0;
}