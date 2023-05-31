#include <Windows.h>
#include <iostream>
#include <thread>
#include <sstream>
#include <vector>
#include <TlHelp32.h>

#include "MinHook/include/MinHook.h"
#pragma comment(lib, "MinHook/lib/libMinHook-x64-v141-mtd.lib")

#define RVA(addr, size) INT64((PBYTE)((INT64)(addr) + *(PINT)((INT64)(addr) + ((size) - sizeof(INT))) + (size)))
std::vector<int> PatternToByte(const char* pattern)
{
	auto bytes = std::vector<int>{};
	const auto start = const_cast<char*>(pattern);
	const auto end = const_cast<char*>(pattern) + strlen(pattern);

	for (auto current = start; current < end; ++current)
	{
		if (*current == '?')
		{
			++current;
			if (*current == '?')
				++current;
			bytes.push_back(-1);
		}
		else { bytes.push_back(strtoul(current, &current, 16)); }
	}
	return bytes;
}
INT64 SigScan(std::string ModuleName, std::string SigPattern, int Result = 0)
{
	auto BaseAddress = (INT64)GetModuleHandleA(ModuleName.c_str());
	if (!BaseAddress)
		return 0;

	const auto dosHeader = (PIMAGE_DOS_HEADER)BaseAddress;
	const auto ntHeaders = (PIMAGE_NT_HEADERS)((std::uint8_t*)BaseAddress + dosHeader->e_lfanew);
	const auto sizeOfImage = ntHeaders->OptionalHeader.SizeOfImage;

	auto patternBytes = PatternToByte(SigPattern.c_str());
	const auto s = patternBytes.size();
	const auto d = patternBytes.data();

	int SkipResults = 0;
	MEMORY_BASIC_INFORMATION mbi{};
	for (INT64 CurrAddr = BaseAddress; CurrAddr < (BaseAddress + sizeOfImage); CurrAddr++)
	{
		if (VirtualQuery((PVOID)CurrAddr, &mbi, sizeof(mbi)) > 0)
		{
			if (mbi.Protect == PAGE_READONLY || mbi.Protect == PAGE_READWRITE || mbi.Protect == PAGE_EXECUTE_READ || mbi.Protect == PAGE_EXECUTE_READWRITE || mbi.Protect == PAGE_EXECUTE_WRITECOPY)
			{
				const auto scanBytes = reinterpret_cast<std::uint8_t*>(CurrAddr);
				for (SIZE_T i = 0; i < mbi.RegionSize; i++)
				{
					bool found = true;
					for (auto j = 0ul; j < s; ++j)
					{
						if (scanBytes[i + j] != d[j] && d[j] != -1)
						{
							found = false;
							break;
						}
					}
					if (found)
					{
						if (SkipResults == Result)
						{
							return reinterpret_cast<INT64>(&scanBytes[i]);
						}
						else
							SkipResults++;
					}
				}
			}
			CurrAddr = (INT64(mbi.BaseAddress) + mbi.RegionSize);
		}
		else
			break;
	}
	return 0;
}

std::wstring GetProcessFullnameBySubname(std::wstring ProcSubname, int iSkip)
{
	std::wstring ResultName{};
	DWORD highestThreadCount = 0;

	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	PROCESSENTRY32W pe;
	pe.dwSize = sizeof(PROCESSENTRY32);
	Process32FirstW(hSnap, &pe);

	int Skipped = 0;
	while (Process32NextW(hSnap, &pe))
	{
		if (std::wstring(pe.szExeFile).find(ProcSubname) != std::wstring().npos && (pe.cntThreads > highestThreadCount))
		{
			if (iSkip == Skipped)
			{
				highestThreadCount = pe.cntThreads;
				ResultName = pe.szExeFile;
				break;
			}
			else
				Skipped++;
		}
	}
	CloseHandle(hSnap);
	return ResultName;
}

unsigned int(__fastcall* DoComplete_Original)(wchar_t* ResultPath, int a2, int a3, int a4, int a5, int a6) = nullptr;
unsigned int __fastcall DoComplete_Hook(wchar_t* ResultPath, int a2, int a3, int a4, int a5, int a6)
{
	if (ResultPath)
	{
		static int LastSkipIndex = 0;
		static std::wstring LastSubName{};
		if (GetAsyncKeyState(VK_SHIFT))
		{
			if (LastSubName.empty())
				LastSubName = ResultPath;

			auto ProcessFullname = GetProcessFullnameBySubname(LastSubName, LastSkipIndex);
			LastSkipIndex++;
			auto ret = DoComplete_Original(ResultPath, a2, a3, a4, a5, a6);	
			if(ProcessFullname.empty())
				return ret;

			memset(ResultPath, 0, wcslen(ResultPath) * 2);
			memcpy(ResultPath, ProcessFullname.data(), ProcessFullname.size() * 2);
			return ProcessFullname.size();
		}
		else
		{
			LastSkipIndex = 0;
			LastSubName = {};
		}
	}
	return DoComplete_Original(ResultPath, a2, a3, a4, a5, a6);
}

INT64 DoCompleteFn = 0;
bool InitHook()
{
    MH_STATUS MhStatus{};
	if (!GetModuleHandleA("cmd.exe")) //wrong process
		return false;

    MhStatus = MH_Initialize();
    if (MhStatus != MH_OK)
    {
        MessageBoxA((HWND)0, std::string("Failed to 'MH_Initialize' with error " + std::to_string(MhStatus)).c_str(), "Setup error", 0);
        return false;
    }

	auto DoCompleteInst = SigScan("cmd.exe", "E8 ? ? ? ? 45 33 E4 85 C0 0F 84 ? ? ? ?");
	if (!DoCompleteInst)
	{
		MessageBoxA((HWND)0, "Failed to find 'DoCompleteInst'!", "Setup error", 0);
		return false;
	}

	DoCompleteFn = RVA(DoCompleteInst, 5);
	if (!DoCompleteFn)
	{
		MessageBoxA((HWND)0, "Failed to find 'DoCompleteFn'!", "Setup error", 0);
		return false;
	}

    MhStatus = MH_CreateHook((PVOID)DoCompleteFn, &DoComplete_Hook, (PVOID*)&DoComplete_Original);
    if (MhStatus != MH_OK)
    {
		DoCompleteFn = 0;
        MessageBoxA((HWND)0, std::string("Failed to 'MH_CreateHook' with error " + std::to_string(MhStatus)).c_str(), "Setup error", 0);
        return false;
    }

	MhStatus = MH_EnableHook((PVOID)DoCompleteFn);
	if (MhStatus != MH_OK)
	{
		DoCompleteFn = 0;
		MessageBoxA((HWND)0, std::string("Failed to 'MH_EnableHook' with error " + std::to_string(MhStatus)).c_str(), "Setup error", 0);
		return false;
	}
	return true;
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
    {
        std::thread hook(InitHook);
        hook.detach();
        break;
    }
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
	{
		//MH_DisableHook((PVOID)DoCompleteFn);
		break;
	}
    }
    return TRUE;
}

