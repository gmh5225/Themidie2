#include "..\Source.hpp"
#include "..\..\Libraries\minhook\MinHook.h"

LPCSTR BadWindows[] = {
	"File Monitor - Sysinternals: www.sysinternals.com",
	"Process Monitor - Sysinternals: www.sysinternals.com",
	"Registry Monitor - Sysinternals: www.sysinternals.com",
	"Regmon",
	"Filemon",
	"18467-41",
	"PROCMON_WINDOW_CLASS",
	"x64dbg",
	"x32dbg",
	"Cheat Engine",
	"Address Scanner",
	"Scylla"
};

LPCWSTR BadWindowsW[] = {
	L"File Monitor - Sysinternals: www.sysinternals.com",
	L"Process Monitor - Sysinternals: www.sysinternals.com",
	L"Registry Monitor - Sysinternals: www.sysinternals.com",
	L"Regmon",
	L"Filemon",
	L"18467-41",
	L"PROCMON_WINDOW_CLASS",
	L"x64dbg",
	L"x32dbg",
	L"Cheat Engine",
	L"Address Scanner",
	L"Scylla"
};

LPCSTR BadModules[] = {
	"dateinj01.dll",
	"cmdvrt32.dll",
	"SbieDll.dll"
};

// Can also work for checking the process name because pretty obvious why lol
LPCSTR BadDirectories[] = {
	"x64dbg",
	"x32dbg",
	"cheatengine",
	"Kernelmoduleunloader",
	"kdmapper",
	"ida64.exe",
	"ida.exe",
	"Address Scanner",
	"Scylla",
	"Procmon"
};

// Wide char versions
LPCWSTR BadDirectoriesW[] = {
	L"x64dbg",
	L"x32dbg",
	L"cheatengine",
	L"Kernelmoduleunloader",
	L"kdmapper",
	L"ida64.exe",
	L"ida.exe",
	L"Address Scanner",
	L"Scylla",
	L"Procmon"
};

// 0 = Succeded, 1 = Failed (RegOpenKeyA)
LPCSTR GoodKeys[] = {
	"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
	"SYSTEM\\ControlSet001\\Control\\Class\\{",
	"Hardware\\description\\System"
};

// Wide char versions
LPCWSTR GoodKeysW[] = {
	L"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
	L"SYSTEM\\ControlSet001\\Control\\Class\\{",
	L"Hardware\\description\\System"
};

LPCSTR GoodValues[] = {
	"EnableLUA",
	"DriverDesc",
	"SystemBiosVersion",
	"VideoBiosVersion"
};

char BadKey[] = "HARDWARE\\ACPI\\DSDT\\VBOX__";
wchar_t BadKeyW[] = L"HARDWARE\\ACPI\\DSDT\\VBOX__";

HMODULE Shell32 = {};
HMODULE KernelBase = {};
HMODULE ntdll = {};
HMODULE user32 = {};
HMODULE Kernel32 = {};

uint32_t GetProcessIdByThreadHandle(PVOID Thread)
{
	THREAD_BASIC_INFORMATION BasicThreadInformation;

	if (NT_SUCCESS(NtQueryInformationThread(Thread, ThreadBasicInformation, &BasicThreadInformation, sizeof(THREAD_BASIC_INFORMATION), 0)))
	{
		return HandleToULong(BasicThreadInformation.ClientId.UniqueProcess);
	}

	return 0;
}

void RemoveRetardedCharacters(LPCSTR string, uint64_t Size)
{
	char* newstring = new char[Size];
	uint64_t newstringindex = 0;

	for (uint64_t i = 0; i < Size; i++)
	{
		if (string[i] != (BYTE)15)
		{
			newstring[newstringindex] = string[i];
			newstringindex++;
		}
	}

	for (uint64_t i = 0; i < newstringindex; i++)
	{
		((char*)string)[i] = newstring[newstringindex];
	}
}

namespace Hooks
{
	SHGetFileInfoA_t SHGetFileInfoA;
	SHGetFileInfoW_t SHGetFileInfoW;
	ExtractIconW_t ExtractIconW;
	ExtractIconExW_t ExtractIconExW;
	RegOpenKeyExW_t RegOpenKeyExW;
	RegOpenKeyExA_t RegOpenKeyExA;
	RegQueryValueExA_t RegQueryValueExA;
	RegQueryValueExW_t RegQueryValueExW;
	GetModuleHandleA_t GetModuleHandleA;
	LoadLibraryExW_t LoadLibraryExW;
	NtSetInformationThread_t NtSetInformationThread;
	NtQueryVirtualMemory_t NtQueryVirtualMemory;
	FindWindowA_t FindWindowA;
	FindWindowW_t FindWindowW;
	Process32NextW_t Process32NextW;

	DWORD_PTR SHGetFileInfoAHook(LPCSTR pszPath, DWORD dwFileAttributes, SHFILEINFOA* psfi, UINT cbFileInfo, UINT uFlags)
	{
		for (uint8_t i = 0; i < ArraySize(BadDirectories); i++)
		{
			if (strstr(pszPath, BadDirectories[i]))
			{
				pszPath = "C:\\Windows";
			}
		}

		return SHGetFileInfoA(pszPath, dwFileAttributes, psfi, cbFileInfo, uFlags);
	}

	DWORD_PTR SHGetFileInfoWHook(LPCWSTR pszPath, DWORD dwFileAttributes, SHFILEINFOW* psfi, UINT cbFileInfo, UINT uFlags)
	{
		for (uint8_t i = 0; i < ArraySize(BadDirectories); i++)
		{
			if (wcsstr(pszPath, BadDirectoriesW[i]))
			{
				pszPath = L"C:\\Windows";
			}
		}

		return SHGetFileInfoW(pszPath, dwFileAttributes, psfi, cbFileInfo, uFlags);
	}

	HICON ExtractIconWHook(HINSTANCE hInst, LPCWSTR pszExeFileName, UINT nIconIndex)
	{
		for (uint8_t i = 0; i < ArraySize(BadDirectories); i++)
		{
			if (wcsstr(pszExeFileName, BadDirectoriesW[i]))
			{
				pszExeFileName = L"C:\\Windows\\explorer.exe"; // hopefully your pc isnt ruined by some malware and you have explorer
			}
		}

		return ExtractIconW(hInst, pszExeFileName, nIconIndex);
	}

	HICON ExtractIconExWHook(LPCWSTR lpszFile, int nIconIndex, HICON* phiconLarge, HICON* phiconSmall, UINT nIcons)
	{
		for (uint8_t i = 0; i < ArraySize(BadDirectories); i++)
		{
			if (wcsstr(lpszFile, BadDirectoriesW[i]))
			{
				lpszFile = L"C:\\Windows\\explorer.exe"; // hopefully your pc isnt ruined by some malware and you have explorer
			}
		}

		return ExtractIconExW(lpszFile, nIconIndex, phiconLarge, phiconSmall, nIcons);
	}

	LSTATUS RegOpenKeyExWHook(HKEY hKey, LPCWSTR lpSubKey, DWORD ulOptions, REGSAM samDesired, PHKEY phkResult)
	{
		for (uint8_t i = 0; i < ArraySize(GoodKeys); i++)
		{
			if (wcsstr(lpSubKey, GoodKeysW[i]))
			{
				return 0;
			}
		}

		if (wcsstr(lpSubKey, BadKeyW)) return 1;

		return RegOpenKeyExW(hKey, lpSubKey, ulOptions, samDesired, phkResult);
	}

	LSTATUS RegOpenKeyExAHook(HKEY hKey, LPCSTR lpSubKey, DWORD ulOptions, REGSAM samDesired, PHKEY phkResult)
	{
		for (uint8_t i = 0; i < ArraySize(GoodKeys); i++)
		{
			if (strstr(lpSubKey, GoodKeys[i]))
			{
				return 0;
			}
		}
		if (strstr(lpSubKey, BadKey)) return 1;

		return RegOpenKeyExA(hKey, lpSubKey, ulOptions, samDesired, phkResult);
	}

	LSTATUS RegQueryValueExAHook(HKEY hKey, LPCSTR lpValueName, LPDWORD lpReserved, LPDWORD lpType, LPBYTE  lpData, LPDWORD lpcbData)
	{
		for (uint8_t i = 0; i < ArraySize(GoodKeys); i++)
		{
			if (strstr(lpValueName, GoodKeys[i]))
			{
				return 0;
			}
		}
		if (strstr(lpValueName, BadKey)) return 1;

		return RegQueryValueExA(hKey, lpValueName, lpReserved, lpType, lpData, lpcbData);
	}

	LSTATUS RegQueryValueExWHook(HKEY hKey, LPCWSTR lpValueName, LPDWORD lpReserved, LPDWORD lpType, LPBYTE lpData, LPDWORD lpcbData)
	{
		for (uint8_t i = 0; i < ArraySize(GoodKeysW); i++)
		{
			if (wcsstr(lpValueName, GoodKeysW[i]))
			{
				return 0;
			}
		}
		if (wcsstr(lpValueName, BadKeyW)) return 1;

		return RegQueryValueExW(hKey, lpValueName, lpReserved, lpType, lpData, lpcbData);
	}

	HMODULE GetModuleHandleAHook(LPCSTR lpModuleName)
	{
		for (uint8_t i = 0; i < ArraySize(BadModules); i++)
		{
			if (strstr(lpModuleName, BadModules[i]))
			{
				return 0;
			}
		}

		return GetModuleHandleA(lpModuleName);
	}

	NTSTATUS NtSetInformationThreadHook(HANDLE ThreadHandle, THREADINFOCLASS ThreadInformationClass, PVOID ThreadInformation, ULONG ThreadInformationLength)
	{
		if (ThreadInformationClass == ThreadHideFromDebugger && !ThreadInformationLength)
		{
			if (ThreadHandle == NtCurrentThread || HandleToULong(NtCurrentTeb()->ClientId.UniqueProcess) == GetProcessIdByThreadHandle(ThreadHandle))
			{
				return 0;
			}
		}

		return NtSetInformationThread(ThreadHandle, ThreadInformationClass, ThreadInformation, ThreadInformationLength);
	}
	
	HWND FindWindowAHook(LPCSTR lpClassName, LPCSTR lpWindowName)
	{
		if (!lpClassName || !lpWindowName)
		{
			return FindWindowA(lpClassName, lpWindowName);
		}

		for (uint8_t i = 0; i < ArraySize(BadWindows); i++)
		{
			if (strstr(lpClassName, BadWindows[i]) || strstr(lpWindowName, BadWindows[i]))
			{
				return 0;
			}
		}

		return FindWindowA(lpClassName, lpWindowName);
	}

	HWND FindWindowWHook(LPCWSTR lpClassName, LPCWSTR lpWindowName)
	{
		if (!lpClassName || !lpWindowName)
		{
			return FindWindowW(lpClassName, lpWindowName);
		}

		for (uint8_t i = 0; i < ArraySize(BadWindows); i++)
		{
			if (wcsstr(lpClassName, BadWindowsW[i]) || wcsstr(lpWindowName, BadWindowsW[i]))
			{
				return 0;
			}
		}

		return FindWindowW(lpClassName, lpWindowName);
	}

	BOOL Process32NextWHook(HANDLE hSnapshot, LPPROCESSENTRY32W lppe)
	{
		BOOL Result = Process32NextW(hSnapshot, lppe);
		if (!Result)
		{
			return Result;
		}

		for (uint8_t i = 0; i < ArraySize(BadDirectoriesW); i++)
		{
			if (wcsstr(lppe->szExeFile, BadDirectoriesW[i]))
			{
				memcpy(lppe->szExeFile, L"C:\\Windows\\explorer.exe", sizeof(L"C:\\Windows\\explorer.exe"));
			}
		}

		return Result;
	}

	NTSTATUS NtQueryVirtualMemoryHook(HANDLE ProcessHandle, PVOID BaseAddress, MEMORY_INFORMATION_CLASS MemoryInformationClass, PVOID MemoryInformation, SIZE_T MemoryInformationLength, PSIZE_T ReturnLength)
	{
		static bool IsLoaded = false;
		static int Calls = 0;

		if (ProcessHandle == NtCurrentProcess && !IsLoaded)
		{
			if (MemoryInformationClass == MemoryBasicInformation && Calls == 0 || MemoryInformationClass == MemoryRegionInformation && Calls == 1)
			{
				Calls++;
			}
			else if (MemoryInformationClass == MemoryMappedFilenameInformation && Calls == 2)
			{
				MH_DisableHook(&::GetModuleHandleA);
				MH_DisableHook(&::NtQueryVirtualMemory);
				IsLoaded = true;
				MessageBoxA(0, "The executable is now loaded in the memory. You can attach x64dbg to the target process.", "Themidie", 64L);
			}
		}

		return NtQueryVirtualMemory(ProcessHandle, BaseAddress, MemoryInformationClass, MemoryInformation, MemoryInformationLength, ReturnLength);
	}

	HMODULE LoadLibraryExWHook(LPCWSTR lpLibFileName, HANDLE hFile, DWORD dwFlags)
	{
		char ModuleName[MAX_PATH] = {};

		wcstombs(ModuleName, lpLibFileName, MAX_PATH);
		RemoveRetardedCharacters(ModuleName, sizeof(ModuleName));

		if (strcmpi(ModuleName, "shell32.dll"))
		{
			Shell32 = LoadLibraryExW(lpLibFileName, hFile, dwFlags);

			PVOID SHGetFileInfoA = GetProcAddress(Shell32, "SHGetFileInfoA");
			PVOID SHGetFileInfoW = GetProcAddress(Shell32, "SHGetFileInfoW");
			PVOID ExtractIconW = GetProcAddress(Shell32, "ExtractIconW");
			PVOID ExtractIconExW = GetProcAddress(Shell32, "ExtractIconExW");

			MH_CreateHook(SHGetFileInfoA, SHGetFileInfoAHook, (void**)&Hooks::SHGetFileInfoA);
			MH_CreateHook(SHGetFileInfoW, SHGetFileInfoWHook, (void**)&Hooks::SHGetFileInfoW);
			MH_CreateHook(ExtractIconW, ExtractIconWHook, (void**)&Hooks::ExtractIconW);
			MH_CreateHook(ExtractIconExW, ExtractIconExWHook, (void**)&Hooks::ExtractIconExW);

			MH_EnableHook(MH_ALL_HOOKS);

			return Shell32;
		}

		if (strcmpi(ModuleName, "kernelbase.dll") && !KernelBase)
		{
			KernelBase = LoadLibraryExW(lpLibFileName, hFile, dwFlags);

			PVOID RegOpenKeyExW = GetProcAddress(KernelBase, "RegOpenKeyExW");
			PVOID RegOpenKeyExA = GetProcAddress(KernelBase, "RegOpenKeyExA");
			PVOID RegQueryValueExA = GetProcAddress(KernelBase, "RegQueryValueExA");
			PVOID RegQueryValueExW = GetProcAddress(KernelBase, "RegQueryValueExW");
			PVOID GetModuleHandleA = GetProcAddress(KernelBase, "GetModuleHandleA");

			MH_CreateHook(RegOpenKeyExA, RegOpenKeyExAHook, (void**)&Hooks::RegOpenKeyExA);
			MH_CreateHook(RegOpenKeyExW, RegOpenKeyExWHook, (void**)&Hooks::RegOpenKeyExW);
			MH_CreateHook(RegQueryValueExA, RegQueryValueExAHook, (void**)&Hooks::RegQueryValueExA);
			MH_CreateHook(RegQueryValueExW, RegQueryValueExWHook, (void**)&Hooks::RegQueryValueExW);
			MH_CreateHook(GetModuleHandleA, GetModuleHandleAHook, (void**)&Hooks::GetModuleHandleA);

			MH_EnableHook(MH_ALL_HOOKS);

			return KernelBase;
		}	

		if (strcmpi(ModuleName, "user32.dll") && !user32)
		{
			user32 = LoadLibraryExW(lpLibFileName, hFile, dwFlags);

			PVOID FindWindowA = GetProcAddress(user32, "FindWindowA");
			PVOID FindWindowW = GetProcAddress(user32, "FindWindowW");

			MH_CreateHook(FindWindowA, FindWindowAHook, (void**)&Hooks::FindWindowA);
			MH_CreateHook(FindWindowW, FindWindowWHook, (void**)&Hooks::FindWindowW);

			MH_EnableHook(MH_ALL_HOOKS);

			return user32;
		}

		if (strcmpi(ModuleName, "kernel32.dll") && !Kernel32)
		{
			Kernel32 = LoadLibraryExW(lpLibFileName, hFile, dwFlags);

			PVOID Process32NextW = GetProcAddress(Kernel32, "Process32NextW");
			MH_CreateHook(Process32NextW, Process32NextWHook, (void**)&Hooks::Process32NextW);

			MH_EnableHook(MH_ALL_HOOKS);

			return Kernel32;
		}

		if (strcmpi(ModuleName, "ntdll.dll") && !ntdll)
		{
			ntdll = LoadLibraryExW(lpLibFileName, hFile, dwFlags);

			PVOID NtSetInformationThread = GetProcAddress(ntdll, "NtSetInformationThread");
			PVOID NtQueryVirtualMemory = GetProcAddress(ntdll, "NtQueryVirtualMemory");

			MH_CreateHook(NtSetInformationThread, NtSetInformationThreadHook, (void**)&Hooks::NtSetInformationThread);
			MH_CreateHook(NtQueryVirtualMemory, NtQueryVirtualMemoryHook, (void**)&Hooks::NtQueryVirtualMemory);

			MH_EnableHook(MH_ALL_HOOKS);

			return ntdll;
		}

		return LoadLibraryExW(lpLibFileName, hFile, dwFlags);
	}

	// to avoid problems with headers
	bool Initalize()
	{
		Shell32 = ::GetModuleHandleA("shell32.dll");
		KernelBase = ::GetModuleHandleA("kernelbase.dll");
		ntdll = ::GetModuleHandleA("ntdll.dll");
		user32 = ::GetModuleHandleA("user32.dll");
		Kernel32 = ::GetModuleHandleA("kernel32.dll");

		uint64_t Fails = 0;

		if (Shell32)
		{
			PVOID SHGetFileInfoA = GetProcAddress(Shell32, "SHGetFileInfoA");
			PVOID SHGetFileInfoW = GetProcAddress(Shell32, "SHGetFileInfoW");
			PVOID ExtractIconW = GetProcAddress(Shell32, "ExtractIconW");
			PVOID ExtractIconExW = GetProcAddress(Shell32, "ExtractIconExW");

			if (MH_CreateHook(SHGetFileInfoA, SHGetFileInfoAHook, (void**)&Hooks::SHGetFileInfoA)) Fails++;
			if (MH_CreateHook(SHGetFileInfoW, SHGetFileInfoWHook, (void**)&Hooks::SHGetFileInfoW)) Fails++;
			if (MH_CreateHook(ExtractIconW, ExtractIconWHook, (void**)&Hooks::ExtractIconW)) Fails++;
			if (MH_CreateHook(ExtractIconExW, ExtractIconExWHook, (void**)&Hooks::ExtractIconExW)) Fails++;
		}

		if (KernelBase)
		{
			PVOID RegOpenKeyExW = GetProcAddress(KernelBase, "RegOpenKeyExW");
			PVOID RegOpenKeyExA = GetProcAddress(KernelBase, "RegOpenKeyExA");
			PVOID RegQueryValueExA = GetProcAddress(KernelBase, "RegQueryValueExA");
			PVOID RegQueryValueExW = GetProcAddress(KernelBase, "RegQueryValueExW");
			PVOID GetModuleHandleA = GetProcAddress(KernelBase, "GetModuleHandleA");
			PVOID LoadLibraryExW = GetProcAddress(KernelBase, "LoadLibraryExW");

			if (MH_CreateHook(RegOpenKeyExA, RegOpenKeyExAHook, (void**)&Hooks::RegOpenKeyExA)) Fails++;
			if (MH_CreateHook(RegOpenKeyExW, RegOpenKeyExWHook, (void**)&Hooks::RegOpenKeyExW)) Fails++;
			if (MH_CreateHook(RegQueryValueExA, RegQueryValueExAHook, (void**)&Hooks::RegQueryValueExA)) Fails++;
			if (MH_CreateHook(RegQueryValueExW, RegQueryValueExWHook, (void**)&Hooks::RegQueryValueExW)) Fails++;
			if (MH_CreateHook(GetModuleHandleA, GetModuleHandleAHook, (void**)&Hooks::GetModuleHandleA)) Fails++;
			if (MH_CreateHook(LoadLibraryExW, LoadLibraryExWHook, (void**)&Hooks::LoadLibraryExW)) Fails++;
		}

		if (user32)
		{
			PVOID FindWindowA = GetProcAddress(user32, "FindWindowA");
			PVOID FindWindowW = GetProcAddress(user32, "FindWindowW");

			if (MH_CreateHook(FindWindowA, FindWindowAHook, (void**)&Hooks::FindWindowA)) Fails++;
			if (MH_CreateHook(FindWindowW, FindWindowWHook, (void**)&Hooks::FindWindowW)) Fails++;
		}

		if (Kernel32)
		{
			PVOID Process32NextW = GetProcAddress(Kernel32, "Process32NextW");
			if (MH_CreateHook(Process32NextW, Process32NextWHook, (void**)&Hooks::Process32NextW)) Fails++;
		}

		if (ntdll)
		{
			PVOID NtSetInformationThread = GetProcAddress(ntdll, "NtSetInformationThread");
			PVOID NtQueryVirtualMemory = GetProcAddress(ntdll, "NtQueryVirtualMemory");

			if (MH_CreateHook(NtSetInformationThread, NtSetInformationThreadHook, (void**)&Hooks::NtSetInformationThread)) Fails++;
			if (MH_CreateHook(NtQueryVirtualMemory, NtQueryVirtualMemoryHook, (void**)&Hooks::NtQueryVirtualMemory)) Fails++;
		}

		if (MH_EnableHook(MH_ALL_HOOKS)) Fails++;
		if (Fails > 0)
		{
			Warning("Some functions are protected")
			return false;
		}

		return true;
	}
}