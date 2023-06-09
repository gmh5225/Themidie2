#include <iostream>
#include <windows.h>
#include <TlHelp32.h>
#include <psapi.h>
#include <thread>

#define Error(Message) MessageBoxA(NULL, Message, "Themidie", MB_ICONERROR);

namespace Hooks
{
	DWORD_PTR SHGetFileInfoAHook(LPCSTR pszPath, DWORD dwFileAttributes, SHFILEINFOA* psfi, UINT cbFileInfo, UINT uFlags);
	DWORD_PTR SHGetFileInfoWHook(LPCWSTR pszPath, DWORD dwFileAttributes, SHFILEINFOW* psfi, UINT cbFileInfo, UINT uFlags);
	HICON ExtractIconExWHook(LPCWSTR lpszFile, int nIconIndex, HICON* phiconLarge, HICON* phiconSmall, UINT nIcons);
	LSTATUS RegOpenKeyExWHook(HKEY hKey, LPCWSTR lpSubKey, DWORD ulOptions, REGSAM samDesired, PHKEY phkResult);
	LSTATUS RegOpenKeyExAHook(HKEY hKey, LPCSTR lpSubKey, DWORD ulOptions, REGSAM samDesired, PHKEY phkResult);
	LSTATUS RegQueryValueExAHook(HKEY hKey, LPCSTR lpValueName, LPDWORD lpReserved, LPDWORD lpType, LPBYTE  lpData, LPDWORD lpcbData);
	LSTATUS RegQueryValueExWHook(HKEY hKey, LPCWSTR lpValueName, LPDWORD lpReserved, LPDWORD lpType, LPBYTE  lpData, LPDWORD lpcbData);
	HMODULE GetModuleHandleAHook(LPCSTR lpModuleName);
	NTSTATUS NtSetInformationThreadHook(HANDLE ThreadHandle, THREADINFOCLASS ThreadInformationClass, PVOID ThreadInformation, ULONG ThreadInformationLength);
	HWND FindWindowAHook(LPCSTR lpClassName, LPCSTR lpWindowName);
	HWND FindWindowWHook(LPCWSTR lpClassName, LPCWSTR lpWindowName);
	BOOL Process32NextWHook(HANDLE hSnapshot, LPPROCESSENTRY32W lppe);
	NTSTATUS NtQueryVirtualMemoryHook(HANDLE ProcessHandle, PVOID BaseAddress, MEMORY_INFORMATION_CLASS MemoryInformationClass, PVOID MemoryInformation, SIZE_T MemoryInformationLength, PSIZE_T ReturnLength);
	bool Initalize();
}