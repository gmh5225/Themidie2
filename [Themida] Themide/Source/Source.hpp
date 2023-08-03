#include <iostream>
#include <windows.h>
#include <TlHelp32.h>
#include <psapi.h>
#include <thread>

#include "ntdll.h"

#define ArraySize(array) sizeof(array) / sizeof(array[0])
#define Error(Message) MessageBoxA(NULL, Message, "Themidie", MB_ICONERROR);
#define Warning(Message) MessageBoxA(NULL, Message, "Themidie", MB_ICONWARNING);

/* shell32.dll */
using SHGetFileInfoA_t = DWORD_PTR(*)(LPCSTR pszPath, DWORD dwFileAttributes, SHFILEINFOA* psfi, UINT cbFileInfo, UINT uFlags);
using SHGetFileInfoW_t = DWORD_PTR(*)(LPCWSTR pszPath, DWORD dwFileAttributes, SHFILEINFOW* psfi, UINT cbFileInfo, UINT uFlags);
using ExtractIconW_t = HICON(*)(HINSTANCE hInst, LPCWSTR pszExeFileName, UINT nIconIndex);
using ExtractIconExW_t = HICON(*)(LPCWSTR lpszFile, int nIconIndex, HICON* phiconLarge, HICON* phiconSmall, UINT nIcons);

/* kernelbase.dll */
using RegOpenKeyExW_t = LSTATUS(*)(HKEY hKey, LPCWSTR lpSubKey, DWORD ulOptions, REGSAM samDesired, PHKEY phkResult);
using RegOpenKeyExA_t = LSTATUS(*)(HKEY hKey, LPCSTR lpSubKey, DWORD ulOptions, REGSAM samDesired, PHKEY phkResult);
using RegQueryValueExA_t = LSTATUS(*)(HKEY hKey, LPCSTR lpValueName, LPDWORD lpReserved, LPDWORD lpType, LPBYTE  lpData, LPDWORD lpcbData);
using RegQueryValueExW_t = LSTATUS(*)(HKEY hKey, LPCWSTR lpValueName, LPDWORD lpReserved, LPDWORD lpType, LPBYTE  lpData, LPDWORD lpcbData);
using GetModuleHandleA_t = HMODULE(*)(LPCSTR lpModuleName);
using LoadLibraryExW_t = HMODULE(*)(LPCWSTR lpLibFileName, HANDLE hFile, DWORD dwFlags);
using FindFirstFileExW_t = HANDLE(*)(LPCWSTR lpFileName, FINDEX_INFO_LEVELS fInfoLevelId, LPVOID lpFindFileData, FINDEX_SEARCH_OPS fSearchOp, LPVOID lpSearchFilter, DWORD dwAdditionalFlags);

/* ntdll.dll */
using NtSetInformationThread_t = NTSTATUS(*)(HANDLE ThreadHandle, THREADINFOCLASS ThreadInformationClass, PVOID ThreadInformation, ULONG ThreadInformationLength);
using NtQueryVirtualMemory_t = NTSTATUS(*)(HANDLE ProcessHandle, PVOID BaseAddress, MEMORY_INFORMATION_CLASS MemoryInformationClass, PVOID MemoryInformation, SIZE_T MemoryInformationLength, PSIZE_T ReturnLength);
using NtOpenFile_t = NTSTATUS(*)(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock, ULONG ShareAccess, ULONG OpenOptions);

/* user32.dll */
using FindWindowA_t = HWND(*)(LPCSTR lpClassName, LPCSTR lpWindowName);
using FindWindowW_t = HWND(*)(LPCWSTR lpClassName, LPCWSTR lpWindowName);

/* kernel32.dll */
using Process32NextW_t = BOOL(*)(HANDLE hSnapshot, LPPROCESSENTRY32W lppe);