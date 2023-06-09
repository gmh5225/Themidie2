#include <iostream>
#include <windows.h>
#include <TlHelp32.h>
#include <psapi.h>
#include <thread>

#define Error(Message) MessageBoxA(NULL, Message, "Themidie", MB_ICONERROR);
#define Warning(Message) MessageBoxA(NULL, Message, "Themidie", MB_ICONWARNING);

bool GetDirectoryFromFileName(LPCSTR FileDirectory, LPCSTR WantedDirectory, char Output[MAX_PATH])
{
	for (int64_t i = strlen(FileDirectory) - 1; i > 0; i--)
	{
		if (FileDirectory[i] == '\\')
		{
			std::string output = "";
			for (uint64_t i1 = 0; i1 < i; i1++)
			{
				output = output + FileDirectory[i1];
			}
			output = output + "\\" + WantedDirectory;
			memcpy(Output, output.c_str(), output.length());

			return true;
		}
	}

	return false;
}

bool GetFileFromDirectory(LPCSTR Directory, LPCSTR FileName, char Output[MAX_PATH])
{
	std::string filepath = Directory;
	filepath = filepath + "\\" + FileName;

	WIN32_FIND_DATAA FileInfo = {};
	if (!FindFirstFileA(filepath.c_str(), &FileInfo))
	{
		return false;
	}

	memcpy(Output, filepath.c_str(), filepath.length());
	return true;
}

namespace Injector
{
	void InjectOnStartup(LPCSTR TargetExecutable)
	{
		char x64dbg[MAX_PATH] = {};
		char plugins[MAX_PATH] = {};
		char ThemidePath[MAX_PATH] = {};

		if (!GetModuleFileNameA(NULL, x64dbg, sizeof(x64dbg)))
		{
			Error("Please restart x64dbg and disable plugins possibly interfering");
			return;
		}

		if (!GetDirectoryFromFileName(x64dbg, "plugins", plugins))
		{
			Error("This is not loaded inside of x64dbg");
			return;
		}

		if (!GetFileFromDirectory(plugins, "Themidie.dll", ThemidePath))
		{
			Error("Please keep the DLL file named to Themidie.dll to allow it to function properly, restart x64dbg");
			return;
		}

		STARTUPINFO StartupInfo = {};
		PROCESS_INFORMATION ProcessInfo = {};

		BOOL Result = CreateProcessA(TargetExecutable, NULL, NULL, NULL, false, NORMAL_PRIORITY_CLASS, nullptr, NULL, &StartupInfo, &ProcessInfo);
		if (!Result)
		{
			Error("Could not start patched process, restart x64dbg");
			return;
		}

		HMODULE KernelBase = GetModuleHandleA("kernelbase.dll");
		if (!KernelBase)
		{
			KernelBase = LoadLibraryA("kernelbase.dll");
			if (!KernelBase)
			{
				Error("Plugins/Priviliage Loss is preventing Themidie from attaching to the process");
				TerminateProcess(ProcessInfo.hProcess, 0);
				CloseHandle(ProcessInfo.hProcess);
				CloseHandle(ProcessInfo.hThread);
				return;
			}
		}

		PVOID LoadLibraryA = GetProcAddress(KernelBase, "LoadLibraryA");
		if (!LoadLibraryA)
		{
			Error("Export patches have been detected, please disable any potential plugins interfering with x64dbg & restart x64dbg");
			TerminateProcess(ProcessInfo.hProcess, 0);
			CloseHandle(ProcessInfo.hProcess);
			CloseHandle(ProcessInfo.hThread);
			return;
		}

		PVOID ExternalThemideDirectory = VirtualAllocEx(ProcessInfo.hProcess, nullptr, sizeof(ThemidePath), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
		if (!ExternalThemideDirectory)
		{
			Error("Access to process is denied, please disable any potential plugins interfering with x64dbg & restart x64dbg");
			TerminateProcess(ProcessInfo.hProcess, 0);
			CloseHandle(ProcessInfo.hProcess);
			CloseHandle(ProcessInfo.hThread);
			return;
		}

		if (!WriteProcessMemory(ProcessInfo.hProcess, ExternalThemideDirectory, ThemidePath, sizeof(ThemidePath), NULL))
		{
			Error("Write access to process is denied, please disable any potential plugins interfering with x64dbg & restart x64dbg");
			TerminateProcess(ProcessInfo.hProcess, 0);
			CloseHandle(ProcessInfo.hProcess);
			CloseHandle(ProcessInfo.hThread);
			return;
		}

		if (!CreateRemoteThread(ProcessInfo.hProcess, NULL, 0, (PTHREAD_START_ROUTINE)LoadLibraryA, ExternalThemideDirectory, 0, 0))
		{
			Error("Execute access to process is denied, please disable any potential plugins interfering with x64dbg & restart x64dbg");
			TerminateProcess(ProcessInfo.hProcess, 0);
			CloseHandle(ProcessInfo.hProcess);
			CloseHandle(ProcessInfo.hThread);
			return;
		}

		if (!ShowWindow(GetForegroundWindow(), SW_MINIMIZE))
		{
			Warning("Plugins are interfering with Themidie's ability to function, unexpected issues may occur");
		}

		CloseHandle(ProcessInfo.hProcess);
		CloseHandle(ProcessInfo.hThread);
	}
}