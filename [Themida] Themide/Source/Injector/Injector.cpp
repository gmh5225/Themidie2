#include <iostream>
#include <windows.h>
#include <TlHelp32.h>
#include <psapi.h>
#include <thread>

//#include "..\ntdll.h"

#define Error(Message) MessageBoxA(NULL, Message, "Themidie", MB_ICONERROR);
#define Warning(Message) MessageBoxA(NULL, Message, "Themidie", MB_ICONWARNING);

bool GetDirectoryFromFileName(LPCSTR FileDirectory, LPCSTR WantedDirectory, LPCSTR Output)
{
	for (int64_t i = strlen(FileDirectory) - 1; i > 0; i--)
	{
		if (FileDirectory[i] == '\\')
		{
			std::string output = "";
			for (uint64_t i1 = i; i1 < i; i1++)
			{
				output = output + FileDirectory[i1];
			}
			output = output + WantedDirectory;
			Output = output.c_str();

			return true;
		}
	}

	return false;
}

bool GetFileFromDirectory(LPCSTR Directory, LPCSTR FileName, LPCSTR Output)
{
	std::string filepath = Directory;
	filepath + "\\" + FileName;

	WIN32_FIND_DATAA FileInfo = {};
	if (!FindFirstFileA(filepath.c_str(), &FileInfo))
	{
		return false;
	}

	Output = filepath.c_str();
	return true;
}

void GetPathFromExplorer(LPCSTR PathChosen)
{
	char ChosenFile[MAX_PATH] = {};

	OPENFILENAMEA ExplorerInfo = {};
	ExplorerInfo.lStructSize = sizeof(ExplorerInfo);
	ExplorerInfo.lpstrFilter = "Executable Files (*.exe*)\0*.exe*\0";
	ExplorerInfo.lpstrFile = ChosenFile;
	ExplorerInfo.nMaxFile = sizeof(ChosenFile);
	ExplorerInfo.Flags = OFN_EXPLORER | OFN_FILEMUSTEXIST | OFN_HIDEREADONLY;
	ExplorerInfo.lpstrDefExt = "";

	GetOpenFileNameA(&ExplorerInfo);
	PathChosen = ChosenFile;
}

namespace Injector
{
	void Inject(LPCSTR TargetExecutable)
	{
		char x64dbg[MAX_PATH] = {};
		char plugins[MAX_PATH] = {};
		char ThemidePath[MAX_PATH] = {};

		if (!GetModuleFileNameA(NULL, x64dbg, MAX_PATH))
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