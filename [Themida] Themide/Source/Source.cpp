#include "Source.hpp"
#include "..\Libraries\minhook\MinHook.h"
#include "Hooks/Hooks.hpp"

int __stdcall DllMain(HMODULE Module, DWORD CallReason, PVOID)
{
	if (CallReason == DLL_PROCESS_ATTACH && !GetModuleHandleA("x64dbg.dll"))
	{
		LdrDisableThreadCalloutsForDll(Module);
		MH_Initialize();

		// to avoid compiliation problems
		Hooks::Initalize();
	}
    return true;
}