#include "Source.hpp"
#include "..\Libraries\minhook\MinHook.h"
#include "Hooks/Hooks.hpp"

void MainFunction()
{
    MH_Initialize();
    
    // to avoid compiliation problems
    Hooks::Initalize();
}

BOOL APIENTRY DllMain(HMODULE Module, DWORD CallReason, PVOID)
{
    return true;
}