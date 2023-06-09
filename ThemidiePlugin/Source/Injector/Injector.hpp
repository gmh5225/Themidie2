#include <iostream>
#include <windows.h>
#include <TlHelp32.h>
#include <psapi.h>
#include <thread>

namespace Injector
{
	void InjectOnStartup(LPCSTR TargetExecutable);
}