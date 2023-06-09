#include <iostream>
#include <windows.h>
#include <TlHelp32.h>
#include <psapi.h>
#include <thread>

#define Error(Message) MessageBoxA(NULL, Message, "Themidie", MB_ICONERROR);

namespace Hooks
{
	bool Initalize();
}