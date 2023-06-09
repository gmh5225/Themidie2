#include <iostream>
#include <windows.h>
#include <TlHelp32.h>
#include <psapi.h>
#include <thread>

#define ArraySize(array) sizeof(array) / sizeof(array[0])
#define Error(Message) MessageBoxA(NULL, Message, "Themidie", MB_ICONERROR);
#define Warning(Message) MessageBoxA(NULL, Message, "Themidie", MB_ICONWARNING);
#define DLL_EXPORT extern "C" __declspec(dllexport)