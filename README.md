# Themidie2 - The predecessor to Themidie
x64dbg plugin to bypass Themida 3.1.x+ Detection Methods (VM, Debug, Monitoring, Modification & Reversing)

## Based off of [Themidie](https://github.com/VenTaz/Themidie)
- **As of now Themidie does not work on the latest versions of Themida which is why this was created**

### Resources
- [x64dbg](https://github.com/x64dbg/x64dbg)
- Injection Method: [LoadLibraryA](https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-loadlibrarya)
- Hooking Library: [minhook](https://github.com/TsudaKageyu/minhook)

### Capabilities
- Bypasses Themida 3.1.x+ Detection Methods (VM, Debug, Monitoring, Modification & Reversing)
- Bypasses garbage Anti-Cheat
- Makes you crash alot

### Functions Hooked
| Module | Function
| - | - 
| kernel32.dll | [Process32NextW](https://learn.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-process32nextw)
| user32.dll | [FindWindowA](https://docs.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-findwindowa)
| user32.dll | [FindWindowW](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-findwindoww)
| ntdll.dll | [NtSetInformationThread](https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntsetinformationthread)
| ntdll.dll | [NtQueryVirtualMemory](https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntqueryvirtualmemory)
| shell32.dll | [SHGetFileInfoA](https://learn.microsoft.com/en-us/windows/win32/api/shellapi/nf-shellapi-shgetfileinfoa)
| shell32.dll | [SHGetFileInfoW](https://learn.microsoft.com/en-us/windows/win32/api/shellapi/nf-shellapi-shgetfileinfow)
| shell32.dll | [ExtractIconW](https://learn.microsoft.com/en-us/windows/win32/api/shellapi/nf-shellapi-ExtractIconW)
| shell32.dll | [ExtractIconExW](https://learn.microsoft.com/en-us/windows/win32/api/shellapi/nf-shellapi-ExtractIconExW)
| kernelbase.dll | [RegOpenKeyExW](https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regopenkeyexw)
| kernelbase.dll | [RegOpenKeyExA](https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regopenkeyexa)
| kernelbase.dll | [RegQueryValueExA](https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-RegQueryValueExA)
| kernelbase.dll | [RegQueryValueExW](https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-RegQueryValueExW)
| kernelbase.dll | [GetModuleHandleA](https://docs.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-getmodulehandlea)
| kernelbase.dll | [LoadLibraryExW](https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-loadlibraryexw)
