#include "Source.hpp"
#include "Injector/Injector.hpp"
#include "resource.h"

// x64dbg plugin sdk
#include "..\Libraries\pluginsdk\bridgemain.h"
#include "..\Libraries\pluginsdk\_plugins.h"

// themidie specific
#define PLUGIN_NAME "Themidie"
#define PLUGIN_VERSION 1

enum ThemidieMenus
{
	MENU_START,
	MENU_ABOUT
};

bool GetPathFromExplorer(char PathChosen[MAX_PATH])
{
	char ChosenFile[MAX_PATH] = {};

	OPENFILENAMEA ExplorerInfo = {};
	ExplorerInfo.lStructSize = sizeof(ExplorerInfo);
	ExplorerInfo.lpstrFilter = "Executable Files (*.exe*)\0*.exe*\0";
	ExplorerInfo.lpstrFile = ChosenFile;
	ExplorerInfo.nMaxFile = sizeof(ChosenFile);
	ExplorerInfo.Flags = OFN_EXPLORER | OFN_FILEMUSTEXIST | OFN_HIDEREADONLY;
	ExplorerInfo.lpstrDefExt = "";

	if (!GetOpenFileNameA(&ExplorerInfo))
	{
		return false;
	}

	memcpy(PathChosen, ChosenFile, sizeof(ChosenFile));
	return true;
}

DLL_EXPORT void CBMENUENTRY(CBTYPE cb_type, PLUG_CB_MENUENTRY * info)
{
	char Executable[MAX_PATH] = {};
	switch (info->hEntry)
	{
	case MENU_START:
		if (!GetPathFromExplorer(Executable))
		{
			break;
		}
		Injector::InjectOnStartup(Executable);
		break;
	case MENU_ABOUT:
		MSGBOXPARAMSA mpar;
		char hdr[64];
		char about[128];
		wsprintfA(hdr, "Themidie");
		wsprintfA(about, "Author: LOOF-sys\nDiscord: Cypher#1452\nOriginal Author: VenTaz");
		memset(&mpar, 0, sizeof(mpar));
		mpar.cbSize = sizeof(mpar);
		mpar.dwStyle = 0L | 128L;
		mpar.dwLanguageId = MAKELANGID(LANG_NEUTRAL, SUBLANG_NEUTRAL);
		mpar.lpszIcon = MAKEINTRESOURCEA(IDI_ICON1);
		mpar.lpszText = about;
		mpar.lpszCaption = hdr;
		MessageBoxIndirectA(&mpar);
		break;
	default:
		break;
	}
}

DLL_EXPORT bool pluginit(PLUG_INITSTRUCT* init_struct)
{
	init_struct->pluginVersion = PLUGIN_VERSION;
	init_struct->sdkVersion = PLUG_SDKVERSION;
	strncpy_s(init_struct->pluginName, PLUGIN_NAME, _TRUNCATE);
	return true;
}

DLL_EXPORT void plugsetup(PLUG_SETUPSTRUCT* setup_struct)
{
	int MenuId = setup_struct->hMenu;
	HMODULE Module = {};

	HRSRC MainIconResource = FindResourceA(Module, MAKEINTRESOURCEA(IDB_PNG1), "PNG");
	HANDLE LoadedIcon = LoadResource(Module, MainIconResource);

	ICONDATA MainIcon = {};
	MainIcon.data = LockResource(LoadedIcon);
	MainIcon.size = SizeofResource(Module, MainIconResource);

	_plugin_menuseticon(MenuId, (const ICONDATA*)&MainIcon);
	_plugin_menuaddentry(MenuId, MENU_START, "&Start");
	_plugin_menuaddseparator(MenuId);
	_plugin_menuaddentry(MenuId, MENU_ABOUT, "&About");
}

DLL_EXPORT bool plugstop()
{
	return true;
}

int __stdcall DllMain(HMODULE Module, DWORD CallReason, PVOID)
{
    return true;
}