#include <Windows.h>

#pragma comment(linker, "/ENTRY:DllMainEntry")

BOOL WINAPI DllMainEntry(HMODULE hmodule, DWORD reason, LPVOID reserved)
{
	switch (reason) {
	case DLL_PROCESS_ATTACH:
		MessageBoxA(0, "Successfully loaded", "Payload", MB_OK);
		break;
	case DLL_PROCESS_DETACH:
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
		break;
	};

	return TRUE;
}
