#include <Windows.h>

extern "C" int abc = 0;

BOOL WINAPI DllMain(HANDLE handle, DWORD reason, LPVOID reserved)
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
