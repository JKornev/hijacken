#include "module.h"
#include <iostream>

using namespace std;

typedef struct _IMAGE_DELAY_IMPORT_DESCRIPTOR {
	DWORD Attrib;
	DWORD Name;
	DWORD Module;
	DWORD AddrTable;
	DWORD NameTable;
	DWORD BoundTable;
	DWORD UnloadTable;
	DWORD Timestamp;
} IMAGE_DELAY_IMPORT_DESCRIPTOR, *PIMAGE_DELAY_IMPORT_DESCRIPTOR;

CModule::CModule(const wchar_t* module_path) : 
	m_path(module_path),
	m_library(false)
{
}

CModule::~CModule() 
{
}

bool CModule::is_library()
{
	return m_library;
}

void CModule::get_import_libs(WStrContainer& libs)
{
	libs = m_imports;
}

void CModule::get_delay_import_libs(WStrContainer& libs)
{
	libs = m_delay_imports;
}

void CModule::get_module_path(wstring& wpath)
{
	::get_module_path(wpath, m_path);
}

void CModule::get_module_full_path(std::wstring& wpath)
{
	wpath = m_path;
}

void CModule::load_module()
{
	void* hmodule = ::load_module(m_path.c_str());
	if (!hmodule)
		throw exception("Error, LoadLibraryExW() failed");

	try {
		PIMAGE_DOS_HEADER pdos = (PIMAGE_DOS_HEADER)hmodule;
		PIMAGE_NT_HEADERS pheaders;
		PIMAGE_IMPORT_DESCRIPTOR pimport;
		PIMAGE_DELAY_IMPORT_DESCRIPTOR pdelay;
		ULONG_PTR offset;

		if (pdos->e_magic != IMAGE_DOS_SIGNATURE)
			throw exception("Error, invalid PE DOS header");

		pheaders = reinterpret_cast<PIMAGE_NT_HEADERS>((ULONG_PTR)hmodule + pdos->e_lfanew);

		if (pheaders->Signature != IMAGE_NT_SIGNATURE)
			throw exception("Error, invalid PE NT header");

		m_library = (pheaders->FileHeader.Characteristics & IMAGE_FILE_DLL ? true : false);

		//Load import directory
		offset = pheaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
		if (offset != 0) {
			unsigned int i = 0;

			pimport = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(offset + (ULONG_PTR)hmodule);

			do {
				if (check_rva_overflow(pheaders, offset + ((i + 1) * sizeof(IMAGE_IMPORT_DESCRIPTOR))))
					break;

				if (!pimport[i].Name || check_rva_overflow(pheaders, pimport[i].Name))
					break;

				string str(reinterpret_cast<char*>(pimport[i].Name + (ULONG_PTR)hmodule));
				transform(str.begin(), str.end(), str.begin(), tolower);
				wstring wstr(str.begin(), str.end());

				if (!is_it_contain_string(m_imports, wstr))
					m_imports.push_back(wstr);

				i++;
			} while (true);
		}

		//Load delay-import directory
		offset = pheaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].VirtualAddress;
		if (offset != 0) {
			unsigned int i = 0;

			pdelay = reinterpret_cast<PIMAGE_DELAY_IMPORT_DESCRIPTOR>(offset + (ULONG_PTR)hmodule);
			
			do {
				if (check_rva_overflow(pheaders, offset + ((i + 1) * sizeof(IMAGE_IMPORT_DESCRIPTOR))))
					break;

				if (!pdelay[i].Name || check_rva_overflow(pheaders, pdelay[i].Name))
					break;

				string str(reinterpret_cast<char*>(pdelay[i].Name + (ULONG_PTR)hmodule));
				transform(str.begin(), str.end(), str.begin(), tolower);
				wstring wstr(str.begin(), str.end());

				if (!is_it_contain_string(m_delay_imports, wstr))
					m_delay_imports.push_back(wstr);

				i++;
			} while (true);
		}

		destroy_module(hmodule);

	} catch (exception& e) {
		destroy_module(hmodule);
		throw e;
	}
}

bool CModule::check_rva_overflow(PIMAGE_NT_HEADERS phead, DWORD offset)
{
	return offset >= phead->OptionalHeader.SizeOfImage;
}
