#pragma once

#include "helper.h"
#include <Windows.h>

class CModule {
public:

	CModule(const wchar_t* module_path);
	~CModule();

	void load_module();

	bool is_library();

	void get_import_libs(WStrContainer& libs);
	void get_delay_import_libs(WStrContainer& libs);
	void get_module_path(std::wstring& wpath);
	void get_module_full_path(std::wstring& wpath);

private:

	CModule(CModule&) {}

	bool m_library;
	std::wstring m_path;
	WStrContainer m_imports;
	WStrContainer m_delay_imports;

	//HMODULE m_hmodule;

	//PIMAGE_NT_HEADERS m_headers;
	bool check_rva_overflow(PIMAGE_NT_HEADERS phead, DWORD offset);
};

