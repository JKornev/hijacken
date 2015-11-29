#pragma once

#include "helper.h"
#include "module.h"

/*
- SafeDllSearchMode
- Search dirs

*/

class CSysConfig {
public:
	CSysConfig();
	~CSysConfig();

	void reload();

	bool is_known(std::wstring& name);
	void get_search_dirs(WStrContainer& dirs);
	void get_known_dlls(WStrContainer& dlls);

	void add_ignore(std::wstring& name);
	void clear_ignore();

	bool is_ignored(std::wstring& name);

private:

	CSysConfig(CSysConfig&) {}

	void load_search_mode();
	void load_search_dirs();
	void load_exclude_known_dlls();
	void load_known_dlls();

	void load_known_import(std::wstring& name);

	bool m_search_safe_mode;
	WStrContainer m_search_dirs;

	WStrContainer m_known_dlls;
	WStrContainer m_exclude_known_dlls;
	std::wstring m_known_path;

	WStrContainer m_ignore_dlls;
};