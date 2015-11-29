#include "sys_config.h"
#include <Windows.h>

using namespace std;

CSysConfig::CSysConfig()
{
	m_search_dirs.reserve(20);

	reload();
}

CSysConfig::~CSysConfig()
{
}

void CSysConfig::reload()
{
	load_search_mode();
	load_search_dirs();
	load_exclude_known_dlls();
	load_known_dlls();
}

bool CSysConfig::is_known(std::wstring& name)
{
	if (is_it_contain_string(m_known_dlls, name) && !is_it_contain_string(m_exclude_known_dlls, name))
		return true;

	return false;
}

void CSysConfig::get_search_dirs(WStrContainer& dirs)
{
	dirs = m_search_dirs;
}

void CSysConfig::get_known_dlls(WStrContainer& dlls)
{//TODO: add exclude ignoring there
	dlls = m_known_dlls;
}

void CSysConfig::add_ignore(std::wstring& name)
{
	m_ignore_dlls.push_back(name);
}

void CSysConfig::clear_ignore()
{
	m_ignore_dlls.clear();
}

bool CSysConfig::is_ignored(std::wstring& name)
{
	return is_it_contain_string(m_ignore_dlls, name);
}

void CSysConfig::load_search_mode()
{
	DWORD value = 1;
	reg_get_dword(L"System\\CurrentControlSet\\Control\\Session Manager", L"SafeDllSearchMode", value, 1);
	m_search_safe_mode = (value != 0);
}

void CSysConfig::load_search_dirs()
{
	wchar_t wpath[MAX_PATH], wcurr_path[MAX_PATH];

	m_search_dirs.clear();

	// curr dir
	if (GetCurrentDirectoryW(MAX_PATH, wcurr_path) == 0)
		throw exception("Error, GetCurrentDirectoryW() failed");

	if (!m_search_safe_mode)
		m_search_dirs.push_back(wstring(wcurr_path));

	// system32
	if (GetSystemDirectoryW(wpath, MAX_PATH) == 0)
		throw exception("Error, GetSystemDirectoryW() failed");

	m_search_dirs.push_back(wstring(wpath));
	m_known_path = wpath;//TODO: mb we need found this path by another way

	// windows dir and 16-bit dir
	if (GetWindowsDirectoryW(wpath, MAX_PATH) == 0)
		throw exception("Error, GetWindowsDirectoryW() failed");

	m_search_dirs.push_back(wstring(wpath));
	m_search_dirs.push_back(wstring(wpath));

	m_search_dirs[m_search_dirs.size() - 2] += L"\\System";

	// curr dir
	if (m_search_safe_mode)
		m_search_dirs.push_back(wstring(wcurr_path));

	// load env vars
	wstring wstr(MAX_PATH, L'\0');

	while(true) {
		DWORD need_size = GetEnvironmentVariableW(L"PATH", const_cast<wchar_t*>(wstr.c_str()), wstr.length());
		if (need_size > wstr.length()) {
			wstr.append(need_size - wstr.length(), L'\0');
			continue;
		} else if (need_size == 0) {
			throw exception("Error, GetEnvironmentVariableW() failed");
		}
		break;
	}

	// separate paths
	DWORD pos = 0, last;
	while (pos < wstr.length()) {
		last = pos + (pos > 0 ? 1 : 0);
		pos = wstr.find(L';', pos + 1);

		if (pos == wstr.npos) {
			m_search_dirs.push_back( wstr.substr(last) );
			break;
		}

		m_search_dirs.push_back( wstr.substr(last, pos - last) );
	}

}

void CSysConfig::load_exclude_known_dlls()
{
	m_exclude_known_dlls.clear();
	reg_get_multi_string(L"System\\CurrentControlSet\\Control\\Session Manager", L"ExcludeFromKnownDlls", m_exclude_known_dlls);
}

void CSysConfig::load_known_dlls()
{
	WStrContainer libs;
	WStrContainer::iterator it;

	m_known_dlls.clear();

	reg_enum_values(L"System\\CurrentControlSet\\Control\\Session Manager\\KnownDLLs", libs);

	for (it = libs.begin(); it != libs.end(); it++) {
		wstring& lib = *it;
		wstring name;

		if (lib == L"DllDirectory" || lib == L"DllDirectory32")
			continue;

		reg_get_string(L"System\\CurrentControlSet\\Control\\Session Manager\\KnownDLLs", lib.c_str(), name, wstring(L""));

		if (is_it_contain_string(m_exclude_known_dlls, name))
			continue;

		load_known_import(name);
	}
}

void CSysConfig::load_known_import(wstring& name)
{
	transform(name.begin(), name.end(), name.begin(), tolower);

	if (is_it_contain_string(m_known_dlls, name))
		return;

	if (is_it_contain_string(m_exclude_known_dlls, name))
		return;
	
	m_known_dlls.push_back(name);

	try {
		wstring path = m_known_path;
		path += L"\\";
		path += name;

		CModule module(path.c_str());
		module.load_module();
		WStrContainer imports;
		WStrContainer::iterator it;
		module.get_import_libs(imports);

		for (it = imports.begin(); it != imports.end(); it++) {
			wstring& lib = *it;
			load_known_import(lib);
		}
	} catch (exception&) {
		// bypass exception if we can't load module
	}
}
