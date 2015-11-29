#include "checker.h"

using namespace std;

CHijackChecker::CHijackChecker() : 
	m_import_recursive_mode(false),
	m_delay_recursive_mode(false),
	m_ignore_list(false)
{
}

CHijackChecker::~CHijackChecker()
{
}

void CHijackChecker::set_recursive_mode(bool enable_import, bool enable_delay)
{
	m_import_recursive_mode = enable_import;
	m_delay_recursive_mode = enable_delay;
}

void CHijackChecker::set_ignore_list(bool enable)
{
	m_ignore_list = enable;
}

void CHijackChecker::scan(CSysConfig& conf, CModule& mod)
{
	check(conf, mod);
}

void CHijackChecker::get_vulnerable_libs(WStrWStrContainer& libs)
{
	libs = m_vuln_libs;
}

void CHijackChecker::check(CSysConfig& conf, CModule& mod)
{
	WStrContainer libs;
	WStrContainer::iterator it;

	mod.get_import_libs(libs);
	mod.get_module_path(m_mod_dir);
	conf.get_search_dirs(m_search_dirs);

	for (it = libs.begin(); it != libs.end(); it++) {
		wstring& lib = *it;
		check_module(conf, lib, true);
	}
}

void CHijackChecker::check_module(CSysConfig& conf, wstring& lib, bool use_ignore)
{
	bool is_vuln = false;
	wstring lib_dir;
	wstring full_path;

	do {
		if (is_it_contain_string(m_vuln_libs, lib))
			break;

		if (conf.is_known(lib))
			break;

		if (m_ignore_list && use_ignore && conf.is_ignored(lib))
			break;

		// Check on local dir
		full_path = m_mod_dir;
		full_path.append(L"\\");
		full_path.append(lib);

		if (is_files_exists(full_path)) {
			lib_dir = m_mod_dir;
			break;
		}

		is_vuln = true;

		// Check other dirs
		WStrContainer::iterator it;
		for (it = m_search_dirs.begin(); it != m_search_dirs.end(); it++) {
			wstring& dir = *it;

			full_path = dir;
			full_path.append(L"\\");
			full_path.append(lib);

			if (is_files_exists(full_path)) {
				lib_dir = dir;
				break;
			}
		}

	} while (false);

	if (is_vuln)
		m_vuln_libs.push_back(pair<std::wstring, std::wstring>(lib, lib_dir));

	if (lib_dir.empty())
		return;

	// Recursive import checking
	if (m_import_recursive_mode) {
		WStrContainer libs;
		WStrContainer::iterator it;
		CModule mod(full_path.c_str());

		mod.load_module();
		mod.get_import_libs(libs);

		for (it = libs.begin(); it != libs.end(); it++) {
			wstring& lib = *it;
			check_module(conf, lib, false);
		}
	}

	// Recursive delay import checking
	if (m_delay_recursive_mode) {
		WStrContainer libs;
		WStrContainer::iterator it;
		CModule mod(full_path.c_str());

		mod.load_module();
		mod.get_delay_import_libs(libs);

		for (it = libs.begin(); it != libs.end(); it++) {
			wstring& lib = *it;
			check_module(conf, lib, false);
		}
	}
}
