#pragma once

#include "module.h"
#include "sys_config.h"


class CHijackChecker {
public:

	CHijackChecker();
	~CHijackChecker();

	void set_recursive_mode(bool enable_import, bool enable_delay);
	void set_ignore_list(bool enable);

	void scan(CSysConfig& conf, CModule& mod);

	void get_vulnerable_libs(WStrWStrContainer& libs);

private:
	CHijackChecker(CHijackChecker&) {}

	void check(CSysConfig& conf, CModule& mod);
	void check_module(CSysConfig& conf, std::wstring& lib, bool use_ignore);

	std::wstring m_mod_dir;
	WStrContainer m_search_dirs;
	WStrWStrContainer m_vuln_libs;

	bool m_import_recursive_mode;
	bool m_delay_recursive_mode;
	bool m_ignore_list;
};

