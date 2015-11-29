#include <iostream>
#include <string.h>
#include "sys_config.h"
#include "module.h"
#include "checker.h"

using namespace std;

enum OperationType {
	OpScan,
	OpPrint,
	OpUnknown,
};

enum StatusType {
	StatusOk,
	StatusFailed,
	StatusUsage,
};

enum ScanType {
	ScanFile,
	ScanDir,
	ScanSrv,
	ScanAutost,
};

bool g_enable_recursive_scan = false;
bool g_enable_import_unwinding = true;
bool g_enable_delay_unwinding = true;
bool g_enable_only_executable = false;
bool g_enable_print_vulnerable = false;
bool g_enable_print_writable = false;

// Print functions

bool print_search_dirs(wstring& module_dir)
{
	try {
		CSysConfig conf;
		WStrContainer dirs;
		WStrContainer::iterator it;
		int i;

		wcout << L"Search directories in right order:" << endl;
		conf.get_search_dirs(dirs);

		wcout << L" 1. " << module_dir << endl;
		for (it = dirs.begin(), i = 2; it != dirs.end(); it++, i++)
			wcout << L" " << i << L". " << *it << endl;

	} catch (exception& e) {
		cout << e.what() << endl;
		return false;
	}

	return true;
}

bool print_known_dlls()
{
	try {
		CSysConfig conf;
		WStrContainer dlls;
		WStrContainer::iterator it;

		conf.get_known_dlls(dlls);
		
		wcout << L"Print all KnownDlls:" << endl;
		for (it = dlls.begin(); it != dlls.end(); it++)
			wcout << L" " << *it << endl;

	} catch (exception& e) {
		cout << e.what() << endl;
		return false;
	}

	return true;
}

void print_recur_dll_tree(wstring& lib, vector<unsigned int>& deep, unsigned int level, WStrContainer& founded)
{//TODO:
	for (unsigned int i = 0; i < level; i++)
		printf(deep[i] ? "" : "");
}

bool print_known_dlls_tree()
{
	try {
		CSysConfig conf;
		WStrContainer dlls;
		WStrContainer founded;
		WStrContainer::iterator it;
		vector<unsigned int> depends;

		conf.get_known_dlls(dlls);

		wcout << L"Print all KnownDlls (three mode):" << endl;
		for (it = dlls.begin(); it != dlls.end(); it++) {
			print_recur_dll_tree(*it, depends, 0, founded);
		}

	} catch (exception& e) {
		cout << e.what() << endl;
		return false;
	}

	return true;
}

// Scan functions

bool scan_module(CModule& module, CSysConfig& conf, bool enable_ignore_list) 
{
	WStrWStrContainer vuln_libs;
	WStrWStrContainer::iterator it;
	CHijackChecker checker;
	wstring file_path;
	int i;

	checker.set_recursive_mode(g_enable_import_unwinding, g_enable_delay_unwinding);
	checker.set_ignore_list(enable_ignore_list);
	checker.scan(conf, module);

	module.get_module_full_path(file_path);
	checker.get_vulnerable_libs(vuln_libs);

	if (g_enable_print_vulnerable && vuln_libs.size() == 0)
		return false;

	wcout << L"Scanning module '" << file_path << "'" << endl;
	wcout << "Found " << vuln_libs.size() << " vulnerable libraries" << endl;

	for (it = vuln_libs.begin(), i = 1; it != vuln_libs.end(); it++, i++) {
		wstring& lib_name = (*it).first;
		wstring& lib_path = (*it).second;

		wcout << L" " << i << L". " << lib_name;
		if (lib_path.empty())
			wcout << L" (unknown path)" << endl;
		else
			wcout << L" (" << lib_path << L"\\" << lib_name << L")" << endl;
	}

	wcout << endl;

	return (vuln_libs.size() > 0 ? true : false);
}

bool scan_file(wstring& file_path)
{
	try {
		CSysConfig conf;
		CModule module(file_path.c_str());
		module.load_module();
		scan_module(module, conf, false);
	} catch (exception& e) {
		cout << e.what() << endl;
		return false;
	}
	return true;
}

void scan_dir_recursive(wstring& dir_path, WStrContainer& files, WStrContainer& dirs, CSysConfig& conf)
{
	WStrContainer::iterator it;
	bool found_on_dir = false;

	conf.clear_ignore();
	for (it = files.begin(); it != files.end(); it++)
		conf.add_ignore(*it);

	for (it = files.begin(); it != files.end(); it++) {

		wstring wpath = dir_path;
		wpath += L"\\";
		wpath += *it;

		try {
			CModule module(wpath.c_str());
			module.load_module();

			if (g_enable_only_executable && module.is_library())
				throw exception();

			try {
				
				bool found = scan_module(module, conf, true);
				if (!found_on_dir && found)
					found_on_dir = true;

			} catch (exception& e) {
				cout << e.what() << endl;
			}
		} catch (exception&) {// Mask this exception
		}
	}

	if (found_on_dir)
		wcout << L"Directory '" << dir_path << L"' is " 
			  << (is_dir_writeble(dir_path) ? L"writable" : L"non-writable") << endl << endl;

	if (g_enable_recursive_scan) {
		for (it = dirs.begin(); it != dirs.end(); it++) {
			WStrContainer files2, dirs2;
			wstring wdir = dir_path;
			wdir += L"\\";
			wdir += *it;

			try {
				enum_files(wdir, files2, dirs2);
			} catch (exception&) {
				continue;
			}

			scan_dir_recursive(wdir, files2, dirs2, conf);
		}
	}
}

bool scan_dir(wstring& file_path)
{
	WStrContainer files, dirs;
	WStrContainer::iterator it;

	try {
		CSysConfig conf;
		enum_files(file_path, files, dirs);
		scan_dir_recursive(file_path, files, dirs, conf);
	} catch (exception& e) {
		cout << e.what() << endl;
		return false;
	}
	return true;
}

bool scan_srv()
{
	wcout << L"Error, not implemented yet" << endl;
	return false;
}

bool scan_autost()
{
	wcout << L"Error, not implemented yet" << endl;
	return false;
}

// Command line engine

void perform_operation(int argc, wchar_t* argv[], OperationType& type)
{
	type = OpUnknown;

	if (argc < 2) {
		wcout << L"Error, not enough arguments" << endl;
		return;
	}

	if (!wcscmp(argv[1], L"scan")) {
		type= OpScan;
		return;
	}

	if (!wcscmp(argv[1], L"print")) {
		type= OpPrint;
		return;
	}
}

StatusType perform_subject_scan(int argc, wchar_t* argv[])
{
	ScanType scan_type;
	wstring wpath;
	bool res;

	if (argc < 3) {
		wcout << L"Error, not enough arguments" << endl;
		return StatusUsage;
	}

	if (!wcscmp(argv[2], L"file")) {
		scan_type = ScanFile;
	} else if (!wcscmp(argv[2], L"dir")) {
		scan_type = ScanDir;
	} else if (!wcscmp(argv[2], L"srv")) {
		scan_type = ScanSrv;
	} else if (!wcscmp(argv[2], L"autost")) {
		scan_type = ScanAutost;
	} else {
		wcout << L"Error, invalid subject" << endl;
		return StatusUsage;
	}

	for (int i = 3; i < argc; i++) {
		if (!wcscmp(argv[i], L"-r")) {

			if (scan_type != ScanDir) {
				wcout << L"Error, you can set flag -r only with 'dir'" << endl;
				return StatusUsage;
			}
			g_enable_recursive_scan = true;

		} else if (!wcscmp(argv[i], L"-i")) {

			g_enable_import_unwinding = false;

		} else if (!wcscmp(argv[i], L"-d")) {

			g_enable_delay_unwinding = false;

		} else if (!wcscmp(argv[i], L"-b")) {

			if (scan_type != ScanDir) {
				wcout << L"Error, you can set flag -b only with 'dir'" << endl;
				return StatusUsage;
			}
			g_enable_only_executable = true;

		} else if (!wcscmp(argv[i], L"-v")) {

			if (scan_type != ScanDir) {
				wcout << L"Error, you can set flag -v only with 'dir'" << endl;
				return StatusUsage;
			}
			g_enable_print_vulnerable = true;

		} else {//file path

			if (scan_type != ScanFile && scan_type != ScanDir) {
				wcout << L"Error, you can't specify path to this <subject>" << endl;
				return StatusUsage;
			}

			if (i + 1 != argc) {
				wcout << L"Error, invalid parameter: '" << argv[i] << L"'" << endl;
				return StatusUsage;
			}

			wpath = argv[i];
		}
	}

	switch (scan_type) {
	case ScanFile:
		res = scan_file(wpath);
		break;
	case ScanDir:
		res = scan_dir(wpath);
		break;
	case ScanSrv:
		res = scan_srv();
		break;
	case ScanAutost:
		res = scan_autost();
		break;
	}

	return (res ? StatusOk : StatusFailed);
}

StatusType perform_subject_print(int argc, wchar_t* argv[])
{
	bool res;
	wstring module_dir;

	if (argc < 3) {
		wcout << L"Error, not enough arguments" << endl;
		return StatusUsage;
	}

	get_module_path(module_dir, wstring(argv[0]));

	if (!wcscmp(argv[2], L"knowndll")) {
		res = print_known_dlls();
	} else if (!wcscmp(argv[2], L"knowntree")) {
		res = print_known_dlls_tree();
	} else if (!wcscmp(argv[2], L"order")) {
		res = print_search_dirs(module_dir);
	} else {
		wcout << L"Error, invalid subject" << endl;
		return StatusUsage;
	}

	return (res ? StatusOk : StatusFailed);
}

// Usage

void print_usage_operation()
{
	wcout << L"Usage: hijack_checker <operation>" << endl << endl
		  << L"operations:" << endl
		  << L"  scan  - perform dll hijacking scanning" << endl
		  << L"  print - print system information" << endl << endl
		  << L"Perform 'hijack_checker <operation> ?' for getting more help information" << endl;
}

void print_usage_subject_scan()
{
	wcout << L"Usage: hijack_checker scan <subject> [options, ...] [path]" << endl << endl
		  << L"subject:" << endl
	 	  << L"  file   - scan executable module, parameter [path] must specify path to binary" << endl
		  << L"  dir    - scan directory, parameter [path] must specify path to directory" << endl
		  << L"  srv    - scan all windows services" << endl
		  << L"  autost - scan binaries that are specified in the autostart" << endl << endl
		  << L"options:" << endl
		  << L"  -r - enable recursive scanning (only for 'dir')" << endl
		  << L"  -i - disable unwinding for import table" << endl
		  << L"  -d - disable scanning & unwinding for delay import table" << endl
		  << L"  -b - scan executable binaries only, don't scan libraries (only for 'dir')" << endl
		  << L"  -v - output only vulnerable (only for 'dir')" << endl
		  << L"  -w - output only binaries on writable directories (only for 'dir', 'srv', 'autost')" << endl;
}

void print_usage_subject_print()
{
	wcout << L"Usage: hijack_checker print <subject>" << endl << endl
		  << L"subjects:" << endl
		  << L"  knowndll - print all libraries that will be processed like KnownDlls" << endl
		  << L"  order    - print current search directories in the right order" << endl;
}

// Main

int wmain(int argc, wchar_t* argv[])
{
	
	OperationType type;
	StatusType status;
	void (*usage_callback)() = 0;
	time_t timer;
	double exec_time;

	disable_fail_messages();

	create_timer_point(timer);
	perform_operation(argc, argv, type);

	switch (type) {
	case OpScan:
		status = perform_subject_scan(argc, argv);
		if (status == StatusUsage)
			usage_callback = &print_usage_subject_scan;
		break;
	case OpPrint:
		status = perform_subject_print(argc, argv);
		if (status == StatusUsage)
			usage_callback = &print_usage_subject_print;
		break;
	default:
		status = StatusUsage;
		usage_callback = &print_usage_operation;
		break;
	}

	exec_time = get_timer_point_mlsc(timer);

	switch (status) {
	case StatusOk:
		wcout << L"Execution completed: " << exec_time << L" sec" << endl;
		break;
	case StatusFailed:
		wcout << L"Execution aborted: " << exec_time << L" sec" << endl;
		break;
	case StatusUsage:
		usage_callback();
		break;
	}

	return 0;
}
