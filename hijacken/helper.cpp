#include "helper.h"
#include <Windows.h>
#include <time.h> 

using namespace std;

bool is_it_contain_string(WStrContainer& conteiner, std::wstring& str)
{
	WStrContainer::iterator it;

	for (it = conteiner.begin(); it != conteiner.end(); it++) {
		const wchar_t* str1 = str.c_str();
		const wchar_t* str2 = (*it).c_str();

		if (!wcscmp(str1, str2))
			return true;
	}

	return false;
}

bool is_it_contain_string(WStrWStrContainer& conteiner, std::wstring& str)
{
	WStrWStrContainer::iterator it;

	for (it = conteiner.begin(); it != conteiner.end(); it++) {
		const wchar_t* str1 = str.c_str();
		const wchar_t* str2 = (*it).first.c_str();

		if (!wcscmp(str1, str2))
			return true;
	}

	return false;
}

void reg_get_dword(const wchar_t* path, const wchar_t* value_name, unsigned long& value, unsigned long default)
{
	HKEY hkey;
	LSTATUS status;
	DWORD type, size;

	value = 0;

	status = RegOpenKeyExW(HKEY_LOCAL_MACHINE, path, 0, KEY_QUERY_VALUE, &hkey);
	if (status != ERROR_SUCCESS)
		throw exception("Error, RegOpenKeyExW() failed");

	type = 0;
	status = RegQueryValueExW(hkey, value_name, 0, &type, 0, &size);
	if (status == ERROR_SUCCESS) {
		if (type != REG_DWORD) {
			RegCloseKey(hkey);
			throw exception("Error, invalid registry value type");
		}

		status = RegQueryValueExW(hkey, value_name, 0, 0, reinterpret_cast<LPBYTE>(&value), &size);
		if (status != ERROR_SUCCESS) {
			RegCloseKey(hkey);
			throw exception("Error, RegQueryValueExW() #2 failed");
		}
	} else if (status != ERROR_FILE_NOT_FOUND) {
		RegCloseKey(hkey);
		throw exception("Error, RegQueryValueExW() #1 failed");
	} else {
		value = default;
	}

	RegCloseKey(hkey);
}

void reg_get_string(const wchar_t* path, const wchar_t* value_name, wstring& value, std::wstring& default)
{
	HKEY hkey;
	LSTATUS status;
	DWORD type, size;

	value.clear();

	status = RegOpenKeyExW(HKEY_LOCAL_MACHINE, path, 0, KEY_QUERY_VALUE, &hkey);
	if (status != ERROR_SUCCESS)
		throw exception("Error, RegOpenKeyExW() failed");

	type = 0;
	status = RegQueryValueExW(hkey, value_name, 0, &type, 0, &size);
	if (status == ERROR_SUCCESS) {
		if (type != REG_SZ) {
			RegCloseKey(hkey);
			throw exception("Error, invalid registry value type");
		}

		value.append((size / 2) + 1, L'\0');
		status = RegQueryValueExW(hkey, value_name, 0, 0, (LPBYTE)const_cast<wchar_t*>(value.c_str()), &size);
		if (status != ERROR_SUCCESS) {
			RegCloseKey(hkey);
			throw exception("Error, RegQueryValueExW() #2 failed");
		}
	} else if (status != ERROR_FILE_NOT_FOUND) {
		RegCloseKey(hkey);
		throw exception("Error, RegQueryValueExW() #1 failed");
	} else {
		value = default;
	}

	RegCloseKey(hkey);
}

void reg_get_multi_string(const wchar_t* path, const wchar_t* value_name, WStrContainer& container)
{
	HKEY hkey;
	LSTATUS status;
	DWORD type, size;

	container.clear();

	status = RegOpenKeyExW(HKEY_LOCAL_MACHINE, path, 0, KEY_QUERY_VALUE, &hkey);
	if (status != ERROR_SUCCESS)
		throw exception("Error, RegOpenKeyExW() failed");

	type = 0;
	status = RegQueryValueExW(hkey, value_name, 0, &type, 0, &size);
	if (status == ERROR_SUCCESS) {
		wstring value;

		if (type != REG_MULTI_SZ) {
			RegCloseKey(hkey);
			throw exception("Error, invalid registry value type");
		}

		value.append((size / 2) + 1, L'\0');
		status = RegQueryValueExW(hkey, value_name, 0, 0, (LPBYTE)const_cast<wchar_t*>(value.c_str()), &size);
		if (status != ERROR_SUCCESS) {
			RegCloseKey(hkey);
			throw exception("Error, RegQueryValueExW() #2 failed");
		}

		wchar_t* entry = const_cast<wchar_t*>(value.c_str());
		wchar_t* current = entry;
		for (unsigned int i = 0; i < size; i++) {
			if (current[i] == L'\0') {
				if (*entry == L'\0')
					continue;
				container.push_back(entry);
				entry = current + i + 1;
			}
		}

	} else {
		RegCloseKey(hkey);
		throw exception("Error, RegQueryValueExW() #1 failed");
	}

	RegCloseKey(hkey);

}

void reg_enum_values(const wchar_t* path, WStrContainer& values)
{
	HKEY hkey;
	LSTATUS status;
	DWORD type, size, index;
	wchar_t wbuf[256] = {};

	values.clear();

	status = RegOpenKeyExW(HKEY_LOCAL_MACHINE, path, 0, KEY_READ, &hkey);
	if (status != ERROR_SUCCESS)
		throw exception("Error, RegOpenKeyExW() failed");

	index = 0;
	while (true) {
		size = _countof(wbuf) - 1;
		status = RegEnumValueW(hkey, index++, wbuf, &size, 0, &type, 0, 0);
		if (status == ERROR_NO_MORE_ITEMS)
			break;

		values.push_back(wbuf);
	}

	RegCloseKey(hkey);
}

bool is_files_exists(std::wstring& path)
{
	HANDLE hfile;
	hfile = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, 0, OPEN_EXISTING, 0, 0);
	if (hfile == INVALID_HANDLE_VALUE)
		return false;
	CloseHandle(hfile);
	return true;
}

bool is_dir_writeble(std::wstring& path)
{
	bool res = false;
	DWORD len, descr_rights, token_rights;
	PSECURITY_DESCRIPTOR pdescr = 0;
	HANDLE htoken = 0, himp_token = 0;
	GENERIC_MAPPING mapping = {0xFFFFFFFF};
	PRIVILEGE_SET privs = {};
	DWORD grand_access = 0, generic_access, privs_len = sizeof(privs);
	BOOL result = FALSE;

	descr_rights = OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION;
	token_rights = TOKEN_IMPERSONATE | TOKEN_QUERY | TOKEN_DUPLICATE | STANDARD_RIGHTS_READ;
	generic_access = GENERIC_WRITE;

	do {

		if (GetFileSecurityW(path.c_str(), descr_rights, NULL, NULL, &len) || GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
			printf("Error, GetFileSecurityW() failed with code %d\n", GetLastError());
			break;
		}

		pdescr = (PSECURITY_DESCRIPTOR)new char[len];

		if (!GetFileSecurity(path.c_str(), descr_rights, pdescr, len, &len)) {
			printf("Error, GetFileSecurityW() failed with code %d\n", GetLastError());
			break;
		}

		if (!OpenProcessToken(GetCurrentProcess(), token_rights, &htoken)) {
			printf("Error, OpenProcessToken() failed with code %d\n", GetLastError());
			break;
		}

		if (!DuplicateToken(htoken, SecurityImpersonation, &himp_token)) {
			printf("Error, DuplicateToken() failed with code %d\n", GetLastError());
			break;
		}

		mapping.GenericRead = FILE_GENERIC_READ;
		mapping.GenericWrite = FILE_GENERIC_WRITE;
		mapping.GenericExecute = FILE_GENERIC_EXECUTE;
		mapping.GenericAll = FILE_ALL_ACCESS;

		MapGenericMask(&generic_access, &mapping);

		if (!AccessCheck(pdescr, himp_token, generic_access, &mapping, &privs, &privs_len, &grand_access, &result)) {
			printf("Error, AccessCheck() failed with code %d\n", GetLastError());
			break;
		}

		res = (result ? true : false);

	} while (false);

	if (pdescr)
		delete[] pdescr;

	if (htoken)
		CloseHandle(htoken);

	if (himp_token)
		CloseHandle(himp_token);

	return res;
}

void get_module_path(wstring& wdir, wstring wpath)
{
	size_t pos = wpath.rfind(L'\\');

	if (pos == 0 || pos == wstring::npos) {
		wdir = L"";
		return;
	}

	wdir = wpath.substr(0, pos);
}

void enum_files(wstring path, WStrContainer& files, WStrContainer& dirs)
{
	HANDLE hfind;
	WIN32_FIND_DATAW data = {};

	files.clear();
	dirs.clear();

	path += L"\\*";
	hfind = FindFirstFileW(path.c_str(), &data);
	if (hfind == INVALID_HANDLE_VALUE)
		throw exception("Error, FindFirstFileW() failed");

	while (true) {
		if (wstring(L".") != data.cFileName && wstring(L"..") != data.cFileName) {

			if (data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
				dirs.push_back(data.cFileName);
			else
				files.push_back(data.cFileName);
		}

		if (!FindNextFileW(hfind, &data)) {
			DWORD error = GetLastError();
			if (GetLastError() != ERROR_NO_MORE_FILES) {
				FindClose(hfind);
				throw exception("Error, FindNextFile() failed");
			}
			break;
		}
	}

	FindClose(hfind);
}

void* load_module(const wchar_t* path)
{
	void* addr = 0;
	HANDLE hfile = INVALID_HANDLE_VALUE, hsect = 0;

	do {

		hfile = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, 0, 0);
		if (hfile == INVALID_HANDLE_VALUE) {
			//printf("Error, CreateFileW() failed with code %d\n", GetLastError());
			break;
		}

		hsect = CreateFileMappingW(hfile, 0, PAGE_READONLY | SEC_IMAGE, 0, 0, 0);
		if (!hsect) {
			//printf("Error, CreateFileMappingW() failed with code %d\n", GetLastError());
			break;
		}

		addr = MapViewOfFile(hsect, PAGE_EXECUTE_READWRITE, 0, 0, 0);
		if (!addr) {
			//printf("Error, MapViewOfFile() failed with code %d\n", GetLastError());
			break;
		}

	} while (false);

	if (hfile != INVALID_HANDLE_VALUE) 
		CloseHandle(hfile);

	if (hsect)
		CloseHandle(hsect);

	return addr;
}

void destroy_module(void* addr)
{
	UnmapViewOfFile(addr);
}

void create_timer_point(time_t& timer)
{
	timer = clock();
}

double get_timer_point_mlsc(time_t timer)
{
	return static_cast<double>(clock() - timer) / static_cast<double>(CLOCKS_PER_SEC);
}

void disable_fail_messages()
{
	SetErrorMode(SEM_FAILCRITICALERRORS);
}