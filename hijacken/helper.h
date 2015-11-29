#pragma once

#include <string>
#include <vector>
#include <algorithm>

typedef std::vector<std::string> StrContainer;
typedef std::vector<std::wstring> WStrContainer;
typedef std::vector<std::pair<std::string,  std::string >> StrStrContainer;
typedef std::vector<std::pair<std::wstring, std::wstring>> WStrWStrContainer;

bool is_it_contain_string(WStrContainer& conteiner, std::wstring& str);
bool is_it_contain_string(WStrWStrContainer& conteiner, std::wstring& str);

void reg_get_dword(const wchar_t* path, const wchar_t* value_name, unsigned long& value, unsigned long default);
void reg_get_string(const wchar_t* path, const wchar_t* value_name, std::wstring& value, std::wstring& default);
void reg_get_multi_string(const wchar_t* path, const wchar_t* value_name, WStrContainer& container);
void reg_enum_values(const wchar_t* path, WStrContainer& values);

bool is_files_exists(std::wstring& path);
bool is_dir_writeble(std::wstring& path);
void get_module_path(std::wstring& wdir, std::wstring wpath);
void enum_files(std::wstring path, WStrContainer& files, WStrContainer& dirs);

void* load_module(const wchar_t* path);
void destroy_module(void* addr);

void create_timer_point(time_t& timer);
double get_timer_point_mlsc(time_t timer);

void disable_fail_messages();

