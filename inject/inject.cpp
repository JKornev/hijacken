#include <Windows.h>
#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <exception>
#include <algorithm>
#include "resource.h"
#include "../inject_stub/resource.h"
#include "../inject_stub/stub_defs.h"

#ifdef _M_AMD64
#define TRAMPLONE_SIZE sizeof(TRAMPLONE64)
#else
#define TRAMPLONE_SIZE sizeof(TRAMPLONE32)
#endif

using namespace std;

typedef pair<string, unsigned int> procedure;
typedef vector< procedure > procedure_container;

typedef struct _export_container_t {
	DWORD base;
	DWORD func_count;
	vector< bool > func_map;
	string name;
	vector< string > names;
	vector< WORD > ords;
} export_container_t, *pexport_container_t;

void get_file_name(string& path, string& name)
{
	const char* buffer = path.c_str();
	int offset;

	for (offset = path.length(); offset >= 0; offset--)
		if (buffer[offset] == '\\' || buffer[offset] == '/')
			break;

	name = &buffer[++offset];
}

bool get_full_path(string& name, string& path)
{
	DWORD error, path_size;

	path_size = GetCurrentDirectoryA(0, NULL);
	if (path_size == 0) {
		error = GetLastError();
		cout << "Error, GetCurrentDirectoryA() failed with code: " << error << endl;
		return false;
	}

	path.insert(path.begin(), path_size, '\0');

	path_size = GetCurrentDirectoryA(path_size, const_cast<char*>(path.c_str()));
	if (path_size == 0) {
		error = GetLastError();
		cout << "Error, GetCurrentDirectoryA() failed with code: " << error << endl;
		return false;
	}

	path.pop_back();
	

	path += '\\';
	path += name;

	return true;
}

void* get_res_buffer(HMODULE hmod, ULONG_PTR res_id, LPWSTR res_type, DWORD* size)
{
	HRSRC hrsrc;
	HGLOBAL hrcdata;
	LPVOID buf;
	DWORD error;

	hrsrc = FindResource(hmod, MAKEINTRESOURCE(res_id), res_type);
	if (!hrsrc) {
		error = GetLastError();
		cout << "Error, FindResource() failed with code: " << error << endl;
		return NULL;
	}

	hrcdata = LoadResource(hmod, hrsrc);
	if (!hrcdata) {
		error = GetLastError();
		cout << "Error, LoadResource() failed with code: " << error << endl;
		return NULL;
	}

	*size = SizeofResource(hmod, hrsrc);
	buf = LockResource(hrcdata);

	return buf;
}

void* map_file_section(string& path, bool image)
{
	DWORD error;
	HANDLE hfile = INVALID_HANDLE_VALUE, hsect = NULL;
	void* hmod = NULL;

	do {

		hfile = CreateFileA(path.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
		if (hfile == INVALID_HANDLE_VALUE) {
			error = GetLastError();
			cout << "Error, CreateFileA() failed with code: " << error << endl;
			break;
		}

		hsect = CreateFileMappingA(hfile, NULL, PAGE_READONLY | (image ? SEC_IMAGE : 0), 0, 0, NULL);
		if (!hsect) {
			error = GetLastError();
			cout << "Error, CreateFileMappingA() failed with code: " << error << endl;
			break;
		}

		hmod = MapViewOfFile(hsect, FILE_MAP_READ, 0, 0, 0);
		if (!hmod) {
			error = GetLastError();
			cout << "Error, MapViewOfFile() failed with code: " << error << endl;
			break;
		}

	} while (false);

	if (hfile != INVALID_HANDLE_VALUE)
		CloseHandle(hfile);

	if (hsect)
		CloseHandle(hsect);

	return hmod;
}

void unmap_file_section(void* view)
{
	UnmapViewOfFile(view);
}

bool get_export_table(string& path, export_container_t& exports)
{
	void* hmod = NULL;
	bool result = false;
	PIMAGE_DOS_HEADER pdos;
	PIMAGE_OPTIONAL_HEADER popt;
	PIMAGE_EXPORT_DIRECTORY pexp;
	PDWORD pnames, pfuncs;
	PWORD pords;

	do {

		hmod = map_file_section(path, true);
		if (!hmod)
			break;

		pdos = (PIMAGE_DOS_HEADER)hmod;
		if (pdos->e_magic != IMAGE_DOS_SIGNATURE) {
			cout << "Error, invalid image signature" << endl;
			break;
		}

		popt = (PIMAGE_OPTIONAL_HEADER)(pdos->e_lfanew + (UINT_PTR)hmod + 4 + sizeof(IMAGE_FILE_HEADER));

		if (!popt->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress) {
			cout << "Error, image doesn't have export directory" << endl;
			break;
		}

		pexp = (PIMAGE_EXPORT_DIRECTORY)(popt->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress + (UINT_PTR)hmod);

		exports.base = pexp->Base;
		exports.func_count = pexp->NumberOfFunctions;

		pnames = (PDWORD)(pexp->AddressOfNames + (UINT_PTR)hmod);
		pfuncs = (PDWORD)(pexp->AddressOfFunctions + (UINT_PTR)hmod);
		pords  = (PWORD)(pexp->AddressOfNameOrdinals + (UINT_PTR)hmod);

		exports.names.reserve(pexp->NumberOfNames);
		exports.ords.reserve(pexp->NumberOfNames);

		for (DWORD i = 0; i < pexp->NumberOfNames; i++) {
			exports.ords.push_back( pords[i] );
			exports.names.push_back( pnames[i] ? (LPSTR)(pnames[i] + (UINT_PTR)hmod) : "" );
		}

		exports.func_map.insert(exports.func_map.begin(), exports.func_count, false);
		for (DWORD i = 0; i < exports.func_count; i++) {
			if (pfuncs[i])
				exports.func_map[i] = true;
		}

		result = true;

	} while (false);

	if (hmod)
		unmap_file_section(hmod);

	return result;
}

bool get_stub_resource_offsets(string& file_name, DWORD export_id, DWORD name_id, DWORD* export_offset, DWORD* name_offset)
{
	HMODULE hmod = NULL;
	DWORD size;
	LPVOID buf;
	bool res = false;

	do {

		hmod = (HMODULE)map_file_section(file_name, true);
		if (!hmod)
			break;

		buf = get_res_buffer(hmod, export_id, RT_RCDATA, &size);
		if (!buf) {
			cout << "Error, cant load resource: " << export_id << endl;
			break;
		}

		*export_offset = (ULONG_PTR)buf - (ULONG_PTR)hmod;

		buf = get_res_buffer(hmod, name_id, RT_RCDATA, &size);
		if (!buf) {
			cout << "Error, cant load resource: " << export_id << endl;
			break;
		}

		*name_offset = (ULONG_PTR)buf - (ULONG_PTR)hmod;

		res = true;

	} while (false);

	if (hmod)
		unmap_file_section(hmod);

	return res;
}

bool get_stub_resource_offset(HMODULE hmod, DWORD id, LPWSTR type, DWORD* rva)
{
	LPVOID buf;
	DWORD size;

	buf = get_res_buffer(hmod, id, type, &size);
	if (!buf) {
		cout << "Error, cant load resource: " << id << endl;
		return false;
	}

	*rva = (ULONG_PTR)buf - (ULONG_PTR)hmod;

	return true;
}

DWORD round_up_offset(DWORD offset, DWORD base)
{
	DWORD diff = offset % base;
	if (diff != 0)
		offset += base - diff;
	return offset;
}

DWORD round_down_offset(DWORD offset, DWORD base)
{
	return (offset / base) * base;
}

unsigned int append_rounded(string& buf, const char* data, unsigned int data_size, unsigned int base = sizeof(DWORD))
{
	unsigned int offset = buf.length();
	buf.append(round_up_offset(data_size, base), '\0');
	memcpy(((char*)buf.c_str()) + offset, data, data_size);
	return buf.length();
}

unsigned int fill_rounded(string& buf, unsigned int data_size, unsigned int base = sizeof(DWORD))
{
	buf.append( string(round_up_offset(data_size, base), '\0') );
	return buf.length();
}

bool compare_procedure_hint(procedure& proc1, procedure& proc2)
{
	return (proc1.second < proc2.second);
}

bool gen_export_dir(export_container_t& exports, string& name, DWORD dir_rva, string& dir_buffer_output, PDWORD exp_size)
{
	enum { TRAMPLONE_STUB_SIZE = TRAMPLONE_SIZE };
	PIMAGE_EXPORT_DIRECTORY pexport;
	DWORD offset = 0, name_offset, func_offset, ord_offset, names_offset, tramp_offset;
	vector< string >::iterator it;
	vector<DWORD> proc_offsets;
	vector<DWORD>::iterator it2;
	LPCSTR pbuf;
	PDWORD pfuncs, pnames;
	PWORD pords;
	unsigned int i;

	dir_buffer_output.clear();
	dir_buffer_output.reserve(0x1000);

	// Prepare buffer space

	offset = fill_rounded(dir_buffer_output, sizeof(IMAGE_EXPORT_DIRECTORY));

	func_offset = offset;
	offset = fill_rounded(dir_buffer_output, sizeof(DWORD) * exports.func_count);

	names_offset = offset;
	offset = fill_rounded(dir_buffer_output, sizeof(DWORD) * exports.ords.size());

	ord_offset = offset;
	offset = fill_rounded(dir_buffer_output, sizeof(WORD) * exports.names.size(), sizeof(WORD));

	name_offset = offset;
	offset = append_rounded(dir_buffer_output, name.c_str(), name.size() + 1, sizeof(BYTE));

	// Pack export names

	proc_offsets.reserve( exports.names.size() );

	for (i = 0; i < exports.names.size(); i++) {
		string& str = exports.names[i];

		if (str == "") {
			proc_offsets.push_back(0);
			continue;
		}

		proc_offsets.push_back(offset);
		offset = append_rounded(dir_buffer_output, str.c_str(), str.length() + 1, sizeof(BYTE));
	}

	tramp_offset = offset;
	offset = fill_rounded(dir_buffer_output, TRAMPLONE_STUB_SIZE * exports.func_count);

	pbuf = dir_buffer_output.c_str();

	pexport = (PIMAGE_EXPORT_DIRECTORY)pbuf;
	pfuncs =  (PDWORD)(pbuf + func_offset);
	pnames =  (PDWORD)(pbuf + names_offset);
	pords =   (PWORD) (pbuf + ord_offset);

	pexport->Base = exports.base;
	pexport->Name = dir_rva + name_offset;
	pexport->AddressOfFunctions = dir_rva + func_offset;
	pexport->AddressOfNames = dir_rva + names_offset;
	pexport->AddressOfNameOrdinals = dir_rva + ord_offset;
	pexport->NumberOfFunctions = exports.func_count;
	pexport->NumberOfNames = exports.ords.size();
	pexport->TimeDateStamp = 0xFFFFFFFF;
	
	for (i = 0; i < exports.ords.size(); i++) {
		pnames[i] = dir_rva + proc_offsets[i];
		pords[i] = exports.ords[i];
	}

	for (i = 0; i < exports.func_count; i++) {
		if (exports.func_map[i])
			pfuncs[i] = dir_rva + tramp_offset + (TRAMPLONE_STUB_SIZE * i);
		else
			pfuncs[i] = 0;
	}

	*exp_size = tramp_offset;

	return true;
}

bool unpack_resource(HMODULE hmod, DWORD res_id, string& file_name)
{
	DWORD size, error, written;
	LPVOID buf;
	HANDLE hfile;

	buf = get_res_buffer(hmod, res_id, RT_RCDATA, &size);
	if (!buf)
		return false;

	//hfile = CreateFileA(file_name.c_str(), GENERIC_WRITE, 0, NULL, CREATE_NEW, 0, NULL);
	hfile = CreateFileA(file_name.c_str(), GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
	if (hfile == INVALID_HANDLE_VALUE) {
		error = GetLastError();
		cout << "Error, CreateFileA() failed with code: " << error << endl;
		return false;
	}

	BOOL res = WriteFile(hfile, buf, size, &written, NULL);
	if (!res) {
		error = GetLastError();
		cout << "Error, WriteFile() failed with code: " << error << endl;
	}

	CloseHandle(hfile);

	return (res ? true : false);
}

DWORD conv_to_file_offset(PIMAGE_SECTION_HEADER psect, DWORD sect_count, DWORD rva)
{
	DWORD offset = round_down_offset(rva, sizeof(DWORD));
	DWORD size;

	for (unsigned int i = 0; i < sect_count; i++) {

		if (psect[i].VirtualAddress > rva)
			continue;

		size = round_up_offset(psect[i].Misc.VirtualSize, sizeof(DWORD));
		if (size == 0)
			size = 0x1000;

		if (rva >= psect[i].VirtualAddress + size)
			continue;

		return (rva - psect[i].VirtualAddress) + psect[i].PointerToRawData;
	}

	return 0;
}

bool write_file(HANDLE hfile, DWORD offset, const void* data, size_t size)
{
	DWORD written, error;

	if (SetFilePointer(hfile, offset, 0, FILE_BEGIN) != offset) {
		error = GetLastError();
		cout << "Error, SetFilePointer() failed with code: " << error << endl;
		return false;
	}

	if (!WriteFile(hfile, data, size, &written, NULL)) {
		error = GetLastError();
		cout << "Error, WriteFile() failed with code: " << error << endl;
		return false;
	}

	return true;
}

bool put_data_to_stub(string& file_name, DWORD payload_offset, string& payload, DWORD exports_offset, string& exports, DWORD exp_size, DWORD original_offset, string& original)
{
	PIMAGE_DOS_HEADER pdos;
	PIMAGE_FILE_HEADER pimg;
	PIMAGE_OPTIONAL_HEADER popt;
	PIMAGE_SECTION_HEADER psect;
	IMAGE_DATA_DIRECTORY exp;
	DWORD export_file_offset, payload_file_offset, exp_data_offset, original_file_offset;
	void* hmod = 0;
	bool res = false;
	HANDLE hfile = INVALID_HANDLE_VALUE;
	DWORD error;

	do {

		hmod = map_file_section(file_name, false);
		if (!hmod)
			break;

		pdos = (PIMAGE_DOS_HEADER)hmod;
		if (pdos->e_magic != IMAGE_DOS_SIGNATURE) {
			cout << "Error, invalid image signature" << endl;
			break;
		}

		pimg = (PIMAGE_FILE_HEADER)(pdos->e_lfanew + (UINT_PTR)hmod + sizeof(DWORD));
		popt = (PIMAGE_OPTIONAL_HEADER)((UINT_PTR)pimg + sizeof(IMAGE_FILE_HEADER));
		psect = (PIMAGE_SECTION_HEADER)((UINT_PTR)popt + sizeof(IMAGE_OPTIONAL_HEADER));

		export_file_offset = conv_to_file_offset(psect, pimg->NumberOfSections, exports_offset);
		payload_file_offset = conv_to_file_offset(psect, pimg->NumberOfSections, payload_offset);
		original_file_offset = conv_to_file_offset(psect, pimg->NumberOfSections, original_offset);

		if (export_file_offset == 0 || payload_file_offset == 0) {
			cout << "Error, invalid image signature" << endl;
			break;
		}

		memset(&exp, 0, sizeof(exp));
		exp.VirtualAddress = exports_offset;
		exp.Size = exp_size;

		exp_data_offset = (UINT_PTR)psect - (UINT_PTR)hmod - ((UINT_PTR)psect - (UINT_PTR)popt->DataDirectory);

		unmap_file_section(hmod);
		hmod = 0;

		hfile = CreateFileA(file_name.c_str(), GENERIC_WRITE, 0, 0, OPEN_EXISTING, 0, NULL);
		if (hfile == INVALID_HANDLE_VALUE) {
			error = GetLastError();
			cout << "Error, CreateFileA() failed with code: " << error << endl;
			break;
		}

		if (!write_file(hfile, exp_data_offset, &exp, sizeof(exp)))
			break;

		if (!write_file(hfile, export_file_offset, exports.c_str(), exports.size()))
			break;

		if (!write_file(hfile, payload_file_offset, payload.c_str(), payload.size() + 1))
			break;

		if (!write_file(hfile, original_file_offset, original.c_str(), original.size() + 1))
			break;

		res = true;

	} while (false);

	if (hmod)
		unmap_file_section(hmod);

	if (hfile != INVALID_HANDLE_VALUE)
		CloseHandle(hfile);

	return res;
}

int main(int argc, char* argv[])
{
	string original_lib, payload_lib, original_name;
	DWORD export_offset, name_offset, payload_offset;
	DWORD exp_dir_size;
	string export_dir;
	HMODULE pstub = 0;
	bool result = false;
	export_container_t exports;

	if (argc < 3) {
		printf("Error, invalid params!\n"\
			"Usage: inject <original_dll_path> <payload_dll_path>\n");
		goto epilog;
	}

	original_lib = argv[1];
	payload_lib  = argv[2];

	get_file_name(original_lib, original_name);

	// get export directory info
	
	if (!get_export_table(original_lib, exports))
		goto epilog;

	// unpack stub from resources

	if(!unpack_resource(GetModuleHandle(NULL), IDR_RCDATA1, original_name))
		goto epilog;

	// generate export directory

	pstub = (HMODULE)map_file_section(original_name, true);
	if (!pstub)
		goto epilog;

	if (!get_stub_resource_offset(pstub, IDR_IMPORT_SPACE1, RT_RCDATA, &export_offset))
		goto epilog;

	if (!get_stub_resource_offset(pstub, IDR_NAME1, RT_RCDATA, &name_offset))
		goto epilog;

	if (!get_stub_resource_offset(pstub, IDR_NAME2, RT_RCDATA, &payload_offset))
		goto epilog;

	if (!gen_export_dir(exports, original_name, export_offset, export_dir, &exp_dir_size))
		goto epilog;

	unmap_file_section(pstub);
	pstub = NULL;

	// put export directory to stub

	if (!put_data_to_stub(original_name, payload_offset, payload_lib, export_offset, export_dir, exp_dir_size, name_offset, original_lib))
		goto epilog;

	// profit!
	cout << "Library '" << original_name << "' successful generated" << endl;
	result = true;

epilog:

	if (pstub)
		unmap_file_section(pstub);

	return (result ? 0 : 1);
}
