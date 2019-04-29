#include "System.h"
#include <tlhelp32.h>
#include <iostream>
#include <aclapi.h>
#include <psapi.h>
#include <sddl.h>
#include <shlwapi.h>

#pragma comment(lib, "shlwapi.lib")

namespace System
{
    // =================

    Handle::Handle() :
        std::shared_ptr<void>(0, &ObjectDeleter)
    {
    }

    Handle::Handle(HANDLE object, DestroyObjectRoutine destroyer) :
        std::shared_ptr<void>(object, destroyer)
    {
    }

    void Handle::ObjectDeleter(HANDLE object)
    {
        if (object && object != INVALID_HANDLE_VALUE)
            ::CloseHandle(object);
    }

    bool Handle::IsValid()
    {
        auto object = get();
        return (object && object != INVALID_HANDLE_VALUE);
    }

    HANDLE Handle::GetNativeHandle()
    {
        return get();
    }

    void Handle::SetHandle(HANDLE object, DestroyObjectRoutine destroyer)
    {
        reset(object, destroyer);
    }

    // =================

    Process::Process(DWORD processId, DWORD access) :
        Handle(::OpenProcess(access, FALSE, processId)),
        _processId(processId)
    {
        if (!Handle::IsValid())
            throw Utils::Exception(::GetLastError(), L"OpenProcess(pid:%d) failed with code %d", _processId, ::GetLastError());
    }

    Process::Process(HANDLE process)
    {
        _processId = ::GetProcessId(process);

        if (process == ::GetCurrentProcess())
        {
            Handle::SetHandle(process, &WithoutRelease);
        }
        else
        {
            if (!::DuplicateHandle(::GetCurrentProcess(), process, ::GetCurrentProcess(), &process, 0, FALSE, DUPLICATE_SAME_ACCESS))
                throw Utils::Exception(::GetLastError(), L"DuplicateHandle() failed with code %d", ::GetLastError());
            Handle::SetHandle(process);
        }
    }

    DWORD Process::GetProcessID()
    {
        return _processId;
    }

    template<typename T>
    void Process::ReadMemoryToContainer(void* address, T& buffer, size_t size)
    {
        SIZE_T readed;

        buffer.resize(size / sizeof(buffer[0]));

        if (!::ReadProcessMemory(
            Handle::GetNativeHandle(),
            address,
            const_cast<char*>(reinterpret_cast<const char*>(buffer.c_str())),
            size,
            &readed))
            throw Utils::Exception(GetLastError(), L"ReadProcessMemory(pid:%d) failed with code %d", _processId, GetLastError());

        if (readed != size)
            throw Utils::Exception(L"ReadProcessMemory(pid:%d) can't read full chunk", _processId);
    }

    void Process::ReadMemory(void* address, std::string& buffer, size_t size)
    {
        ReadMemoryToContainer<std::string>(address, buffer, size);
    }

    void Process::ReadMemory(void* address, std::wstring& buffer, size_t size)
    {
        ReadMemoryToContainer<std::wstring>(address, buffer, size);
    }

    void Process::WriteMemory(void* address, std::string& buffer, bool unprotect)
    {
        SIZE_T written = 0;

        auto result = ::WriteProcessMemory(Handle::GetNativeHandle(), address, const_cast<char*>(buffer.c_str()), buffer.size(), &written);
        if (!result && unprotect)
        {
            DWORD old;
            if (::VirtualProtectEx(Handle::GetNativeHandle(), address, buffer.size(), PAGE_EXECUTE_READWRITE, &old))
            {
                result = ::WriteProcessMemory(Handle::GetNativeHandle(), address, const_cast<char*>(buffer.c_str()), buffer.size(), &written);
                ::VirtualProtectEx(Handle::GetNativeHandle(), address, buffer.size(), old, &old);
                if (!result)
                    throw Utils::Exception(::GetLastError(), L"WriteProcessMemory(pid:%d) failed with code %d", _processId, ::GetLastError());
            }
            else
            {
                throw Utils::Exception(::GetLastError(), L"VirtualProtectEx(pid:%d) failed with code %d", _processId, ::GetLastError());
            }
        }

        if (written != buffer.size())
            throw Utils::Exception(L"Error, WriteProcessMemory() can't write full chunk");
    }

    void Process::WithoutRelease(HANDLE object)
    {
    }

    // =================

    ProcessesSnapshot::ProcessesSnapshot() :
        Handle(::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0))
    {
        if (!Handle::IsValid())
            throw Utils::Exception(::GetLastError(), L"CreateToolhelp32Snapshot(processes) failed with code %d", ::GetLastError());

        ResetWalking();
    }

    bool ProcessesSnapshot::GetNextProcess(DWORD& processId)
    {
        std::wstring name;
        return GetNextProcess(processId, name);
    }

    bool ProcessesSnapshot::GetNextProcess(DWORD& processId, std::wstring& name)
    {
        PROCESSENTRY32W entry = {};
        entry.dwSize = sizeof(entry);

        if (_fromStart)
        {
            if (!::Process32FirstW(Handle::GetNativeHandle(), &entry))
                return false;

            _fromStart = false;
        }
        else
        {
            if (!::Process32NextW(Handle::GetNativeHandle(), &entry))
                return false;
        }

        name = entry.szExeFile;
        processId = entry.th32ProcessID;
        return true;
    }

    void ProcessesSnapshot::ResetWalking()
    {
        _fromStart = true;
    }

    // =================

    ModulesSnapshot::ModulesSnapshot(DWORD processId) :
        Handle(::CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, processId))
    {
        if (!Handle::IsValid())
            throw Utils::Exception(::GetLastError(), L"CreateToolhelp32Snapshot(modules) failed with code %d", ::GetLastError());

        ResetWalking();
    }

    bool ModulesSnapshot::GetNextModule(HMODULE& module)
    {
        MODULEENTRY32W entry = {};
        entry.dwSize = sizeof(entry);

        if (_fromStart)
        {
            if (!::Module32FirstW(Handle::GetNativeHandle(), &entry))
                return false;

            _fromStart = false;
        }
        else
        {
            if (!::Module32NextW(Handle::GetNativeHandle(), &entry))
                return false;
        }

        module = entry.hModule;
        return true;
    }

    bool ModulesSnapshot::GetNextModule(HMODULE& module, std::wstring& name)
    {
        MODULEENTRY32W entry = {};
        entry.dwSize = sizeof(entry);

        if (_fromStart)
        {
            if (!::Module32FirstW(Handle::GetNativeHandle(), &entry))
                return false;

            _fromStart = false;
        }
        else
        {
            if (!::Module32NextW(Handle::GetNativeHandle(), &entry))
                return false;
        }

        name = entry.szModule;
        module = entry.hModule;
        return true;
    }

    void ModulesSnapshot::ResetWalking()
    {
        _fromStart = true;
    }

    // =================

    ProcessInformation::ProcessInformation(DWORD processId) : _pebAddress(nullptr)
    {
        _process.reset(
            new Process(
                processId,
                PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_READ
            )
        );
    }

    ProcessPtr ProcessInformation::GetProcess()
    {
        return _process;
    }

    PPEB ProcessInformation::GetPEBAddress()
    {
        PROCESS_BASIC_INFORMATION basic;
        DWORD written;

        if (!_pebAddress)
        {

            auto status = ::NtQueryInformationProcess(_process->GetNativeHandle(), ProcessBasicInformation, &basic, sizeof(basic), &written);
            if (!NT_SUCCESS(status))
                throw Utils::Exception(status, L"NtQueryInformationProcess(pid:%d) failed with code %08X", _process->GetProcessID(), status);

            _pebAddress = reinterpret_cast<PPEB>(basic.PebBaseAddress);
        }

        return _pebAddress;
    }

    ProcessEnvironmentBlockPtr ProcessInformation::GetProcessEnvironmentBlock()
    {
        if (!_peb.get())
            _peb.reset(new ProcessEnvironmentBlock(*this));

        return _peb;
    }

    void ProcessInformation::GetImagePath(std::wstring& path)
    {
        DWORD written;
        PUNICODE_STRING imagePath;
        std::string buffer;

        buffer.resize(MAX_PATH * 2);

        auto status = ::NtQueryInformationProcess(
            _process->GetNativeHandle(),
            ProcessImageFileNameWin32,
            const_cast<char*>(buffer.c_str()),
            static_cast<ULONG>(buffer.size()),
            &written
        );
        if (!NT_SUCCESS(status))
            throw Utils::Exception(status, L"NtQueryInformationProcess(pid:%d) failed with code %08X", _process->GetProcessID(), status);

        if (buffer.size() < sizeof(UNICODE_STRING))
            throw Utils::Exception(L"Buffer received from pid:%d is crowed", _process->GetProcessID());

        imagePath = reinterpret_cast<PUNICODE_STRING>(const_cast<char*>(buffer.c_str()));

        if (buffer.size() < sizeof(UNICODE_STRING)+imagePath->Length)
            throw Utils::Exception(L"String received from pid:%d is crowed", _process->GetProcessID());

        auto chars = imagePath->Length / sizeof(wchar_t);
        auto begin = reinterpret_cast<wchar_t*>(imagePath->Buffer);
        auto end = reinterpret_cast<wchar_t*>(imagePath->Buffer + chars);

        path.insert(path.begin(), begin, end);
    }

    void ProcessInformation::GetImageDirectory(std::wstring& directory)
    {
        std::wstring path;
        GetImagePath(path);
        System::FileUtils::ExtractFileDirectory(path, directory);
    }

    void ProcessInformation::GetModulePath(HMODULE module, std::wstring& path)
    {
        wchar_t buffer[MAX_PATH * 2];

        auto result = ::GetModuleFileNameExW(_process->GetNativeHandle(), module, buffer, _countof(buffer));
        if (!result)
            throw Utils::Exception(L"GetModuleFileNameExW(pid:%d) failed with code %d", _process->GetProcessID(), ::GetLastError());

        path = buffer;
    }

    Bitness ProcessInformation::GetCurrentProcessBitness()
    {
        return (sizeof(void*) == sizeof(long long) ? Bitness::Arch64 : Bitness::Arch32);
    }

    // =================

    ProcessEnvironmentBlock::ProcessEnvironmentBlock(ProcessInformation& processInfo) : _peb(nullptr)
    {
        auto pebPtr = processInfo.GetPEBAddress();
        if (!pebPtr)
            throw Utils::Exception(L"Can't get a PEB for this process");

        processInfo.GetProcess()->ReadMemory(pebPtr, _pebBuffer, sizeof(PEB));
        _peb = reinterpret_cast<PPEB>(
            const_cast<char*>(_pebBuffer.c_str())
        );
        _process = processInfo.GetProcess();
    }

    ProcessEnvironmentPtr ProcessEnvironmentBlock::GetProcessEnvironment()
    {
        LoadProcessParameters();
        
        if (!_paramsEnv.size())
            _process->ReadMemory(_params->Environment, _paramsEnv, _params->EnvironmentSize);

        return ProcessEnvironmentPtr(new ProcessEnvironment(_paramsEnv));
    }

    void ProcessEnvironmentBlock::GetCurrentDir(std::wstring& directory)
    {
        LoadProcessParameters();

        if (!_currentDirectory.size())
            _process->ReadMemory(_params->CurrentDirectory.DosPath.Buffer, _currentDirectory, _params->CurrentDirectory.DosPath.Length);

        directory = _currentDirectory;
    }

    void ProcessEnvironmentBlock::LoadProcessParameters()
    {
        if (_paramsBuffer.size())
            return;

        _process->ReadMemory(_peb->ProcessParameters, _paramsBuffer, sizeof(RTL_USER_PROCESS_PARAMETERS));
        _params = reinterpret_cast<PRTL_USER_PROCESS_PARAMETERS>(
            const_cast<char*>(_paramsBuffer.c_str())
        );
    }


    // =================

    ProcessEnvironment::ProcessEnvironment(std::wstring& environment)
    {
        size_t startOffset = 0;
        auto endOffset = environment.find(L'\0');

        while (endOffset != std::wstring::npos)
        {
            auto entry = std::wstring(&environment[startOffset]);

            auto keyEnd = entry.find(L'=');
            if (keyEnd != 0 && keyEnd < entry.size())
                _variables[std::wstring(&entry[0], &entry[keyEnd])] = std::wstring(&entry[keyEnd + 1], &entry[entry.size()]);

            startOffset = endOffset + 1;
            endOffset = environment.find(L'\0', startOffset);
        }
    }

    bool ProcessEnvironment::GetValue(const wchar_t* key, std::wstring& output)
    {
        auto value = _variables.find(std::wstring(key));

        if (value == _variables.end())
            return false;

        output = value->second;
        return true;
    }

    // =================

    void TokenBase::SetPrivilege(wchar_t* privelege, bool enable)
    {
        TOKEN_PRIVILEGES priveleges = {};
        LUID luid = {};

        if (!::LookupPrivilegeValueW(NULL, privelege, &luid))
            throw Utils::Exception(::GetLastError(), L"LookupPrivilegeValue() failed with code %d", ::GetLastError());

        priveleges.PrivilegeCount = 1;
        priveleges.Privileges[0].Luid = luid;
        priveleges.Privileges[0].Attributes = (enable ? SE_PRIVILEGE_ENABLED : 0);

        //TODO: query privelege if it's different than set it and check getlasterror()
        if (!::AdjustTokenPrivileges(Handle::GetNativeHandle(), FALSE, &priveleges, sizeof(priveleges), NULL, NULL) /*|| ::GetLastError() != ERROR_SUCCESS*/)
            throw Utils::Exception(::GetLastError(), L"AdjustTokenPrivileges() failed with code %d", ::GetLastError());
    }

    IntegrityLevel TokenBase::GetIntegrityLevel()
    {
        std::string buffer;
        DWORD written = 0;

        buffer.resize(64);

        auto result = ::GetTokenInformation(
            Handle::GetNativeHandle(),
            TokenIntegrityLevel, 
            const_cast<char*>(buffer.c_str()), 
            static_cast<DWORD>(buffer.size()), 
            &written
        );

        if (!result && ::GetLastError() == ERROR_INSUFFICIENT_BUFFER)
        {
            buffer.resize(written);
            result = ::GetTokenInformation(
                Handle::GetNativeHandle(),
                TokenIntegrityLevel, 
                const_cast<char*>(buffer.c_str()), 
                static_cast<DWORD>(buffer.size()), 
                &written
            );
        }

        if (!result)
            throw Utils::Exception(::GetLastError(), L"GetTokenInformation() failed with code %d", ::GetLastError());

        auto mandatory = reinterpret_cast<PTOKEN_MANDATORY_LABEL>(
            const_cast<char*>(buffer.c_str())
        );

        if (!::IsValidSid(mandatory->Label.Sid))
            throw Utils::Exception(L"A seed you received isn't valid");

        IntegrityLevel level;
        auto sub = *::GetSidSubAuthority(mandatory->Label.Sid, 0);

        switch (sub)
        {
        case SECURITY_MANDATORY_UNTRUSTED_RID:
            level = IntegrityLevel::Untrusted;
            break;
        case SECURITY_MANDATORY_LOW_RID:
            level = IntegrityLevel::Low;
            break;
        case SECURITY_MANDATORY_MEDIUM_RID:
            level = IntegrityLevel::Medium;
            break;
        case SECURITY_MANDATORY_MEDIUM_PLUS_RID:
            level = IntegrityLevel::MediumPlus;
            break;
        case SECURITY_MANDATORY_HIGH_RID:
            level = IntegrityLevel::High;
            break;
        case SECURITY_MANDATORY_SYSTEM_RID:
            level = IntegrityLevel::System;
            break;
        case SECURITY_MANDATORY_PROTECTED_PROCESS_RID:
            level = IntegrityLevel::Protected;
            break;
        //case 0x6000:
        //    level = ???;
        //    break;
        case 0x7000:
            level = IntegrityLevel::Secure;
            break;
        default:
            throw Utils::Exception(L"Unknown mandatory authority %x", sub);
        }

        return level;
    }

    void TokenBase::SetIntegrityLevel(IntegrityLevel level)
    {
        auto sid = AllocateSidByIntegrityLevel(level);

        TOKEN_MANDATORY_LABEL label = {};
        label.Label.Attributes = SE_GROUP_INTEGRITY;
        label.Label.Sid = sid;

        auto result = ::SetTokenInformation(Handle::GetNativeHandle(), TokenIntegrityLevel, &label, sizeof(label) + ::GetLengthSid(sid));
        auto error = ::GetLastError();
        
        ::LocalFree(sid);
        
        if (!result)
            throw Utils::Exception(error, L"SetTokenInformation(IntegrityLevel) failed with code %d", error);
    }

    HANDLE TokenBase::GetLinkedToken()
    {
        DWORD written = 0;
        HANDLE linked;

        if (!::GetTokenInformation(Handle::GetNativeHandle(), TokenLinkedToken, &linked, sizeof(linked), &written))
            throw Utils::Exception(::GetLastError(), L"SetTokenInformation(LinkedToken) failed with code %d", ::GetLastError());

        return linked;
    }

    void TokenBase::SetLinkedToken(HANDLE token)
    {
        if (!::SetTokenInformation(Handle::GetNativeHandle(), TokenLinkedToken, &token, sizeof(token)))
            throw Utils::Exception(::GetLastError(), L"SetTokenInformation(LinkedToken) failed with code %d", ::GetLastError());
    }

    void TokenBase::GetUserNameString(std::wstring& userName)
    {
        DWORD written = 0;
        char buffer[256];

        if (!::GetTokenInformation(Handle::GetNativeHandle(), TokenUser, &buffer, sizeof(buffer), &written))
            throw Utils::Exception(::GetLastError(), L"GetTokenInformation(TokenUser) failed with code %d", ::GetLastError());

        auto user = reinterpret_cast<PTOKEN_USER>(buffer);

        wchar_t name[256], domain[256];
        DWORD nameSize = _countof(name),
            domainSize = _countof(domain);
        SID_NAME_USE type;
        if (!::LookupAccountSidW(NULL, user->User.Sid, name, &nameSize, domain, &domainSize, &type))
            throw Utils::Exception(::GetLastError(), L"LookupAccountSidW() failed with code %d", ::GetLastError());

        if (domainSize > 1)
        {
            userName = domain;
            userName += L"\\";
            userName += name;
        }
        else
        {
            userName = name;
        }
    }

    void TokenBase::GetUserSIDString(std::wstring& sid)
    {
        DWORD written = 0;
        char buffer[256];

        if (!::GetTokenInformation(Handle::GetNativeHandle(), TokenUser, &buffer, sizeof(buffer), &written))
            throw Utils::Exception(::GetLastError(), L"GetTokenInformation(TokenUser) failed with code %d", ::GetLastError());

        LPWSTR sidString = nullptr;
        auto user = reinterpret_cast<PTOKEN_USER>(buffer);
        if (!::ConvertSidToStringSidW(user->User.Sid, &sidString))
            throw Utils::Exception(::GetLastError(), L"ConvertSidToStringSid() failed with code %d", ::GetLastError());

        sid = sidString;
    }

    bool TokenBase::IsElevated()
    {
        DWORD written = 0;
        TOKEN_ELEVATION elevated;

        if (!::GetTokenInformation(Handle::GetNativeHandle(), TokenElevation, &elevated, sizeof(elevated), &written))
            throw Utils::Exception(::GetLastError(), L"GetTokenInformation(TokenElevation) failed with code %d", ::GetLastError());

        return (elevated.TokenIsElevated ? true : false);
    }

    PSID TokenBase::AllocateSidByIntegrityLevel(IntegrityLevel level)
    {
        std::wstring sidName;

        switch (level)
        {
        case IntegrityLevel::Untrusted:
            sidName = L"S-1-16-0";
            break;
        case IntegrityLevel::Low:
            sidName = L"S-1-16-4096";
            break;
        case IntegrityLevel::Medium:
            sidName = L"S-1-16-8192";
            break;
        case IntegrityLevel::MediumPlus:
            sidName = L"S-1-16-8448";
            break;
        case IntegrityLevel::High:
            sidName = L"S-1-16-12288";
            break;
        case IntegrityLevel::System:
            sidName = L"S-1-16-16384";
            break;
        case IntegrityLevel::Protected:
            sidName = L"S-1-16-20480";
            break;
        case IntegrityLevel::Secure:
            sidName = L"S-1-16-28672";
            break;
        default:
            throw Utils::Exception(L"Unknown integrity level %d", level);
            break;
        };

        PSID sid = NULL;
        if (!::ConvertStringSidToSidW(sidName.c_str(), &sid))
            throw Utils::Exception(::GetLastError(), L"ConvertStringSidToSid() failed with code %d", ::GetLastError());

        return sid;
    }

    // =================

    PrimaryToken::PrimaryToken(Process& source, DWORD access, bool duplicate)
    {
        HANDLE object = nullptr;

        if (!::OpenProcessToken(source.GetNativeHandle(), access | (duplicate ? TOKEN_DUPLICATE : 0), &object))
            throw Utils::Exception(::GetLastError(), L"OpenProcessToken(pid:%d) failed with code %d", source.GetProcessID(), ::GetLastError());

        if (duplicate)
        {
            Handle primary(object);
            if (!::DuplicateTokenEx(object, 0, NULL, SecurityImpersonation, TokenPrimary, &object))
                throw Utils::Exception(::GetLastError(), L"DuplicateToken(pid:%d) failed with code %d", source.GetProcessID(), ::GetLastError());
        }

        Handle::SetHandle(object);
    }

    PrimaryToken::PrimaryToken(HANDLE token, bool duplicate)
    {
        if (duplicate)
        {
            Handle primary(token);
            if (!::DuplicateTokenEx(token, 0, NULL, SecurityImpersonation, TokenPrimary, &token))
                throw Utils::Exception(::GetLastError(), L"DuplicateToken() failed with code %d", ::GetLastError());
        }

        Handle::SetHandle(token);
    }

    // =================

    ImpersonateToken::ImpersonateToken(Process& source, DWORD access)
    {
        HANDLE object = nullptr;

        if (!::OpenProcessToken(source.GetNativeHandle(), access | TOKEN_DUPLICATE, &object))
            throw Utils::Exception(::GetLastError(), L"OpenProcessToken(pid:%d) failed with code %d", source.GetProcessID(), ::GetLastError());

        Handle primary(object);
        if (!::DuplicateTokenEx(object, access, NULL, SecurityImpersonation, TokenImpersonation, &object))
            throw Utils::Exception(::GetLastError(), L"DuplicateToken(pid:%d) failed with code %d", source.GetProcessID(), ::GetLastError());

        Handle::SetHandle(object);
    }

    ImpersonateToken::ImpersonateToken(HANDLE token, bool duplicate)
    {
        if (duplicate)
        {
            Handle primary(token);
            if (!::DuplicateTokenEx(token, 0, NULL, SecurityImpersonation, TokenImpersonation, &token))
                throw Utils::Exception(::GetLastError(), L"DuplicateToken() failed with code %d", ::GetLastError());
        }

        Handle::SetHandle(token);
    }

    // =================

    SecurityDescriptor::SecurityDescriptor(Handle& file) : 
        _descriptor(nullptr), 
        _dacl(nullptr)
    {
        auto result = ::GetSecurityInfo(
            file.GetNativeHandle(),
            SE_FILE_OBJECT, 
            DACL_SECURITY_INFORMATION | OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION,
            &_owner,
            &_group, 
            &_dacl,
            NULL, 
            &_descriptor
        );
        if (result != ERROR_SUCCESS)
            throw Utils::Exception(::GetLastError(), L"GetSecurityInfo() failed with code %d", ::GetLastError());
    }

    SecurityDescriptor::~SecurityDescriptor()
    {
        ::LocalFree(_descriptor);
    }

    PSECURITY_DESCRIPTOR SecurityDescriptor::GetNativeSecurityDescriptor()
    {
        return _descriptor;
    }

    // =================

    TokenAccessChecker::TokenAccessChecker(Process& process) :
        _token(process, TOKEN_DUPLICATE | TOKEN_QUERY)
    {
    }

    TokenAccessChecker::TokenAccessChecker(ImpersonateToken& token) :
        _token(token)
    {
    }

    bool TokenAccessChecker::IsFileObjectAccessible(SecurityDescriptor& descriptor, DWORD desiredAccess)
    {
        BOOL accessStatus = FALSE;
        GENERIC_MAPPING mapping = {};
        PRIVILEGE_SET PrivilegeSet;
        DWORD dwPrivSetSize = sizeof(PRIVILEGE_SET);
        DWORD dwAccessAllowed = 0;

        mapping.GenericRead  = FILE_GENERIC_READ;
        mapping.GenericWrite = FILE_GENERIC_WRITE;
        mapping.GenericAll   = FILE_GENERIC_READ | FILE_GENERIC_WRITE;

        MapGenericMask(&desiredAccess, &mapping);

        if (!::IsValidSecurityDescriptor(descriptor.GetNativeSecurityDescriptor()))
            throw Utils::Exception(::GetLastError(), L"IsValidSecurityDescriptor() failed with code %d", ::GetLastError());

        if (!::AccessCheck(descriptor.GetNativeSecurityDescriptor(), _token.GetNativeHandle(), desiredAccess, &mapping, &PrivilegeSet, &dwPrivSetSize, &dwAccessAllowed, &accessStatus))
            throw Utils::Exception(::GetLastError(), L"AccessCheck() failed with code %d", ::GetLastError());

        return (accessStatus != FALSE);
    }

    // =================

    File::File(const wchar_t* path, DWORD access, DWORD share) :
        Handle(::CreateFileW(path, access, share, NULL, OPEN_EXISTING, 0, NULL))
    {
        if (!Handle::IsValid())
            throw Utils::Exception(::GetLastError(), L"CreateFileW(file) failed with code %d", ::GetLastError());
    }

    // =================

    ImageMapping::ImageMapping(const wchar_t* path) : _mappingSize(0)
    {
        File file(path, GENERIC_READ);
        
        Handle::SetHandle(
            ::CreateFileMappingW(
                file.GetNativeHandle(),
                NULL,
                PAGE_READONLY | SEC_IMAGE,
                0,
                0,
                NULL
            )
        );
        if (!Handle::IsValid())
            throw Utils::Exception(::GetLastError(), L"CreateFileMappingW(image) failed with code %d", ::GetLastError());

        _mapping = ::MapViewOfFile(Handle::GetNativeHandle(), FILE_MAP_READ, 0, 0, 0);
        if (!_mapping)
            throw Utils::Exception(::GetLastError(), L"MapViewOfFile(image) failed with code %d", ::GetLastError());
    }

    ImageMapping::~ImageMapping()
    {
        ::UnmapViewOfFile(_mapping);
    }

    void* ImageMapping::GetAddress()
    {
        return _mapping;
    }

    size_t ImageMapping::GetSize()
    {
        if (_mappingSize)
            return _mappingSize;

        MEMORY_BASIC_INFORMATION info;
        if (!::VirtualQuery(_mapping, &info, sizeof(info)))
            throw Utils::Exception(::GetLastError(), L"VirtualQuery() failed with code %d", ::GetLastError());

        auto   regionBase = info.AllocationBase;
        size_t regionSize = 0;
        void*  regionPtr = nullptr;
        do
        {
            if (regionBase != info.AllocationBase)
                break;

            regionSize += info.RegionSize;
            regionPtr = reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(info.BaseAddress) + info.RegionSize);
        }
        while (::VirtualQuery(regionPtr, &info, sizeof(info)));

        if (::GetLastError() != ERROR_SUCCESS)
            throw Utils::Exception(::GetLastError(), L"VirtualQuery() failed with code %d", ::GetLastError());

        return _mappingSize = regionSize;
    }

    // =================

    std::wstring FileUtils::BuildPath(const std::wstring& directory, const std::wstring& file)
    {
        std::wstring path = directory;
        path += L"\\";
        path += file;
        return path;
    }

    void FileUtils::ExtractFileDirectory(const std::wstring& path, std::wstring& directory)
    {
        auto index = path.rfind('\\');
        if (index == std::wstring::npos)
            directory.clear();
        else
            directory = path.substr(0, index);
    }

    void FileUtils::NormalizePath(std::wstring& path)
    {
        std::vector<wchar_t> buffer;
        buffer.resize(1/*MAX_PATH*/);
        
        for (int i = 0; i < 5; i++)
        {
            wchar_t* output;
            auto length = ::GetFullPathNameW(path.c_str(), buffer.size(), &buffer[0], &output);
            if (!length)
            {
                throw Utils::Exception(L"GetFullPathNameW() failed with code %d", ::GetLastError());
            }
            else if (length && output)
            {
                path = &buffer[0];
                return;
            }

            buffer.resize(length + buffer.size());
        }

        throw Utils::Exception(L"Can't normalize path");
    }

    bool FileUtils::IsPathRelative(std::wstring& path)
    {
        return !!::PathIsRelativeW(path.c_str());
    }

    // =================

    Directory::Directory(const wchar_t* path, DWORD access, DWORD share) :
        Handle(::CreateFileW(path, access, share, NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL))
    {
        if (!Handle::IsValid())
            throw Utils::Exception(::GetLastError(), L"CreateFileW(dir) failed with code %d", ::GetLastError());
    }

    bool Directory::IsDirectory(const wchar_t* path)
    {
        DWORD attribs = ::GetFileAttributesW(path);
        return (attribs & FILE_ATTRIBUTE_DIRECTORY ? true : false);
    }

    // =================

    Bitness SystemInformation::GetSystemBitness()
    {
        SYSTEM_INFO info;
        ::GetNativeSystemInfo(&info);

        Bitness bitness;
        switch (info.wProcessorArchitecture)
        {
        case PROCESSOR_ARCHITECTURE_AMD64:
        case 12/*PROCESSOR_ARCHITECTURE_ARM64*/:
        case PROCESSOR_ARCHITECTURE_IA64:
            bitness = Bitness::Arch64;
            break;
        case PROCESSOR_ARCHITECTURE_INTEL:
        case PROCESSOR_ARCHITECTURE_ARM:
            bitness = Bitness::Arch32;
            break;
        default:
            throw Utils::Exception(L"Unknown architecture %d", info.wProcessorArchitecture);
        }

        return bitness;
    }

    std::wstring SystemInformation::GetSystem32Dir()
    {
        wchar_t buffer[MAX_PATH];

        if (!::GetSystemDirectoryW(buffer, _countof(buffer)))
            throw Utils::Exception(::GetLastError(), L"GetSystemDirectoryW() failed with code %d", ::GetLastError());

        return buffer;
    }

    std::wstring SystemInformation::GetSysWow64Dir()
    {
        wchar_t buffer[MAX_PATH];

        if (!::GetWindowsDirectoryW(buffer, _countof(buffer)))
            throw Utils::Exception(::GetLastError(), L"GetCurrentDirectoryW() failed with code %d", ::GetLastError());

        wcscat_s(buffer, L"\\SysWOW64");

        return buffer;
    }

    std::wstring SystemInformation::GetSystemDir()
    {
        wchar_t buffer[MAX_PATH];

        if (!::GetWindowsDirectoryW(buffer, _countof(buffer)))
            throw Utils::Exception(::GetLastError(), L"GetCurrentDirectoryW() failed with code %d", ::GetLastError());

        wcscat_s(buffer, L"\\System");

        return buffer;
    }

    std::wstring SystemInformation::GetWindowsDir()
    {
        wchar_t buffer[MAX_PATH];

        if (!::GetWindowsDirectoryW(buffer, _countof(buffer)))
            throw Utils::Exception(::GetLastError(), L"GetCurrentDirectoryW() failed with code %d", ::GetLastError());

        return buffer;
    }

    // =================

    Wow64NoFsRedirection::Wow64NoFsRedirection() : _revert(false)
    {
        if (SystemInformation::GetSystemBitness() != Bitness::Arch64)
            return;

        if (ProcessInformation::GetCurrentProcessBitness() == Bitness::Arch64)
            return;

        if (!::Wow64DisableWow64FsRedirection(&_old))
            throw Utils::Exception(::GetLastError(), L"Wow64DisableWow64FsRedirection() failed with code %d", ::GetLastError());

        _revert = true;
    }

    Wow64NoFsRedirection::~Wow64NoFsRedirection()
    {
        if (!_revert)
            return;

        if (!::Wow64RevertWow64FsRedirection(_old))
            throw Utils::Exception(::GetLastError(), L"Wow64RevertWow64FsRedirection() failed with code %d", ::GetLastError());
    }

    // =================

    RegistryKey::RegistryKey(BaseKeys base, const wchar_t* key, DWORD access) : _hkey(0)
    {
        auto result = ::RegOpenKeyExW(ConvertBaseToHKEY(base), key, 0, access, &_hkey);
        if (result != ERROR_SUCCESS)
            throw Utils::Exception(result, L"RegOpenKeyExW() failed with code %d", result);
    }

    RegistryKey::~RegistryKey()
    {
        ::RegCloseKey(_hkey);
    }

    HKEY RegistryKey::GetNativeHKEY() const
    {
        return _hkey;
    }

    HKEY RegistryKey::ConvertBaseToHKEY(BaseKeys base)
    {
        switch (base)
        {
        case BaseKeys::Root:
            return HKEY_CLASSES_ROOT;
        case BaseKeys::CurrentConfig:
            return HKEY_CURRENT_CONFIG;
        case BaseKeys::CurrentUser:
            return HKEY_CURRENT_USER;
        case BaseKeys::LocalMachine:
            return HKEY_LOCAL_MACHINE;
        default:
            break;
        }
        throw Utils::Exception(L"Unknown base registry key");
    }

    // =================

    RegistryValue::RegistryValue(const RegistryKey& key, const wchar_t* value)
    {
        DWORD size = 0x400;

        _value.resize(size / sizeof(wchar_t));
        
        while (true) //TODO: max amount of attempts
        {
            auto result = ::RegQueryValueExW(
                key.GetNativeHKEY(), 
                value, 
                NULL, 
                &_type, 
                reinterpret_cast<LPBYTE>(
                    const_cast<wchar_t*>(_value.c_str())
                ), 
                &size
            );
            if (result == ERROR_MORE_DATA)
            {
                _value.resize(_value.size() + 0x100);
                continue;
            }
            else if (result != ERROR_SUCCESS)
            {
                throw Utils::Exception(result, L"RegQueryValueExW failed with code %d", result);
            }

            size_t charsSize = size / sizeof(wchar_t);
            charsSize += (size % 2 ? 1 : 0);
            _value.resize(charsSize);
            break;
        }
    }

    DWORD RegistryValue::GetType() const
    {
        return _type;
    }

    const std::wstring& RegistryValue::GetValue() const
    {
        return _value;
    }

    // =================

    RegistryDwordValue::RegistryDwordValue(const RegistryValue& value)
    {
        LoadDword(value);
    }

    RegistryDwordValue::RegistryDwordValue(const RegistryKey& key, const wchar_t* value)
    {
        RegistryValue regValue(key, value);
        LoadDword(regValue);
    }

    DWORD RegistryDwordValue::GetValue() const
    {
        return _value;
    }

    void RegistryDwordValue::LoadDword(const RegistryValue& value)
    {
        if (value.GetType() != REG_DWORD)
            throw Utils::Exception(L"Not a multi-string value '%s'", value);

        auto& data = value.GetValue();
        if (data.size() < sizeof(DWORD))
            throw Utils::Exception(L"Invalid DWORD data size %d", data.size());

        _value = *reinterpret_cast<const DWORD*>(data.c_str());
    }

    // =================

    RegistryMultiStringValue::RegistryMultiStringValue(const RegistryValue& value)
    {
        LoadStrings(value);
    }

    RegistryMultiStringValue::RegistryMultiStringValue(const RegistryKey& key, const wchar_t* value)
    {
        RegistryValue regValue(key, value);
        LoadStrings(regValue);
    }

    void RegistryMultiStringValue::LoadStrings(const RegistryValue& value)
    {
        if (value.GetType() != REG_MULTI_SZ)
            throw Utils::Exception(L"Not a multi-string value '%s'", value);

        auto data = value.GetValue();
        const wchar_t* string = data.c_str();
        auto size = data.size();
        for (size_t i = 0; i < size; i++)
        {
            if (string)
            {
                if (data[i] != L'\0')
                    continue;

                std::vector<std::wstring>::push_back(string);
                string = nullptr;
            }
            else
            {
                if (data[i] == L'\0')
                    continue;

                string = &data[i];
            }
        }

        if (string)
            std::vector<std::wstring>::push_back(string);
    }

    // =================

    RegistryStringValue::RegistryStringValue(const RegistryValue& value)
    {
        LoadRegString(value);
    }

    RegistryStringValue::RegistryStringValue(const RegistryKey& key, const wchar_t* value)
    {
        RegistryValue regValue(key, value);
        LoadRegString(regValue);
    }

    const std::wstring& RegistryStringValue::GetValue() const
    {
        return _value;
    }

    void RegistryStringValue::LoadRegString(const RegistryValue& value)
    {
        if (value.GetType() != REG_SZ)
            throw Utils::Exception(L"Not a multi-string value '%s'", value);

        _value = value.GetValue();
    }

    // =================

    RegistryExpandedStringValue::RegistryExpandedStringValue(const RegistryValue& value)
    {
        LoadRegString(value);
    }

    RegistryExpandedStringValue::RegistryExpandedStringValue(const RegistryKey& key, const wchar_t* value)
    {
        RegistryValue regValue(key, value);
        LoadRegString(regValue);
    }

    const std::wstring& RegistryExpandedStringValue::GetValue() const
    {
        return _value;
    }

    void RegistryExpandedStringValue::LoadRegString(const RegistryValue& value)
    {
        if (value.GetType() != REG_EXPAND_SZ)
            throw Utils::Exception(L"Not a multi-string value '%s'", value);

        // ExpandEnvironmentStrings insted of PathUnExpandEnvStringsA
        //_value = value.GetValue();

        auto unexpanded = value.GetValue();
        _value.resize(unexpanded.size() + 0x200);

        for (int i = 0; i < 5; i++)
        {
            auto result = ::ExpandEnvironmentStringsW(
                unexpanded.c_str(),
                const_cast<wchar_t*>(_value.c_str()),
                _value.size()
            );
            if (result)
            {
                _value.resize(result);
                return;
            }

            if (::GetLastError() == ERROR_INSUFFICIENT_BUFFER)
            {
                _value.resize(_value.size() + 0x200);
                continue;
            }

            throw Utils::Exception(L"Can't expand registry value, code: %d", ::GetLastError());
        }

        throw Utils::Exception(L"Can't expand registry value");
    }

    // =================

    EnumRegistryValues::EnumRegistryValues(BaseKeys base, const wchar_t* key)
    {
        RegistryKey hkey(base, key);
        std::wstring name;

        DWORD index = 0;
        while (true)
        {
            name.resize(0x100);

            DWORD nameSize = name.size(), nameType;
            auto result = ::RegEnumValueW(
                hkey.GetNativeHKEY(), 
                index,
                const_cast<wchar_t*>(name.c_str()), 
                &nameSize, 
                NULL, 
                &nameType, 
                NULL, 
                NULL
            );
            if (result == ERROR_MORE_DATA)
            {
                name.resize(name.size() + 0x100);
                continue;
            }
            else if (result == ERROR_NO_MORE_ITEMS)
            {
                break;
            }
            else if (result != ERROR_SUCCESS)
            {
                throw Utils::Exception(result, L"RegEnumValueW failed with code %d", result);
            }

            name.resize(wcslen(name.c_str()));
            //_values[name] = RegistryValue(hkey, name.c_str());
            _values.emplace(name, RegistryValue(hkey, name.c_str()));
            index++;
        }
    }

    const RegistryValues EnumRegistryValues::GetValues()
    {
        return _values;
    }

};