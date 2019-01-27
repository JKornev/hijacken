#include "System.h"
#include <tlhelp32.h>
#include <iostream>
#include <aclapi.h>
#include <psapi.h>
#include <sddl.h>

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
        Utils::ExtractFileDirectory(path, directory);
    }

    void ProcessInformation::GetModulePath(HMODULE module, std::wstring& path)
    {
        wchar_t buffer[MAX_PATH * 2];

        auto result = ::GetModuleFileNameExW(_process->GetNativeHandle(), module, buffer, _countof(buffer));
        if (!result)
            throw Utils::Exception(L"GetModuleFileNameExW(pid:%d) failed with code %d", _process->GetProcessID(), ::GetLastError());

        path = buffer;
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

        if (!::AdjustTokenPrivileges(Handle::GetNativeHandle(), FALSE, &priveleges, sizeof(priveleges), NULL, NULL))
            throw Utils::Exception(::GetLastError(), L"AdjustTokenPrivileges() failed with code %d", ::GetLastError());
    }

    TokenIntegrityLvl TokenBase::GetIntegrityLevel()
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

        TokenIntegrityLvl level;
        auto sub = *::GetSidSubAuthority(mandatory->Label.Sid, 0);

        switch (sub)
        {
        case SECURITY_MANDATORY_UNTRUSTED_RID:
            level = TokenIntegrityLvl::Untrusted;
            break;
        case SECURITY_MANDATORY_LOW_RID:
            level = TokenIntegrityLvl::Low;
            break;
        case SECURITY_MANDATORY_MEDIUM_RID:
            level = TokenIntegrityLvl::Medium;
            break;
        case SECURITY_MANDATORY_MEDIUM_PLUS_RID:
            level = TokenIntegrityLvl::MediumPlus;
            break;
        case SECURITY_MANDATORY_HIGH_RID:
            level = TokenIntegrityLvl::High;
            break;
        case SECURITY_MANDATORY_SYSTEM_RID:
            level = TokenIntegrityLvl::System;
            break;
        default:
            throw Utils::Exception(L"Unknown mandatory authority %x", sub);
        }

        return level;
    }

    void TokenBase::SetIntegrityLevel(TokenIntegrityLvl level)
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

    PSID TokenBase::AllocateSidByIntegrityLevel(TokenIntegrityLvl level)
    {
        std::wstring sidName;

        switch (level)
        {
        case TokenIntegrityLvl::Untrusted:
            sidName = L"S-1-16-0";
            break;
        case TokenIntegrityLvl::Low:
            sidName = L"S-1-16-4096";
            break;
        case TokenIntegrityLvl::Medium:
            sidName = L"S-1-16-8192";
            break;
        case TokenIntegrityLvl::MediumPlus:
            sidName = L"S-1-16-8448";
            break;
        case TokenIntegrityLvl::High:
            sidName = L"S-1-16-12288";
            break;
        case TokenIntegrityLvl::System:
            sidName = L"S-1-16-16384";
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

        if (!::OpenProcessToken(source.GetNativeHandle(), access, &object))
            throw Utils::Exception(::GetLastError(), L"OpenProcessToken(pid:%d) failed with code %d", source.GetProcessID(), ::GetLastError());

        if (duplicate)
        {
            if (!::DuplicateTokenEx(object, 0, NULL, SecurityImpersonation, TokenPrimary, &object))
                throw Utils::Exception(::GetLastError(), L"DuplicateToken(pid:%d) failed with code %d", source.GetProcessID(), ::GetLastError());
        }

        Handle::SetHandle(object);
    }

// =================

    ImpersonateToken::ImpersonateToken(Process& source, DWORD access)
    {
        HANDLE object = nullptr;

        access |= TOKEN_DUPLICATE;

        if (!::OpenProcessToken(source.GetNativeHandle(), access, &object))
            throw Utils::Exception(::GetLastError(), L"OpenProcessToken(pid:%d) failed with code %d", source.GetProcessID(), ::GetLastError());

        if (!::DuplicateTokenEx(object, 0, NULL, SecurityImpersonation, TokenImpersonation, &object))
            throw Utils::Exception(::GetLastError(), L"DuplicateToken(pid:%d) failed with code %d", source.GetProcessID(), ::GetLastError());

        Handle::SetHandle(object);
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

    bool TokenAccessChecker::IsAccessible(SecurityDescriptor& descriptor, DWORD desiredAccess)
    {
        BOOL accessStatus = FALSE;
        GENERIC_MAPPING mapping = {};
        PRIVILEGE_SET PrivilegeSet;
        DWORD dwPrivSetSize = sizeof(PRIVILEGE_SET);
        DWORD dwAccessAllowed = 0;

        //TODO: common logic
        mapping.GenericRead  = FILE_GENERIC_READ;
        mapping.GenericWrite = FILE_GENERIC_WRITE;
        mapping.GenericAll   = FILE_GENERIC_READ | FILE_GENERIC_WRITE;

        MapGenericMask(&desiredAccess, &mapping);

        if (!IsValidSecurityDescriptor(descriptor.GetNativeSecurityDescriptor()))
            std::wcout << L"invalid" << std::endl;

        if (!AccessCheck(descriptor.GetNativeSecurityDescriptor(), _token.GetNativeHandle(), desiredAccess, &mapping, &PrivilegeSet, &dwPrivSetSize, &dwAccessAllowed, &accessStatus))
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

    Directory::Directory(const wchar_t* path, DWORD access, DWORD share) :
        Handle(::CreateFileW(path, access, share, NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL))
    {
        if (!Handle::IsValid())
            throw Utils::Exception(::GetLastError(), L"CreateFileW(dir) failed with code %d", ::GetLastError());
    }

};