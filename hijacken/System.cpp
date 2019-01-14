#include "System.h"
#include <tlhelp32.h>
#include <iostream>

namespace System
{
// =================

    Handle::Handle() :
        std::shared_ptr<void>(0, &ObjectDeleter)
    {
    }

    Handle::Handle(HANDLE object) :
        std::shared_ptr<void>(object, &ObjectDeleter)
    {
    }

    Handle::~Handle()
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

// =================

    Process::Process(DWORD processId, DWORD access) : _processId(processId)
    {
        auto process = ::OpenProcess(access, FALSE, _processId);
        if (!process)
            throw Utils::Exception(::GetLastError(), L"OpenProcess(pid:%d) failed with code %d", _processId, ::GetLastError());

        _process = process;
    }

    Process::Process(HANDLE process)
    {
        if (!::DuplicateHandle(::GetCurrentProcess(), process, ::GetCurrentProcess(), &process, 0, FALSE, DUPLICATE_SAME_ACCESS))
            throw Utils::Exception(::GetLastError(), L"DuplicateHandle() failed with code %d", ::GetLastError());

        _processId = ::GetProcessId(process);
        _process = process;
    }

    Process::~Process()
    {
    }

    DWORD Process::GetProcessID()
    {
        return _processId;
    }

    HANDLE Process::GetNativeHandle()
    {
        return _process.GetNativeHandle();
    }

    template<typename T>
    void Process::ReadMemoryToContainer(void* address, T& buffer, size_t size)
    {
        SIZE_T readed;

        buffer.resize(size / sizeof(buffer[0]));

        if (!::ReadProcessMemory(
                _process.GetNativeHandle(), 
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
        /*SIZE_T readed;

        buffer.resize(size);

        if (!::ReadProcessMemory(_process.GetNativeHandle(), address, const_cast<char*>(buffer.c_str()), size, &readed))
            throw Utils::Exception(GetLastError(), L"ReadProcessMemory(pid:%d) failed with code %d", _processId, GetLastError());

        if (readed != size)
            throw Utils::Exception(L"ReadProcessMemory(pid:%d) can't read full chunk", _processId);*/
        ReadMemoryToContainer<std::string>(address, buffer, size);
    }

    void Process::ReadMemory(void* address, std::wstring& buffer, size_t size)
    {
        ReadMemoryToContainer<std::wstring>(address, buffer, size);
    }

    void Process::WriteMemory(void* address, std::string& buffer, bool unprotect)
    {
        SIZE_T written = 0;

        auto result = ::WriteProcessMemory(_process.GetNativeHandle(), address, const_cast<char*>(buffer.c_str()), buffer.size(), &written);
        if (!result && unprotect)
        {
            DWORD old;
            if (::VirtualProtectEx(_process.GetNativeHandle(), address, buffer.size(), PAGE_EXECUTE_READWRITE, &old))
            {
                result = ::WriteProcessMemory(_process.GetNativeHandle(), address, const_cast<char*>(buffer.c_str()), buffer.size(), &written);
                ::VirtualProtectEx(_process.GetNativeHandle(), address, buffer.size(), old, &old);
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

    void Process::SetPrivilege(wchar_t* Privelege, bool Enable)
    {
        HANDLE object = NULL;
        TOKEN_PRIVILEGES priveleges = {};
        LUID luid = {};

        if (!::OpenProcessToken(_process.GetNativeHandle(), TOKEN_ADJUST_PRIVILEGES, &object))
            throw Utils::Exception(::GetLastError(), L"OpenProcessToken(pid:%d) failed with code %d", _processId, ::GetLastError());

        Handle token(object);

        if (!::LookupPrivilegeValueW(NULL, Privelege, &luid))
            throw Utils::Exception(::GetLastError(), L"LookupPrivilegeValue(pid:%d) failed with code %d", _processId, ::GetLastError());

        priveleges.PrivilegeCount = 1;
        priveleges.Privileges[0].Luid = luid;
        priveleges.Privileges[0].Attributes = (Enable ? SE_PRIVILEGE_ENABLED : 0);

        if (!::AdjustTokenPrivileges(token.GetNativeHandle(), FALSE, &priveleges, sizeof(priveleges), NULL, NULL))
            throw Utils::Exception(::GetLastError(), L"AdjustTokenPrivileges(pid:%d) failed with code %d", _processId, ::GetLastError());
    }

// =================

    ProcessesSnapshot::ProcessesSnapshot()
    {
        _snapshot = ::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (!_snapshot.IsValid())
            throw Utils::Exception(::GetLastError(), L"CreateToolhelp32Snapshot() failed with code %d", ::GetLastError());

        _fromStart = true;
    }

    ProcessesSnapshot::~ProcessesSnapshot()
    {
    }

    bool ProcessesSnapshot::GetNextProcess(DWORD& processId)
    {
        PROCESSENTRY32W entry = {};
        entry.dwSize = sizeof(entry);

        if (_fromStart)
        {
            if (!::Process32FirstW(_snapshot.GetNativeHandle(), &entry))
                return false;

            _fromStart = false;
        }
        else
        {
            if (!::Process32NextW(_snapshot.GetNativeHandle(), &entry))
                return false;
        }

        processId = entry.th32ProcessID;
        return true;
    }

    void ProcessesSnapshot::ResetWalking()
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

    ProcessInformation::~ProcessInformation()
    {
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
        //std::wcout << L" ProcessPEB (" << std::dec << _process->GetProcessID() << L"): ";
        //std::wcout << std::hex << basic.PebBaseAddress << std::endl;

        return _pebAddress;
    }

    ProcessEnvironmentBlockPtr ProcessInformation::GetProcessEnvironmentBlock()
    {
        if (!_peb.get())
            _peb.reset(new ProcessEnvironmentBlock(*this));

        return _peb;
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

    ProcessEnvironmentBlock::~ProcessEnvironmentBlock()
    {
    }

    ProcessEnvironmentPtr ProcessEnvironmentBlock::GetProcessEnvironment()
    {
        LoadProcessParameters();
        
        if (!_paramsEnv.size())
            _process->ReadMemory(_params->Environment, _paramsEnv, _params->EnvironmentSize);

        return ProcessEnvironmentPtr(new ProcessEnvironment(_paramsEnv));
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

    ProcessEnvironment::~ProcessEnvironment()
    {
    }

    bool ProcessEnvironment::GetValue(const wchar_t* key, std::wstring& output)
    {
        auto value = _variables.find(std::wstring(key));

        if (value == _variables.end())
            return false;

        output = value->second;
        return true;
    }
};