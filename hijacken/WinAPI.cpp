#include "WinAPI.h"
#include <tlhelp32.h>

namespace WinAPI
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

    ProcessInformation::ProcessInformation(DWORD processId)
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

// =================

    ProcessEnvironment::ProcessEnvironment(ProcessInformation& processInfo)
    {
    }

    ProcessEnvironment::~ProcessEnvironment()
    {
    }
};