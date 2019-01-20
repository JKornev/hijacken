#pragma once

#include "Utils.h"
#include <NTLib.h>
#include <map>

namespace System
{
// =================

    class Handle : private std::shared_ptr<void>
    {
    public:
        typedef void(*DestroyObjectRoutine)(HANDLE object);

    private:
        static void ObjectDeleter(HANDLE object);

    public:
        Handle();
        Handle(HANDLE object, DestroyObjectRoutine destroyer = &ObjectDeleter);

        bool IsValid();

        HANDLE GetNativeHandle();

    protected:

        void SetHandle(HANDLE object, DestroyObjectRoutine destroyer = &ObjectDeleter);
    };

// =================

    class Process : public Handle
    {
    private:
        DWORD  _processId;

        template<typename T>
        void ReadMemoryToContainer(void* address, T& buffer, size_t size);

        static void WithoutRelease(HANDLE object);

    public:
        Process(DWORD processId, DWORD access = PROCESS_ALL_ACCESS);
        Process(HANDLE process);

        DWORD GetProcessID();

        void ReadMemory(void* address, std::string& buffer, size_t size);
        void ReadMemory(void* address, std::wstring& buffer, size_t size);
        void WriteMemory(void* address, std::string& buffer, bool unprotect = true);
        void WriteMemory(void* address, std::wstring& buffer, bool unprotect = true);

        void SetPrivilege(wchar_t* privelege, bool enable);

    };

    typedef std::shared_ptr<Process> ProcessPtr;

// =================

    class ProcessesSnapshot : protected Handle
    {
    private:
        bool   _fromStart;

    public:
        ProcessesSnapshot();

        bool GetNextProcess(DWORD& processId);

        void ResetWalking();
    };

// =================

    class ProcessEnvironment;
    typedef std::shared_ptr<ProcessEnvironment> ProcessEnvironmentPtr;

    class ProcessEnvironmentBlock;
    typedef std::shared_ptr<ProcessEnvironmentBlock> ProcessEnvironmentBlockPtr;

// =================

    class ProcessInformation
    {
    private:
        
        ProcessPtr _process;

        PPEB                       _pebAddress;
        ProcessEnvironmentBlockPtr _peb;

    public:
        ProcessInformation(DWORD processId);

        ProcessPtr GetProcess();

        PPEB GetPEBAddress();
        ProcessEnvironmentBlockPtr GetProcessEnvironmentBlock();

    };

// =================

    class ProcessEnvironmentBlock
    {
    private:
        ProcessPtr  _process;
        
        std::string _pebBuffer;
        PPEB        _peb;

        std::string                  _paramsBuffer;
        PRTL_USER_PROCESS_PARAMETERS _params;
        std::wstring                 _paramsEnv;

        std::wstring                 _currentDirectory;

        void LoadProcessParameters();

    public:
        ProcessEnvironmentBlock(ProcessInformation& processInfo);

        ProcessEnvironmentPtr GetProcessEnvironment();

        void GetCurrentDir(std::wstring& directory);
    };

// =================

    class ProcessEnvironment
    {
    private:
        std::map<std::wstring, std::wstring> _variables;

    public:
        ProcessEnvironment(std::wstring& environment);

        bool GetValue(const wchar_t* key, std::wstring& output);
    };

// =================

    class PrimaryToken : public Handle
    {
    public:
        PrimaryToken(Process& source, DWORD access = TOKEN_ALL_ACCESS);
    };

    class ImpersonateToken : public Handle
    {
    public:
        ImpersonateToken(Process& source, DWORD access = TOKEN_ALL_ACCESS);
    };

    class SecurityDescriptor
    {
    private:
        PSECURITY_DESCRIPTOR _descriptor;
        PACL _dacl;
        PSID _owner;
        PSID _group;

    public:
        SecurityDescriptor(Handle& file);
        ~SecurityDescriptor();

        PSECURITY_DESCRIPTOR GetNativeSecurityDescriptor();
    };

    class TokenAccessChecker
    {
    private:
        ImpersonateToken _token;

    public:
        TokenAccessChecker(Process& process);
        TokenAccessChecker(ImpersonateToken& token);
        
        bool IsAccessible(SecurityDescriptor& descriptor, DWORD desiredAccess);
    };

// =================

    class Directory : public Handle
    {
    public:
        Directory(const wchar_t* path, DWORD access = READ_CONTROL, DWORD share = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE);
    };
};
