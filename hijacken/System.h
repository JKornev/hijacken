#pragma once

#include "Utils.h"
#include <NTLib.h>
#include <map>

namespace System
{
    // =================

    class Handle : private std::shared_ptr<void>
    {
    private:
        static void ObjectDeleter(HANDLE object);

    public:
        Handle();
        Handle(HANDLE object);
        ~Handle();

        bool IsValid();

        HANDLE GetNativeHandle();
    };

    // =================

    class Process
    {
    private:
        Handle _process;
        DWORD  _processId;

        template<typename T>
        void ReadMemoryToContainer(void* address, T& buffer, size_t size);

    public:
        Process(DWORD processId, DWORD access = PROCESS_ALL_ACCESS);
        Process(HANDLE process);
        ~Process();

        DWORD GetProcessID();
        HANDLE GetNativeHandle();

        void ReadMemory(void* address, std::string& buffer, size_t size);
        void ReadMemory(void* address, std::wstring& buffer, size_t size);
        void WriteMemory(void* address, std::string& buffer, bool unprotect = true);
        void WriteMemory(void* address, std::wstring& buffer, bool unprotect = true);

        void SetPrivilege(wchar_t* privelege, bool enable);

    };

    typedef std::shared_ptr<Process> ProcessPtr;

    // =================

    class ProcessesSnapshot
    {
    private:
        Handle _snapshot;
        bool   _fromStart;

    public:
        ProcessesSnapshot();
        ~ProcessesSnapshot();

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
        ~ProcessInformation();

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
        std::wstring                  _paramsEnv;

        void LoadProcessParameters();

    public:
        ProcessEnvironmentBlock(ProcessInformation& processInfo);
        ~ProcessEnvironmentBlock();

        ProcessEnvironmentPtr GetProcessEnvironment();
    };

    // =================

    class ProcessEnvironment
    {
    private:
        std::map<std::wstring, std::wstring> _variables;

    public:
        ProcessEnvironment(std::wstring& environment);
        ~ProcessEnvironment();

        bool GetValue(const wchar_t* key, std::wstring& output);
    };
};
