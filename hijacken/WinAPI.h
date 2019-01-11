#pragma once

#include "Utils.h"

namespace WinAPI
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

    public:
        Process(DWORD processId, DWORD access = PROCESS_ALL_ACCESS);
        Process(HANDLE process);
        ~Process();

        DWORD GetProcessID();

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

    class ProcessInformation
    {
    private:
        ProcessPtr _process;

    public:
        ProcessInformation(DWORD processId);
        ~ProcessInformation();
    };

    // =================

    class ProcessEnvironment
    {
    public:
        ProcessEnvironment(ProcessInformation& processInfo);
        ~ProcessEnvironment();
    };
};
