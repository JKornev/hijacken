#include "Commands.h"
#include "WinAPI.h"
#include <iostream>

namespace Commands
{
    // =================

    ScanSystem::ScanSystem()
    {
        WinAPI::Process self(::GetCurrentProcess());
        self.SetPrivilege(L"SeDebugPrivilege", true);
    }

    ScanSystem::~ScanSystem()
    {
    }

    void ScanSystem::LoadArgs(Utils::Arguments& args)
    {
    }

    void ScanSystem::Perform()
    {
        WinAPI::ProcessesSnapshot snapshot;
        DWORD processId;

        while (snapshot.GetNextProcess(processId))
        {
            enum { IdlePID = 0, SystemPID = 4};

            if (processId == IdlePID || processId == SystemPID)
                continue;

            try
            {
                WinAPI::ProcessInformation info(processId);
                WinAPI::ProcessEnvironment environment(info);


            }
            catch (Utils::Exception& exception)
            {
                std::wcout << L"Process with ID " << processId << L" has been skipped, reason: " << exception.GetMessage() << std::endl;
                continue;
            }
        }
    }

    // =================

    ScanFile::ScanFile()
    {
    }

    ScanFile::~ScanFile()
    {
    }

    void ScanFile::LoadArgs(Utils::Arguments& args)
    {
    }

    void ScanFile::Perform()
    {
    }

    // =================

    MakeDll::MakeDll()
    {
    }

    MakeDll::~MakeDll()
    {
    }

    void MakeDll::LoadArgs(Utils::Arguments& args)
    {
    }

    void MakeDll::Perform()
    {
    }
};