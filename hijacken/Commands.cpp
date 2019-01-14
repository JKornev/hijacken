#include "Commands.h"
#include "System.h"
#include <iostream>

namespace Commands
{
    // =================

    ScanSystem::ScanSystem()
    {
        System::Process self(::GetCurrentProcess());
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
        System::ProcessesSnapshot snapshot;
        DWORD processId;

        while (snapshot.GetNextProcess(processId))
        {
            enum { IdlePID = 0, SystemPID = 4 };

            if (processId == IdlePID || processId == SystemPID)
                continue;

            try
            {
                System::ProcessInformation info(processId);
                System::ProcessEnvironmentBlock peb(info);
                
                std::wstring pathsStr;
                auto env = peb.GetProcessEnvironment();
                
                if (!env->GetValue(L"Path", pathsStr) && !env->GetValue(L"PATH", pathsStr) && !env->GetValue(L"path", pathsStr))
                    throw Utils::Exception(L"Can't obtain 'Path' environment variable");

                Utils::SeporatedStrings paths(pathsStr, L';');
                for (auto& dir : paths)
                    std::wcout << L" " << dir.c_str() <<  std::endl;

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