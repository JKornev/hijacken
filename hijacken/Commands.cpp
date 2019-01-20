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
        std::wstring command;

        _tokenSourceId = ::GetCurrentProcessId();

        if (!args.Probe(command))
            return;

        if (command != L"/toksrc")
            throw Utils::Exception(L"Invalid command '%s'", command.c_str());

        args.SwitchToNext();

        if (!args.GetNext(command))
            throw Utils::Exception(L"Invalid command argument '%s'", command.c_str());

        _tokenSourceId = _wtoi(command.c_str());
    }

    void ScanSystem::Perform()
    {
        System::ProcessesSnapshot snapshot;
        DWORD processId;

        System::Process process(_tokenSourceId, PROCESS_QUERY_INFORMATION);
        System::ImpersonateToken token(process);
        System::TokenAccessChecker access(token);

        while (snapshot.GetNextProcess(processId))
        {
            enum { IdlePID = 0, SystemPID = 4 };

            if (processId == IdlePID || processId == SystemPID)
                continue;

            try
            {
                std::vector<std::wstring> writable;
                System::ProcessInformation info(processId);
                System::ProcessEnvironmentBlock peb(info);
                
                std::wstring pathSet;
                auto env = peb.GetProcessEnvironment();
                
                if (!env->GetValue(L"Path", pathSet) && !env->GetValue(L"PATH", pathSet) && !env->GetValue(L"path", pathSet))
                    throw Utils::Exception(L"Can't obtain 'Path' environment variable");

                Utils::SeparatedStrings paths(pathSet, L';');

                //TODO: refactor
                for (auto& dir : paths)
                {
                    try
                    {
                        System::Directory directory(dir.c_str());
                        System::SecurityDescriptor descriptor(directory);
                        
                        auto accessible = access.IsAccessible(descriptor, GENERIC_WRITE);
                        if (accessible)
                            writable.push_back(dir);
                    }
                    catch (...)
                    {
                        //std::wcout << L" Skipped dir: " << dir.c_str() << std::endl;
                        continue;
                    }
                }

                std::wstring currentDirPath;
                peb.GetCurrentDir(currentDirPath);
                System::Directory directory(currentDirPath.c_str());
                System::SecurityDescriptor descriptor(directory);

                auto accessible = access.IsAccessible(descriptor, GENERIC_WRITE);
                if (accessible)
                    writable.push_back(currentDirPath);

                if (!writable.size())
                    continue;

                std::wcout << L"Process " << processId << L" has the following writable dirs:" << std::endl;
                for (auto& dir : writable)
                    std::wcout << L"  " << dir.c_str() << std::endl;
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