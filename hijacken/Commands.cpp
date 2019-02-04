#include "Commands.h"
#include <iostream>

namespace Commands
{
// =================

    ImpersonationOptions::ImpersonationOptions() :
        _tokenSourceProcessId(::GetCurrentProcessId()),
        _tokenIntegrityLevel(System::IntegrityLevel::Untrusted),
        _changeIntegrityLevel(false)
    {
    }

    void ImpersonationOptions::LoadArgs(Utils::Arguments& args)
    {
        std::wstring command;

        if (!args.Probe(command))
            return;

        if (command == L"/impersonate")
        {
            args.SwitchToNext();

            if (!args.GetNext(command))
                throw Utils::Exception(L"Invalid impersonation argument '%s'", command.c_str());

            _tokenSourceProcessId = _wtoi(command.c_str());

            if (!args.Probe(command))
                return;
        }

        if (command == L"/integrity")
        {
            args.SwitchToNext();

            if (!args.GetNext(command))
                throw Utils::Exception(L"Invalid impersonation argument '%s'", command.c_str());

            _tokenIntegrityLevel = ConvertStrToIntegrityLevel(command);
            _changeIntegrityLevel = true;
        }
    }

    System::ImpersonateTokenPtr ImpersonationOptions::CraftToken()
    {
        System::Process target(_tokenSourceProcessId, PROCESS_QUERY_INFORMATION);
        auto token = System::ImpersonateTokenPtr(new System::ImpersonateToken(target, TOKEN_ADJUST_DEFAULT | TOKEN_QUERY));

        if (_changeIntegrityLevel)
            ChangeIntegrity(token, _tokenIntegrityLevel);

        return token;
    }

    void ImpersonationOptions::ChangeIntegrity(System::ImpersonateTokenPtr& token, System::IntegrityLevel expectedIntegrity)
    {
        auto currentIntegrity  = token->GetIntegrityLevel();

        if (currentIntegrity == expectedIntegrity)
            return;

        if (currentIntegrity < expectedIntegrity)
            throw Utils::Exception(L"Access token can't be elevated to higher integrity level");

        if (currentIntegrity == System::IntegrityLevel::High)
        {
            token.reset(new System::ImpersonateToken(token->GetLinkedToken()));
            currentIntegrity = token->GetIntegrityLevel();
            if (currentIntegrity == System::IntegrityLevel::High)
                throw Utils::Exception(L"Attempt to elevate token has been failed");
        }

        if (currentIntegrity != expectedIntegrity)
            token->SetIntegrityLevel(expectedIntegrity);

        if (token->GetIntegrityLevel() == expectedIntegrity)
            return;

        throw Utils::Exception(L"Attempt to prepare token with specific integrity level has been failed");
    }

    System::IntegrityLevel ImpersonationOptions::ConvertStrToIntegrityLevel(std::wstring& level)
    {
        auto integrity = System::IntegrityLevel::Untrusted;

        if (level == L"medium")
            integrity = System::IntegrityLevel::Medium;
        else if (level == L"low")
            integrity = System::IntegrityLevel::Low;
        else if (level == L"untrusted")
            integrity = System::IntegrityLevel::Untrusted;
        else
            throw Utils::Exception(L"Unknown integrity level '%d'", integrity);

        return integrity;
    }

    void ImpersonationOptions::PrintTokenInformation(System::ImpersonateTokenPtr& token)
    {
        std::wstring str;

        std::wcout << L"Access token information:" << std::endl;
        token->GetUserNameString(str);
        std::wcout << L"  " << str.c_str() << std::endl;
        token->GetUserSIDString(str);
        std::wcout << L"  " << str.c_str() << std::endl;
        std::wcout << L"  Integrity: " << ConvertIntegrityLevelToString(token->GetIntegrityLevel()) 
                   << L", " << (token->IsElevated() ? L"Elevated" : L"Not-Elevated") << std::endl;
        std::wcout << std::endl;
    }

    const wchar_t* ImpersonationOptions::ConvertIntegrityLevelToString(System::IntegrityLevel level)
    {
        switch (level)
        {
        case System::IntegrityLevel::Untrusted:
            return L"Untrusted";
        case System::IntegrityLevel::Low:
            return L"Low";
        case System::IntegrityLevel::Medium:
            return L"Medium";
        case System::IntegrityLevel::MediumPlus:
            return L"MediumPlus";
        case System::IntegrityLevel::High:
            return L"High";
        case System::IntegrityLevel::System:
            return L"System";
        case System::IntegrityLevel::Protected:
            return L"Protected";
        case System::IntegrityLevel::Secure:
            return L"Secure";
        default:
            break;
        }
        return L"Unknown";
    }

// =================

    ScanFile::ScanFile()
    {
    }

    void ScanFile::LoadArgs(Utils::Arguments& args)
    {
    }

    void ScanFile::Perform()
    {
    }

// =================

    ScanDirectory::ScanDirectory()
    {
    }

    void ScanDirectory::LoadArgs(Utils::Arguments& args)
    {
    }

    void ScanDirectory::Perform()
    {
    }

// =================

    ScanProcess::ScanProcess() : _targetProcessId(0)
    {
        System::Process self(::GetCurrentProcess());
        System::PrimaryToken token(self);
        token.SetPrivilege(L"SeDebugPrivilege", true);
    }

    void ScanProcess::LoadArgs(Utils::Arguments& args)
    {
        std::wstring command;

        if (!args.GetNext(command))
            throw Utils::Exception(L"Invalid command argument '%s'", command.c_str());

        _targetProcessId = _wtoi(command.c_str());

        ImpersonationOptions::LoadArgs(args);

        if (!args.IsEnded())
            throw Utils::Exception(L"Too much arguments");
    }

    void ScanProcess::Perform()
    {
        auto token = ImpersonationOptions::CraftToken();
        System::TokenAccessChecker access(*token);

        ImpersonationOptions::PrintTokenInformation(token);

        Engine::ProcessScanEngine::Scan(_targetProcessId, access);

        for (auto& detection : _detectedDirs)
        {
            std::wcout << ConvertDirDetectionToString(detection.first) << L":" << std::endl;
            for (auto& dir : detection.second)
                std::wcout << L"  " << dir.c_str() << std::endl;
        }

        for (auto& detection : _detectedFiles)
        {
            std::wcout << ConvertFileDetectionToString(detection.first) << L":" << std::endl;
            for (auto& file : detection.second)
                std::wcout << L"  " << file.c_str() << std::endl;
        }
    }

    void ScanProcess::NotifyWritableDirectory(DetectionDirType detection, std::wstring& dirPath)
    {
        _detectedDirs[detection].insert(dirPath);
    }

    void ScanProcess::NotifyWritableFile(DetectionFileType detection, std::wstring& filePath)
    {
        _detectedFiles[detection].insert(filePath);
    }

// =================

    ScanProcesses::ScanProcesses()
    {
        System::Process self(::GetCurrentProcess());
        System::PrimaryToken token(self);
        token.SetPrivilege(L"SeDebugPrivilege", true);
    }

    void ScanProcesses::LoadArgs(Utils::Arguments& args)
    {
        ImpersonationOptions::LoadArgs(args);

        if (!args.IsEnded())
            throw Utils::Exception(L"Too much arguments");
    }

    void ScanProcesses::Perform()
    {
        auto token = ImpersonationOptions::CraftToken();
        System::TokenAccessChecker access(*token);

        ImpersonationOptions::PrintTokenInformation(token);

        std::wcout << L"===============" << std::endl;
        std::wcout << L"   FINDINGS" << std::endl;
        std::wcout << L"===============" << std::endl << std::endl;

        DWORD processId;
        std::wstring processName;
        System::ProcessesSnapshot snapshot;
        while (snapshot.GetNextProcess(processId, processName))
        {
            enum { IdlePID = 0, SystemPID = 4 };

            if (processId == IdlePID || processId == SystemPID)
                continue;

            try
            {
                Engine::ProcessScanEngine::Scan(processId, access);

                if (!_detectedDirs.empty() || !_detectedFiles.empty())
                {
                    std::wcout << L"Process " << processId << L", " << processName.c_str() << std::endl;

                    for (auto& detection : _detectedDirs)
                    {
                        std::wcout << L"  " << ConvertDirDetectionToString(detection.first) << L":" << std::endl;
                        for (auto& dir : detection.second)
                            std::wcout << L"    " << dir.c_str() << std::endl;
                    }

                    for (auto& detection : _detectedFiles)
                    {
                        std::wcout << L"  " << ConvertFileDetectionToString(detection.first) << L":" << std::endl;
                        for (auto& file : detection.second)
                            std::wcout << L"    " << file.c_str() << std::endl;
                    }

                    std::wcout << std::endl;
                }
            }
            catch (Utils::Exception& exception)
            {
                //std::wcout << L"Process with ID " << processId << L" has been skipped, reason: " << exception.GetMessage() << std::endl;
                continue;
            }

            _detectedDirs.clear();
            _detectedFiles.clear();
        }
    }

    void ScanProcesses::NotifyWritableDirectory(DetectionDirType detection, std::wstring& dirPath)
    {
        _detectedDirs[detection].insert(dirPath);
    }

    void ScanProcesses::NotifyWritableFile(DetectionFileType detection, std::wstring& filePath)
    {
        _detectedFiles[detection].insert(filePath);
    }

// =================

    ScanAutorun::ScanAutorun()
    {
    }

    void ScanAutorun::LoadArgs(Utils::Arguments& args)
    {
    }

    void ScanAutorun::Perform()
    {
    }

// =================

    ScanTask::ScanTask()
    {
    }

    void ScanTask::LoadArgs(Utils::Arguments& args)
    {
    }

    void ScanTask::Perform()
    {
    }

// =================

    ScanTasks::ScanTasks()
    {
    }

    void ScanTasks::LoadArgs(Utils::Arguments& args)
    {
    }

    void ScanTasks::Perform()
    {
    }

// =================

    ScanService::ScanService()
    {
    }

    void ScanService::LoadArgs(Utils::Arguments& args)
    {
    }

    void ScanService::Perform()
    {
    }

// =================

    ScanServices::ScanServices()
    {
    }

    void ScanServices::LoadArgs(Utils::Arguments& args)
    {
    }

    void ScanServices::Perform()
    {
    }

// =================

    ScanSystem::ScanSystem()
    {
    }

    void ScanSystem::LoadArgs(Utils::Arguments& args)
    {
    }

    void ScanSystem::Perform()
    {
    }

// =================

    MakeDll::MakeDll()
    {
    }

    void MakeDll::LoadArgs(Utils::Arguments& args)
    {
    }

    void MakeDll::Perform()
    {
    }
};