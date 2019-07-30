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
        auto currentIntegrity = token->GetIntegrityLevel();

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
        std::wcout << L"  " << str << std::endl;
        token->GetUserSIDString(str);
        std::wcout << L"  " << str << std::endl;
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

    SystemOptions::SystemOptions() :
        _scanElevated(false)
    {
    }

    void SystemOptions::LoadArgs(Utils::Arguments& args)
    {
        std::wstring command;

        if (!args.Probe(command))
            return;

        if (command == L"/elevation")
        {
            _scanElevated = true;
            args.SwitchToNext();
        }
    }

    bool SystemOptions::ShouldScanProcess(System::ImpersonateTokenPtr& token, DWORD targetProcessId)
    {
        if (!_scanElevated)
            return true;

        System::Process process(targetProcessId, PROCESS_QUERY_INFORMATION);
        System::ImpersonateToken targetToken(process);

        auto sourceIntegrity = token->GetIntegrityLevel();
        auto targetIntegrity = targetToken.GetIntegrityLevel();

        return (sourceIntegrity < targetIntegrity);
    }

    // =================

    EnvironmentOptions::EnvironmentOptions() :
        _envSource(EnvironmentSource::User),
        _sourceProcessId(0)
    {
    }

    void EnvironmentOptions::LoadArgs(Utils::Arguments& args)
    {
        std::wstring command;

        if (!args.Probe(command))
            return;

        if (command != L"/environment")
            return;

        args.SwitchToNext();

        if (!args.GetNext(command))
            return;

        if (command == L"system")
        {
            _envSource = EnvironmentSource::System;
        }
        else if (command == L"user")
        {
            _envSource = EnvironmentSource::User;
        }
        else if (command == L"process")
        {
            std::wstring param;

            if (!args.GetNext(param))
                throw Utils::Exception(L"Not enough arguments");//TODO

            _sourceProcessId = _wtoi(param.c_str());
            _envSource = EnvironmentSource::Process;
        }
        else if (command == L"inherit")
        {
            _envSource = EnvironmentSource::Inherit;
        }
        else if (command == L"off")
        {
            _envSource = EnvironmentSource::Off;
        }
        else
        {
            throw Utils::Exception(L"Invalid environment argument '%s'", command.c_str());
        }
    }

    System::EnvironmentVariablesPtr EnvironmentOptions::GetEnvironment()
    {
        System::EnvironmentVariablesPtr env;

        if (_envSource == EnvironmentSource::User)
        {
            System::EnumRegistryValues user(System::BaseKeys::CurrentUser, L"Environment");
            System::EnumRegistryValues system(
                System::BaseKeys::LocalMachine,
                L"System\\CurrentControlSet\\Control\\Session Manager\\Environment"
            );

            auto vars = user.GetValues();
            auto& sysVars = system.GetValues();
            vars.insert(sysVars.begin(), sysVars.end());
            env.reset(new System::EnvironmentVariables(vars));
        }
        else if (_envSource == EnvironmentSource::System)
        {
            System::EnumRegistryValues system(
                System::BaseKeys::LocalMachine,
                L"System\\CurrentControlSet\\Control\\Session Manager\\Environment"
            );
            env.reset(new System::EnvironmentVariables(system.GetValues()));
        }
        else if (_envSource == EnvironmentSource::Process)
        {
            System::ProcessInformation info(_sourceProcessId);
            auto peb = info.GetProcessEnvironmentBlock();
            env = peb->GetProcessEnvironment();
        }
        else if (_envSource == EnvironmentSource::Inherit)
        {
            env = System::ProcessInformation::GetCurrentEnvironmentVariables();
        }
        else if (_envSource == EnvironmentSource::Off)
        {
            env.reset(new System::EnvironmentVariables());
        }

        return env;
    }

// =================

    ScanFile::ScanFile() :
        _unwindImports(true),
        _scanDelayLoad(true),
        _checkAccess(false),
        _firstFound(false)
    {
    }

    void ScanFile::LoadArgs(Utils::Arguments& args)
    {
        std::wstring option;

        if (!args.Probe(option))
            throw Utils::Exception(L"Not enough arguments");

        if (option == L"/nounwinding")
        {
            _unwindImports = false;

            args.SwitchToNext();
            if (!args.Probe(option))
                throw Utils::Exception(L"Not enough arguments");
        }

        if (option == L"/nodelay")
        {
            _scanDelayLoad = false;

            args.SwitchToNext();
            if (!args.Probe(option))
                throw Utils::Exception(L"Not enough arguments");
        }

        if (option == L"/accessible")
        {
            _checkAccess = true;

            args.SwitchToNext();
            ImpersonationOptions::LoadArgs(args);
        }

        EnvironmentOptions::LoadArgs(args);

        if (!args.GetNext(_filePath))
            throw Utils::Exception(L"Not enough arguments");
    }

    void ScanFile::Perform()
    {
        auto token = ImpersonationOptions::CraftToken();
        System::TokenAccessChecker access(*token);

        auto env = EnvironmentOptions::GetEnvironment();

        Engine::ImageScanEngine::SetOptionUnwindImport(_unwindImports);
        Engine::ImageScanEngine::SetOptionUnwindDelayLoadImport(_scanDelayLoad);
        Engine::ImageScanEngine::SetOptionAccessibleOnly(_checkAccess);

        Engine::ImageScanEngine::Scan(_filePath, *env, access);
    }

    void ScanFile::NotifyLoadImageOrder(Engine::LoadImageOrder& dirs)
    {
        std::wcout << std::endl;
        std::wcout << L"Safe search: " << (Engine::LoadImageOrder::IsSafeSearchEnabled() ? L"enabled" : L"disabled") << std::endl;
        std::wcout << L"Expected image load order:" << std::endl;

        int i = 0;
        for (auto& dir : dirs.GetOrder())
            std::wcout << L" " << ++i << L". " << ConvertImageDirStateToString(dir) << " [" << ConvertImageDirTypeToString(dir.GetType()) << "] " << dir.GetPath() << std::endl;

        std::wcout << std::endl;

        std::wcout << L" * attributes meaning:" << std::endl;
        std::wcout << L"    N - directory doesn't exist" << std::endl;
        std::wcout << L"    A - directory existing and accessible" << std::endl;
        std::wcout << L"    O - a name of the directory is owned by a file, it should break an image loading when loader meets a file instead of directory" << std::endl;

        std::wcout << std::endl;
    }

    void ScanFile::NotifyVulnerableDll(Engine::ImageDirectory& dir, std::wstring& dll, bool writtable, std::vector<const Engine::ImageDirectory*>& vulnDirs)
    {
        if (!_firstFound)
        {
            _firstFound = true;
            std::wcout << L"Vulnerable DLLs:" << std::endl << std::endl;
        }

        std::wcout << L" " << dll << (writtable ? L", is writable" : L"") << std::endl;
        std::wcout << L"  Location: " << (dir.GetType() != Engine::ImageDirectory::Type::Unknown ? dir.GetPath() : L"not found") << std::endl;
        std::wcout << L"  Type: " << ConvertImageDirTypeToString(dir.GetType()) << std::endl;

        if (dir.GetType() != Engine::ImageDirectory::Type::Base)
        {
            std::wcout << L"  Vulnerable dirs:" << std::endl;

            int i = 0;
            for (auto& vulnDir : vulnDirs)
                std::wcout << L"    " << ++i << L". [" << ConvertImageDirTypeToString(vulnDir->GetType()) << "] " << vulnDir->GetPath() << std::endl;
        }

        std::wcout << std::endl;
    }

    void ScanFile::NotifyVulnerableSxSDll(Engine::ImageDirectory& dir, std::wstring& dll, bool writtable)
    {
        if (!_firstFound)
        {
            _firstFound = true;
            std::wcout << L"Vulnerable DLLs:" << std::endl << std::endl;
        }

        std::wcout << L" " << dll << (writtable ? L", is writable" : L"") << std::endl;
        std::wcout << L"  Type: " << ConvertImageDirTypeToString(dir.GetType()) << std::endl;
        std::wcout << L"  Vulnerable dir: " << std::endl << L"    " << dir.GetPath() << std::endl;
        std::wcout << std::endl;
    }

    const wchar_t* ScanFile::ConvertImageDirTypeToString(Engine::ImageDirectory::Type type)
    {
        switch (type)
        {
        case Engine::ImageDirectory::Type::Base:
            return L"Base";
        case Engine::ImageDirectory::Type::System32:
            return L"System32";
        case Engine::ImageDirectory::Type::System:
            return L"System";
        case Engine::ImageDirectory::Type::Windows:
            return L"Windows";
        case Engine::ImageDirectory::Type::Current:
            return L"Current";
        case Engine::ImageDirectory::Type::Environment:
            return L"Environment";
        case Engine::ImageDirectory::Type::FullPath:
            return L"FullPath";
        case Engine::ImageDirectory::Type::SxS:
            return L"Side-by-Side";
        default:
            break;
        }
        return L"Unknown";
    }

    const wchar_t* ScanFile::ConvertImageDirStateToString(const Engine::ImageDirectory& dir)
    {
        auto state = dir.GetState();
        if (state == Engine::ImageDirectory::State::NotExisting)
            return L"N";
        else if (state == Engine::ImageDirectory::State::Overlapped)
            return L"O";
        else if (state == Engine::ImageDirectory::State::Existing && dir.IsAccessible())
            return L"A";
        
        return L" ";
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
                std::wcout << L"  " << dir << std::endl;
        }

        for (auto& detection : _detectedFiles)
        {
            std::wcout << ConvertFileDetectionToString(detection.first) << L":" << std::endl;
            for (auto& file : detection.second)
                std::wcout << L"  " << file << std::endl;
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

        if (token.GetIntegrityLevel() < System::IntegrityLevel::High)
            std::wcout << std::endl
                       << L" Warning! Hijacken has been run without administrator rights." << std::endl
                       << L" Therefore scan is limited to an accessible scope of processes." << std::endl
                       << std::endl;
    }

    void ScanProcesses::LoadArgs(Utils::Arguments& args)
    {
        SystemOptions::LoadArgs(args);
        ImpersonationOptions::LoadArgs(args);

        if (!args.IsEnded())
            throw Utils::Exception(L"Too much arguments");
    }

    void ScanProcesses::Perform()
    {
        auto token = ImpersonationOptions::CraftToken();
        System::TokenAccessChecker access(*token);

        ImpersonationOptions::PrintTokenInformation(token);

        std::wcout << L"==============" << std::endl;
        std::wcout << L"   FINDINGS" << std::endl;
        std::wcout << L"==============" << std::endl << std::endl;

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
                if (!SystemOptions::ShouldScanProcess(token, processId))
                    continue;

                Engine::ProcessScanEngine::Scan(processId, access);

                if (!_detectedDirs.empty() || !_detectedFiles.empty())
                {
                    std::wcout << L"Process " << processId << L", " << processName << std::endl;

                    for (auto& detection : _detectedDirs)
                    {
                        std::wcout << L"  " << Engine::ProcessScanEngine::ConvertDirDetectionToString(detection.first) << L":" << std::endl;
                        for (auto& dir : detection.second)
                            std::wcout << L"    " << dir << std::endl;
                    }

                    for (auto& detection : _detectedFiles)
                    {
                        std::wcout << L"  " << Engine::ProcessScanEngine::ConvertFileDetectionToString(detection.first) << L":" << std::endl;
                        for (auto& file : detection.second)
                            std::wcout << L"    " << file << std::endl;
                    }

                    std::wcout << std::endl;
                }
            }
            catch (Utils::Exception& exception)
            {
                //std::wcout << L"Process with ID " << processId << L" has been skipped, reason: " << exception.GetMessage() << std::endl;
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