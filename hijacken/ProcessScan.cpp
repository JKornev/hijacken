#include "ProcessScan.h"

namespace Engine
{
    ProcessScanEngine::ProcessScanEngine()
    {
    }

    void ProcessScanEngine::Scan(DWORD pid, System::TokenAccessChecker& access)
    {
        System::ProcessInformation info(pid);
        System::ProcessEnvironmentBlock peb(info);

        ScanImage(access, info);
        ScanCurrentDirectory(access, peb);
        ScanEnvironmentPaths(access, peb);
        ScanModules(access, info);
    }

    void ProcessScanEngine::ScanImage(System::TokenAccessChecker& access, System::ProcessInformation& info)
    {
        try
        {
            std::wstring imageDir;
            info.GetImageDirectory(imageDir);

            if (IsDirWritable(imageDir, access))
            {
                NotifyWritableDirectory(DetectionDirType::Executable, imageDir);
                return;
            }

            std::wstring imageFile;
            info.GetImagePath(imageFile);

            if (IsFileWritable(imageFile, access))
            {
                NotifyWritableFile(DetectionFileType::Executable, imageFile);
                return;
            }
        }
        catch (...)
        {
        }
    }

    void ProcessScanEngine::ScanCurrentDirectory(System::TokenAccessChecker& access, System::ProcessEnvironmentBlock& peb)
    {
        try
        {
            std::wstring currentDirPath;
            peb.GetCurrentDir(currentDirPath);

            if (IsDirWritable(currentDirPath, access))
            {
                NotifyWritableDirectory(DetectionDirType::Current, currentDirPath);
                return;
            }
        }
        catch (...)
        {
        }
    }

    void ProcessScanEngine::ScanEnvironmentPaths(System::TokenAccessChecker& access, System::ProcessEnvironmentBlock& peb)
    {
        std::wstring pathSet;
        auto env = peb.GetProcessEnvironment();

        if (!env->GetValue(L"Path", pathSet) && !env->GetValue(L"PATH", pathSet) && !env->GetValue(L"path", pathSet))
            throw Utils::Exception(L"Can't obtain 'Path' environment variable");

        Utils::SeparatedStrings paths(pathSet, L';');

        for (auto& dir : paths)
        {
            try
            {
                if (IsDirWritable(dir, access))
                    NotifyWritableDirectory(DetectionDirType::Environment, dir);
            }
            catch (...)
            {
            }
        }
    }

    void ProcessScanEngine::ScanModules(System::TokenAccessChecker& access, System::ProcessInformation& info)
    {
        System::ModulesSnapshot snapshot(info.GetProcess()->GetProcessID());
        HMODULE module;

        while (snapshot.GetNextModule(module))
        {
            std::wstring modulePath, moduleDir;
            info.GetModulePath(module, modulePath);

            System::FileUtils::ExtractFileDirectory(modulePath, moduleDir);

            if (IsDirWritable(moduleDir, access))
            {
                NotifyWritableDirectory(DetectionDirType::LoadedModule, moduleDir);
                continue;
            }

            if (IsFileWritable(modulePath, access))
            {
                NotifyWritableFile(DetectionFileType::LoadedModule, modulePath);
                continue;
            }
        }
    }

    bool ProcessScanEngine::IsFileWritable(std::wstring path, System::TokenAccessChecker& access)
    {
        System::File file(path.c_str());
        System::SecurityDescriptor descriptor(file);
        return access.IsFileObjectAccessible(descriptor, FILE_WRITE_DATA);
    }

    bool ProcessScanEngine::IsDirWritable(std::wstring path, System::TokenAccessChecker& access)
    {
        System::Directory directory(path.c_str());
        System::SecurityDescriptor descriptor(directory);
        return access.IsFileObjectAccessible(descriptor, FILE_ADD_FILE);
    }

    const wchar_t* ProcessScanEngine::ConvertDirDetectionToString(DetectionDirType detection)
    {
        switch (detection)
        {
        case DetectionDirType::Executable:
            return L"Executable directory";
        case DetectionDirType::Current:
            return L"Current directory";
        case DetectionDirType::Users:
            return L"Users directory";
        case DetectionDirType::Environment:
            return L"Environment directory";
        case DetectionDirType::LoadedModule:
            return L"Module directory";
        default:
            break;
        }
        return L"Unknown";
    }

    const wchar_t* ProcessScanEngine::ConvertFileDetectionToString(DetectionFileType detection)
    {
        switch (detection)
        {
        case DetectionFileType::Executable:
            return L"Executable file";
        case DetectionFileType::LoadedModule:
            return L"Loaded module";
        default:
            break;
        }
        return L"Unknown";
    }
}
