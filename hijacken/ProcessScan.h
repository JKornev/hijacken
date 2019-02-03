#pragma once

#include "System.h"

namespace Engine
{
    class ProcessScanEngine
    {
    public:

        enum class DetectionDirType
        {
            Executable,
            Current,
            Users,
            Environment,
            LoadedModule
        };

        enum class DetectionFileType
        {
            Executable,
            LoadedModule
        };

        ProcessScanEngine();

        void Scan(DWORD pid, System::TokenAccessChecker& access);

        virtual void NotifyWritableDirectory(DetectionDirType detection, std::wstring& dirPath) = 0;
        virtual void NotifyWritableFile(DetectionFileType detection, std::wstring& filePath) = 0;

    private:

        void ScanImage(System::TokenAccessChecker& access, System::ProcessInformation& info);
        void ScanCurrentDirectory(System::TokenAccessChecker& access, System::ProcessEnvironmentBlock& peb);
        void ScanEnvironmentPaths(System::TokenAccessChecker& access, System::ProcessEnvironmentBlock& peb);
        void ScanModules(System::TokenAccessChecker& access, System::ProcessInformation& info);

        bool IsFileWritable(std::wstring path, System::TokenAccessChecker& access);
        bool IsDirWritable(std::wstring path, System::TokenAccessChecker& access);
    };
};