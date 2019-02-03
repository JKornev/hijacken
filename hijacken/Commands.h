#pragma once

#include "Utils.h"
#include "System.h"
#include "ProcessScan.h"
#include <set>

namespace Commands
{
// =================

    class ICommand
    {
    public:
        virtual ~ICommand() {}
        
        virtual void LoadArgs(Utils::Arguments& args) = 0;
        virtual void Perform() = 0;
    };

    typedef std::shared_ptr<ICommand> CommandPtr;

// =================

    class ImpersonationOptions
    {
    private:
        DWORD _tokenSourceProcessId;
        bool  _changeIntegrityLevel;
        System::TokenIntegrityLvl _tokenIntegrityLevel;

        void ChangeIntegrity(System::ImpersonateTokenPtr& token, System::TokenIntegrityLvl);
        static System::TokenIntegrityLvl ConvertStrToIntegrityLevel(std::wstring& level);

    protected:
        ImpersonationOptions();

        void LoadArgs(Utils::Arguments& args);
        System::ImpersonateTokenPtr CraftToken();
    };

// =================

    class ScanFile : public ICommand
    {
    private:

    public:
        ScanFile();
        virtual ~ScanFile() {}

        virtual void LoadArgs(Utils::Arguments& args);
        virtual void Perform();
    };

// =================

    class ScanDirectory : public ICommand
    {
    private:

    public:
        ScanDirectory();
        virtual ~ScanDirectory() {}

        virtual void LoadArgs(Utils::Arguments& args);
        virtual void Perform();
    };

// =================

    class ScanProcess : 
        public ICommand, 
        protected ImpersonationOptions, 
        protected Engine::ProcessScanEngine
    {
    private:
        DWORD _targetProcessId;

        std::map<DetectionDirType,  std::set<std::wstring>> _detectedDirs;
        std::map<DetectionFileType, std::set<std::wstring>> _detectedFiles;

    public:
        ScanProcess();
        virtual ~ScanProcess() {}

        virtual void LoadArgs(Utils::Arguments& args);
        virtual void Perform();

    protected:
        virtual void NotifyWritableDirectory(DetectionDirType detection, std::wstring& dirPath);
        virtual void NotifyWritableFile(DetectionFileType detection, std::wstring& filePath);
    };

// =================

    class ScanProcesses : 
        public ICommand, 
        protected ImpersonationOptions, 
        protected Engine::ProcessScanEngine
    {
    private:

    public:
        ScanProcesses();
        virtual ~ScanProcesses() {}

        virtual void LoadArgs(Utils::Arguments& args);
        virtual void Perform();

    protected:
        virtual void NotifyWritableDirectory(DetectionDirType detection, std::wstring& dirPath);
        virtual void NotifyWritableFile(DetectionFileType detection, std::wstring& filePath);
    };

// =================

    class ScanAutorun : public ICommand
    {
    private:

    public:
        ScanAutorun();
        virtual ~ScanAutorun() {}

        virtual void LoadArgs(Utils::Arguments& args);
        virtual void Perform();
    };

// =================

    class ScanTask : public ICommand
    {
    private:

    public:
        ScanTask();
        virtual ~ScanTask() {}

        virtual void LoadArgs(Utils::Arguments& args);
        virtual void Perform();
    };

// =================

    class ScanTasks : public ICommand
    {
    private:

    public:
        ScanTasks();
        virtual ~ScanTasks() {}

        virtual void LoadArgs(Utils::Arguments& args);
        virtual void Perform();
    };

// =================

    class ScanService : public ICommand
    {
    private:

    public:
        ScanService();
        virtual ~ScanService() {}

        virtual void LoadArgs(Utils::Arguments& args);
        virtual void Perform();
    };

// =================

    class ScanServices : public ICommand
    {
    private:

    public:
        ScanServices();
        virtual ~ScanServices() {}

        virtual void LoadArgs(Utils::Arguments& args);
        virtual void Perform();
    };

// =================

    class ScanSystem : public ICommand
    {
    private:
        DWORD _tokenSourceId;

        void ScanImage(System::TokenAccessChecker& access, System::ProcessInformation& info);
        void ScanCurrentDirectory(System::TokenAccessChecker& access, System::ProcessEnvironmentBlock& peb);
        void ScanEnvironmentPaths(System::TokenAccessChecker& access, System::ProcessEnvironmentBlock& peb);
        void ScanModules(System::TokenAccessChecker& access, System::ProcessInformation& info);

        bool IsFileWritable(std::wstring path, System::TokenAccessChecker& access);
        bool IsDirWritable(std::wstring path, System::TokenAccessChecker& access);

    public:
        ScanSystem();
        virtual ~ScanSystem() {}

        virtual void LoadArgs(Utils::Arguments& args);
        virtual void Perform();
    };

// =================

    class MakeDll : public ICommand
    {
    private:

    public:
        MakeDll();
        virtual ~MakeDll() {}

        virtual void LoadArgs(Utils::Arguments& args);
        virtual void Perform();
    };
};
