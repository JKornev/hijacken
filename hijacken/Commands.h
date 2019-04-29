#pragma once

#include "Utils.h"
#include "System.h"
#include "ProcessScan.h"
#include "ImageScan.h"
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
        System::IntegrityLevel _tokenIntegrityLevel;

    protected:
        ImpersonationOptions();

        void LoadArgs(Utils::Arguments& args);
        System::ImpersonateTokenPtr CraftToken();
        
        static void PrintTokenInformation(System::ImpersonateTokenPtr& token);
        static const wchar_t* ConvertIntegrityLevelToString(System::IntegrityLevel level);

    private:
        void ChangeIntegrity(System::ImpersonateTokenPtr& token, System::IntegrityLevel level);
        static System::IntegrityLevel ConvertStrToIntegrityLevel(std::wstring& level);
    };

// =================

    class SystemOptions
    {
    private:
        bool _scanElevated;

    protected:
        SystemOptions();

        void LoadArgs(Utils::Arguments& args);
        bool ShouldScanProcess(System::ImpersonateTokenPtr& token, DWORD targetProcessId);
    };

// =================

    class ScanFile : 
        public ICommand,
        protected ImpersonationOptions,
        protected Engine::ImageScanEngine
    {
    private:
        bool _unwindImports;
        bool _scanDelayLoad;
        bool _checkAccess;

        bool _firstFound;

        std::wstring _filePath;

        void ScanImage(std::string path);

    public:
        ScanFile();
        virtual ~ScanFile() {}

        void LoadArgs(Utils::Arguments& args) override;
        void Perform() override;

    protected:
        void NotifyLoadImageOrder(Engine::LoadImageOrder& dirs) override;
        void NotifyVulnerableDll(Engine::ImageDirectory& dir, std::wstring& dll, bool writtable) override;

    public:
        static const wchar_t* ConvertImageDirTypeToString(Engine::ImageDirectory::Type type);
    };

// =================

    class ScanDirectory : 
        public ICommand,
        protected SystemOptions
    {
    private:

    public:
        ScanDirectory();
        virtual ~ScanDirectory() {}

        void LoadArgs(Utils::Arguments& args) override;
        void Perform() override;
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

        void LoadArgs(Utils::Arguments& args) override;
        void Perform() override;

    protected:
        void NotifyWritableDirectory(DetectionDirType detection, std::wstring& dirPath) override;
        void NotifyWritableFile(DetectionFileType detection, std::wstring& filePath) override;
    };

// =================

    class ScanProcesses : 
        public ICommand, 
        protected SystemOptions,
        protected ImpersonationOptions, 
        protected Engine::ProcessScanEngine
    {
    private:

        std::map<DetectionDirType,  std::set<std::wstring>> _detectedDirs;
        std::map<DetectionFileType, std::set<std::wstring>> _detectedFiles;

    public:
        ScanProcesses();
        virtual ~ScanProcesses() {}

        void LoadArgs(Utils::Arguments& args) override;
        void Perform() override;

    protected:
        void NotifyWritableDirectory(DetectionDirType detection, std::wstring& dirPath) override;
        void NotifyWritableFile(DetectionFileType detection, std::wstring& filePath) override;
    };

// =================

    class ScanAutorun : 
        public ICommand,
        protected SystemOptions
    {
    private:

    public:
        ScanAutorun();
        virtual ~ScanAutorun() {}

        void LoadArgs(Utils::Arguments& args) override;
        void Perform() override;
    };

// =================

    class ScanTask : public ICommand
    {
    private:

    public:
        ScanTask();
        virtual ~ScanTask() {}

        void LoadArgs(Utils::Arguments& args) override;
        void Perform() override;
    };

// =================

    class ScanTasks : 
        public ICommand,
        protected SystemOptions
    {
    private:

    public:
        ScanTasks();
        virtual ~ScanTasks() {}

        void LoadArgs(Utils::Arguments& args) override;
        void Perform() override;
    };

// =================

    class ScanService : public ICommand
    {
    private:

    public:
        ScanService();
        virtual ~ScanService() {}

        void LoadArgs(Utils::Arguments& args) override;
        void Perform() override;
    };

// =================

    class ScanServices : 
        public ICommand,
        protected SystemOptions
    {
    private:

    public:
        ScanServices();
        virtual ~ScanServices() {}

        void LoadArgs(Utils::Arguments& args) override;
        void Perform() override;
    };

// =================

    class ScanSystem : public ICommand
    {
    private:

    public:
        ScanSystem();
        virtual ~ScanSystem() {}

        void LoadArgs(Utils::Arguments& args) override;
        void Perform() override;
    };

// =================

    class MakeDll : public ICommand
    {
    private:

    public:
        MakeDll();
        virtual ~MakeDll() {}

        void LoadArgs(Utils::Arguments& args) override;
        void Perform() override;
    };
};
