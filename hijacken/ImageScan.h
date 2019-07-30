#pragma once

#include "System.h"
#include "PEParser.h"
#include <vector>
#include <set>
#include <unordered_set>

namespace Engine
{
    // =================

    class ImageDirectory
    {
    public:

        enum class Type
        {
            Base,
            System32,
            System,
            Windows,
            Current,
            Environment,
            FullPath,
            SxS,
            Unknown
        };

        enum class State
        {
            Existing,
            NotExisting,
            Overlapped
        };

    private:

        std::wstring _directory;
        Type         _type;
        bool         _accessible;
        State        _state;

    public:

        ImageDirectory();
        ImageDirectory(Type type, const std::wstring& imageDir, const System::TokenAccessChecker& access);

        bool operator==(const ImageDirectory& compared) const;

        const std::wstring& GetPath() const;
        Type GetType() const;
        State GetState() const;
        bool IsAccessible() const;

    };

    typedef std::vector<ImageDirectory> ImageDirectories;

    // =================

    class LoadImageOrder
    {
    private:
        ImageDirectories _order;
        ImageDirectories _orderWow64;
        bool _wow64mode;

    public:
        LoadImageOrder(const std::wstring& imageDir, const std::wstring& currentDir, const System::EnvironmentVariables& envVars, const System::TokenAccessChecker& access);

        void SetWow64Mode(bool value);

        const ImageDirectories& GetOrder() const;
        const ImageDirectory& GetBaseDir() const;
        static bool IsSafeSearchEnabled();


    private:
        void LoadEnvironmentVariables(const System::EnvironmentVariables& envVars, bool wow64mode, const System::TokenAccessChecker& access);
    };

    // =================

    class ImageScanOrder : public LoadImageOrder
    {
    public:
        ImageScanOrder(const std::wstring& imageDir, const std::wstring& currentDir, const System::EnvironmentVariables& envVars, const System::TokenAccessChecker& access);
        
        ImageDirectory FindDllDirectory(const std::wstring& dllname) const;

    private:
        bool DirContainsDll(const std::wstring& dllname, ImageDirectory& dir) const;
        
    };

    // =================

    class DllCache
    {
    private:
        std::unordered_set<std::wstring> _dlls;
    public:
        bool InsertOnlyNew(const std::wstring& dllName);
        bool Contain(const std::wstring& dllName);
    };

    // =================

    class KnownDlls
    {
    private:
        DllCache _known;
        DllCache _knownWow64;
        DllCache _excluded;

        bool _supportWow64;

    public:
        KnownDlls();

        bool Contain(std::wstring& dllName, System::Bitness bitness);

    private:

        void LoadExcludedDlls();
        void UnwindImports(const std::wstring& dllName, bool wow64mode);
    };

    // =================

    class ActivationContextStack
    {
    private:
        std::vector<System::ActivationContextAssemblies> _stack;

    public:
        void Push(System::ActivationContext& context);
        void Pop();

        bool IsLibrarySxS(const std::wstring& dllName, std::wstring& sxsDir);

    private:

        bool IsLibrarySxSInDefaultActx(const std::wstring& dllName, std::wstring& sxsDir);
    };

    class LoadManifestAndPush
    {
    public:
        LoadManifestAndPush(System::ImageMapping& module, const std::wstring& imageDir, ActivationContextStack& stack);

    private:
        std::vector<char> ReadManifestFromResources(System::ImageMapping& module);
        std::vector<char> NormalizeManifest(const std::vector<char>& manifest);
        std::wstring SafeManifestToTempFile(const std::vector<char>& manifest);
    };

    // =================

    class ImageScanContext
    {
    private:

        std::shared_ptr<System::ImageMapping> _image;
        PEParser::ImagePtr          _parser;

        std::wstring                _imagePath;
        std::wstring                _imageDir;
        std::wstring                _imageFile;
        System::Bitness             _bitness;

        DllCache                    _scannedDlls;

        const System::TokenAccessChecker& _accessChecker;
        
        ActivationContextStack      _actxStack;

    public:
        ImageScanContext(const std::wstring& imagePath, const System::TokenAccessChecker& access);

        System::ImageMapping GetAppImage() const;
        const PEParser::ImagePtr GetAppParser() const;

        const std::wstring& GetAppPath() const;
        const std::wstring& GetAppDirectory() const;
        const std::wstring& GetAppFileName() const;
        System::Bitness GetAppBitness() const;

        DllCache& GetDllsCache();

        const System::TokenAccessChecker& GetAccessChecker() const;

        ActivationContextStack& GetActivationContextStack();
    };

    // =================

    class ImageScanEngine : public System::Wow64NoFsRedirection
    {
    private:

        bool _unwindImports;
        bool _scanDelayLoad;
        bool _checkAccessible;

        KnownDlls _knownDlls;

    public:

        void SetOptionUnwindImport(bool enable);
        void SetOptionUnwindDelayLoadImport(bool enable);
        void SetOptionAccessibleOnly(bool enable);

        void Scan(std::wstring& imagePath, System::EnvironmentVariables& envVars, System::TokenAccessChecker& access);

    private:

        void ScanModule(ImageScanContext& context, std::wstring& dllName, ImageScanOrder& order);
        void ScanImports(System::ImageMapping& module, ImageScanContext& context, ImageScanOrder& order);
        void ScanImports(const PEParser::ImagePtr& image, ImageScanContext& context, ImageScanOrder& order);
        void PerformExistingModuleAction(ImageScanContext& context, std::wstring& dllName, ImageDirectory& dir, ImageScanOrder& order);
        void PerformNotExistingModuleAction(ImageScanContext& context, std::wstring& dllName, ImageDirectory& dir, ImageScanOrder& order);
        void PerformSxSModuleAction(ImageScanContext& context, std::wstring& dllName, std::wstring& sxsDir, ImageScanOrder& order);

        std::vector<const ImageDirectory*> CollectVulnerableDirs(const ImageDirectory& last, ImageScanOrder& order);

        static bool IsFileWritable(const std::wstring& path, const System::TokenAccessChecker& access);
        static bool IsDirectoryWritable(const std::wstring& path, const System::TokenAccessChecker& access);

    protected:

        virtual void NotifyLoadImageOrder(LoadImageOrder& dir);
        virtual void NotifyVulnerableDll(ImageDirectory& dir, std::wstring& dll, bool writtable, std::vector<const ImageDirectory*>& vulnDirs);
        virtual void NotifyVulnerableSxSDll(ImageDirectory& dir, std::wstring& dll, bool writtable);
    };
};
