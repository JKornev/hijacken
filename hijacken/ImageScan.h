#pragma once

#include "System.h"
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
            Unknown
        };

    private:

        std::wstring _directory;
        Type         _type;
        bool         _accessible;

    public:

        ImageDirectory();
        ImageDirectory(Type type, std::wstring& imageDir, System::TokenAccessChecker& access);

        bool operator==(const ImageDirectory& compared) const;

        const std::wstring& GetPath() const;
        Type GetType() const;
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
        LoadImageOrder(std::wstring& imageDir, std::wstring& currentDir, System::TokenAccessChecker& access);

        void SetWow64Mode(bool value);

        const ImageDirectories& GetOrder();
        static bool IsSafeSearchEnabled();

    private:
        bool LoadEnvironmentVariables(System::BaseKeys sourceBase, const wchar_t* sourceKey, bool wow64mode, System::TokenAccessChecker& access);
    };

    // =================

    class ImageScanOrder : public LoadImageOrder
    {
    public:
        ImageScanOrder(std::wstring& imageDir, std::wstring& currentDir, System::TokenAccessChecker& access);
        
        ImageDirectory FindDllDirectory(std::wstring& dllname);

    private:
        bool DirContainsDll(std::wstring& dllname, ImageDirectory& dir);
        
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

        void Scan(std::wstring& imagePath, System::TokenAccessChecker& access);

    private:

        void ScanModule(std::wstring& dllName, System::Bitness bitness, ImageScanOrder& order, DllCache& scannedDlls, System::TokenAccessChecker& access);
        void ScanImports(std::wstring& dllPath, System::Bitness bitness, ImageScanOrder& order, DllCache& scannedDlls, System::TokenAccessChecker& access);

        std::vector<const ImageDirectory*> CollectVulnerableDirs(const ImageDirectory& last, ImageScanOrder& order);

        static bool IsFileWritable(std::wstring& path, System::TokenAccessChecker& access);

    protected:

        virtual void NotifyLoadImageOrder(LoadImageOrder& dir);
        virtual void NotifyVulnerableDll(ImageDirectory& dir, std::wstring& dll, bool writtable, std::vector<const ImageDirectory*>& vulnDirs);

    };
};
