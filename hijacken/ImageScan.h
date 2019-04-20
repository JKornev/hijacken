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

        const std::wstring& GetPath() const;
        Type GetType() const;
        bool IsAccessible() const;

    };

    // =================

    class LoadImageOrder
    {
    private:
        std::vector<ImageDirectory> _dirs;

    public:
        LoadImageOrder(std::wstring& imageDir, std::wstring& currentDir, System::TokenAccessChecker& access);

        const std::vector<ImageDirectory> GetOrder();
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

        std::unordered_set<std::wstring>& GetContainer();
    };

    // =================

    /*class KnownDll
    {
    public:
        KnownDll(std::wstring& dllName);
    };*/

    class KnownDlls
    {
    private:
        std::map<std::wstring, DllCache> _known;
        DllCache _active;

    public:
        KnownDlls();

        bool Contain(std::wstring& dllName, DllCache& loadedDlls);

        void ActivateKnownDependencyIfKnown(std::wstring& dllName);

    private:

        //TODO;
        void UnwindImports(const std::wstring& dllName, const DllCache& cache);
    };

    // =================

    class ImageScanEngine
    {
    private:

        bool _unwindImports;
        bool _scanDelayLoad;
        bool _checkAccessible;

        DllCache  _scannedDlls;
        KnownDlls _knownDlls;

    public:

        void SetOptionUnwindImport(bool enable);
        void SetOptionUnwindDelayLoadImport(bool enable);
        void SetOptionAccessibleOnly(bool enable);

        void Scan(std::wstring& imagePath, System::TokenAccessChecker& access);

    private:

        void ScanModule(std::wstring& dllName, ImageScanOrder& order, DllCache& scannedDlls, System::TokenAccessChecker& access);

        void ScanImports(std::wstring& dllPath, ImageScanOrder& order, DllCache& scannedDlls, System::TokenAccessChecker& access);

        static bool IsFileWritable(std::wstring path, System::TokenAccessChecker& access);

    protected:

        virtual void NotifyLoadImageOrder(LoadImageOrder& dir);
        virtual void NotifyVulnerableDll(ImageDirectory& dir, std::wstring& dll, bool writtable);

    };
};
