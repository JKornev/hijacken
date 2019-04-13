#pragma once

#include "System.h"
#include <vector>
#include <set>

namespace Engine
{
    // =================

    class ImageDirectory
    {
    public:

        enum class Type
        {
            Image,
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
        
        ImageDirectory FindDllDirectory(std::wstring& dllname, bool checkAccess);

    private:

        bool CheckDirectoryForDll(std::wstring& dllname, ImageDirectory& dir, bool checkAccess);
        bool DirContainsDll(std::wstring& dllname, ImageDirectory& dir);
        
    };

    // =================

    class KnownDll
    {

    };

    class KnownDlls
    {
    private:
        //std::map<std::wstring, DllSet> _known;

    public:
        KnownDlls();

        bool Contain(std::wstring& dllName);
    };

    // =================

    class DllCache
    {
    private:
        std::set<std::wstring> _dlls;
    public:
        bool InsertOnlyNew(std::wstring& dllName);
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

        ImageScanEngine();

        void SetOptionUnwindImport(bool enable);
        void SetOptionUnwindDelayLoadImport(bool enable);
        void SetOptionAccessibleOnly(bool enable);

        void Scan(std::wstring& imagePath, System::TokenAccessChecker& access);

    private:

        void ScanModule(std::wstring& dllName, ImageScanOrder& order, DllCache& scannedDlls);

        void ScanImports(std::wstring& dllPath, ImageScanOrder& order, DllCache& scannedDlls);

    protected:

        virtual void NotifyLoadImageOrder(LoadImageOrder& dir);
        virtual void NotifyVulnerableDll(ImageDirectory& dir, std::wstring dll);

    };
};
