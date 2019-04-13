#include "ImageScan.h"
#include "PEParser.h"
#include <iostream>

namespace Engine
{
    // =================

    ImageDirectory::ImageDirectory() :
        _type(ImageDirectory::Type::Unknown),
        _accessible(false)
    {
    }

    ImageDirectory::ImageDirectory(Type type, std::wstring& imageDir, System::TokenAccessChecker& access) :
        _directory(imageDir),
        _accessible(false),
        _type(type)
    {
        if (!System::Directory::IsDirectory(_directory.c_str()))
            throw Utils::Exception(L"Isn't directory '%s'", _directory.c_str());

        System::Directory directory(_directory.c_str());
        System::SecurityDescriptor descriptor(directory);
        _accessible = access.IsFileObjectAccessible(descriptor, FILE_ADD_FILE);
    }

    const std::wstring& ImageDirectory::GetPath()  const
    {
        return _directory;
    }

    ImageDirectory::Type ImageDirectory::GetType() const
    {
        return _type;
    }

    bool ImageDirectory::IsAccessible() const
    {
        return _accessible;
    }

    // =================

    LoadImageOrder::LoadImageOrder(std::wstring& imageDir, std::wstring& currentDir, System::TokenAccessChecker& access)
    {
        _dirs.push_back(
            ImageDirectory(
                ImageDirectory::Type::Image,
                imageDir, 
                access
            )
        );

        //TODO: SafeDllSerachMode???

        _dirs.push_back(
            ImageDirectory(
                ImageDirectory::Type::System32, 
                System::SystemInformation::GetSystem32Dir(),
                access
            )
        );

        _dirs.push_back(
            ImageDirectory(
                ImageDirectory::Type::System, 
                System::SystemInformation::GetSystemDir(),
                access
            )
        );

        _dirs.push_back(
            ImageDirectory(
                ImageDirectory::Type::Windows, 
                System::SystemInformation::GetWindowsDir(),
                access
            )
        );

        _dirs.push_back(
            ImageDirectory(
                ImageDirectory::Type::Current, 
                currentDir,
                access
            )
        );

        //TODO: %PATH%
    }

    const std::vector<ImageDirectory> LoadImageOrder::GetOrder()
    {
        return _dirs;
    }

    // =================

    ImageScanOrder::ImageScanOrder(std::wstring& imageDir, std::wstring& currentDir, System::TokenAccessChecker& access) :
        LoadImageOrder(imageDir, currentDir, access)
    {
    }

    ImageDirectory ImageScanOrder::FindDllDirectory(std::wstring& dllname, bool checkAccess)
    {
        auto dirs = LoadImageOrder::GetOrder();

        for (auto& dir : dirs)
            if (CheckDirectoryForDll(dllname, dir, checkAccess))
                return dir;

        return ImageDirectory();
    }

    bool ImageScanOrder::CheckDirectoryForDll(std::wstring& dllname, ImageDirectory& dir, bool checkAccess)
    {
        if (checkAccess && !dir.IsAccessible())
            return false;

        if (!DirContainsDll(dllname, dir))
            return false;
        
        return true;
    }

    bool ImageScanOrder::DirContainsDll(std::wstring& dllname, ImageDirectory& dir)
    {
        std::wstring path = dir.GetPath();
        path += L"\\";
        path += dllname;

        auto attribs = ::GetFileAttributesW(path.c_str());
        if (attribs == INVALID_FILE_ATTRIBUTES)
            return false;

        if (attribs & FILE_ATTRIBUTE_DIRECTORY)
            return false;

        return true;
    }

    // =================

    KnownDlls::KnownDlls()
    {
    }

    bool KnownDlls::Contain(std::wstring& dllName)
    {
        //TODO:
        return false;
    }

    // =================

    bool DllCache::InsertOnlyNew(std::wstring& dllName)
    {
        return _dlls.insert(dllName).second;
    }

    // =================

    ImageScanEngine::ImageScanEngine()
    {
    }

    void ImageScanEngine::SetOptionUnwindImport(bool enable)
    {
        _unwindImports = enable;
    }

    void ImageScanEngine::SetOptionUnwindDelayLoadImport(bool enable)
    {
        _scanDelayLoad = enable;
    }

    void ImageScanEngine::SetOptionAccessibleOnly(bool enable)
    {
        _checkAccessible = enable;
    }

    void ImageScanEngine::Scan(std::wstring& imagePath, System::TokenAccessChecker& access)
    {
        std::wstring imageDir;
        //TODO: normalyze imagePath???
        Utils::ExtractFileDirectory(imagePath, imageDir);

        ImageScanOrder order(imageDir, imageDir, access);
        DllCache scannedDlls;

        NotifyLoadImageOrder(order);

        // Scan initial import table
        ScanImports(imagePath, order, scannedDlls);
    }

    void ImageScanEngine::ScanModule(std::wstring& dllName, ImageScanOrder& order, DllCache& scannedDlls)
    {
        try
        {
            if (!scannedDlls.InsertOnlyNew(dllName))
                return;

            if (_knownDlls.Contain(dllName))
                return;

            auto dir = order.FindDllDirectory(dllName, _checkAccessible);

            if (dir.GetType() == ImageDirectory::Type::Unknown)
                return;
            
            if (dir.GetType() == ImageDirectory::Type::Image)
                return;

            std::wcout << L"Found: " << dllName.c_str() << L" " << (int)dir.GetType() << std::endl;
            if (_unwindImports)
            {
                std::wstring path = dir.GetPath();
                path += L"\\";
                path += dllName;

                ScanImports(path, order, scannedDlls);
            }
        }
        catch (Utils::Exception& e)
        {
            //TODO:
        }
    }

    void ImageScanEngine::ScanImports(std::wstring& dllPath, ImageScanOrder& order, DllCache& scannedDlls)
    {
        System::ImageMapping mapping(dllPath.c_str());
        PEParser::ImageFactory factory;
        auto image = factory.GetImage(mapping);
        auto imports = image->LoadImportTable();
        for (auto& import : imports)
            ScanModule(std::wstring(import.begin(), import.end()), order, scannedDlls);
    }

    void ImageScanEngine::NotifyLoadImageOrder(LoadImageOrder& dir)
    {
    }

    void ImageScanEngine::NotifyVulnerableDll(ImageDirectory& dir, std::wstring dll)
    {
    }
};
