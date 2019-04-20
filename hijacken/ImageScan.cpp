#include "ImageScan.h"
#include "PEParser.h"
#include <iostream>
#include <algorithm>

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
                ImageDirectory::Type::Base,
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

    ImageDirectory ImageScanOrder::FindDllDirectory(std::wstring& dllname)
    {
        auto dirs = LoadImageOrder::GetOrder();

        for (auto& dir : dirs)
            if (DirContainsDll(dllname, dir))
                return dir;

        return ImageDirectory();
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
        System::EnumRegistryValues knowndlls(System::BaseKeys::LocalMachine, L"System\\CurrentControlSet\\Control\\Session Manager\\KnownDLLs");
        auto& values = knowndlls.GetValues();

        //TODO: load L"System\\CurrentControlSet\\Control\\Session Manager", L"ExcludeFromKnownDlls" MULTISTR
        //      and check it in the following cycle

        auto loadPredefined = [&](const std::wstring dll)
        {
            _known.emplace(dll, DllCache());
            UnwindImports(dll, _known[dll]);
        };

        loadPredefined(L"ntdll.dll");
        loadPredefined(L"kernel32.dll");
        loadPredefined(L"kernelbase.dll");

        for (auto& value : values)
        {
            if (value.first == L"DllDirectory" || value.first == L"DllDirectory32")
                continue;

            if (value.second.GetType() != REG_SZ)
                continue;

            DllCache cache;
            auto dllName = std::wstring(value.second.GetValue().c_str());
            std::transform(dllName.begin(), dllName.end(), dllName.begin(), towlower);
            if (_known.find(dllName) == _known.end())
            {
                _known[dllName] = DllCache();
                UnwindImports(dllName, _known[dllName]);
                ActivateKnownDependencyIfKnown(dllName);//TODO: delete me
            }
        }
    }

    bool KnownDlls::Contain(std::wstring& dllName, DllCache& loadedDlls)
    {
        return _active.Contain(dllName);
    }

    void KnownDlls::ActivateKnownDependencyIfKnown(std::wstring& dllName)
    {
        auto known = _known.find(dllName);
        if (known == _known.end())
            return;

        _active.InsertOnlyNew((*known).first);

        for (const auto& dll : (*known).second.GetContainer())
            _active.InsertOnlyNew(dll);
    }

    void KnownDlls::UnwindImports(const std::wstring& dllName, const DllCache& cache)
    {
        //TOTHINK: x64 and x86 binaries can have different known dlls
    }

    // =================

    bool DllCache::InsertOnlyNew(const std::wstring& dllName)
    {
        return _dlls.insert(dllName).second;
    }

    bool DllCache::Contain(const std::wstring& dllName)
    {
        return (_dlls.find(dllName) != _dlls.end());
    }

    std::unordered_set<std::wstring>& DllCache::GetContainer()
    {
        return _dlls;
    }

    // =================

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
        ScanImports(imagePath, order, scannedDlls, access);
    }

    void ImageScanEngine::ScanModule(std::wstring& dllName, ImageScanOrder& order, DllCache& scannedDlls, System::TokenAccessChecker& access)
    {
        try
        {
            std::transform(dllName.begin(), dllName.end(), dllName.begin(), towlower);

            if (!scannedDlls.InsertOnlyNew(dllName))
                return;

            _knownDlls.ActivateKnownDependencyIfKnown(dllName);

            if (_knownDlls.Contain(dllName, _scannedDlls))
                return;

            auto dir = order.FindDllDirectory(dllName);
            auto dllPath = dir.GetPath();
            dllPath += L"\\";
            dllPath += dllName;

            bool writtable = false;
            if (_checkAccessible && IsFileWritable(dllPath, access))
                writtable = true;

            if (dir.GetType() != ImageDirectory::Type::Base)
                NotifyVulnerableDll(dir, dllName, writtable);
            else if (dir.GetType() == ImageDirectory::Type::Base && writtable)
                NotifyVulnerableDll(dir, dllName, true);

            if (_unwindImports && dir.GetType() != ImageDirectory::Type::Unknown)
                ScanImports(dllPath, order, scannedDlls, access);
        }
        catch (Utils::Exception& e)
        {
            //TODO:
        }
    }

    void ImageScanEngine::ScanImports(std::wstring& dllPath, ImageScanOrder& order, DllCache& scannedDlls, System::TokenAccessChecker& access)
    {
        System::ImageMapping mapping(dllPath.c_str());
        PEParser::ImageFactory factory;
        auto image = factory.GetImage(mapping);
        auto imports = image->LoadImportTable();
        for (auto& import : imports)
            ScanModule(std::wstring(import.begin(), import.end()), order, scannedDlls, access);
    }

    void ImageScanEngine::NotifyLoadImageOrder(LoadImageOrder& dir)
    {
        // Stub
    }

    void ImageScanEngine::NotifyVulnerableDll(ImageDirectory& dir, std::wstring& dll, bool writtable)
    {
        // Stub
    }

    bool ImageScanEngine::IsFileWritable(std::wstring path, System::TokenAccessChecker& access)
    {
        System::File file(path.c_str());
        System::SecurityDescriptor descriptor(file);
        return access.IsFileObjectAccessible(descriptor, FILE_WRITE_DATA);
    }

};
