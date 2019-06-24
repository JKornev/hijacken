#include "ImageScan.h"
#include "PEParser.h"
#include <iostream>
#include <algorithm>

namespace Engine
{
    // =================

    ImageDirectory::ImageDirectory() :
        _type(ImageDirectory::Type::Unknown),
        _accessible(false),
        _state(State::NotExisting)
    {
    }

    ImageDirectory::ImageDirectory(Type type, std::wstring& imageDir, System::TokenAccessChecker& access) :
        _directory(imageDir),
        _accessible(false),
        _type(type),
        _state(State::Existing)
    {
        if (!System::FileUtils::PathExists(_directory.c_str()))
        {
            _state = State::NotExisting;
            return;
        }

        if (!System::Directory::IsDirectory(_directory.c_str()))
            _state = State::Overlapped;

        System::Directory directory(_directory.c_str());
        System::SecurityDescriptor descriptor(directory);
        _accessible = access.IsFileObjectAccessible(descriptor, FILE_ADD_FILE);
    }

    bool ImageDirectory::operator==(const ImageDirectory& compared) const
    {
        if (_type != compared._type)
            return false;

        if (_state != compared._state)
            return false;
        
        if (_accessible != compared._accessible)
            return false;
        
        if (_directory != compared._directory)
            return false;

        return true;
    }

    const std::wstring& ImageDirectory::GetPath()  const
    {
        return _directory;
    }

    ImageDirectory::Type ImageDirectory::GetType() const
    {
        return _type;
    }

    ImageDirectory::State ImageDirectory::GetState() const
    {
        return _state;
    }

    bool ImageDirectory::IsAccessible() const
    {
        return _accessible;
    }

    // =================

    LoadImageOrder::LoadImageOrder(std::wstring& imageDir, std::wstring& currentDir, System::EnvironmentVariables& envVars, System::TokenAccessChecker& access) :
        _wow64mode(false)
    {
        auto supportWow64 = (System::SystemInformation::GetSystemBitness() == System::Bitness::Arch64);
        bool safeSearch = IsSafeSearchEnabled();

        auto putDirectory = [&](ImageDirectory::Type type, std::wstring& dir)
        {
            _order.emplace_back(type, dir, access);
            if (supportWow64)
                _orderWow64.emplace_back(type, dir, access);
        };

        // Base image dir
        putDirectory(ImageDirectory::Type::Base, imageDir);

        // Current dir
        if (!safeSearch)
            putDirectory(ImageDirectory::Type::Current, imageDir);

        // System32 and SysWOW64 dirs
        _order.emplace_back(
            ImageDirectory::Type::System32,
            System::SystemInformation::GetSystem32Dir(),
            access
        );
        if (supportWow64)
            _orderWow64.emplace_back(
                ImageDirectory::Type::System32,
                System::SystemInformation::GetSysWow64Dir(),
                access
            );

        // System dir
        putDirectory(ImageDirectory::Type::System, System::SystemInformation::GetSystemDir());

        // Windows dir
        putDirectory(ImageDirectory::Type::Windows, System::SystemInformation::GetWindowsDir());

        // Current dir
        if (safeSearch)
            putDirectory(ImageDirectory::Type::Current, imageDir);

        // Environment dirs
        LoadEnvironmentVariables(envVars, supportWow64, access);
    }

    void LoadImageOrder::SetWow64Mode(bool value)
    {
        _wow64mode = value;
    }

    const ImageDirectories& LoadImageOrder::GetOrder()
    {
        if (_wow64mode)
            return _orderWow64;

        return _order;
    }

    bool LoadImageOrder::IsSafeSearchEnabled()
    {
        //TODO: seems like when value isn't present than system think that SafeSearch is enabled,
        //      needs to be clarified
        bool enabled = true;

        try
        {
            System::RegistryKey key(
                System::BaseKeys::LocalMachine,
                L"System\\CurrentControlSet\\Control\\Session Manager"
            );
            System::RegistryDwordValue value(key, L"SafeDllSearchMode");
            enabled = (value.GetValue() != 0);
        }
        catch (...)
        {
        }

        return enabled;
    }

    void LoadImageOrder::LoadEnvironmentVariables(System::EnvironmentVariables& envVars, bool wow64mode, System::TokenAccessChecker& access)
    {
        std::wstring rawPaths;

        if (!envVars.GetValue(L"Path", rawPaths) && !envVars.GetValue(L"PATH", rawPaths) && !envVars.GetValue(L"path", rawPaths))
            return;

        Utils::SeparatedStrings paths(rawPaths, L';');

        for (auto& dir : paths)
        {
            //TODO: remove a '\\' symbol in the end
            _order.emplace_back(ImageDirectory::Type::Environment, dir, access);
            if (wow64mode)
                _orderWow64.emplace_back(ImageDirectory::Type::Environment, dir, access);
        }

        return;
    }

    // =================

    ImageScanOrder::ImageScanOrder(std::wstring& imageDir, std::wstring& currentDir, System::EnvironmentVariables& envVars, System::TokenAccessChecker& access) :
        LoadImageOrder(imageDir, currentDir, envVars, access)
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
        auto path = System::FileUtils::BuildPath(
            dir.GetPath(),
            dllname
        );

        return System::FileUtils::PathExists(path.c_str());
    }

    // =================

    KnownDlls::KnownDlls()
    {
        _supportWow64 = (System::SystemInformation::GetSystemBitness() == System::Bitness::Arch64);

        System::EnumRegistryValues knowndlls(
            System::BaseKeys::LocalMachine,
            L"System\\CurrentControlSet\\Control\\Session Manager\\KnownDLLs"
        );
        auto& values = knowndlls.GetValues();

        LoadExcludedDlls();

        auto loadKnownDll = [&](const std::wstring& dll)
        {
            if (_excluded.Contain(dll))
                return;

            if (_known.InsertOnlyNew(dll))
                UnwindImports(dll, false);

            if (_supportWow64 && _knownWow64.InsertOnlyNew(dll))
                UnwindImports(dll, true);
        };

        //TODO: check is it possible to remove following libs from known list
        loadKnownDll(L"ntdll.dll");
        loadKnownDll(L"kernel32.dll");
        loadKnownDll(L"kernelbase.dll");

        for (auto& value : values)
        {
            if (value.first == L"DllDirectory" || value.first == L"DllDirectory32")
                continue;

            if (value.second.GetType() != System::RegistryValueType::String)
                continue;

            auto dllName = std::wstring(value.second.GetValue().c_str());
            std::transform(dllName.begin(), dllName.end(), dllName.begin(), towlower);
            loadKnownDll(dllName);
        }
    }

    bool KnownDlls::Contain(std::wstring& dllName, System::Bitness bitness)
    {
        return _known.Contain(dllName);
    }

    void KnownDlls::LoadExcludedDlls()
    {
        try
        {
            System::RegistryKey key(
                System::BaseKeys::LocalMachine, 
                L"System\\CurrentControlSet\\Control\\Session Manager"
            );
            System::RegistryMultiStringValue excludedList(key, L"ExcludeFromKnownDlls");

            for (auto& dllName : excludedList)
            {
                std::transform(dllName.begin(), dllName.end(), dllName.begin(), towlower);
                _excluded.InsertOnlyNew(dllName);
            }
        }
        catch (...)
        {
        }
    }

    void KnownDlls::UnwindImports(const std::wstring& dllName, bool wow64mode)
    {
        auto dllPath = System::FileUtils::BuildPath(
            wow64mode ? 
                System::SystemInformation::GetSysWow64Dir() 
              : System::SystemInformation::GetSystem32Dir(),
            dllName
        );

        System::ImageMapping mapping(dllPath.c_str());
        PEParser::ImageFactory factory;
        auto image = factory.GetImage(mapping);

        if (wow64mode && image->GetBitness() == System::Bitness::Arch64)
            throw Utils::Exception(L"Invalid knowndll '%s' bitness", dllName.c_str());
        else if (!wow64mode && image->GetBitness() != System::SystemInformation::GetSystemBitness())
            throw Utils::Exception(L"Invalid knowndll '%s' bitness", dllName.c_str());

        auto imports = image->LoadImportTable();
        for (auto& import : imports)
        {
            auto dll = std::wstring(import.begin(), import.end());
            std::transform(dll.begin(), dll.end(), dll.begin(), towlower);
            auto& known = (wow64mode ? _knownWow64 : _known);
            if (known.InsertOnlyNew(dll))
                UnwindImports(dll, wow64mode);
        }
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

    void ImageScanEngine::Scan(std::wstring& imagePath, System::EnvironmentVariables& envVars, System::TokenAccessChecker& access)
    {
        std::wstring normalized(imagePath);
        System::FileUtils::NormalizePath(normalized);

        System::ImageMapping mapping(normalized.c_str());
        PEParser::ImageFactory factory;
        auto image = factory.GetImage(mapping);
        auto bitness = image->GetBitness();

        bool wow64mode = false;
        if (System::SystemInformation::GetSystemBitness() == System::Bitness::Arch64 && bitness == System::Bitness::Arch32)
            wow64mode = true;

        std::wstring imageDir;
        System::FileUtils::ExtractFileDirectory(normalized, imageDir);

        //TODO: don't need to calculate order each time scan started,
        //      in other way we can calculate it on constructor and
        //      change an image dir or current dir before we start a
        //      scan.
        ImageScanOrder order(imageDir, imageDir, envVars, access);
        order.SetWow64Mode(wow64mode);
        NotifyLoadImageOrder(order);

        // Load SxS
        ActivationContextStack actxStack;
        LoadManifestAndPush manifest(mapping, actxStack);

        // Scan initial import table
        DllCache scannedDlls;
        ScanImports(imagePath, bitness, order, scannedDlls, actxStack, access);
    }

    void ImageScanEngine::ScanModule(std::wstring& dllName, System::Bitness bitness, ImageScanOrder& order, DllCache& scannedDlls, ActivationContextStack& actxStack, System::TokenAccessChecker& access)
    {
        try
        {
            std::transform(dllName.begin(), dllName.end(), dllName.begin(), towlower);

            if (!scannedDlls.InsertOnlyNew(dllName))
                return;

            if (_knownDlls.Contain(dllName, bitness))
                return;

            auto dir = order.FindDllDirectory(dllName);
            auto dllPath = System::FileUtils::BuildPath(dir.GetPath(), dllName);
            
            auto vulnerableDirs = CollectVulnerableDirs(dir, order);

            bool writtable = false;
            if (_checkAccessible && dir.GetType() != ImageDirectory::Type::Unknown && IsFileWritable(dllPath, access))
                writtable = true;

            if (dir.GetType() != ImageDirectory::Type::Base)
                NotifyVulnerableDll(dir, dllName, writtable, vulnerableDirs);
            else if (dir.GetType() == ImageDirectory::Type::Base && writtable)
                NotifyVulnerableDll(dir, dllName, true, vulnerableDirs);

            if (_unwindImports && dir.GetType() != ImageDirectory::Type::Unknown)
                ScanImports(dllPath, bitness, order, scannedDlls, actxStack, access);
        }
        catch (Utils::Exception& e)
        {
            std::wcout << L"Skipped: Exception while processing the dll '" << dllName << L"'" << std::endl;
        }
    }

    void ImageScanEngine::ScanImports(std::wstring& dllPath, System::Bitness bitness, ImageScanOrder& order, DllCache& scannedDlls, ActivationContextStack& actxStack, System::TokenAccessChecker& access)
    {
        System::ImageMapping mapping(dllPath.c_str());
        PEParser::ImageFactory factory;
        auto image = factory.GetImage(mapping);

        if (image->GetBitness() != bitness)
            throw Utils::Exception(L"Image bitness mismatched");

        auto imports = image->LoadImportTable();
        for (auto& import : imports)
        {
            std::wstring importDll(import.begin(), import.end());
            if (!System::FileUtils::IsPathRelative(importDll))
            {
                std::wcout << L"Skipped: Non-relative path of dll '" << importDll << L"'" << std::endl;
                continue;
            }

            ScanModule(std::wstring(import.begin(), import.end()), bitness, order, scannedDlls, actxStack, access);
        }
    }

    std::vector<const ImageDirectory*> ImageScanEngine::CollectVulnerableDirs(const ImageDirectory& last, ImageScanOrder& order)
    {
        std::vector<const ImageDirectory*> vulnerableDirs;
        
        for (const auto& dir : order.GetOrder())
        {
            if (dir == last)
                break;

            if (_checkAccessible)
            {
                if (dir.IsAccessible())
                    vulnerableDirs.push_back(&dir);
            }
            else
            {
                vulnerableDirs.push_back(&dir);
            }
        }

        return vulnerableDirs;
    }

    void ImageScanEngine::NotifyLoadImageOrder(LoadImageOrder& dir)
    {
        // Stub, does nothing here
    }

    void ImageScanEngine::NotifyVulnerableDll(ImageDirectory& dir, std::wstring& dll, bool writtable, std::vector<const ImageDirectory*>& vulnDirs)
    {
        // Stub, does nothing here
    }

    bool ImageScanEngine::IsFileWritable(std::wstring& path, System::TokenAccessChecker& access)
    {
        System::File file(path.c_str());
        System::SecurityDescriptor descriptor(file);
        return access.IsFileObjectAccessible(descriptor, FILE_WRITE_DATA);
    }
};
