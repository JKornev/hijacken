#include "ImageScan.h"
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

    ImageDirectory::ImageDirectory(Type type, const std::wstring& imageDir, const System::TokenAccessChecker& access) :
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

    LoadImageOrder::LoadImageOrder(const std::wstring& imageDir, const std::wstring& currentDir, const System::EnvironmentVariables& envVars, const System::TokenAccessChecker& access) :
        _wow64mode(false)
    {
        auto supportWow64 = (System::SystemInformation::GetSystemBitness() == System::Bitness::Arch64);
        bool safeSearch = IsSafeSearchEnabled();

        auto putDirectory = [&](ImageDirectory::Type type, const std::wstring& dir)
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

    const ImageDirectories& LoadImageOrder::GetOrder() const
    {
        if (_wow64mode)
            return _orderWow64;

        return _order;
    }

    const ImageDirectory& LoadImageOrder::GetBaseDir() const
    {
        for (const auto& dir : _order)
            if (dir.GetType() == ImageDirectory::Type::Base)
                return dir;

        throw Utils::Exception(L"Base dir hasn't been found");
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

    void LoadImageOrder::LoadEnvironmentVariables(const System::EnvironmentVariables& envVars, bool wow64mode, const System::TokenAccessChecker& access)
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

    ImageScanOrder::ImageScanOrder(const std::wstring& imageDir, const std::wstring& currentDir, const System::EnvironmentVariables& envVars, const System::TokenAccessChecker& access) :
        LoadImageOrder(imageDir, currentDir, envVars, access)
    {
    }

    ImageDirectory ImageScanOrder::FindDllDirectory(const std::wstring& dllname) const
    {
        auto dirs = LoadImageOrder::GetOrder();

        for (auto& dir : dirs)
        if (DirContainsDll(dllname, dir))
            return dir;

        return ImageDirectory();
    }

    bool ImageScanOrder::DirContainsDll(const std::wstring& dllname, ImageDirectory& dir) const
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

    void ActivationContextStack::Push(System::ActivationContext& context)
    {
        _stack.emplace_back(context);
    }

    void ActivationContextStack::Pop()
    {
        _stack.pop_back();
    }

    bool ActivationContextStack::IsLibrarySxS(const std::wstring& dllName, std::wstring& sxsDir)
    {
        if (!_stack.size())
            return IsLibrarySxSInDefaultActx(dllName, sxsDir);

        const auto& assemblies = *_stack.rbegin();
        for (const auto& assembly : assemblies)
            for (const auto& library : assembly.GetFiles())
                if (dllName == library)
                {
                    sxsDir = assembly.GetID();
                    return true;
                }

        return IsLibrarySxSInDefaultActx(dllName, sxsDir);
    }

    bool ActivationContextStack::IsLibrarySxSInDefaultActx(const std::wstring& dllName, std::wstring& sxsDir)
    {
        try
        {
            //TODO: 
            //  Unfortunately results are not valid if a scanned DLL has different architecture to hijacken
            //  because it's not possible to get a Default System Activateion Context for different architecture

            auto dll = System::ActivationContextUtils::LookupSxSDirUsingDefaultSystemActivationContext(dllName);

            if (dll.empty())
                return false;

            std::wstring assemblyDir;
            System::FileUtils::ExtractFileDirectory(dll, assemblyDir);
            std::transform(assemblyDir.begin(), assemblyDir.end(), assemblyDir.begin(), ::tolower);

            auto winsxs = System::SystemInformation::GetWindowsDir();
            winsxs += L"\\winsxs";
            std::transform(winsxs.begin(), winsxs.end(), winsxs.begin(), ::tolower);

            if (assemblyDir.find(winsxs) != 0)
                return false;

            System::FileUtils::ExtractFileName(assemblyDir, sxsDir);
        }
        catch (...)
        {
            return false;
        }

        return true;
    }

    // =================

    LoadManifestAndPush::LoadManifestAndPush(System::ImageMapping& module, const  std::wstring& imageDir, ActivationContextStack& stack)
    {
        std::wstring tempName;

        try
        {
            auto manifest = ReadManifestFromResources(module);
            manifest = NormalizeManifest(manifest);
            tempName = SafeManifestToTempFile(manifest);
            System::ActivationContext context(
                tempName.c_str(), 
                imageDir.c_str()
            );
            stack.Push(context);
        }
        catch (Utils::Exception& e)
        {
            //std::wcerr << L"eee " << std::endl;//TODO:
        }

        if (!tempName.empty())
        {
            System::File deleter(tempName.c_str(), DELETE, 0);
            deleter.SetDeleteOnClose();
        }
    }

    std::vector<char> LoadManifestAndPush::ReadManifestFromResources(System::ImageMapping& module)
    {
        PEParser::ImageFactory factory;
        auto image = factory.GetImage(module);
        auto resources = image->LoadResources();
        return PEParser::ResourceUtils::LoadFirstResource(resources, module, PEParser::ResourceEntry(24));
    }

    std::vector<char> LoadManifestAndPush::NormalizeManifest(const std::vector<char>& manifest)
    {
        //TODO: manifest.xml normalization
        return manifest;
    }

    std::wstring LoadManifestAndPush::SafeManifestToTempFile(const std::vector<char>& manifest)
    {
        std::wstring name;
        auto temp = System::FileUtils::CreateTempFile(name, FILE_WRITE_ACCESS, FILE_SHARE_READ);
        temp.Write(const_cast<char*>(&manifest[0]), manifest.size());
        return name;
    }

    // =================

    ImageScanContext::ImageScanContext(const std::wstring& imagePath, const System::TokenAccessChecker& access) :
        _imagePath(imagePath),
        _accessChecker(access)
    {
        System::FileUtils::NormalizePath(_imagePath);
        System::FileUtils::ExtractFileDirectory(_imagePath, _imageDir);
        System::FileUtils::ExtractFileName(_imagePath, _imageFile);

        _image.reset(new System::ImageMapping(_imagePath.c_str()));
        PEParser::ImageFactory factory;
        _parser = factory.GetImage(*_image);
        _bitness = _parser->GetBitness();
    }

    System::ImageMapping ImageScanContext::GetAppImage() const
    {
        return *_image;
    }

    const PEParser::ImagePtr ImageScanContext::GetAppParser() const
    {
        return _parser;
    }

    const std::wstring& ImageScanContext::GetAppPath() const
    {
        return _imagePath;
    }

    const std::wstring& ImageScanContext::GetAppDirectory() const
    {
        return _imageDir;
    }

    const std::wstring& ImageScanContext::GetAppFileName() const
    {
        return _imageFile;
    }

    System::Bitness ImageScanContext::GetAppBitness() const
    {
        return _bitness;
    }

    DllCache& ImageScanContext::GetDllsCache()
    {
        return _scannedDlls;
    }

    const System::TokenAccessChecker& ImageScanContext::GetAccessChecker() const
    {
        return _accessChecker;
    }

    ActivationContextStack& ImageScanContext::GetActivationContextStack()
    {
        return _actxStack;
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
        ImageScanContext context(imagePath, access);

        bool wow64mode = false;
        if (System::SystemInformation::GetSystemBitness() == System::Bitness::Arch64 && context.GetAppBitness() == System::Bitness::Arch32)
            wow64mode = true;

        //TODO: don't need to calculate order each time scan started,
        //      in other way we can calculate it on constructor and
        //      change an image dir or current dir before we start a
        //      scan.
        ImageScanOrder order(context.GetAppDirectory(), context.GetAppDirectory(), envVars, context.GetAccessChecker());
        order.SetWow64Mode(wow64mode);
        NotifyLoadImageOrder(order);

        //TODO: do we really need to open mapping again? context already did it
        System::ImageMapping mapping(context.GetAppPath().c_str());
        LoadManifestAndPush appManifest(mapping, context.GetAppDirectory(), context.GetActivationContextStack());

        ScanImports(context.GetAppImage(), context, order);
    }

    void ImageScanEngine::ScanModule(ImageScanContext& context, std::wstring& dllName, ImageScanOrder& order)
    {
        try
        {
            auto actxStack   = context.GetActivationContextStack();
            auto scannedDlls = context.GetDllsCache();
            auto access      = context.GetAccessChecker();
            auto bitness     = context.GetAppBitness();

            std::transform(dllName.begin(), dllName.end(), dllName.begin(), towlower);

            std::wstring sxsDir;
            if (actxStack.IsLibrarySxS(dllName, sxsDir))
            {
                // When we process a SxS DLL we should care that it can have a one short DLL name but multiple paths.
                // For instance:
                //     C:\Windows\winsxs\x86_microsoft.windows.common-controls_6595b64144ccf1df_5.82.7601.18837_none_ec86b8d6858ec0bc\comctl32.dll
                //     C:\Windows\winsxs\x86_microsoft.windows.common-controls_6595b64144ccf1df_6.0.7601.24460_none_2b1e532a457961ba\comctl32.dll
                // Therefore we put to the dll cache a dll name with SxS directory, for examples above it would be:
                //     x86_microsoft.windows.common-controls_6595b64144ccf1df_5.82.7601.18837_none_ec86b8d6858ec0bc\comctl32.dll
                //     x86_microsoft.windows.common-controls_6595b64144ccf1df_6.0.7601.24460_none_2b1e532a457961ba\comctl32.dll
                
                std::wstring cached = sxsDir;
                cached += L"\\";
                cached += dllName;

                if (!scannedDlls.InsertOnlyNew(cached))
                    return;

                //TODO: known DLLs have a priority over SxS?

                PerformSxSModuleAction(context, dllName, sxsDir, order);
            }
            else
            {
                if (!scannedDlls.InsertOnlyNew(dllName))
                    return;

                if (_knownDlls.Contain(dllName, bitness))
                    return;

                auto dir = order.FindDllDirectory(dllName);

                if (dir.GetType() == ImageDirectory::Type::Unknown)
                    PerformNotExistingModuleAction(context, dllName, dir, order);
                else
                    PerformExistingModuleAction(context, dllName, dir, order);
            }
        }
        catch (Utils::Exception& e)
        {
            std::wcout << L"Skipped: Exception while processing the dll '" << dllName << L"'" << std::endl;
        }
    }

    void ImageScanEngine::ScanImports(System::ImageMapping& module, ImageScanContext& context, ImageScanOrder& order)
    {
        PEParser::ImageFactory factory;
        auto image = factory.GetImage(module);
        ScanImports(image, context, order);
    }

    void ImageScanEngine::ScanImports(const PEParser::ImagePtr& image, ImageScanContext& context, ImageScanOrder& order)
    {
        if (image->GetBitness() != context.GetAppBitness())
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

            ScanModule(context, std::wstring(import.begin(), import.end()), order);
        }
    }

    void ImageScanEngine::PerformExistingModuleAction(ImageScanContext& context, std::wstring& dllName, ImageDirectory& dir, ImageScanOrder& order)
    {
        auto dllPath = System::FileUtils::BuildPath(dir.GetPath(), dllName);

        auto vulnerableDirs = CollectVulnerableDirs(dir, order);

        bool writtable = false;
        if (_checkAccessible && IsFileWritable(dllPath, context.GetAccessChecker()))
            writtable = true;

        if (dir.GetType() != ImageDirectory::Type::Base && !vulnerableDirs.empty())
            NotifyVulnerableDll(dir, dllName, writtable, vulnerableDirs);
        else if (dir.GetType() == ImageDirectory::Type::Base && writtable)
            NotifyVulnerableDll(dir, dllName, true, vulnerableDirs);

        if (_unwindImports)
        {
            System::ImageMapping mapping(dllPath.c_str());
            LoadManifestAndPush dllManifest(mapping, dir.GetPath(), context.GetActivationContextStack());
            ScanImports(mapping, context, order);
        }
    }

    void ImageScanEngine::PerformNotExistingModuleAction(ImageScanContext& context, std::wstring& dllName, ImageDirectory& dir, ImageScanOrder& order)
    {
        auto vulnerableDirs = CollectVulnerableDirs(dir, order);
        NotifyVulnerableDll(dir, dllName, false, vulnerableDirs);
    }

    void ImageScanEngine::PerformSxSModuleAction(ImageScanContext& context, std::wstring& dllName, std::wstring& sxsDir, ImageScanOrder& order)
    {
        // Initial Plan:
        //   0. Push SxS 
        //   1. Get base dir
        //   2. Check is it possible to create App.exe.Local or it already existing and writable
        //   3. If detected notify SxS callback
        //   4. Unwind if it's enabled

        std::vector<const ImageDirectory*> vulnerableDirs;
        auto base = order.GetBaseDir();

        auto sxsLocal = base.GetPath();
        sxsLocal += L"\\";
        sxsLocal += context.GetAppFileName();
        sxsLocal += L".Local\\";
        sxsLocal += sxsDir;

        ImageDirectory sxsLocalDir(ImageDirectory::Type::SxS, sxsLocal, context.GetAccessChecker());

        if (_checkAccessible)
        {
            // 1. Can create Local dir
            // 2. Can overwrite local file
            auto baseDir = base.GetPath();
            auto dllPath = System::FileUtils::BuildPath(sxsLocal, dllName);
            if (System::FileUtils::PathExists(dllPath) && IsFileWritable(dllPath, context.GetAccessChecker()))
                NotifyVulnerableSxSDll(sxsLocalDir, dllName, true);
            else if (System::FileUtils::PathExists(baseDir) && IsDirectoryWritable(baseDir, context.GetAccessChecker()))
                NotifyVulnerableSxSDll(sxsLocalDir, dllName, false);
        }

        auto sxsGlobal = System::SystemInformation::GetWindowsDir();
        sxsGlobal += L"\\WinSxS\\";
        sxsGlobal += sxsDir;

        ImageDirectory sxsGlobalDir(ImageDirectory::Type::SxS, sxsGlobal, context.GetAccessChecker());
        auto sxsPath = System::FileUtils::BuildPath(sxsGlobal, dllName);

        if (_checkAccessible)
        {
            // 3. Can overwrite public file
            if (IsFileWritable(sxsPath, context.GetAccessChecker()))
                NotifyVulnerableSxSDll(sxsGlobalDir, dllName, true);
        }

        if (_unwindImports)
        {
            System::ImageMapping mapping(sxsPath.c_str());
            LoadManifestAndPush dllManifest(mapping, sxsGlobalDir.GetPath(), context.GetActivationContextStack());
            ScanImports(mapping, context, order);
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

    void ImageScanEngine::NotifyVulnerableSxSDll(ImageDirectory& dir, std::wstring& dll, bool writtable)
    {
        // Stub, does nothing here
    }

    bool ImageScanEngine::IsFileWritable(const std::wstring& path, const System::TokenAccessChecker& access)
    {
        System::File file(path.c_str());
        System::SecurityDescriptor descriptor(file);
        return access.IsFileObjectAccessible(descriptor, FILE_WRITE_DATA);
    }

    bool ImageScanEngine::IsDirectoryWritable(const std::wstring& path, const System::TokenAccessChecker& access)
    {
        System::Directory dir(path.c_str());
        System::SecurityDescriptor descriptor(dir);
        return access.IsFileObjectAccessible(descriptor, FILE_ADD_SUBDIRECTORY);
    }
};
