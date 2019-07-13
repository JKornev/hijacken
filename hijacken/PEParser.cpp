#include "PEParser.h"
#include <iostream>

namespace PEParser
{
    // =================

    ResourceEntry::ResourceEntry() : 
        _type(NamedResourceType::Unnamed),
        _id(0)
    {
    }

    ResourceEntry::ResourceEntry(std::wstring& name) :
        _type(NamedResourceType::HasName),
        _name(name), 
        _id(0)
    {
    }

    ResourceEntry::ResourceEntry(unsigned short id) :
        _type(NamedResourceType::HasId),
        _id(id)
    {
    }

    bool ResourceEntry::operator==(const ResourceEntry& other) const
    {
        if (_type != other.GetType())
            return false;

        if (_type == NamedResourceType::HasName)
            return (_name == other.GetName());
        
        if (_type == NamedResourceType::HasId)
            return (_id == other.GetID());
        
        return true;
    }

    ResourceEntry::NamedResourceType ResourceEntry::GetType() const
    {
        return _type;
    }

    std::wstring ResourceEntry::GetName() const
    {
        return _name;
    }

    unsigned short ResourceEntry::GetID() const
    {
        return _id;
    }

    // =================

    ResourceDirectory::ResourceDirectory()
    {
    }

    ResourceDirectory::ResourceDirectory(std::wstring& name) : 
        ResourceEntry(name)
    {
    }

    ResourceDirectory::ResourceDirectory(unsigned short id) :
        ResourceEntry(id)
    {
    }

    void ResourceDirectory::Push(ResourceDirectory& dir)
    {
        _dirs.push_back(dir);
    }

    void ResourceDirectory::Push(ResourceData& data)
    {
        _data.push_back(data);
    }
    
    const ResourceDirectorySet& ResourceDirectory::GetDirs() const
    {
        return _dirs;
    }

    const ResourceDataSet& ResourceDirectory::GetData() const
    {
        return _data;
    }

    // =================

    ResourceData::ResourceData()
    {
    }

    ResourceData::ResourceData(std::wstring& name, unsigned long offset, System::ImageMapping& image) :
        ResourceEntry(name)
    {
        LoadDataEntry(offset, image);
    }

    ResourceData::ResourceData(unsigned short id, unsigned long offset, System::ImageMapping& image) :
        ResourceEntry(id)
    {
        LoadDataEntry(offset, image);
    }

    std::vector<char> ResourceData::ReadData(System::ImageMapping& image)
    {
        //TODO: it's incorrect to parse a data without section info, rewrite it
        std::vector<char> buffer;
        if (_offset + _size > image.GetSize())
            throw Utils::Exception(L"Resource data out of range");

        auto ptr = reinterpret_cast<char*>(image.GetAddress()) + _offset;
        return std::vector<char>(ptr, ptr + _size);
    }

    void ResourceData::LoadDataEntry(unsigned long offset, System::ImageMapping& image)
    {
        auto imagePtr = reinterpret_cast<uintptr_t>(image.GetAddress());
        auto imageSize = image.GetSize();

        if (offset > imageSize)
            throw Utils::Exception(L"Resource data entry out of range");

        auto entry = reinterpret_cast<PIMAGE_RESOURCE_DATA_ENTRY>(imagePtr + offset);
        _offset   = entry->OffsetToData;
        _size     = entry->Size;
        _codepage = entry->CodePage;
    }

    // =================

    Resources::Resources()
    {
    }

    Resources::Resources(ResourceDirectory& root) : 
        _root(root)
    {
    }

    const ResourceDirectory& Resources::GetRoot() const
    {
        return _root;
    }

    // =================

    const ResourceDirectory& ResourceUtils::FindDirectory(const ResourceDirectory& dir, const ResourceEntry& id)
    {
        for (auto& entry : dir.GetDirs())
            if (entry == id)
                return entry;
        
        throw Utils::Exception(L"Can't find a specific resource directory");
    }

    const ResourceData& ResourceUtils::FindData(const ResourceDirectory& dir, const ResourceEntry& id)
    {
        for (auto& entry : dir.GetData())
            if (entry == id)
                return entry;
        
        throw Utils::Exception(L"Can't find a specific resource data");
    }

    const std::vector<char> ResourceUtils::LoadFirstResource(const Resources& resources, System::ImageMapping& image, const ResourceEntry& id)
    {
        std::vector<char> buffer;

        const auto& root = resources.GetRoot();
        auto getFirstDir = [](const ResourceDirectory& dir)
        {
            auto dirs = dir.GetDirs();
            if (!dirs.size())
                throw Utils::Exception(L"A resource directory is empty");

            return *dirs.begin();
        };
        auto getFirstData = [](const ResourceDirectory& dir)
        {
            auto data = dir.GetData();
            if (!data.size())
                throw Utils::Exception(L"A resource directory is empty");

            return *data.begin();
        };

        auto second = getFirstDir(FindDirectory(root, id));
        auto third = getFirstData(second);
        
        return third.ReadData(image);
    }

    // =================

    ImagePtr ImageFactory::GetImage(System::ImageMapping& mapping)
    {
        auto bitness = GetImageBitness(mapping);
        if (bitness == System::Bitness::Arch32)
            return ImagePtr(new ImageImpl<IMAGE_NT_HEADERS32>(mapping));
        else if (bitness == System::Bitness::Arch64)
            return ImagePtr(new ImageImpl<IMAGE_NT_HEADERS64>(mapping));

        throw Utils::Exception(L"Unknown image bitness");
    }

    System::Bitness ImageFactory::GetImageBitness(System::ImageMapping& mapping)
    {
        auto imageSize = mapping.GetSize();

        if (imageSize < 0x1000)
            throw Utils::Exception(L"Invalid image size, can't be less 0x1000");

        auto dos = reinterpret_cast<PIMAGE_DOS_HEADER>(mapping.GetAddress());
        if (dos->e_magic != IMAGE_DOS_SIGNATURE)
            throw Utils::Exception(L"Invalid DOS signature");

        if (sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) + dos->e_lfanew > 0x1000)
            throw Utils::Exception(L"Invalid NT headers size, can't be bigger than 0x1000");

        auto signature = *reinterpret_cast<PDWORD>(reinterpret_cast<uintptr_t>(dos) + dos->e_lfanew);
        if (signature != IMAGE_NT_SIGNATURE)
            throw Utils::Exception(L"Invalid NT signature");

        auto header = reinterpret_cast<PIMAGE_FILE_HEADER>(
            reinterpret_cast<uintptr_t>(dos) + dos->e_lfanew + sizeof(DWORD)
        );
        if (header->Machine == IMAGE_FILE_MACHINE_I386)
            return System::Bitness::Arch32;
        else if (header->Machine == IMAGE_FILE_MACHINE_AMD64)
            return System::Bitness::Arch64;

        throw Utils::Exception(L"Unknown PE architecture");
    }

    // =================

    Image::Image(System::ImageMapping& mapping) :
        _mapping(mapping)
    {
    }

    void* Image::GetAddressByRVA(DWORD rva)
    {
        if (rva > _mapping.GetSize())
            throw Utils::Exception(L"RVA offset %x overflows the mapping", rva);

        return reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(_mapping.GetAddress()) + rva);
    }

    std::string Image::LoadStringByRVA(DWORD rva)
    {
        char* str = reinterpret_cast<char*>(GetAddressByRVA(rva));

        size_t i;
        for (i = 0; str[i] != '\0'; i++)
            if (i > _mapping.GetSize())
                throw Utils::Exception(L"String RVA %x overflows the mapping", rva);

        return std::string(str, str + i);
    }

    std::wstring Image::LoadWStringByRVA(DWORD rva)
    {
        wchar_t* str = reinterpret_cast<wchar_t*>(GetAddressByRVA(rva));

        size_t i;
        for (i = 0; str[i] != '\0'; i++)
            if (i * sizeof(wchar_t) > _mapping.GetSize())
                throw Utils::Exception(L"String RVA %x overflows the mapping", rva);

        return std::wstring(str, str + i);
    }

    System::Bitness Image::GetBitness()
    {
        return _bitness;
    }

    // =================

    template<typename T>
    ImageImpl<T>::ImageImpl(System::ImageMapping& mapping) :
        Image(mapping),
        _header(nullptr)
    {
        if (sizeof(T) == sizeof(IMAGE_NT_HEADERS32))
            _bitness = System::Bitness::Arch32;
        else if (sizeof(T) == sizeof(IMAGE_NT_HEADERS64))
            _bitness = System::Bitness::Arch64;
        else
            throw Utils::Exception(L"Invalid architecture");

        if (mapping.GetSize() < 0x1000)
            throw Utils::Exception(L"Invalid image size, can't be less 0x1000");

        auto dos = reinterpret_cast<PIMAGE_DOS_HEADER>(mapping.GetAddress());
        if (dos->e_magic != IMAGE_DOS_SIGNATURE)
            throw Utils::Exception(L"Invalid DOS signature");

        if (sizeof(T) + dos->e_lfanew > 0x1000)
            throw Utils::Exception(L"Invalid NT headers size, can't be bigger than 0x1000");

        _header = reinterpret_cast<T*>(reinterpret_cast<uintptr_t>(dos) + dos->e_lfanew);
        if (_header->Signature != IMAGE_NT_SIGNATURE)
            throw Utils::Exception(L"Invalid NT signature");

        if (_bitness == System::Bitness::Arch32 && _header->FileHeader.Machine != IMAGE_FILE_MACHINE_I386)
            throw Utils::Exception(L"Invalid NT architecture");
        else if (_bitness == System::Bitness::Arch64 && _header->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64)
            throw Utils::Exception(L"Invalid NT architecture");

        if (!_header->FileHeader.NumberOfSections)
            return;

        auto sectionOffset = dos->e_lfanew + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) + _header->FileHeader.SizeOfOptionalHeader;
        if (sectionOffset + (sizeof(IMAGE_SECTION_HEADER) * _header->FileHeader.NumberOfSections) >= mapping.GetSize())
            throw Utils::Exception(L"Invalid sections offset");

        auto sections = reinterpret_cast<PIMAGE_SECTION_HEADER>(reinterpret_cast<uintptr_t>(mapping.GetAddress()) + sectionOffset);

        for (auto i = 0; i < _header->FileHeader.NumberOfSections; i++)
        {
            //TODO: alignment for offset and size
            SectionRegion region;
            region.rawOffset     = sections[i].PointerToRawData;
            region.rawSize       = sections[i].SizeOfRawData;
            region.virtualOffset = sections[i].VirtualAddress;
            region.virtualSize   = sections[i].Misc.VirtualSize;
            _sections.push_back(region);
        }
    }

    template<typename T>
    ImportTable ImageImpl<T>::LoadImportTable()
    {
        ImportTable table;
        auto imageSize = _mapping.GetSize();
        auto importDirOffset = _header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
        if (!importDirOffset)
            return table;

        auto imports = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(Image::GetAddressByRVA(importDirOffset));
        DWORD importPeakOffset = sizeof(IMAGE_IMPORT_DESCRIPTOR);
        for (int i = 0; true; i++, importPeakOffset += sizeof(IMAGE_IMPORT_DESCRIPTOR))
        {
            if (importPeakOffset > imageSize)
                throw Utils::Exception(L"Invalid import descriptor table");

            if (!imports[i].Characteristics)
                break;

            std::string dllname = Image::LoadStringByRVA(imports[i].Name);
            table.push_back(dllname);
        }

        return table;
    }

    template<typename T>
    Resources ImageImpl<T>::LoadResources()
    { 
        Resources resources;
        auto resourceDirOffset = _header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress;
        if (!resourceDirOffset)
            return resources;

        ResourceDirectory directory;
        LoadResourceDirectory(resourceDirOffset, resourceDirOffset, directory);
        return Resources(directory);
    }

    template<typename T>
    void ImageImpl<T>::LoadResourceDirectory(DWORD baseOffset, DWORD dirOffset, ResourceDirectory& parent)
    {
        //TODO: - add protection against a resource recursion
        //      - simplify this routine
        auto imageSize = _mapping.GetSize();

        auto peakOffset = dirOffset + sizeof(IMAGE_RESOURCE_DIRECTORY);
        if (peakOffset > imageSize)
            throw Utils::Exception(L"Resource table out of range");

        auto dir = reinterpret_cast<PIMAGE_RESOURCE_DIRECTORY>(Image::GetAddressByRVA(dirOffset));

        auto loadEntries = [&](size_t count)
        {
            auto entries = reinterpret_cast<PIMAGE_RESOURCE_DIRECTORY_ENTRY>(Image::GetAddressByRVA(peakOffset));
            peakOffset += count * sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY);
            if (peakOffset > imageSize)
                throw Utils::Exception(L"Resource entries table out of range");

            return entries;
        };

        auto names = loadEntries(dir->NumberOfNamedEntries);
        auto ids   = loadEntries(dir->NumberOfIdEntries);

        for (int i = 0; i < dir->NumberOfNamedEntries; i++)
        {
            if (!names[i].NameIsString)
                continue;

            auto loadName = [&](DWORD offset)
            {
                auto str = reinterpret_cast<PIMAGE_RESOURCE_DIR_STRING_U>(Image::GetAddressByRVA(baseOffset + offset));

                offset += baseOffset + sizeof(WORD);
                if (offset > imageSize)
                    throw Utils::Exception(L"Resource entries table out of range");

                if (offset + (str->Length * sizeof(wchar_t)) > imageSize)
                    throw Utils::Exception(L"Resource entries table out of range");

                return std::wstring(str->NameString, str->NameString + str->Length);
            };

            auto name = loadName(names[i].NameOffset);

            if (names[i].DataIsDirectory)
            {
                ResourceDirectory child(name);
                LoadResourceDirectory(baseOffset, baseOffset + names[i].OffsetToDirectory, child);
                parent.Push(child);
            }
            else
            {
                ResourceData data(name, baseOffset + names[i].OffsetToData, _mapping);
                parent.Push(data);
            }
        }

        for (int i = 0; i < dir->NumberOfIdEntries; i++)
        {
            if (ids[i].NameIsString)
                continue;

            if (ids[i].DataIsDirectory)
            {
                ResourceDirectory child(ids[i].Id);
                LoadResourceDirectory(baseOffset, baseOffset + ids[i].OffsetToDirectory, child);
                parent.Push(child);
            }
            else
            {
                ResourceData data(ids[i].Id, baseOffset + ids[i].OffsetToData, _mapping);
                parent.Push(data);
            }
        }
    }

}
