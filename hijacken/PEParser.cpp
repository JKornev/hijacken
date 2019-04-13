#include "PEParser.h"
#include <iostream>

namespace PEParser
{
    // =================

    ImagePtr ImageFactory::GetImage(System::ImageMapping& mapping)
    {
        auto bitness = GetImageBitness(mapping);
        if (bitness == Bitness::Arch32)
            return ImagePtr(new ImageImpl<IMAGE_NT_HEADERS32>(mapping));
        else if (bitness == Bitness::Arch64)
            return ImagePtr(new ImageImpl<IMAGE_NT_HEADERS64>(mapping));

        throw Utils::Exception(L"Unknown image bitness");
    }

    Bitness ImageFactory::GetImageBitness(System::ImageMapping& mapping)
    {
        auto imageSize = mapping.GetSize();

        if (imageSize < 0x1000)
            throw Utils::Exception(L"Invalid image size, can't be less 0x1000");

        auto dos = reinterpret_cast<PIMAGE_DOS_HEADER>(mapping.GetAddress());
        if (dos->e_magic != IMAGE_DOS_SIGNATURE)
            throw Utils::Exception(L"Invalid DOS signature");

        if (sizeof(DWORD)+sizeof(IMAGE_FILE_HEADER)+dos->e_lfanew > 0x1000)
            throw Utils::Exception(L"Invalid NT headers size, can't be bigger than 0x1000");

        auto signature = *reinterpret_cast<PDWORD>(reinterpret_cast<uintptr_t>(dos)+dos->e_lfanew);
        if (signature != IMAGE_NT_SIGNATURE)
            throw Utils::Exception(L"Invalid NT signature");

        auto header = reinterpret_cast<PIMAGE_FILE_HEADER>(
            reinterpret_cast<uintptr_t>(dos)+dos->e_lfanew + sizeof(DWORD)
        );
        if (header->Machine == IMAGE_FILE_MACHINE_I386)
            return Bitness::Arch32;
        else if (header->Machine == IMAGE_FILE_MACHINE_AMD64)
            return Bitness::Arch64;

        throw Utils::Exception(L"Unknown PE architecture");
    }

    // =================

    Image::Image(System::ImageMapping& mapping) :
        _mapping(mapping)
    {
    }

    Image::~Image()
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
        {
            if (i > _mapping.GetSize())
                throw Utils::Exception(L"String RVA %x overflows the mapping", rva);
        }

        return std::string(str, str + i);
    }

    // =================

    template<typename T>
    ImageImpl<T>::ImageImpl(System::ImageMapping& mapping) :
        Image(mapping),
        _header(nullptr)
    {
        if (sizeof(T) == sizeof(IMAGE_NT_HEADERS32))
            _bitness = Bitness::Arch32;
        else if (sizeof(T) == sizeof(IMAGE_NT_HEADERS64))
            _bitness = Bitness::Arch64;
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

        if (_bitness == Bitness::Arch32 && _header->FileHeader.Machine != IMAGE_FILE_MACHINE_I386)
            throw Utils::Exception(L"Invalid NT architecture");
        else if (_bitness == Bitness::Arch64 && _header->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64)
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
            _sections.emplace_back(region);
        }
    }

    template<typename T>
    ImageImpl<T>::~ImageImpl()
    {
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

}
