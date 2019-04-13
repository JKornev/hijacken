#pragma once

#include "System.h"
#include <vector>
#include <string>

namespace PEParser
{
// =================
    
    typedef public std::vector<std::string> ImportTable;

// =================

    enum class Bitness
    {
        Arch32,
        Arch64
    };

    class Image
    {
    protected:

        struct SectionRegion
        {
            DWORD rawOffset;
            DWORD rawSize;
            DWORD virtualOffset;
            DWORD virtualSize;
        };

        System::ImageMapping&      _mapping;
        std::vector<SectionRegion> _sections;

        void* GetAddressByRVA(DWORD rva);
        std::string LoadStringByRVA(DWORD rva);

    public:
        Image(System::ImageMapping& mapping);
        virtual ~Image();

        virtual ImportTable LoadImportTable() = 0;
    };

    typedef std::shared_ptr<Image> ImagePtr;

// =================

    class ImageFactory
    {
    private:
        static Bitness GetImageBitness(System::ImageMapping& mapping);

    public:
        ImagePtr GetImage(System::ImageMapping& mapping);
    };

// =================

    template<typename T>
    class ImageImpl : public Image
    {
    private:
        Bitness _bitness;
        T* _header;

    public:
        ImageImpl(System::ImageMapping& mapping);
        virtual ~ImageImpl();

        ImportTable LoadImportTable() override;
    };

}
