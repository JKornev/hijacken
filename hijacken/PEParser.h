#pragma once

#include "System.h"
#include <vector>
#include <string>

namespace PEParser
{

    // =================
    
    typedef public std::vector<std::string> ImportTable;

    // =================

    class ResourceData;
    class ResourceDirectory;
    typedef std::vector<ResourceData> ResourceDataSet;
    typedef std::vector<ResourceDirectory> ResourceDirectorySet;

    // =================

    class ResourceEntry
    {
    public:
        
        enum class NamedResourceType {
            HasName,
            HasId,
            Unnamed
        };

        ResourceEntry();
        ResourceEntry(std::wstring& name);
        ResourceEntry(unsigned short id);

        bool operator==(const ResourceEntry& other) const;

        NamedResourceType GetType() const;

        std::wstring GetName() const;
        unsigned short GetID() const;

    private:
        NamedResourceType _type;
        std::wstring      _name;
        unsigned short    _id;
    };

    // =================

    class ResourceData : public ResourceEntry
    {
    private:
        unsigned long _offset;
        unsigned long _size;
        unsigned long _codepage;

    public:
        ResourceData();
        ResourceData(std::wstring& name, unsigned long offset, System::ImageMapping& image);
        ResourceData(unsigned short id, unsigned long offset, System::ImageMapping& image);

        std::vector<char> ReadData(System::ImageMapping& image);

    private:
        void LoadDataEntry(unsigned long offset, System::ImageMapping& image);
    };

    // =================

    class ResourceDirectory : public ResourceEntry
    {
    private:
        ResourceDirectorySet _dirs;
        ResourceDataSet      _data;
         
    public:
        ResourceDirectory();
        ResourceDirectory(std::wstring& name);
        ResourceDirectory(unsigned short id);

        void Push(ResourceDirectory& dir);
        void Push(ResourceData& data);

        const ResourceDirectorySet& GetDirs() const;
        const ResourceDataSet& GetData() const;
    };


    // =================

    class Resources
    {
    private:
        ResourceDirectory _root;

    public:
        Resources();
        Resources(ResourceDirectory& root);

        const ResourceDirectory& GetRoot() const;
    };

    // =================

    class ResourceUtils
    {
    public:
        static const ResourceDirectory& FindDirectory(const ResourceDirectory& dir, const ResourceEntry& id);
        static const ResourceData& FindData(const ResourceDirectory& dir, const ResourceEntry& id);
        static const std::vector<char> LoadFirstResource(const Resources& resources, System::ImageMapping& image, const ResourceEntry& id);
    };

    // =================

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

        System::Bitness _bitness;

        void* GetAddressByRVA(DWORD rva);
        std::string LoadStringByRVA(DWORD rva);
        std::wstring LoadWStringByRVA(DWORD rva);

    public:
        Image(System::ImageMapping& mapping);
        virtual ~Image() = default;

        System::Bitness GetBitness();

        virtual ImportTable LoadImportTable() = 0;
        virtual Resources LoadResources() = 0;
    };

    typedef std::shared_ptr<Image> ImagePtr;

    // =================

    class ImageFactory
    {
    private:
        static System::Bitness GetImageBitness(System::ImageMapping& mapping);

    public:
        ImagePtr GetImage(System::ImageMapping& mapping);
    };

    // =================

    template<typename T>
    class ImageImpl : public Image
    {
    private:
        T* _header;

    public:
        ImageImpl(System::ImageMapping& mapping);
        virtual ~ImageImpl() = default;

        ImportTable LoadImportTable() override;

        Resources LoadResources() override;

    private:
        void LoadResourceDirectory(DWORD resourceBase, DWORD resourceDir, ResourceDirectory& resource);
    };

}
