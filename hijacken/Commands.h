#pragma once

#include "Utils.h"

namespace Commands
{
    // =================

    class ICommand
    {
    public:
        virtual ~ICommand() {};
        
        virtual void LoadArgs(Utils::Arguments& args) = 0;
        virtual void Perform() = 0;
    };

    typedef std::shared_ptr<ICommand> CommandPtr;

    // =================

    class ScanSystem : public ICommand
    {
    private:

    public:
        ScanSystem();
        virtual ~ScanSystem();

        virtual void LoadArgs(Utils::Arguments& args);
        virtual void Perform();
    };

    // =================

    class ScanFile : public ICommand
    {
    private:

    public:
        ScanFile();
        virtual ~ScanFile();

        virtual void LoadArgs(Utils::Arguments& args);
        virtual void Perform();
    };

    // =================

    class MakeDll : public ICommand
    {
    private:

    public:
        MakeDll();
        virtual ~MakeDll();

        virtual void LoadArgs(Utils::Arguments& args);
        virtual void Perform();
    };
};
