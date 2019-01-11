#include "Utils.h"
#include "Commands.h"
#include <stdio.h>
#include <fcntl.h>
#include <io.h>
#include <iostream>

namespace
{

    bool PrintUsageIfNeeded(Utils::Arguments& args)
    {
        std::wstring command;

        if (!args.Probe(command))
            return false;

        if (command != L"/help" && command != L"/?")
            return false;

        return true;
    }

    Commands::CommandPtr ChooseCommand(Utils::Arguments& args)
    {
        std::wstring command, sub;
        Commands::CommandPtr ptr;

        if (!args.GetNext(command))
            throw Utils::Explanation(L"Error, invalid usage. Please use 'hijacken /?'");

        if (command == L"/scansys")
            ptr = Commands::CommandPtr(new Commands::ScanSystem());
        else if (command == L"/scanfile")
            ptr = Commands::CommandPtr(new Commands::ScanFile());
        else if (command == L"/makedll")
            ptr = Commands::CommandPtr(new Commands::MakeDll());
        else
            throw Utils::Explanation(L"Error, invalid command. Please use 'hijacken /?'");

        return ptr;
    }
};

int wmain(int argc, wchar_t* argv[])
{
    _setmode(_fileno(stdout), _O_U16TEXT);

    try
    {
        Utils::Arguments arguments(argc, argv);
		
        if (!arguments.GetAmount())
            throw Utils::Explanation(L"Welcome to Hijacken. Please use 'hijacken /?' to get a usage information");

        if (PrintUsageIfNeeded(arguments))
            return 0;

        auto command = ChooseCommand(arguments);
        command->LoadArgs(arguments);
        command->Perform();
    }
    catch (Utils::Explanation& exception)
    {
        std::wcerr << exception.GetMessage() << std::endl;
        return exception.GetCode();
    }
    catch (Utils::Exception& exception)
    {
        std::wcerr << L"Unhandled exception, program has been terminated" << std::endl;
        std::wcerr << L" reason: " << exception.GetMessage() << std::endl;
        return exception.GetCode();
    }
    catch (std::exception& exception)
    {
        std::wcerr << L"Unhandled STD exception, program has been terminated" << std::endl;
        std::wcerr << L" reason: " << exception.what() << std::endl;
        return Utils::NoExceptionCode;
    }

    return 0;
}
