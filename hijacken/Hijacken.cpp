#include "Utils.h"
#include "Commands.h"
#include <stdio.h>
#include <fcntl.h>
#include <io.h>
#include <iostream>

namespace
{
    void SwitchConsoleToUTF16Mode()
    {
        _setmode(_fileno(stdout), _O_U16TEXT);
        _setmode(_fileno(stderr), _O_U16TEXT);
    }

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

        if (command == L"/scan")
        {
            if (!args.GetNext(sub))
                throw Utils::Explanation(L"Error, /scan argument isn't presented");

            if (sub == L"file")
                ptr = Commands::CommandPtr(new Commands::ScanFile());
            else if (sub == L"directory")
                ptr = Commands::CommandPtr(new Commands::ScanDirectory());
            else if (sub == L"process")
                ptr = Commands::CommandPtr(new Commands::ScanProcess());
            else if (sub == L"processes")
                ptr = Commands::CommandPtr(new Commands::ScanProcesses());
            else if (sub == L"autorun")
                ptr = Commands::CommandPtr(new Commands::ScanAutorun());
            else if (sub == L"task")
                ptr = Commands::CommandPtr(new Commands::ScanTask());
            else if (sub == L"tasks")
                ptr = Commands::CommandPtr(new Commands::ScanTasks());
            else if (sub == L"service")
                ptr = Commands::CommandPtr(new Commands::ScanService());
            else if (sub == L"services")
                ptr = Commands::CommandPtr(new Commands::ScanServices());
            else if (sub == L"system")
                ptr = Commands::CommandPtr(new Commands::ScanSystem());
            else
                throw Utils::Explanation(L"Error, invalid /scan argument");
        }
        else if (command == L"/makedll")
        {
            ptr = Commands::CommandPtr(new Commands::MakeDll());
        }
        else
        {
            throw Utils::Explanation(L"Error, invalid command. Please use 'hijacken /?'");
        }

        return ptr;
    }
}

int wmain(int argc, wchar_t* argv[])
{
    SwitchConsoleToUTF16Mode();

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
