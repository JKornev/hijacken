#include "Utils.h"
#include <stdarg.h>

namespace Utils
{

// =================

    Exception::Exception(unsigned int code, const wchar_t* format, ...) :
        _code(code)
    {
        wchar_t buffer[256];

        va_list args;
        va_start(args, format);
        _vsnwprintf_s(buffer, _countof(buffer), _TRUNCATE, format, args);
        va_end(args);

        _message = buffer;
    }

    Exception::Exception(const wchar_t* format, ...) :
        _code(NoExceptionCode)
    {
        wchar_t buffer[256];

        va_list args;
        va_start(args, format);
        _vsnwprintf_s(buffer, _countof(buffer), _TRUNCATE, format, args);
        va_end(args);

        _message = buffer;
    }

    std::wstring Exception::GetMessage()
    {
        return _message;
    }

    unsigned int Exception::GetCode()
    {
        return _code;
    }

// =================

    Arguments::Arguments(int argc, wchar_t* argv[], int start) :
        _index(0)
    {
        for (int i = start; i < argc; i++)
            _arguments.push_back(argv[i]);
    }

    size_t Arguments::GetAmount()
    {
        return _arguments.size();
    }

    bool Arguments::Probe(std::wstring& arg)
    {
        if (_index >= _arguments.size())
            return false;

        arg = _arguments[_index];
        return true;
    }

    bool Arguments::SwitchToNext()
    {
        if (_index >= _arguments.size())
            return false;

        _index++;
        return true;
    }

    bool Arguments::GetNext(std::wstring& arg)
    {
        if (_index >= _arguments.size())
            return false;

        arg = _arguments[_index++];
        return true;
    }

    bool Arguments::IsEnded()
    {
        return (_index >= _arguments.size());
    }

// =================

    SeparatedStrings::SeparatedStrings(const std::wstring& str, wchar_t seporator)
    {
        size_t startOffset = 0;
        auto endOffset = str.find(seporator);

        while (endOffset != std::wstring::npos)
        {
            if (startOffset != endOffset)
                push_back(std::wstring(&str[startOffset], &str[endOffset]));
            startOffset = endOffset + 1;
            endOffset = str.find(seporator, startOffset);
        }
    }

};