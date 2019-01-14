#pragma once

#include <Windows.h>
#include <string>
#include <vector>
#include <memory>

namespace Utils
{
    // =================

    class Exception
    {
    private:
        std::wstring _message;
        unsigned int _code;

    public:
        Exception(unsigned int code, const wchar_t* format, ...);
        Exception(const wchar_t* format, ...);

        std::wstring GetMessage();
        unsigned int GetCode();
    };

    static const unsigned int NoExceptionCode = -1;

    // =================

    class Explanation : public Utils::Exception
    {
    public:
        Explanation(const wchar_t* message) : Utils::Exception(message) {}
    };

    // =================

    class Arguments
    {
    private:
        std::vector<std::wstring> _arguments;
        unsigned int              _index;

    public:

        Arguments(int argc, wchar_t* argv[], int start = 1);

        size_t GetAmount();

        bool Probe(std::wstring& arg);
        bool SwitchToNext();
        bool GetNext(std::wstring& arg);
    };

    // =================

    class SeporatedStrings : public std::vector<std::wstring>
    {
    public:
        SeporatedStrings(std::wstring& str, wchar_t seporator);
    };

};
