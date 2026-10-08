#pragma once

#include <string>

namespace utilities
{
    std::string convert_wide_to_utf8( const std::wstring& wide_str );
    std::wstring convert_utf8_to_wide( const std::string& utf8_str );
}