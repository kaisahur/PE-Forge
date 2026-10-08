#include "utilities.h"

std::string utilities::convert_wide_to_utf8( const std::wstring& wide_str )
{
    return std::string( wide_str.begin( ), wide_str.end( ) );
}

std::wstring utilities::convert_utf8_to_wide( const std::string& utf8_str )
{
    return std::wstring( utf8_str.begin( ), utf8_str.end( ) );
}
