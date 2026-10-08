#pragma once
#include <string_view>
#include <string>

namespace console
{
    void initialize( );

    void set_title( std::string_view title );
    void set_font( std::wstring font_name, short font_size );
    void set_size( short width, short height );

    enum output_type_t
    {
        OUTPUT_TYPE_INFO,
        OUTPUT_TYPE_WARNING,
        OUTPUT_TYPE_ERROR
    };

    void clear( );
    void output( output_type_t type, const char* message, ... );
}