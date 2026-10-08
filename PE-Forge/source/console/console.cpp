#include "console.h"
#include <Windows.h>

void console::initialize( )
{
    set_title( "PE-Forge" );
    set_size( 300, 400 );
    set_font( L"Courier New", 14 );
}

void console::set_title( std::string_view title )
{
    SetConsoleTitleA( title.data( ) );
}

void console::set_font( std::wstring font_name, short font_size )
{
    HANDLE handle = GetStdHandle( STD_OUTPUT_HANDLE );
    CONSOLE_FONT_INFOEX cfi{};
    cfi.cbSize = sizeof( CONSOLE_FONT_INFOEX );
    GetCurrentConsoleFontEx( handle, FALSE, &cfi );
    cfi.dwFontSize.Y = font_size;
    wcscpy_s( cfi.FaceName, font_name.c_str( ) );
    SetCurrentConsoleFontEx( handle, FALSE, &cfi );
}

void console::set_size( short width, short height )
{
    HANDLE handle = GetStdHandle( STD_OUTPUT_HANDLE );
    SMALL_RECT rect{};
    rect.Left = 0;
    rect.Top = 0;
    rect.Right = width - 1;
    rect.Bottom = height - 1;
    SetConsoleWindowInfo( handle, TRUE, &rect );
    COORD buffer_size{};
    buffer_size.X = width;
    buffer_size.Y = height;
    SetConsoleScreenBufferSize( handle, buffer_size );
}

void console::clear( )
{
    system( "cls" );
}

void console::output( output_type_t type, const char* message, ... )
{
    printf( "[" );

    if ( type == OUTPUT_TYPE_INFO )
    {
        SetConsoleTextAttribute( GetStdHandle( STD_OUTPUT_HANDLE ), FOREGROUND_GREEN );
        printf( "info" );
    }
    else if ( type == OUTPUT_TYPE_WARNING )
    {
        SetConsoleTextAttribute( GetStdHandle( STD_OUTPUT_HANDLE ), FOREGROUND_RED | FOREGROUND_GREEN );
        printf( "warning" );
    }
    else if ( type == OUTPUT_TYPE_ERROR )
    {
        SetConsoleTextAttribute( GetStdHandle( STD_OUTPUT_HANDLE ), FOREGROUND_RED );
        printf( "error" );
    }

    SetConsoleTextAttribute( GetStdHandle( STD_OUTPUT_HANDLE ), FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE );

    printf( "] " );

    va_list args;
    va_start( args, message );
    vprintf( message, args );
    va_end( args );
}
