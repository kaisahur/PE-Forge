#include <gfx/overlay/overlay.hpp>
#include <dump/dump.hpp>
#include <console/console.h>

int main( )
{
    console::initialize( );
    console::output( console::OUTPUT_TYPE_INFO, "Welcome to PE Forge!" );
    dump::initialize( );
    overlay::tick( );
    return 0;
}
