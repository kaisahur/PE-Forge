#include "memory.h"

#include <algorithm>
#include <cstring>
#include <cwchar>
#include "../console/console.h"

#undef min

bool memory::initialize( )
{
    return syscall_initialize( );
}

HANDLE memory::open_process( DWORD pid, ACCESS_MASK access )
{
    HANDLE handle = nullptr;
    client_id_t cid{};
    object_attributes_t attrs{};

    cid.unique_process = reinterpret_cast< HANDLE >( static_cast< std::uint64_t >( pid ) );
    cid.unique_thread = nullptr;
    attrs.length = sizeof( object_attributes_t );

    const NTSTATUS s = nt_open_process_stub( &handle, access, &attrs, &cid );
    return NT_SUCCESS( s ) ? handle : nullptr;
}

void memory::close_process( HANDLE& handle )
{
    if ( handle && handle != INVALID_HANDLE_VALUE )
    {
        nt_close_stub( handle );
        handle = nullptr;
    }
}

bool memory::suspend_process( HANDLE handle )
{
    return NT_SUCCESS( nt_suspend_process_stub( handle ) );
}

bool memory::resume_process( HANDLE handle )
{
    return NT_SUCCESS( nt_resume_process_stub( handle ) );
}

memory::result_t memory::read_raw( HANDLE handle, std::uint64_t address, void* buf, std::size_t size )
{
    ULONG transferred = 0;
    const NTSTATUS s = nt_read_virtual_memory_stub( handle, reinterpret_cast< PVOID >( address ), buf, static_cast< ULONG >( size ), &transferred );
    return { s, static_cast< std::size_t >( transferred ) };
}

memory::result_t memory::write_raw( HANDLE handle, std::uint64_t address, const void* buf, std::size_t size )
{
    ULONG transferred = 0;
    const NTSTATUS s = nt_write_virtual_memory_stub(
        handle, reinterpret_cast< PVOID >( address ), const_cast< PVOID >( buf ), static_cast< ULONG >( size ), &transferred );
    return { s, static_cast< std::size_t >( transferred ) };
}

std::optional< std::vector< std::uint8_t > > memory::read_buf( HANDLE handle, std::uint64_t address, std::size_t size )
{
    std::vector< std::uint8_t > buf( size );
    const auto r = memory::read_raw( handle, address, buf.data( ), size );
    if ( !r.valid( ) )
        return std::nullopt;
    buf.resize( r.bytes_transferred );
    return buf;
}

std::vector< std::uint8_t > memory::read_partial( HANDLE handle, std::uint64_t address, std::size_t size )
{
    std::vector< std::uint8_t > buf( size );
    const auto r = memory::read_raw( handle, address, buf.data( ), size );
    buf.resize( r.bytes_transferred );
    return buf;
}

std::vector< std::uint8_t > memory::read_forced( HANDLE handle, std::uint64_t address, std::size_t size )
{
    std::vector< std::uint8_t > result( size, 0 );

    std::uint64_t cur = address;
    const auto end = address + size;

    while ( cur < end )
    {
        const auto page_base = cur & ~( 0x1000 - 1 );
        const std::size_t page_offset = static_cast< std::size_t >( cur - page_base );
        const std::size_t chunk = static_cast< std::size_t >( std::min( 0x1000 - page_offset, static_cast< std::uint64_t >( end - cur ) ) );
        const std::size_t buf_off = static_cast< std::size_t >( cur - address );

        const auto res = memory::read_raw( handle, cur, result.data( ) + buf_off, chunk );
        if ( !res.valid( ) )
        {
            const auto region = memory::query_region( handle, cur );
            if ( region && region->state == MEM_COMMIT )
            {
                const bool was_exec = ( region->protect &
                    ( PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY ) ) != 0;
                const DWORD new_prot = was_exec ? PAGE_EXECUTE_READWRITE : PAGE_READWRITE;
                DWORD old_prot = 0;

                if ( memory::protect( handle, page_base, 0x1000, new_prot, &old_prot ) )
                {
                    memory::read_raw( handle, cur, result.data( ) + buf_off, chunk );
                    memory::protect( handle, page_base, 0x1000, old_prot, nullptr );
                }
            }
        }

        cur += chunk;
    }

    return result;
}

std::vector< std::uint8_t > memory::read_bruteforce( HANDLE handle, std::uint64_t address, std::size_t size, const volatile bool* stop )
{
    static constexpr std::size_t page_size = 0x1000;
    std::vector< std::uint8_t > buf( size, 0 );

    const std::size_t n_pages = ( size + page_size - 1 ) / page_size;
    std::vector< bool > captured( n_pages, false );

    std::size_t remaining = 0;
    for ( std::size_t i = 0; i < n_pages; i++ )
    {
        const auto page_addr = address + i * page_size;
        const std::size_t chunk = std::min( page_size, size - i * page_size );
        const auto res = memory::read_raw( handle, page_addr, buf.data( ) + i * page_size, chunk );
        if ( res.valid( ) && res.bytes_transferred > 0 )
            captured[ i ] = true;
        else
            remaining++;
    }

    if ( remaining == 0 || ( stop && *stop ) )
        return buf;

    const auto total = remaining;
    console::output( console::OUTPUT_TYPE_INFO, "bruteforcing %zu unreadable page(s)\n", remaining );

    while ( remaining > 0 && !( stop && *stop ) )
    {
        for ( auto i = 0; i < n_pages; i++ )
        {
            if ( captured[ i ] )
                continue;
            if ( stop && *stop )
                break;

            const auto page_addr = address + i * page_size;
            const auto chunk = std::min( page_size, size - i * page_size );
            const auto res = memory::read_raw( handle, page_addr, buf.data( ) + i * page_size, chunk );
            if ( res.valid( ) && res.bytes_transferred > 0 )
            {
                captured[ i ] = true;
                remaining--;
                console::output( console::OUTPUT_TYPE_INFO, "\r%zu / %zu pages resolved", total - remaining, total );
                fflush( stdout );
            }
        }
    }

    printf( "\n" );
    return buf;
}

std::optional< memory::region_t > memory::query_region( HANDLE handle, std::uint64_t address )
{
    MEMORY_BASIC_INFORMATION mbi{};
    std::size_t return_len = 0;
    const auto status = nt_query_virtual_memory_stub( handle, reinterpret_cast< PVOID >( address ), mem_basic_information, &mbi, sizeof( mbi ), &return_len );
    if ( !NT_SUCCESS( status ) )
        return std::nullopt;

    memory::region_t r{};
    r.base = reinterpret_cast< std::uint64_t >( mbi.BaseAddress );
    r.size = mbi.RegionSize;
    r.state = mbi.State;
    r.protect = mbi.Protect;
    r.type = mbi.Type;
    return r;
}

std::vector< memory::region_t > memory::enum_regions( HANDLE handle, std::uint64_t start, std::uint64_t end )
{
    std::vector< memory::region_t > result;
    std::uint64_t cur = start;

    while ( cur < end )
    {
        const auto region = memory::query_region( handle, cur );
        if ( !region )
            break;

        result.push_back( *region );
        const auto next = region->base + region->size;
        if ( next <= cur )
            break;
        cur = next;
    }
    return result;
}

std::vector< memory::region_t > memory::enum_readable_regions( HANDLE handle, std::uint64_t start, std::uint64_t end )
{
    auto all = memory::enum_regions( handle, start, end );
    all.erase( std::remove_if( all.begin( ), all.end( ), []( const memory::region_t& r ) { return !r.is_readable( ); } ), all.end( ) );
    return all;
}

std::vector< memory::list_entry_t > memory::enum_modules( HANDLE handle )
{
    std::vector< memory::list_entry_t > result;

    const auto peb = memory::get_peb_address( handle );
    if ( !peb )
        return result;

    const auto ldr = memory::read< std::uint64_t >( handle, peb + 0x18 );
    if ( !ldr.value() )
        return result;

    const auto head = *memory::read< std::uint64_t >( handle, *ldr + 0x10 );
    auto node = *memory::read< std::uint64_t >( handle, head );

    while ( head != node )
    {
        struct ldr_data_table_entry_t
        {
            std::uint64_t in_load_order_links[ 2 ];
            std::uint64_t in_memory_order_links[ 2 ];
            std::uint64_t in_initialization_order_links[ 2 ];
            std::uint64_t dll_base;
            std::uint64_t entry_point;
            ULONG size_of_image;
            unicode_string_t full_dll_name;
            unicode_string_t base_dll_name;
        };

        const auto table_entry = memory::read< ldr_data_table_entry_t >( handle, node );
        if ( table_entry.has_value() )
        {   
            memory::list_entry_t list_entry{};
            list_entry.dll_base = table_entry->dll_base;
            list_entry.entry_point = table_entry->entry_point;
            list_entry.size_of_image = table_entry->size_of_image;
            
            if ( table_entry->base_dll_name.buffer && table_entry->base_dll_name.length > 0 )
            {
                const std::size_t chars = table_entry->base_dll_name.length / sizeof( wchar_t );
                const std::size_t copy = std::min( chars, static_cast< std::size_t >( 259 ) );
                std::wmemcpy( list_entry.name, table_entry->base_dll_name.buffer, copy );
                list_entry.name[ copy ] = L'\0';
            }
            
            result.push_back( list_entry );
        }
        const auto next = memory::read< std::uint64_t >( handle, node );
        if ( !next.value( ) || *next == head )
            break;
        node = *next;
    }
    return result;
}

memory::list_entry_t memory::get_module_info( HANDLE handle, const wchar_t* module_name )
{
    for ( const auto& m : memory::enum_modules( handle ) )
    {
        if ( _wcsicmp( m.name, module_name ) == 0 )
            return m;
    }
    return memory::list_entry_t( );
}

std::uint64_t memory::alloc( HANDLE handle, std::uint64_t preferred_base, std::size_t size, DWORD protect )
{
    PVOID base = reinterpret_cast< PVOID >( preferred_base );
    std::size_t reg_size = size;
    const auto status = nt_allocate_virtual_memory_stub( handle, &base, 0, &reg_size, MEM_COMMIT | MEM_RESERVE, protect );
    return NT_SUCCESS( status ) ? reinterpret_cast< std::uint64_t >( base ) : 0;
}

bool memory::free( HANDLE handle, std::uint64_t address )
{
    PVOID base = reinterpret_cast< PVOID >( address );
    std::size_t reg_size = 0;
    return NT_SUCCESS( nt_free_virtual_memory_stub( handle, &base, &reg_size, MEM_RELEASE ) );
}

bool memory::protect( HANDLE handle, std::uint64_t address, std::size_t size, DWORD new_protect, DWORD* old_protect )
{
    PVOID base = reinterpret_cast< PVOID >( address );
    std::size_t reg_size = size;
    DWORD old = 0;
    const auto status = nt_protect_virtual_memory_stub( handle, &base, &reg_size, new_protect, &old );
    if ( old_protect )
        *old_protect = old;
    return NT_SUCCESS( status );
}

std::optional< memory::proc_info_t > memory::get_proc_info( HANDLE handle )
{
    process_basic_information_t pbi{};
    ULONG return_len = 0;
    const auto status = nt_query_information_process_stub( handle, proc_basic_information, &pbi, sizeof( pbi ), &return_len );
    if ( !NT_SUCCESS( status ) )
        return std::nullopt;
    memory::proc_info_t info{};
    info.pid = pbi.unique_process_id;
    info.parent_pid = pbi.inherited_from_unique_process_id;
    info.peb_base = reinterpret_cast< std::uint64_t >( pbi.peb_base_address );
    info.image_base = 0;  
    return info;
}

std::uint64_t memory::get_peb_address( HANDLE handle )
{
    const auto info = memory::get_proc_info( handle );
    return info ? info->peb_base : 0;
}

std::uint64_t memory::get_image_base( HANDLE handle )
{
    const auto peb = memory::get_peb_address( handle );
    if ( !peb )
        return 0;
    const auto base = memory::read< std::uint64_t >( handle, peb + 0x10 );
    return base.value_or( 0 );
}

std::vector< memory::proc_entry_t > memory::list_processes( )
{
    std::vector< memory::proc_entry_t > result;

    ULONG buf_size = 1024 * 1024;
    std::vector< std::uint8_t > buf;

    NTSTATUS status;
    do
    {
        buf.resize( buf_size );
        ULONG returned = 0;
        status = nt_query_system_information_stub( sys_process_information, buf.data( ), static_cast< ULONG >( buf.size( ) ), &returned );
        if ( status == STATUS_INFO_LENGTH_MISMATCH )
        {
            buf_size = returned + 0x1000;
        }
    } while ( status == STATUS_INFO_LENGTH_MISMATCH );

    if ( !NT_SUCCESS( status ) )
        return result;

    const auto* entry = reinterpret_cast< const system_process_information_t* >( buf.data( ) );
    for ( ;; )
    {
        proc_entry_t pe{};
        pe.pid = reinterpret_cast< ULONG_PTR >( entry->unique_process_id );
        pe.parent_pid = reinterpret_cast< ULONG_PTR >( entry->inherited_from_unique_process_id );
        pe.session_id = entry->session_id;
        pe.thread_count = entry->number_of_threads;

        if ( entry->image_name.buffer && entry->image_name.length > 0 )
        {
            const std::size_t chars = entry->image_name.length / sizeof( wchar_t );
            const std::size_t copy = std::min( chars, static_cast< std::size_t >( 259 ) );
            std::wmemcpy( pe.name, entry->image_name.buffer, copy );
            pe.name[ copy ] = L'\0';
        }
        result.push_back( pe );

        if ( entry->next_entry_offset == 0 )
            break;
        entry = reinterpret_cast< const system_process_information_t* >( reinterpret_cast< const std::uint8_t* >( entry ) + entry->next_entry_offset );
    }
    return result;
}

DWORD memory::find_process_by_name( const wchar_t* name )
{
    for ( const auto& p : memory::list_processes( ) )
    {
        if ( _wcsicmp( p.name, name ) == 0 )
            return static_cast< DWORD >( p.pid );
    }
    return 0;
}

std::vector< std::uint64_t > memory::scan_buf_pattern( const std::uint8_t* buf, std::size_t buf_size, std::uint64_t region_base, const std::uint8_t* pattern, const char* mask )
{
    std::vector< std::uint64_t > hits;
    const auto len = std::strlen( mask );
    if ( len == 0 || buf_size < len )
        return hits;

    for ( auto i = 0; i <= buf_size - len; i++ )
    {
        bool match = true;
        for ( std::size_t j = 0; j < len; j++ )
        {
            if ( mask[ j ] == 'x' && buf[ i + j ] != pattern[ j ] )
            {
                match = false;
                break;
            }
        }
        if ( match )
            hits.push_back( region_base + i );
    }
    return hits;
}

std::vector< std::uint64_t > memory::scan_pattern( HANDLE handle, const std::uint8_t* pattern, const char* mask, std::uint64_t start, std::uint64_t end )
{
    std::vector< std::uint64_t > hits;
    for ( const auto& region : memory::enum_readable_regions( handle, start, end ) )
    {
        const auto buf = memory::read_buf( handle, region.base, region.size );
        if ( !buf )
            continue;
        auto local = memory::scan_buf_pattern( buf->data( ), buf->size( ), region.base, pattern, mask );
        hits.insert( hits.end( ), local.begin( ), local.end( ) );
    }
    return hits;
}

std::vector< std::uint64_t > memory::scan_value( HANDLE handle, const void* value, std::size_t value_size, std::uint64_t start, std::uint64_t end )
{
    std::vector< std::uint64_t > hits;
    for ( const auto& region : memory::enum_readable_regions( handle, start, end ) )
    {
        const auto buf = memory::read_buf( handle, region.base, region.size );
        if ( !buf || buf->size( ) < value_size )
            continue;
        for ( std::size_t i = 0; i <= buf->size( ) - value_size; i++ )
        {
            if ( std::memcmp( buf->data( ) + i, value, value_size ) == 0 )
                hits.push_back( region.base + i );
        }
    }
    return hits;
}
