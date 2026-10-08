#pragma once

#include <cstdint>
#include <optional>
#include <vector>

#include "syscall.h"

namespace memory
{
    struct result_t
    {
        NTSTATUS status;
        std::size_t bytes_transferred;

        bool valid( ) const
        {
            return NT_SUCCESS( status );
        }
    };

    struct region_t
    {
        std::uint64_t base;
        std::size_t size;
        DWORD state;
        DWORD protect;
        DWORD type;

        bool is_committed( ) const
        {
            return state == MEM_COMMIT;
        }
        bool is_reserved( ) const
        {
            return state == MEM_RESERVE;
        }
        bool is_free( ) const
        {
            return state == MEM_FREE;
        }
        bool is_image( ) const
        {
            return type == MEM_IMAGE;
        }
        bool is_private( ) const
        {
            return type == MEM_PRIVATE;
        }
        bool is_mapped( ) const
        {
            return type == MEM_MAPPED;
        }

        bool is_readable( ) const
        {
            if ( !is_committed( ) )
                return false;
            if ( protect & PAGE_NOACCESS )
                return false;
            if ( protect & PAGE_GUARD )
                return false;
            return true;
        }
        bool is_executable( ) const
        {
            return is_readable( ) && ( protect & ( PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY ) );
        }
        bool is_writable( ) const
        {
            return is_readable( ) && ( protect & ( PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY ) );
        }
    };

    struct proc_info_t
    {
        ULONG_PTR pid;
        ULONG_PTR parent_pid;
        std::uint64_t peb_base;
        std::uint64_t image_base;
    };

    struct proc_entry_t
    {
        ULONG_PTR pid;
        ULONG_PTR parent_pid;
        wchar_t name[ 260 ];
        ULONG session_id;
        ULONG thread_count;
    };

    struct list_entry_t
    {
        std::uint64_t dll_base;
        std::uint64_t entry_point;
        ULONG size_of_image;
        wchar_t name[ 260 ];
    };

    bool initialize( );

    HANDLE open_process( DWORD pid, ACCESS_MASK access = PROCESS_ALL_ACCESS );
    void close_process( HANDLE& handle );

    bool suspend_process( HANDLE handle );
    bool resume_process( HANDLE handle );

    result_t read_raw( HANDLE handle, std::uint64_t address, void* buf, size_t size );
    result_t write_raw( HANDLE handle, std::uint64_t address, const void* buf, size_t size );

    template< typename T >
    std::optional< T > read( HANDLE handle, std::uint64_t address )
    {
        T val{};
        if ( !read_raw( handle, address, &val, sizeof( T ) ).valid( ) )
            return std::nullopt;
        return val;
    }

    template< typename T >
    bool write( HANDLE handle, std::uint64_t address, const T& value )
    {
        return write_raw( handle, address, &value, sizeof( T ) ).valid( );
    }

    std::optional< std::vector< std::uint8_t > > read_buf( HANDLE handle, std::uint64_t address, std::size_t size );

    std::vector< std::uint8_t > read_partial( HANDLE handle, std::uint64_t address, std::size_t size );
    std::vector< std::uint8_t > read_forced( HANDLE handle, std::uint64_t address, std::size_t size );
    std::vector< std::uint8_t > read_bruteforce( HANDLE handle, std::uint64_t address, std::size_t size, const volatile bool* stop );
    std::optional< region_t > query_region( HANDLE handle, std::uint64_t address );
    std::vector< region_t > enum_regions( HANDLE handle, std::uint64_t start = 0, std::uint64_t end = 0x7FFFFFFFFFFF );
    std::vector< region_t > enum_readable_regions( HANDLE handle, std::uint64_t start = 0, std::uint64_t end = 0x7FFFFFFFFFFF );
    std::vector< list_entry_t > enum_modules( HANDLE handle );

    list_entry_t get_module_info( HANDLE handle, const wchar_t* module_name );

    std::uint64_t alloc( HANDLE handle, std::uint64_t preferred_base, std::size_t size, DWORD protect = PAGE_READWRITE );

    bool free( HANDLE handle, std::uint64_t address );
    bool protect( HANDLE handle, std::uint64_t address, std::size_t size, DWORD new_protect, DWORD* old_protect = nullptr );

    std::optional< proc_info_t > get_proc_info( HANDLE handle );
    std::uint64_t get_peb_address( HANDLE handle );
    std::uint64_t get_image_base( HANDLE handle );

    std::vector< proc_entry_t > list_processes( );
    DWORD find_process_by_name( const wchar_t* name );

    std::vector< std::uint64_t > scan_pattern( HANDLE handle, const uint8_t* pattern, const char* mask, std::uint64_t start, std::uint64_t end );
    std::vector< std::uint64_t > scan_value( HANDLE handle, const void* value, std::size_t value_size, std::uint64_t start, std::uint64_t end );
    std::vector< std::uint64_t >
    scan_buf_pattern( const uint8_t* buf, std::size_t buf_size, std::uint64_t region_base, const uint8_t* pattern, const char* mask );
}  // namespace memory