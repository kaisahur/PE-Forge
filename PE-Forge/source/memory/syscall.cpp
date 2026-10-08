#include "syscall.h"

#include <algorithm>
#include <cstring>
#include <vector>

static bool is_clean_stub( const uint8_t* fn )
{
    return fn[ 0 ] == 0x4C && fn[ 1 ] == 0x8B && fn[ 2 ] == 0xD1 && fn[ 3 ] == 0xB8;
}

static DWORD extract_ssn( const uint8_t* fn )
{
    DWORD ssn;
    std::memcpy( &ssn, fn + 4, sizeof( DWORD ) );
    return ssn;
}

struct nt_export_t
{
    const char* name;
    const std::uint8_t* fn;
    DWORD ssn;
};

static std::vector< nt_export_t > collect_nt_exports( const std::uint8_t* base )
{
    std::vector< nt_export_t > out;

    const auto* dos = reinterpret_cast< const IMAGE_DOS_HEADER* >( base );
    const auto* nt = reinterpret_cast< const IMAGE_NT_HEADERS64* >( base + dos->e_lfanew );
    const auto& edir = nt->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT ];
    if ( edir.VirtualAddress == 0 )
        return out;

    const auto* exp = reinterpret_cast< const IMAGE_EXPORT_DIRECTORY* >( base + edir.VirtualAddress );
    const DWORD* rva_names = reinterpret_cast< const DWORD* >( base + exp->AddressOfNames );
    const WORD* rva_ords = reinterpret_cast< const WORD* >( base + exp->AddressOfNameOrdinals );
    const DWORD* rva_funcs = reinterpret_cast< const DWORD* >( base + exp->AddressOfFunctions );

    out.reserve( 512 );
    for ( DWORD i = 0; i < exp->NumberOfNames; i++ )
    {
        const char* name = reinterpret_cast< const char* >( base + rva_names[ i ] );
        if ( name[ 0 ] != 'N' || name[ 1 ] != 't' )
            continue;

        const uint8_t* fn = base + rva_funcs[ rva_ords[ i ] ];
        out.push_back( { name, fn, 0 } );
    }

    std::sort( out.begin( ), out.end( ), []( const nt_export_t& a, const nt_export_t& b ) { return a.fn < b.fn; } );

    for ( auto& e : out )
    {
        if ( is_clean_stub( e.fn ) )
            e.ssn = extract_ssn( e.fn );
    }

    for ( std::size_t i = 0; i < out.size( ); i++ )
    {
        if ( out[ i ].ssn != 0 )
            continue;

        for ( std::size_t j = i; j > 0; j-- )
        {
            if ( out[ j - 1 ].ssn != 0 )
            {
                out[ i ].ssn = out[ j - 1 ].ssn + static_cast< DWORD >( i - ( j - 1 ) );
                break;
            }
        }
        if ( out[ i ].ssn != 0 )
            continue;

        for ( std::size_t j = i + 1; j < out.size( ); j++ )
        {
            if ( out[ j ].ssn != 0 )
            {
                out[ i ].ssn = out[ j ].ssn - static_cast< DWORD >( j - i );
                break;
            }
        }
    }

    return out;
}

struct ssn_entry_t
{
    const char* nt_name;
    DWORD* p_ssn;
};

static const ssn_entry_t k_ssn_table[] = {
    { "NtReadVirtualMemory", &g_ssn_nt_read_virtual_memory },
    { "NtWriteVirtualMemory", &g_ssn_nt_write_virtual_memory },
    { "NtQueryVirtualMemory", &g_ssn_nt_query_virtual_memory },
    { "NtOpenProcess", &g_ssn_nt_open_process },
    { "NtClose", &g_ssn_nt_close },
    { "NtQueryInformationProcess", &g_ssn_nt_query_information_process },
    { "NtAllocateVirtualMemory", &g_ssn_nt_allocate_virtual_memory },
    { "NtFreeVirtualMemory", &g_ssn_nt_free_virtual_memory },
    { "NtProtectVirtualMemory", &g_ssn_nt_protect_virtual_memory },
    { "NtQuerySystemInformation", &g_ssn_nt_query_system_information },
    { "NtSuspendProcess", &g_ssn_nt_suspend_process },
    { "NtResumeProcess", &g_ssn_nt_resume_process },
    { "NtCreateFile", &g_ssn_nt_create_file },
    { "NtWriteFile", &g_ssn_nt_write_file },
    { "NtFlushBuffersFile", &g_ssn_nt_flush_buffers_file },
};

bool syscall_initialize( )
{
    const auto ntdll = GetModuleHandleA( "ntdll.dll" );
    if ( !ntdll )
        return false;

    const auto* base = reinterpret_cast< const uint8_t* >( ntdll );
    const auto exports = collect_nt_exports( base );
    if ( exports.empty( ) )
        return false;

    for ( const auto& entry : k_ssn_table )
    {
        DWORD resolved = 0;
        for ( const auto& exp : exports )
        {
            if ( _stricmp( exp.name, entry.nt_name ) == 0 )
            {
                resolved = exp.ssn;
                break;
            }
        }
        if ( resolved == 0 )
            return false;
        *entry.p_ssn = resolved;
    }
    return true;
}
