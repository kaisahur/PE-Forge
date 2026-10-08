#pragma once

#include <Windows.h>

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "../memory/memory.h"

namespace pe
{
    enum class arch_t
    {
        x86,
        x64,
        unknown,
    };

    struct section_t
    {
        char name[ IMAGE_SIZEOF_SHORT_NAME + 1 ];
        std::uint32_t virtual_address;
        std::uint32_t virtual_size;
        std::uint32_t raw_offset;
        std::uint32_t raw_size;
        std::uint32_t characteristics;
        std::vector< uint8_t > data;

        bool has_data( ) const
        {
            return !data.empty( );
        }
        bool is_code( ) const
        {
            return ( characteristics & IMAGE_SCN_CNT_CODE ) != 0;
        }
        bool is_executable( ) const
        {
            return ( characteristics & IMAGE_SCN_MEM_EXECUTE ) != 0;
        }
        bool is_readable( ) const
        {
            return ( characteristics & IMAGE_SCN_MEM_READ ) != 0;
        }
        bool is_writable( ) const
        {
            return ( characteristics & IMAGE_SCN_MEM_WRITE ) != 0;
        }
        bool is_discardable( ) const
        {
            return ( characteristics & IMAGE_SCN_MEM_DISCARDABLE ) != 0;
        }
    };

    struct export_t
    {
        std::string name;
        std::uint32_t ordinal;
        std::uint32_t rva;
        bool is_forwarded;
        std::string forward_name;
    };

    struct import_thunk_t
    {
        std::string name;
        uint16_t hint;
        bool is_ordinal;
        uint16_t ordinal;
        uint64_t iat_rva;
        uint64_t original_thunk;
        uint64_t iat_thunk;
    };

    struct import_module_t
    {
        std::string name;
        std::uint32_t original_first_thunk;
        std::uint32_t first_thunk;
        std::uint32_t time_date_stamp;
        std::uint32_t forwarder_chain;
        std::vector< import_thunk_t > thunks;
    };

    struct reloc_block_t
    {
        std::uint32_t page_rva;
        std::vector< uint16_t > entries;
    };

    struct context_t
    {
        HANDLE process;
        std::uint64_t image_base;
        arch_t arch;
        bool force_read;
        bool bruteforce;
        const volatile bool* bruteforce_stop;

        std::vector< uint8_t > header_data;

        IMAGE_DOS_HEADER* dos_header;
        IMAGE_NT_HEADERS64* nt64;
        IMAGE_NT_HEADERS32* nt32;

        std::vector< section_t > sections;
        std::vector< export_t > exports;
        std::vector< import_module_t > imports;
        std::vector< reloc_block_t > relocs;

        std::vector< uint8_t > reconstructed;

        bool is_64bit( ) const
        {
            return arch == arch_t::x64;
        }
    };

    context_t* create( HANDLE process, std::uint64_t image_base );
    void destroy( context_t* ctx );

    bool parse_headers( context_t* ctx );
    bool parse_sections( context_t* ctx );
    bool parse_exports( context_t* ctx );
    bool parse_imports( context_t* ctx );
    bool parse_relocs( context_t* ctx );

    bool parse_all( context_t* ctx );
    bool reconstruct( context_t* ctx );
    bool fixup_iat( context_t* ctx );
    bool rebuild_imports( context_t* ctx );
    bool fixup_relocs( context_t* ctx, std::uint64_t new_base = 0 );

    bool write_to_file( const context_t* ctx, const wchar_t* path );

    arch_t get_arch( const context_t* ctx );
    std::uint64_t get_image_base( const context_t* ctx );
    size_t get_image_size( const context_t* ctx );
    std::uint64_t get_entry_point( const context_t* ctx );
    std::uint16_t get_characteristics( const context_t* ctx );
    std::uint16_t get_subsystem( const context_t* ctx );

    const section_t* find_section( const context_t* ctx, const char* name );
    const export_t* find_export_by_name( const context_t* ctx, const char* name );
    const export_t* find_export_by_ordinal( const context_t* ctx, std::uint32_t ordinal );

    const section_t* rva_to_section( const context_t* ctx, std::uint32_t rva );
    std::uint32_t rva_to_raw_offset( const context_t* ctx, std::uint32_t rva );
    std::uint64_t rva_to_va( const context_t* ctx, std::uint32_t rva );
    std::uint32_t va_to_rva( const context_t* ctx, std::uint64_t va );

    const IMAGE_DATA_DIRECTORY* get_data_dir( const context_t* ctx, DWORD directory_index );

    struct call_site_t
    {
        std::uint64_t call_va;
        std::uint64_t target_va;
        bool indirect;
        bool resolved;
        std::string module;
        std::string function;
        std::uint32_t ordinal;
    };

    std::vector< call_site_t > scan_calls( context_t* ctx );

}  // namespace pe
