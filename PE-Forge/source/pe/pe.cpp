#include "pe.h"

#include <winternl.h>

#include <algorithm>
#include <cassert>
#include <cstring>
#include <cwchar>
#include <unordered_map>

#undef min
#undef max

static std::uint32_t align_up( std::uint32_t value, std::uint32_t alignment )
{
    if ( alignment == 0 )
        return value;
    return ( value + alignment - 1 ) & ~( alignment - 1 );
}

static IMAGE_DATA_DIRECTORY* get_data_dir_rw( pe::context_t* ctx, DWORD idx )
{
    if ( idx >= IMAGE_NUMBEROF_DIRECTORY_ENTRIES )
        return nullptr;
    if ( ctx->is_64bit( ) )
        return &ctx->nt64->OptionalHeader.DataDirectory[ idx ];
    return &ctx->nt32->OptionalHeader.DataDirectory[ idx ];
}

pe::context_t* pe::create( HANDLE process, std::uint64_t image_base )
{
    auto* ctx = new pe::context_t{};
    ctx->process = process;
    ctx->image_base = image_base;
    ctx->arch = pe::arch_t::unknown;
    ctx->force_read = false;
    ctx->bruteforce = false;
    ctx->bruteforce_stop = nullptr;
    ctx->dos_header = nullptr;
    ctx->nt64 = nullptr;
    ctx->nt32 = nullptr;
    return ctx;
}

void pe::destroy( pe::context_t* ctx )
{
    delete ctx;
}

bool pe::parse_headers( pe::context_t* ctx )
{
    const auto dos_size = sizeof( IMAGE_DOS_HEADER );
    auto dos_buf = memory::read_buf( ctx->process, ctx->image_base, dos_size );
    if ( !dos_buf )
        return false;

    const auto* dos = reinterpret_cast< const IMAGE_DOS_HEADER* >( dos_buf->data( ) );
    if ( dos->e_magic != IMAGE_DOS_SIGNATURE )
        return false;

    const std::uint32_t nt_offset = dos->e_lfanew;
    const auto read_size = nt_offset + sizeof( IMAGE_NT_HEADERS64 ) + 128;
    auto full_buf = memory::read_buf( ctx->process, ctx->image_base, read_size );
    if ( !full_buf )
        return false;

    ctx->header_data = std::move( *full_buf );

    ctx->dos_header = reinterpret_cast< IMAGE_DOS_HEADER* >( ctx->header_data.data( ) );
    if ( ctx->dos_header->e_magic != IMAGE_DOS_SIGNATURE )
        return false;

    const DWORD sig_offset = ctx->dos_header->e_lfanew;
    if ( sig_offset + sizeof( DWORD ) > ctx->header_data.size( ) )
        return false;

    const DWORD sig = *reinterpret_cast< const DWORD* >( ctx->header_data.data( ) + sig_offset );
    if ( sig != IMAGE_NT_SIGNATURE )
        return false;

    const auto* fh = reinterpret_cast< const IMAGE_FILE_HEADER* >( ctx->header_data.data( ) + sig_offset + sizeof( DWORD ) );

    if ( fh->Machine == IMAGE_FILE_MACHINE_AMD64 )
    {
        ctx->arch = pe::arch_t::x64;
        ctx->nt64 = reinterpret_cast< IMAGE_NT_HEADERS64* >( ctx->header_data.data( ) + sig_offset );
    }
    else if ( fh->Machine == IMAGE_FILE_MACHINE_I386 )
    {
        ctx->arch = pe::arch_t::x86;
        ctx->nt32 = reinterpret_cast< IMAGE_NT_HEADERS32* >( ctx->header_data.data( ) + sig_offset );
    }
    else
    {
        return false;
    }

    const std::size_t headers_size = ctx->is_64bit( ) ? ctx->nt64->OptionalHeader.SizeOfHeaders : ctx->nt32->OptionalHeader.SizeOfHeaders;

    if ( headers_size > ctx->header_data.size( ) )
    {
        auto full_headers = memory::read_buf( ctx->process, ctx->image_base, headers_size );
        if ( !full_headers )
            return false;
        ctx->header_data = std::move( *full_headers );
        ctx->dos_header = reinterpret_cast< IMAGE_DOS_HEADER* >( ctx->header_data.data( ) );
        if ( ctx->is_64bit( ) )
            ctx->nt64 = reinterpret_cast< IMAGE_NT_HEADERS64* >( ctx->header_data.data( ) + sig_offset );
        else
            ctx->nt32 = reinterpret_cast< IMAGE_NT_HEADERS32* >( ctx->header_data.data( ) + sig_offset );
    }
    return true;
}

bool pe::parse_sections( pe::context_t* ctx )
{
    if ( !ctx->dos_header )
        return false;

    const std::uint32_t nt_offset = ctx->dos_header->e_lfanew;
    WORD num_sections;
    const IMAGE_SECTION_HEADER* first_section;

    if ( ctx->is_64bit( ) )
    {
        if ( !ctx->nt64 )
            return false;
        num_sections = ctx->nt64->FileHeader.NumberOfSections;
        first_section = IMAGE_FIRST_SECTION( ctx->nt64 );
    }
    else
    {
        if ( !ctx->nt32 )
            return false;
        num_sections = ctx->nt32->FileHeader.NumberOfSections;
        first_section = IMAGE_FIRST_SECTION( ctx->nt32 );
    }

    const auto* hdr_base = ctx->header_data.data( );
    const auto* sect_ptr = reinterpret_cast< const uint8_t* >( first_section );
    if ( sect_ptr < hdr_base || sect_ptr + num_sections * sizeof( IMAGE_SECTION_HEADER ) > hdr_base + ctx->header_data.size( ) )
        return false;

    ctx->sections.clear( );
    ctx->sections.reserve( num_sections );

    for ( WORD i = 0; i < num_sections; i++ )
    {
        const auto* sh = first_section + i;
        pe::section_t s{};
        std::memcpy( s.name, sh->Name, IMAGE_SIZEOF_SHORT_NAME );
        s.name[ IMAGE_SIZEOF_SHORT_NAME ] = '\0';
        s.virtual_address = sh->VirtualAddress;
        s.virtual_size = sh->Misc.VirtualSize;
        s.raw_offset = sh->PointerToRawData;
        s.raw_size = sh->SizeOfRawData;
        s.characteristics = sh->Characteristics;

        const std::size_t read_size = std::max( s.virtual_size, s.raw_size );
        if ( read_size > 0 )
        {
            if ( ctx->bruteforce )
            {
                printf( "  section %-10s\n", s.name );
                s.data = memory::read_bruteforce( ctx->process, ctx->image_base + s.virtual_address, read_size, ctx->bruteforce_stop );
            }
            else if ( ctx->force_read )
            {
                s.data = memory::read_forced( ctx->process, ctx->image_base + s.virtual_address, read_size );
            }
            else
            {
                auto data = memory::read_buf( ctx->process, ctx->image_base + s.virtual_address, read_size );
                if ( data )
                    s.data = std::move( *data );
            }
        }
        ctx->sections.push_back( std::move( s ) );
    }
    return true;
}

bool pe::parse_exports( pe::context_t* ctx )
{
    if ( !ctx->dos_header )
        return false;

    const IMAGE_DATA_DIRECTORY* edir = pe::get_data_dir( ctx, IMAGE_DIRECTORY_ENTRY_EXPORT );
    if ( !edir || edir->VirtualAddress == 0 )
        return true;

    const std::size_t dir_size = std::max( static_cast< DWORD >( sizeof( IMAGE_EXPORT_DIRECTORY ) ), edir->Size );
    auto raw = memory::read_buf( ctx->process, ctx->image_base + edir->VirtualAddress, dir_size );
    if ( !raw )
        return false;

    const auto* exp = reinterpret_cast< const IMAGE_EXPORT_DIRECTORY* >( raw->data( ) );

    const std::size_t name_arr_size = exp->NumberOfNames * sizeof( DWORD );
    const std::size_t ord_arr_size = exp->NumberOfNames * sizeof( WORD );
    const std::size_t func_arr_size = exp->NumberOfFunctions * sizeof( DWORD );

    auto name_rvas = memory::read_buf( ctx->process, ctx->image_base + exp->AddressOfNames, name_arr_size );
    auto ordinals = memory::read_buf( ctx->process, ctx->image_base + exp->AddressOfNameOrdinals, ord_arr_size );
    auto func_rvas = memory::read_buf( ctx->process, ctx->image_base + exp->AddressOfFunctions, func_arr_size );

    if ( !name_rvas || !ordinals || !func_rvas )
        return false;

    const DWORD* p_name_rvas = reinterpret_cast< const DWORD* >( name_rvas->data( ) );
    const WORD* p_ords = reinterpret_cast< const WORD* >( ordinals->data( ) );
    const DWORD* p_func_rvas = reinterpret_cast< const DWORD* >( func_rvas->data( ) );

    const auto export_dir_start = ctx->image_base + edir->VirtualAddress;
    const auto export_dir_end = export_dir_start + edir->Size;

    ctx->exports.clear( );

    for ( DWORD i = 0; i < exp->NumberOfNames; i++ )
    {
        const WORD ord = p_ords[ i ];
        if ( ord >= exp->NumberOfFunctions )
            continue;

        const DWORD func_rva = p_func_rvas[ ord ];

        pe::export_t e{};
        e.ordinal = exp->Base + ord;
        e.rva = func_rva;

        if ( p_name_rvas[ i ] != 0 )
        {
            auto name_buf = memory::read_buf( ctx->process, ctx->image_base + p_name_rvas[ i ], 256 );
            if ( name_buf )
            {
                name_buf->push_back( 0 );
                e.name = reinterpret_cast< const char* >( name_buf->data( ) );
            }
        }

        const auto func_va = ctx->image_base + func_rva;
        if ( func_va >= export_dir_start && func_va < export_dir_end )
        {
            e.is_forwarded = true;
            auto fwd_buf = memory::read_buf( ctx->process, func_va, 256 );
            if ( fwd_buf )
            {
                fwd_buf->push_back( 0 );
                e.forward_name = reinterpret_cast< const char* >( fwd_buf->data( ) );
            }
        }
        ctx->exports.push_back( std::move( e ) );
    }

    for ( DWORD ord = 0; ord < exp->NumberOfFunctions; ord++ )
    {
        const DWORD func_rva = p_func_rvas[ ord ];
        if ( func_rva == 0 )
            continue;

        const bool already_named =
            std::any_of( ctx->exports.begin( ), ctx->exports.end( ), [ & ]( const pe::export_t& e ) { return e.ordinal == exp->Base + ord; } );
        if ( already_named )
            continue;

        pe::export_t e{};
        e.ordinal = exp->Base + ord;
        e.rva = func_rva;
        ctx->exports.push_back( std::move( e ) );
    }
    return true;
}

template< typename thunk_t >
static pe::import_thunk_t read_thunk( HANDLE process, std::uint64_t image_base, std::uint64_t orig_thunk_va, std::uint64_t iat_va, bool is_64bit )
{
    pe::import_thunk_t t{};
    t.iat_rva = iat_va - image_base;

    thunk_t orig = 0;
    thunk_t iat = 0;
    memory::read_raw( process, orig_thunk_va, &orig, sizeof( thunk_t ) );
    memory::read_raw( process, iat_va, &iat, sizeof( thunk_t ) );
    t.original_thunk = orig;
    t.iat_thunk = iat;

    const thunk_t ordinal_flag = is_64bit ? static_cast< thunk_t >( IMAGE_ORDINAL_FLAG64 ) : static_cast< thunk_t >( IMAGE_ORDINAL_FLAG32 );

    if ( orig & ordinal_flag )
    {
        t.is_ordinal = true;
        t.ordinal = static_cast< uint16_t >( orig & 0xFFFF );
    }
    else
    {
        t.is_ordinal = false;
        const auto ibn_va = image_base + static_cast< std::uint32_t >( orig & 0x7FFFFFFF );
        auto name_buf = memory::read_buf( process, ibn_va, 258 );
        if ( name_buf && name_buf->size( ) >= 2 )
        {
            t.hint = *reinterpret_cast< const uint16_t* >( name_buf->data( ) );
            name_buf->push_back( 0 );
            t.name = reinterpret_cast< const char* >( name_buf->data( ) + 2 );
        }
    }
    return t;
}

bool pe::parse_imports( pe::context_t* ctx )
{
    if ( !ctx->dos_header )
        return false;

    const auto* idir = pe::get_data_dir( ctx, IMAGE_DIRECTORY_ENTRY_IMPORT );
    if ( !idir || idir->VirtualAddress == 0 )
        return true;

    ctx->imports.clear( );

    std::uint64_t desc_va = ctx->image_base + idir->VirtualAddress;
    for ( ;; )
    {
        auto desc_buf = memory::read_buf( ctx->process, desc_va, sizeof( IMAGE_IMPORT_DESCRIPTOR ) );
        if ( !desc_buf )
            break;

        const auto* desc = reinterpret_cast< const IMAGE_IMPORT_DESCRIPTOR* >( desc_buf->data( ) );
        if ( desc->Name == 0 && desc->FirstThunk == 0 )
            break;

        pe::import_module_t mod{};
        mod.original_first_thunk = desc->OriginalFirstThunk;
        mod.first_thunk = desc->FirstThunk;
        mod.time_date_stamp = desc->TimeDateStamp;
        mod.forwarder_chain = desc->ForwarderChain;

        if ( desc->Name != 0 )
        {
            auto name_buf = memory::read_buf( ctx->process, ctx->image_base + desc->Name, 256 );
            if ( name_buf )
            {
                name_buf->push_back( 0 );
                mod.name = reinterpret_cast< const char* >( name_buf->data( ) );
            }
        }

        const std::uint32_t int_rva = desc->OriginalFirstThunk ? desc->OriginalFirstThunk : desc->FirstThunk;
        const std::uint32_t iat_rva = desc->FirstThunk;

        if ( int_rva != 0 && iat_rva != 0 )
        {
            const std::size_t thunk_size = ctx->is_64bit( ) ? 8 : 4;
            std::uint64_t int_va = ctx->image_base + int_rva;
            std::uint64_t iat_va = ctx->image_base + iat_rva;

            for ( ;; )
            {
                uint64_t orig = 0;
                memory::read_raw( ctx->process, int_va, &orig, thunk_size );
                if ( orig == 0 )
                    break;

                pe::import_thunk_t thunk;
                if ( ctx->is_64bit( ) )
                {
                    thunk = read_thunk< uint64_t >( ctx->process, ctx->image_base, int_va, iat_va, true );
                }
                else
                {
                    thunk = read_thunk< std::uint32_t >( ctx->process, ctx->image_base, int_va, iat_va, false );
                }
                mod.thunks.push_back( std::move( thunk ) );
                int_va += thunk_size;
                iat_va += thunk_size;
            }
        }
        ctx->imports.push_back( std::move( mod ) );
        desc_va += sizeof( IMAGE_IMPORT_DESCRIPTOR );
    }

    return true;
}

bool pe::parse_relocs( pe::context_t* ctx )
{
    if ( !ctx->dos_header )
        return false;

    const IMAGE_DATA_DIRECTORY* rdir = pe::get_data_dir( ctx, IMAGE_DIRECTORY_ENTRY_BASERELOC );
    if ( !rdir || rdir->VirtualAddress == 0 )
        return true;

    ctx->relocs.clear( );

    std::uint64_t cur_va = ctx->image_base + rdir->VirtualAddress;
    const auto end_va = cur_va + rdir->Size;

    while ( cur_va < end_va )
    {
        auto block_buf = memory::read_buf( ctx->process, cur_va, sizeof( IMAGE_BASE_RELOCATION ) );
        if ( !block_buf )
            break;

        const auto* block = reinterpret_cast< const IMAGE_BASE_RELOCATION* >( block_buf->data( ) );
        if ( block->SizeOfBlock < sizeof( IMAGE_BASE_RELOCATION ) || block->SizeOfBlock == 0 )
            break;

        const std::size_t entry_count = ( block->SizeOfBlock - sizeof( IMAGE_BASE_RELOCATION ) ) / sizeof( WORD );
        auto entry_buf = memory::read_buf( ctx->process, cur_va + sizeof( IMAGE_BASE_RELOCATION ), entry_count * sizeof( WORD ) );
        if ( !entry_buf )
            break;

        pe::reloc_block_t rb{};
        rb.page_rva = block->VirtualAddress;
        rb.entries.resize( entry_count );
        std::memcpy( rb.entries.data( ), entry_buf->data( ), entry_count * sizeof( WORD ) );
        ctx->relocs.push_back( std::move( rb ) );

        cur_va += block->SizeOfBlock;
    }
    return true;
}

bool pe::parse_all( pe::context_t* ctx )
{
    return pe::parse_headers( ctx ) && pe::parse_sections( ctx ) && pe::parse_exports( ctx ) && pe::parse_imports( ctx ) && pe::parse_relocs( ctx );
}

bool pe::reconstruct( pe::context_t* ctx )
{
    if ( !ctx->dos_header || ctx->sections.empty( ) )
        return false;

    const std::uint32_t file_alignment = ctx->is_64bit( ) ? ctx->nt64->OptionalHeader.FileAlignment : ctx->nt32->OptionalHeader.FileAlignment;
    const std::uint32_t section_alignment =
        ctx->is_64bit( ) ? ctx->nt64->OptionalHeader.SectionAlignment : ctx->nt32->OptionalHeader.SectionAlignment;
    const std::uint32_t headers_size = ctx->is_64bit( ) ? ctx->nt64->OptionalHeader.SizeOfHeaders : ctx->nt32->OptionalHeader.SizeOfHeaders;

    std::uint32_t raw_cursor = align_up( headers_size, file_alignment );
    std::vector< std::pair< std::uint32_t, std::uint32_t > > raw_layout;

    for ( const auto& sec : ctx->sections )
    {
        const std::uint32_t raw_size = align_up( std::min( static_cast< std::uint32_t >( sec.data.size( ) ), sec.virtual_size ), file_alignment );
        raw_layout.push_back( { raw_cursor, raw_size } );
        raw_cursor = align_up( raw_cursor + raw_size, file_alignment );
    }

    ctx->reconstructed.assign( raw_cursor, 0 );

    const std::size_t hdr_copy = std::min( ctx->header_data.size( ), static_cast< std::size_t >( headers_size ) );
    std::memcpy( ctx->reconstructed.data( ), ctx->header_data.data( ), hdr_copy );

    const auto* dos = reinterpret_cast< const IMAGE_DOS_HEADER* >( ctx->reconstructed.data( ) );
    IMAGE_SECTION_HEADER* first_sh;
    if ( ctx->is_64bit( ) )
    {
        auto* nt = reinterpret_cast< IMAGE_NT_HEADERS64* >( ctx->reconstructed.data( ) + dos->e_lfanew );
        first_sh = IMAGE_FIRST_SECTION( nt );
    }
    else
    {
        auto* nt = reinterpret_cast< IMAGE_NT_HEADERS32* >( ctx->reconstructed.data( ) + dos->e_lfanew );
        first_sh = IMAGE_FIRST_SECTION( nt );
    }

    for ( std::size_t i = 0; i < ctx->sections.size( ); i++ )
    {
        auto& sh = first_sh[ i ];
        const auto& [ raw_off, raw_sz ] = raw_layout[ i ];
        sh.PointerToRawData = raw_off;
        sh.SizeOfRawData = raw_sz;

        const auto& sec = ctx->sections[ i ];
        const std::size_t copy_size = std::min( sec.data.size( ), static_cast< std::size_t >( raw_sz ) );
        if ( copy_size > 0 && raw_off + copy_size <= ctx->reconstructed.size( ) )
            std::memcpy( ctx->reconstructed.data( ) + raw_off, sec.data.data( ), copy_size );
    }
    return true;
}

bool pe::fixup_iat( pe::context_t* ctx )
{
    if ( ctx->reconstructed.empty( ) || ctx->imports.empty( ) )
        return false;

    const std::size_t thunk_size = ctx->is_64bit( ) ? 8 : 4;

    for ( const auto& mod : ctx->imports )
    {
        for ( const auto& thunk : mod.thunks )
        {
            const std::uint32_t raw_off = pe::rva_to_raw_offset( ctx, static_cast< std::uint32_t >( thunk.iat_rva ) );
            if ( raw_off == 0 || raw_off + thunk_size > ctx->reconstructed.size( ) )
                continue;

            const auto restore_val = thunk.original_thunk ? thunk.original_thunk : thunk.iat_thunk;
            std::memcpy( ctx->reconstructed.data( ) + raw_off, &restore_val, thunk_size );
        }
    }
    return true;
}

bool pe::rebuild_imports( pe::context_t* ctx )
{
    if ( ctx->reconstructed.empty( ) || ctx->imports.empty( ) )
        return false;

    const bool is64 = ctx->is_64bit( );
    const std::size_t thunk_size = is64 ? 8 : 4;

    const std::uint32_t file_align = is64 ? ctx->nt64->OptionalHeader.FileAlignment : ctx->nt32->OptionalHeader.FileAlignment;

    const std::uint32_t sect_align = is64 ? ctx->nt64->OptionalHeader.SectionAlignment : ctx->nt32->OptionalHeader.SectionAlignment;

    std::uint32_t next_rva = 0;
    for ( const auto& s : ctx->sections )
    {
        next_rva = std::max( next_rva, s.virtual_address + align_up( s.virtual_size, sect_align ) );
    }
    next_rva = align_up( next_rva, sect_align );

    const std::size_t n_mods = ctx->imports.size( );

    const std::size_t descs_off = 0;
    const std::size_t descs_size = ( n_mods + 1 ) * sizeof( IMAGE_IMPORT_DESCRIPTOR );

    std::vector< std::size_t > int_off( n_mods );
    std::size_t cur = descs_size;
    for ( std::size_t i = 0; i < n_mods; i++ )
    {
        int_off[ i ] = cur;
        cur += ( ctx->imports[ i ].thunks.size( ) + 1 ) * thunk_size;
    }

    std::vector< std::vector< std::size_t > > ibn_off( n_mods );
    for ( std::size_t i = 0; i < n_mods; i++ )
    {
        ibn_off[ i ].resize( ctx->imports[ i ].thunks.size( ), 0 );
        for ( std::size_t j = 0; j < ctx->imports[ i ].thunks.size( ); j++ )
        {
            const auto& t = ctx->imports[ i ].thunks[ j ];
            if ( !t.is_ordinal )
            {
                ibn_off[ i ][ j ] = cur;
                cur += sizeof( WORD ) + t.name.size( ) + 1;
                cur = ( cur + 1 ) & ~std::size_t{ 1 };
            }
        }
    }

    std::vector< std::size_t > dll_name_off( n_mods );
    for ( std::size_t i = 0; i < n_mods; i++ )
    {
        dll_name_off[ i ] = cur;
        cur += ctx->imports[ i ].name.size( ) + 1;
    }

    const std::size_t unpadded_size = cur;
    const std::size_t raw_size = align_up( static_cast< std::uint32_t >( cur ), file_align );
    const std::uint32_t raw_off = static_cast< std::uint32_t >( ctx->reconstructed.size( ) );

    std::vector< std::uint8_t > blob( raw_size, 0 );

    auto* descs = reinterpret_cast< IMAGE_IMPORT_DESCRIPTOR* >( blob.data( ) + descs_off );
    for ( std::size_t i = 0; i < n_mods; i++ )
    {
        descs[ i ].OriginalFirstThunk = next_rva + static_cast< std::uint32_t >( int_off[ i ] );
        descs[ i ].TimeDateStamp = 0;
        descs[ i ].ForwarderChain = 0;
        descs[ i ].Name = next_rva + static_cast< std::uint32_t >( dll_name_off[ i ] );
        descs[ i ].FirstThunk = ctx->imports[ i ].first_thunk;
    }

    for ( std::size_t i = 0; i < n_mods; i++ )
    {
        const auto& mod = ctx->imports[ i ];
        std::uint8_t* int_ptr = blob.data( ) + int_off[ i ];

        for ( std::size_t j = 0; j < mod.thunks.size( ); j++ )
        {
            const auto& t = mod.thunks[ j ];
            std::uint64_t thunk_val = 0;

            if ( t.is_ordinal )
            {
                thunk_val = is64 ? ( IMAGE_ORDINAL_FLAG64 | t.ordinal ) : ( IMAGE_ORDINAL_FLAG32 | t.ordinal );
            }
            else
            {
                thunk_val = next_rva + static_cast< std::uint32_t >( ibn_off[ i ][ j ] );
            }

            std::memcpy( int_ptr + j * thunk_size, &thunk_val, thunk_size );
        }
    }

    for ( std::size_t i = 0; i < n_mods; i++ )
    {
        const auto& mod = ctx->imports[ i ];
        for ( std::size_t j = 0; j < mod.thunks.size( ); j++ )
        {
            const auto& t = mod.thunks[ j ];
            if ( t.is_ordinal )
                continue;

            std::uint8_t* p = blob.data( ) + ibn_off[ i ][ j ];
            std::memcpy( p, &t.hint, sizeof( WORD ) );
            std::memcpy( p + sizeof( WORD ), t.name.c_str( ), t.name.size( ) + 1 );
        }
    }

    for ( std::size_t i = 0; i < n_mods; i++ )
    {
        std::uint8_t* p = blob.data( ) + dll_name_off[ i ];
        std::memcpy( p, ctx->imports[ i ].name.c_str( ), ctx->imports[ i ].name.size( ) + 1 );
    }

    for ( std::size_t i = 0; i < n_mods; i++ )
    {
        const auto& mod = ctx->imports[ i ];
        for ( std::size_t j = 0; j < mod.thunks.size( ); j++ )
        {
            const auto& t = mod.thunks[ j ];
            const std::uint32_t iat_raw = pe::rva_to_raw_offset( ctx, static_cast< std::uint32_t >( t.iat_rva ) );
            if ( iat_raw == 0 || iat_raw + thunk_size > ctx->reconstructed.size( ) )
                continue;

            std::uint64_t thunk_val = 0;
            if ( t.is_ordinal )
            {
                thunk_val = is64 ? ( IMAGE_ORDINAL_FLAG64 | t.ordinal ) : ( IMAGE_ORDINAL_FLAG32 | t.ordinal );
            }
            else
            {
                thunk_val = next_rva + static_cast< std::uint32_t >( ibn_off[ i ][ j ] );
            }

            std::memcpy( ctx->reconstructed.data( ) + iat_raw, &thunk_val, thunk_size );
        }
    }

    ctx->reconstructed.insert( ctx->reconstructed.end( ), blob.begin( ), blob.end( ) );

    auto* dos_r = reinterpret_cast< IMAGE_DOS_HEADER* >( ctx->reconstructed.data( ) );
    IMAGE_SECTION_HEADER* first_sh_r = nullptr;
    WORD num_sects = 0;
    std::uint32_t headers_capacity = 0;

    if ( is64 )
    {
        auto* nt = reinterpret_cast< IMAGE_NT_HEADERS64* >( ctx->reconstructed.data( ) + dos_r->e_lfanew );
        num_sects = nt->FileHeader.NumberOfSections;
        first_sh_r = IMAGE_FIRST_SECTION( nt );
        headers_capacity = nt->OptionalHeader.SizeOfHeaders;
    }
    else
    {
        auto* nt = reinterpret_cast< IMAGE_NT_HEADERS32* >( ctx->reconstructed.data( ) + dos_r->e_lfanew );
        num_sects = nt->FileHeader.NumberOfSections;
        first_sh_r = IMAGE_FIRST_SECTION( nt );
        headers_capacity = nt->OptionalHeader.SizeOfHeaders;
    }

    const auto* new_sh_end = reinterpret_cast< const std::uint8_t* >( first_sh_r + num_sects + 1 );
    if ( new_sh_end > ctx->reconstructed.data( ) + headers_capacity )
        return false;

    auto* new_sh = first_sh_r + num_sects;
    std::memset( new_sh, 0, sizeof( IMAGE_SECTION_HEADER ) );
    static_assert( sizeof( new_sh->Name ) == 8 );
    std::memcpy( new_sh->Name, ".peforge\0", 9 );
    new_sh->Misc.VirtualSize = static_cast< DWORD >( unpadded_size );
    new_sh->VirtualAddress = next_rva;
    new_sh->SizeOfRawData = static_cast< DWORD >( raw_size );
    new_sh->PointerToRawData = raw_off;
    new_sh->Characteristics = IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE;

    if ( is64 )
    {
        auto* nt = reinterpret_cast< IMAGE_NT_HEADERS64* >( ctx->reconstructed.data( ) + dos_r->e_lfanew );
        nt->FileHeader.NumberOfSections++;
        nt->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_IMPORT ].VirtualAddress = next_rva;
        nt->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_IMPORT ].Size = static_cast< DWORD >( descs_size );
        nt->OptionalHeader.SizeOfImage = align_up( next_rva + align_up( static_cast< std::uint32_t >( unpadded_size ), sect_align ), sect_align );
    }
    else
    {
        auto* nt = reinterpret_cast< IMAGE_NT_HEADERS32* >( ctx->reconstructed.data( ) + dos_r->e_lfanew );
        nt->FileHeader.NumberOfSections++;
        nt->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_IMPORT ].VirtualAddress = next_rva;
        nt->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_IMPORT ].Size = static_cast< DWORD >( descs_size );
        nt->OptionalHeader.SizeOfImage = align_up( next_rva + align_up( static_cast< std::uint32_t >( unpadded_size ), sect_align ), sect_align );
    }

    return true;
}

bool pe::fixup_relocs( pe::context_t* ctx, std::uint64_t new_base )
{
    if ( ctx->reconstructed.empty( ) || ctx->relocs.empty( ) )
        return false;

    const auto old_base = ctx->image_base;
    if ( new_base == 0 )
        new_base = old_base;
    const int64_t delta = static_cast< int64_t >( new_base ) - static_cast< int64_t >( old_base );
    if ( delta == 0 )
        return true;

    for ( const auto& block : ctx->relocs )
    {
        for ( const WORD entry : block.entries )
        {
            const int type = entry >> 12;
            const int offset = entry & 0x0FFF;
            if ( type == IMAGE_REL_BASED_ABSOLUTE )
                continue;

            const std::uint32_t rva = block.page_rva + offset;
            const std::uint32_t raw_off = pe::rva_to_raw_offset( ctx, rva );
            if ( raw_off == 0 )
                continue;

            if ( type == IMAGE_REL_BASED_DIR64 && ctx->is_64bit( ) )
            {
                if ( raw_off + 8 > ctx->reconstructed.size( ) )
                    continue;
                uint64_t val;
                std::memcpy( &val, ctx->reconstructed.data( ) + raw_off, 8 );
                val += static_cast< uint64_t >( delta );
                std::memcpy( ctx->reconstructed.data( ) + raw_off, &val, 8 );
            }
            else if ( type == IMAGE_REL_BASED_HIGHLOW )
            {
                if ( raw_off + 4 > ctx->reconstructed.size( ) )
                    continue;
                std::uint32_t val;
                std::memcpy( &val, ctx->reconstructed.data( ) + raw_off, 4 );
                val += static_cast< std::uint32_t >( delta );
                std::memcpy( ctx->reconstructed.data( ) + raw_off, &val, 4 );
            }
        }
    }

    if ( ctx->is_64bit( ) )
    {
        auto* nt = reinterpret_cast< IMAGE_NT_HEADERS64* >( ctx->reconstructed.data( ) + ctx->dos_header->e_lfanew );
        nt->OptionalHeader.ImageBase = new_base;
    }
    else
    {
        auto* nt = reinterpret_cast< IMAGE_NT_HEADERS32* >( ctx->reconstructed.data( ) + ctx->dos_header->e_lfanew );
        nt->OptionalHeader.ImageBase = static_cast< DWORD >( new_base );
    }
    return true;
}

bool pe::write_to_file( const pe::context_t* ctx, const wchar_t* path )
{
    if ( ctx->reconstructed.empty( ) || !path )
        return false;

    HANDLE h = CreateFileW( path, GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr );

    if ( h == INVALID_HANDLE_VALUE )
        return false;

    DWORD written = 0;
    const BOOL ok = WriteFile( h, ctx->reconstructed.data( ), static_cast< DWORD >( ctx->reconstructed.size( ) ), &written, nullptr );

    CloseHandle( h );
    return ok && written == static_cast< DWORD >( ctx->reconstructed.size( ) );
}

struct export_record_t
{
    std::string module;
    std::string function;
    std::uint32_t ordinal;
};
using export_map_t = std::unordered_map< std::uint64_t, export_record_t >;

static std::string narrow( const wchar_t* w )
{
    std::string s;
    while ( *w )
        s += static_cast< char >( *w++ );
    return s;
}

static export_map_t build_export_map( HANDLE process )
{
    export_map_t map;
    for ( const auto& mod : memory::enum_modules( process ) )
    {
        if ( !mod.dll_base )
            continue;

        auto* mctx = pe::create( process, mod.dll_base );
        if ( pe::parse_headers( mctx ) && pe::parse_exports( mctx ) )
        {
            const std::string mod_name = narrow( mod.name );
            for ( const auto& exp : mctx->exports )
            {
                if ( exp.is_forwarded )
                    continue;
                const auto va = mod.dll_base + exp.rva;
                map[ va ] = { mod_name, exp.name, exp.ordinal };
            }
        }
        pe::destroy( mctx );
    }
    return map;
}

static std::uint64_t follow_jmp_thunk( pe::context_t* ctx, std::uint64_t target_va )
{
    const bool is64 = ctx->is_64bit( );

    for ( const auto& sec : ctx->sections )
    {
        if ( !sec.is_executable( ) || sec.data.empty( ) )
            continue;

        const auto sec_va = ctx->image_base + sec.virtual_address;
        if ( target_va < sec_va || target_va >= sec_va + sec.data.size( ) )
            continue;

        const std::size_t off = static_cast< std::size_t >( target_va - sec_va );
        const std::uint8_t* p = sec.data.data( ) + off;
        const std::size_t remain = sec.data.size( ) - off;

        if ( is64 && remain >= 6 && p[ 0 ] == 0xFF && p[ 1 ] == 0x25 )
        {
            std::int32_t rel32 = 0;
            std::memcpy( &rel32, p + 2, 4 );
            const auto ptr_va = target_va + 6 + static_cast< std::int64_t >( rel32 );
            std::uint64_t func_va = 0;
            memory::read_raw( ctx->process, ptr_va, &func_va, 8 );
            return func_va;
        }
        else if ( !is64 && remain >= 6 && p[ 0 ] == 0xFF && p[ 1 ] == 0x25 )
        {
            std::uint32_t abs32 = 0;
            std::memcpy( &abs32, p + 2, 4 );
            std::uint32_t func_va32 = 0;
            memory::read_raw( ctx->process, abs32, &func_va32, 4 );
            return func_va32;
        }
        break;
    }
    return 0;
}

std::vector< pe::call_site_t > pe::scan_calls( pe::context_t* ctx )
{
    std::vector< pe::call_site_t > results;

    if ( !ctx->dos_header || ctx->sections.empty( ) )
        return results;

    const bool is64 = ctx->is_64bit( );
    const auto image_end = ctx->image_base + ( is64 ? ctx->nt64->OptionalHeader.SizeOfImage : ctx->nt32->OptionalHeader.SizeOfImage );

    const export_map_t exp_map = build_export_map( ctx->process );

    std::unordered_map< std::uint64_t, bool > seen;

    for ( const auto& sec : ctx->sections )
    {
        if ( !sec.is_executable( ) || sec.data.empty( ) )
            continue;

        const auto sec_va = ctx->image_base + sec.virtual_address;
        const std::uint8_t* data = sec.data.data( );
        const std::size_t data_size = sec.data.size( );

        for ( std::size_t i = 0; i < data_size; )
        {
            std::uint64_t target_va = 0;
            bool indirect = false;
            std::size_t instr_len = 0;

            if ( data_size - i >= 5 && data[ i ] == 0xE8 )
            {
                std::int32_t rel32 = 0;
                std::memcpy( &rel32, data + i + 1, 4 );
                const auto call_va = sec_va + i;
                target_va = call_va + 5 + static_cast< std::int64_t >( rel32 );
                instr_len = 5;

                if ( target_va >= ctx->image_base && target_va < image_end )
                {
                    const auto thunk_dest = follow_jmp_thunk( ctx, target_va );
                    if ( thunk_dest )
                    {
                        target_va = thunk_dest;
                        indirect = true;
                    }
                }
            }
            else if ( is64 && data_size - i >= 6 && data[ i ] == 0xFF && data[ i + 1 ] == 0x15 )
            {
                std::int32_t rel32 = 0;
                std::memcpy( &rel32, data + i + 2, 4 );
                const auto call_va = sec_va + i;
                const auto ptr_va = call_va + 6 + static_cast< std::int64_t >( rel32 );
                std::uint64_t func_va = 0;
                memory::read_raw( ctx->process, ptr_va, &func_va, 8 );
                target_va = func_va;
                indirect = true;
                instr_len = 6;
            }
            else if ( !is64 && data_size - i >= 6 && data[ i ] == 0xFF && data[ i + 1 ] == 0x15 )
            {
                std::uint32_t abs32 = 0;
                std::memcpy( &abs32, data + i + 2, 4 );
                std::uint32_t func_va32 = 0;
                memory::read_raw( ctx->process, abs32, &func_va32, 4 );
                target_va = func_va32;
                indirect = true;
                instr_len = 6;
            }
            else
            {
                i++;
                continue;
            }

            i += instr_len;

            if ( !target_va )
                continue;

            if ( target_va >= ctx->image_base && target_va < image_end )
                continue;

            if ( seen.count( target_va ) )
                continue;
            seen[ target_va ] = true;

            pe::call_site_t site{};
            site.call_va = sec_va + ( i - instr_len );
            site.target_va = target_va;
            site.indirect = indirect;

            const auto it = exp_map.find( target_va );
            if ( it != exp_map.end( ) )
            {
                site.resolved = true;
                site.module = it->second.module;
                site.function = it->second.function;
                site.ordinal = it->second.ordinal;
            }

            results.push_back( std::move( site ) );
        }
    }

    return results;
}

pe::arch_t pe::get_arch( const pe::context_t* ctx )
{
    return ctx->arch;
}

std::uint64_t pe::get_image_base( const pe::context_t* ctx )
{
    return ctx->image_base;
}

std::size_t pe::get_image_size( const pe::context_t* ctx )
{
    if ( ctx->is_64bit( ) && ctx->nt64 )
        return ctx->nt64->OptionalHeader.SizeOfImage;
    if ( ctx->nt32 )
        return ctx->nt32->OptionalHeader.SizeOfImage;
    return 0;
}

std::uint64_t pe::get_entry_point( const pe::context_t* ctx )
{
    std::uint32_t ep_rva = 0;
    if ( ctx->is_64bit( ) && ctx->nt64 )
        ep_rva = ctx->nt64->OptionalHeader.AddressOfEntryPoint;
    else if ( ctx->nt32 )
        ep_rva = ctx->nt32->OptionalHeader.AddressOfEntryPoint;
    return ep_rva ? ctx->image_base + ep_rva : 0;
}

uint16_t pe::get_characteristics( const pe::context_t* ctx )
{
    if ( ctx->is_64bit( ) && ctx->nt64 )
        return ctx->nt64->FileHeader.Characteristics;
    if ( ctx->nt32 )
        return ctx->nt32->FileHeader.Characteristics;
    return 0;
}

uint16_t pe::get_subsystem( const pe::context_t* ctx )
{
    if ( ctx->is_64bit( ) && ctx->nt64 )
        return ctx->nt64->OptionalHeader.Subsystem;
    if ( ctx->nt32 )
        return ctx->nt32->OptionalHeader.Subsystem;
    return 0;
}

const pe::section_t* pe::find_section( const pe::context_t* ctx, const char* name )
{
    for ( const auto& s : ctx->sections )
    {
        if ( std::strncmp( s.name, name, IMAGE_SIZEOF_SHORT_NAME ) == 0 )
            return &s;
    }
    return nullptr;
}

const pe::export_t* pe::find_export_by_name( const pe::context_t* ctx, const char* name )
{
    for ( const auto& e : ctx->exports )
    {
        if ( e.name == name )
            return &e;
    }
    return nullptr;
}

const pe::export_t* pe::find_export_by_ordinal( const pe::context_t* ctx, std::uint32_t ordinal )
{
    for ( const auto& e : ctx->exports )
    {
        if ( e.ordinal == ordinal )
            return &e;
    }
    return nullptr;
}

const pe::section_t* pe::rva_to_section( const pe::context_t* ctx, std::uint32_t rva )
{
    for ( const auto& s : ctx->sections )
    {
        if ( rva >= s.virtual_address && rva < s.virtual_address + s.virtual_size )
            return &s;
    }
    return nullptr;
}

std::uint32_t pe::rva_to_raw_offset( const pe::context_t* ctx, std::uint32_t rva )
{
    const pe::section_t* sec = pe::rva_to_section( ctx, rva );
    if ( !sec )
        return 0;
    return sec->raw_offset + ( rva - sec->virtual_address );
}

std::uint64_t pe::rva_to_va( const pe::context_t* ctx, std::uint32_t rva )
{
    return rva ? ctx->image_base + rva : 0;
}

std::uint32_t pe::va_to_rva( const pe::context_t* ctx, std::uint64_t va )
{
    if ( va < ctx->image_base )
        return 0;
    return static_cast< std::uint32_t >( va - ctx->image_base );
}

const IMAGE_DATA_DIRECTORY* pe::get_data_dir( const pe::context_t* ctx, DWORD idx )
{
    if ( idx >= IMAGE_NUMBEROF_DIRECTORY_ENTRIES )
        return nullptr;
    if ( ctx->is_64bit( ) && ctx->nt64 )
        return &ctx->nt64->OptionalHeader.DataDirectory[ idx ];
    if ( ctx->nt32 )
        return &ctx->nt32->OptionalHeader.DataDirectory[ idx ];
    return nullptr;
}
