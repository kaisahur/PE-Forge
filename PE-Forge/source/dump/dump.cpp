#include <utilities/utilities.h>

#include <dump/dump.hpp>

namespace dump
{
    HANDLE open_process( )
    {
        if ( !g_state->pid )
        {
            g_state->output( log_level_t::error, "no process selected" );
            return nullptr;
        }
        HANDLE handle = memory::open_process( g_state->pid );
        if ( !handle )
            g_state->output( log_level_t::error, "failed to open pid %lu", g_state->pid );
        return handle;
    }

    pe::context_t* make_context( HANDLE handle )
    {
        auto* context = pe::create( handle, g_state->base );
        context->force_read = g_state->opt_force;
        context->bruteforce = g_state->opt_bf;
        context->bruteforce_stop = &g_state->stop;
        return context;
    }

    void task_dump( )
    {
        HANDLE handle = open_process( );
        if ( !handle )
        {
            g_state->busy = false;
            return;
        }

        const auto fin = [ & ]( pe::context_t* context )
        {
            if ( g_state->opt_suspend )
            {
                memory::resume_process( handle );
                g_state->output( log_level_t::info, "process resumed" );
            }
            if ( context )
                pe::destroy( context );
            memory::close_process( handle );
            g_state->busy = false;
        };

        auto* context = make_context( handle );

        if ( g_state->opt_suspend )
        {
            memory::suspend_process( handle );
            g_state->output( log_level_t::info, "process suspended" );
        }

        g_state->output( log_level_t::info, "parsing headers..." );
        if ( !pe::parse_headers( context ) )
        {
            g_state->output( log_level_t::error, "header parse failed" );
            fin( context );
            return;
        }
        g_state->output(
            log_level_t::info,
            "%s base 0x%llx, size %zu",
            context->is_64bit( ) ? "x64" : "x86",
            ( unsigned long long )context->image_base,
            pe::get_image_size( context ) );

        g_state->output( log_level_t::info, "parsing sections..." );
        if ( !pe::parse_sections( context ) )
        {
            g_state->output( log_level_t::error, "section parse failed" );
            fin( context );
            return;
        }
        g_state->output( log_level_t::info, "%zu section(s)", context->sections.size( ) );

        pe::parse_imports( context );
        {
            size_t n = 0;
            for ( auto& m : context->imports )
                n += m.thunks.size( );
            g_state->output( log_level_t::info, "%zu module(s), %zu import(s)", context->imports.size( ), n );
        }

        pe::parse_exports( context );
        g_state->output( log_level_t::info, "%zu export(s)", context->exports.size( ) );

        pe::parse_relocs( context );
        g_state->output( log_level_t::info, "%zu reloc block(s)", context->relocs.size( ) );

        g_state->output( log_level_t::info, "reconstructing..." );
        if ( !pe::reconstruct( context ) )
        {
            g_state->output( log_level_t::error, "reconstruction failed" );
            fin( context );
            return;
        }
        g_state->output( log_level_t::info, "%zu bytes", context->reconstructed.size( ) );

        if ( g_state->opt_imports && !context->imports.empty( ) )
        {
            g_state->output( log_level_t::info, "rebuilding imports..." );
            if ( !pe::rebuild_imports( context ) )
                g_state->output( log_level_t::warn, "import rebuild failed" );
            else
                g_state->output( log_level_t::info, "done" );
        }

        if ( g_state->opt_relocs )
        {
            if ( !pe::fixup_relocs( context ) )
                g_state->output( log_level_t::warn, "reloc fixup failed" );
            else
                g_state->output( log_level_t::info, "relocs applied" );
        }

        const auto wpath = utilities::convert_utf8_to_wide( g_state->out_path );
        g_state->output( log_level_t::info, "writing to %s...", g_state->out_path );
        if ( !pe::write_to_file( context, wpath.c_str( ) ) )
            g_state->output( log_level_t::error, "write failed" );
        else
            g_state->output( log_level_t::info, "done %zu bytes written", context->reconstructed.size( ) );

        fin( context );
    }

    void task_info( )
    {
        HANDLE handle = open_process( );
        if ( !handle )
        {
            g_state->busy = false;
            return;
        }

        auto* context = make_context( handle );

        if ( pe::parse_headers( context ) )
        {
            g_state->output( log_level_t::info, "arch %s", context->is_64bit( ) ? "x64" : "x86" );
            g_state->output( log_level_t::info, "image base 0x%llx", ( unsigned long long )context->image_base );
            g_state->output( log_level_t::info, "image size %zu", pe::get_image_size( context ) );
            g_state->output( log_level_t::info, "entry point 0x%llx", ( unsigned long long )pe::get_entry_point( context ) );

            const char* sub = "unknown";
            switch ( pe::get_subsystem( context ) )
            {
                case IMAGE_SUBSYSTEM_WINDOWS_GUI: sub = "Windows GUI"; break;
                case IMAGE_SUBSYSTEM_WINDOWS_CUI: sub = "Windows Console"; break;
                case IMAGE_SUBSYSTEM_NATIVE: sub = "Native"; break;
            }
            g_state->output( log_level_t::info, "subsystem %s", sub );
        }
        else
        {
            g_state->output( log_level_t::error, "failed to parse headers" );
        }

        pe::destroy( context );
        memory::close_process( handle );
        g_state->busy = false;
    }

    void task_sections( )
    {
        HANDLE handle = open_process( );
        if ( !handle )
        {
            g_state->busy = false;
            return;
        }

        auto* context = make_context( handle );

        if ( !pe::parse_headers( context ) || !pe::parse_sections( context ) )
        {
            g_state->output( log_level_t::error, "parse failed" );
            pe::destroy( context );
            memory::close_process( handle );
            g_state->busy = false;
            return;
        }

        g_state->sections = context->sections;
        g_state->active_tab = 0;
        g_state->output( log_level_t::info, "%zu section(s)", context->sections.size( ) );

        pe::destroy( context );
        memory::close_process( handle );
        g_state->busy = false;
    }

    void task_imports( )
    {
        HANDLE handle = open_process( );
        if ( !handle )
        {
            g_state->busy = false;
            return;
        }

        auto* context = make_context( handle );

        if ( !pe::parse_headers( context ) || !pe::parse_imports( context ) )
        {
            g_state->output( log_level_t::error, "parse failed" );
            pe::destroy( context );
            memory::close_process( handle );
            g_state->busy = false;
            return;
        }

        size_t n = 0;
        for ( auto& m : context->imports )
            n += m.thunks.size( );

        g_state->imports = context->imports;
        g_state->active_tab = 1;
        g_state->output( log_level_t::info, "%zu module(s), %zu import(s)", context->imports.size( ), n );

        pe::destroy( context );
        memory::close_process( handle );
        g_state->busy = false;
    }

    void task_exports( )
    {
        HANDLE handle = open_process( );
        if ( !handle )
        {
            g_state->busy = false;
            return;
        }

        auto* context = make_context( handle );

        if ( !pe::parse_headers( context ) || !pe::parse_exports( context ) )
        {
            g_state->output( log_level_t::error, "parse failed" );
            pe::destroy( context );
            memory::close_process( handle );
            g_state->busy = false;
            return;
        }

        g_state->exports = context->exports;
        g_state->active_tab = 2;
        g_state->output( log_level_t::info, "%zu export(s)", context->exports.size( ) );

        pe::destroy( context );
        memory::close_process( handle );
        g_state->busy = false;
    }

    void task_regions( )
    {
        HANDLE handle = open_process( );
        if ( !handle )
        {
            g_state->busy = false;
            return;
        }

        g_state->regions = memory::enum_regions( handle );
        g_state->active_tab = 3;
        g_state->output( log_level_t::info, "%zu region(s)", g_state->regions.size( ) );

        memory::close_process( handle );
        g_state->busy = false;
    }

    void task_load_all( )
    {
        HANDLE handle = open_process( );
        if ( !handle )
        {
            g_state->busy = false;
            return;
        }

        auto* context = make_context( handle );

        if ( !pe::parse_headers( context ) )
        {
            g_state->output( log_level_t::error, "header parse failed" );
            pe::destroy( context );
            memory::close_process( handle );
            g_state->busy = false;
            return;
        }

        g_state->output(
            log_level_t::info,
            "%s base 0x%llx size %zu",
            context->is_64bit( ) ? "x64" : "x86",
            ( unsigned long long )context->image_base,
            pe::get_image_size( context ) );

        pe::parse_sections( context );
        g_state->sections = context->sections;
        g_state->output( log_level_t::info, "%zu section(s)", context->sections.size( ) );

        pe::parse_imports( context );
        g_state->imports = context->imports;
        {
            size_t n = 0;
            for ( auto& m : context->imports )
                n += m.thunks.size( );
            g_state->output( log_level_t::info, "%zu module(s), %zu import(s)", context->imports.size( ), n );
        }

        pe::parse_exports( context );
        g_state->exports = context->exports;
        g_state->output( log_level_t::info, "%zu export(s)", context->exports.size( ) );

        pe::destroy( context );

        g_state->regions = memory::enum_regions( handle );
        g_state->output( log_level_t::info, "%zu region(s)", g_state->regions.size( ) );

        memory::close_process( handle );
        g_state->busy = false;
    }

    void initialize( )
    {
        memory::initialize( );
        refresh_processes( );
    }

    void refresh_processes( )
    {
        g_state->proc_list = memory::list_processes( );
        g_state->selected = -1;
        g_state->pid = 0;
        g_state->base = 0;
    }

}  // namespace dump
