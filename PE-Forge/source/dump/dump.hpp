#pragma once

#include <Windows.h>
#include <memory/memory.h>
#include <pe/pe.h>

#include <atomic>
#include <cstdarg>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace dump
{
    enum class log_level_t
    {
        info,
        warn,
        error
    };

    struct log_entry_t
    {
        log_level_t level;
        std::string text;
    };

    struct state_t
    {
        std::vector< memory::proc_entry_t > proc_list;
        char filter[ 128 ]{};
        int selected = -1;
        DWORD pid = 0;
        uint64_t base = 0;

        bool opt_imports = true;
        bool opt_relocs = false;
        bool opt_suspend = false;
        bool opt_force = false;
        bool opt_bf = false;
        char out_path[ MAX_PATH ] = "output.exe";

        std::thread worker;
        std::atomic< bool > busy{ false };
        volatile bool stop = false;

        std::vector< log_entry_t > log_buf;
        std::mutex log_mx;
        bool log_scroll = true;

        std::vector< pe::section_t > sections;
        std::vector< pe::import_module_t > imports;
        std::vector< pe::export_t > exports;
        std::vector< memory::region_t > regions;
        std::vector< pe::call_site_t > calls;
        int active_tab = 0;

        void output( log_level_t lvl, const char* fmt, ... )
        {
            char buf[ 1024 ];
            va_list ap;
            va_start( ap, fmt );
            vsnprintf( buf, sizeof buf, fmt, ap );
            va_end( ap );
            std::lock_guard g( log_mx );
            log_buf.push_back( { lvl, buf } );
            log_scroll = true;
        }
    };

    inline std::unique_ptr< state_t > g_state = std::make_unique< state_t >();

    template< typename Fn >
    void launch( Fn&& fn )
    {
        if ( g_state->busy )
            return;
        g_state->stop = false;
        g_state->busy = true;
        if ( g_state->worker.joinable( ) )
            g_state->worker.join( );
        g_state->worker = std::thread( std::forward< Fn >( fn ) );
    }

    void task_dump( );
    void task_info( );
    void task_sections( );
    void task_imports( );
    void task_regions( );
    void task_load_all( );

    void initialize( );
    void refresh_processes( );
}  // namespace dump
