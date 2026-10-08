#include <dump/dump.hpp>
#include <gfx/interface/interface.hpp>

void draw_process_panel( )
{
    ImGui::Text( "Process" );
    ImGui::SameLine( );
    if ( ImGui::Button( "Refresh" ) )
        dump::refresh_processes( );

    ImGui::SetNextItemWidth( -1.f );
    ImGui::InputTextWithHint( "##filt", "filter...", dump::g_state->filter, sizeof dump::g_state->filter );

    const float list_h = ImGui::GetContentRegionAvail( ).y * 0.35f;
    ImGui::BeginChild( "##pl", { 0.f, list_h }, true );

    for ( int i = 0; i < ( int )dump::g_state->proc_list.size( ); ++i )
    {
        const auto& p = dump::g_state->proc_list[ i ];

        if ( p.pid == 0 )
            continue;

        char name_a[ 260 ];
        WideCharToMultiByte( CP_UTF8, 0, p.name, -1, name_a, sizeof name_a, nullptr, nullptr );

        if ( dump::g_state->filter[ 0 ] && !strstr( name_a, dump::g_state->filter ) )
            continue;

        char label[ 300 ];
        snprintf( label, sizeof label, "%-28s %5lu", name_a, p.pid );

        if ( ImGui::Selectable( label, dump::g_state->selected == i, ImGuiSelectableFlags_SpanAllColumns ) )
        {
            dump::g_state->selected = i;
            dump::g_state->pid = ( DWORD )p.pid;

            HANDLE h = memory::open_process( dump::g_state->pid );
            if ( h )
            {
                dump::g_state->base = memory::get_image_base( h );
                memory::close_process( h );
            }
            else
                dump::g_state->base = 0;

            dump::launch( dump::task_load_all );
        }
    }

    ImGui::EndChild( );

    if ( dump::g_state->pid )
    {
        ImGui::TextColored( u_interface::dim, "pid" );
        ImGui::SameLine( );
        ImGui::TextColored( u_interface::address, "%lu", dump::g_state->pid );
        ImGui::SameLine( 0.f, 12.f );
        ImGui::TextColored( u_interface::dim, "image base" );
        ImGui::SameLine( );
        ImGui::TextColored( u_interface::address, "0x%llx", ( unsigned long long )dump::g_state->base );
    }
}

void draw_options_panel( )
{
    ImGui::Separator( );
    ImGui::Text( "Options" );

    ImGui::Checkbox( "Rebuild Imports", &dump::g_state->opt_imports );
    ImGui::Checkbox( "Fix Relocs", &dump::g_state->opt_relocs );
    ImGui::Checkbox( "Suspend", &dump::g_state->opt_suspend );
    ImGui::Checkbox( "Force Read (Unsafe)", &dump::g_state->opt_force );
    ImGui::Checkbox( "Bruteforce Guarded Pages", &dump::g_state->opt_bf );

    if ( dump::g_state->opt_bf )
        ImGui::TextColored( u_interface::warn, " polls NOACCESS until readable" );
}

void draw_actions_panel( )
{
    const bool busy = dump::g_state->busy.load( );

    ImGui::Text( "Dump" );

    ImGui::SetNextItemWidth( -1.f );
    ImGui::InputText( "##path", dump::g_state->out_path, sizeof dump::g_state->out_path );

    if ( busy )
        ImGui::BeginDisabled( );
    if ( ImGui::Button( "Dump PE", { -1.f, 0.f } ) )
        dump::launch( dump::task_dump );
    if ( busy )
        ImGui::EndDisabled( );

    if ( busy )
    {
        if ( ImGui::Button( "Stop", { -1.f, 0.f } ) )
            dump::g_state->stop = true;
        ImGui::TextColored( u_interface::warn, " working..." );
    }
}

void draw_log( )
{
    ImGui::BeginChild( "##log", { 0.f, 0.f }, false, ImGuiWindowFlags_HorizontalScrollbar );
    {
        std::lock_guard lk( dump::g_state->log_mx );
        for ( const auto& e : dump::g_state->log_buf )
        {
            const ImVec4& col = e.level == dump::log_level_t::error  ? u_interface::error
                                : e.level == dump::log_level_t::warn ? u_interface::warn
                                                                     : u_interface::info;
            ImGui::TextColored( col, "%s", e.text.c_str( ) );
        }
        if ( dump::g_state->log_scroll )
        {
            ImGui::SetScrollHereY( 1.0f );
            dump::g_state->log_scroll = false;
        }
    }
    ImGui::EndChild( );
}

void draw_sections( )
{
    if ( dump::g_state->sections.empty( ) )
    {
        return;
    }

    ImGui::Text( "%zu section(s)", dump::g_state->sections.size( ) );
    ImGui::Separator( );

    if ( ImGui::BeginTable(
             "##s",
             6,
             ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY | ImGuiTableFlags_SizingFixedFit |
                 ImGuiTableFlags_Resizable ) )
    {
        ImGui::TableSetupScrollFreeze( 0, 1 );
        ImGui::TableSetupColumn( "Name", ImGuiTableColumnFlags_WidthFixed, 90 );
        ImGui::TableSetupColumn( "VirtualAddress", ImGuiTableColumnFlags_WidthFixed, 100 );
        ImGui::TableSetupColumn( "VirtualSize", ImGuiTableColumnFlags_WidthFixed, 90 );
        ImGui::TableSetupColumn( "RawOffset", ImGuiTableColumnFlags_WidthFixed, 90 );
        ImGui::TableSetupColumn( "RawSize", ImGuiTableColumnFlags_WidthFixed, 90 );
        ImGui::TableSetupColumn( "Flags", ImGuiTableColumnFlags_WidthStretch );
        ImGui::TableHeadersRow( );

        for ( const auto& section : dump::g_state->sections )
        {
            ImGui::TableNextRow( );
            ImGui::TableSetColumnIndex( 0 );
            ImGui::TextColored( u_interface::module, "%s", section.name );
            ImGui::TableSetColumnIndex( 1 );
            ImGui::TextColored( u_interface::address, "0x%llx", section.virtual_address );
            ImGui::TableSetColumnIndex( 2 );
            ImGui::TextColored( u_interface::address, "0x%llx", section.virtual_size );
            ImGui::TableSetColumnIndex( 3 );
            ImGui::TextColored( u_interface::address, "0x%llx", section.raw_offset );
            ImGui::TableSetColumnIndex( 4 );
            ImGui::TextColored( u_interface::address, "0x%llx", section.raw_size );
            ImGui::TableSetColumnIndex( 5 );
            char flags[ 32 ] = {};
            if ( section.is_code( ) )
                strcat_s( flags, "CODE " );
            if ( section.is_executable( ) )
                strcat_s( flags, "EXECUTE " );
            if ( section.is_readable( ) )
                strcat_s( flags, "R" );
            if ( section.is_writable( ) )
                strcat_s( flags, "W" );
            if ( section.is_discardable( ) )
                strcat_s( flags, " DISCARDABLE" );
            ImGui::TextColored( u_interface::dim, "%s", flags );
        }

        ImGui::EndTable( );
    }
}

void draw_imports( )
{
    if ( dump::g_state->imports.empty( ) )
    {
        return;
    }

    size_t total = 0;
    for ( auto& m : dump::g_state->imports )
        total += m.thunks.size( );
    ImGui::Text( "%zu module(s) %zu import(s)", dump::g_state->imports.size( ), total );
    ImGui::Separator( );

    if ( ImGui::BeginTable(
             "##i",
             3,
             ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY | ImGuiTableFlags_SizingFixedFit |
                 ImGuiTableFlags_Resizable ) )
    {
        ImGui::TableSetupScrollFreeze( 0, 1 );
        ImGui::TableSetupColumn( "Module", ImGuiTableColumnFlags_WidthFixed, 180 );
        ImGui::TableSetupColumn( "Function", ImGuiTableColumnFlags_WidthStretch );
        ImGui::TableSetupColumn( "Ordinal", ImGuiTableColumnFlags_WidthFixed, 60 );
        ImGui::TableHeadersRow( );

        for ( const auto& mod : dump::g_state->imports )
        {
            for ( const auto& th : mod.thunks )
            {
                ImGui::TableNextRow( );
                ImGui::TableSetColumnIndex( 0 );
                ImGui::TextColored( u_interface::module, "%s", mod.name.c_str( ) );
                ImGui::TableSetColumnIndex( 1 );
                if ( th.is_ordinal )
                    ImGui::TextColored( u_interface::dim, "<ordinal>" );
                else
                    ImGui::TextColored( u_interface::function, "%s", th.name.c_str( ) );
                ImGui::TableSetColumnIndex( 2 );
                ImGui::TextColored( u_interface::dim, "%u", ( unsigned )th.ordinal );
            }
        }

        ImGui::EndTable( );
    }
}

void draw_exports( )
{
    if ( dump::g_state->exports.empty( ) )
    {
        return;
    }

    ImGui::Text( "%zu export(s)", dump::g_state->exports.size( ) );
    ImGui::Separator( );

    if ( ImGui::BeginTable(
             "##e",
             4,
             ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY | ImGuiTableFlags_SizingFixedFit |
                 ImGuiTableFlags_Resizable ) )
    {
        ImGui::TableSetupScrollFreeze( 0, 1 );
        ImGui::TableSetupColumn( "Ordinal", ImGuiTableColumnFlags_WidthFixed, 70 );
        ImGui::TableSetupColumn( "RVA", ImGuiTableColumnFlags_WidthFixed, 100 );
        ImGui::TableSetupColumn( "Name", ImGuiTableColumnFlags_WidthStretch );
        ImGui::TableSetupColumn( "Forward", ImGuiTableColumnFlags_WidthFixed, 200 );
        ImGui::TableHeadersRow( );

        for ( const auto& e : dump::g_state->exports )
        {
            ImGui::TableNextRow( );
            ImGui::TableSetColumnIndex( 0 );
            ImGui::TextColored( u_interface::dim, "%u", e.ordinal );
            ImGui::TableSetColumnIndex( 1 );
            ImGui::TextColored( u_interface::address, "0x%08X", e.rva );
            ImGui::TableSetColumnIndex( 2 );
            ImGui::TextColored( u_interface::function, "%s", e.name.c_str( ) );
            ImGui::TableSetColumnIndex( 3 );
            if ( e.is_forwarded )
                ImGui::TextColored( u_interface::module, "%s", e.forward_name.c_str( ) );
        }

        ImGui::EndTable( );
    }
}

const char* prot_str( DWORD p )
{
    p &= ~( PAGE_GUARD | PAGE_NOCACHE | PAGE_WRITECOMBINE );
    switch ( p )
    {
        case PAGE_NOACCESS: return "NOACCESS";
        case PAGE_READONLY: return "READONLY";
        case PAGE_READWRITE: return "READWRITE";
        case PAGE_WRITECOPY: return "WRITECOPY";
        case PAGE_EXECUTE: return "EXECUTE";
        case PAGE_EXECUTE_READ: return "EXECUTE_READ";
        case PAGE_EXECUTE_READWRITE: return "EXECUTE_READWRITE";
        case PAGE_EXECUTE_WRITECOPY: return "EXECUTE_WRITECOPY";
        default: return "?";
    }
}

void draw_regions( )
{
    if ( dump::g_state->regions.empty( ) )
    {
        return;
    }

    ImGui::Text( "%zu region(s)", dump::g_state->regions.size( ) );
    ImGui::Separator( );

    if ( ImGui::BeginTable(
             "##r",
             5,
             ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY | ImGuiTableFlags_SizingFixedFit |
                 ImGuiTableFlags_Resizable ) )
    {
        ImGui::TableSetupScrollFreeze( 0, 1 );
        ImGui::TableSetupColumn( "Base", ImGuiTableColumnFlags_WidthFixed, 145 );
        ImGui::TableSetupColumn( "Size", ImGuiTableColumnFlags_WidthFixed, 100 );
        ImGui::TableSetupColumn( "State", ImGuiTableColumnFlags_WidthFixed, 80 );
        ImGui::TableSetupColumn( "Protect", ImGuiTableColumnFlags_WidthFixed, 100 );
        ImGui::TableSetupColumn( "Type", ImGuiTableColumnFlags_WidthFixed, 70 );
        ImGui::TableHeadersRow( );

        for ( const auto& r : dump::g_state->regions )
        {
            ImGui::TableNextRow( );
            ImGui::TableSetColumnIndex( 0 );
            ImGui::TextColored( u_interface::address, "0x%llx", ( unsigned long long )r.base );
            ImGui::TableSetColumnIndex( 1 );
            ImGui::TextColored( u_interface::dim, "0x%llx", ( unsigned long long )r.size );
            ImGui::TableSetColumnIndex( 2 );
            ImGui::TextColored(
                r.is_committed( ) ? u_interface::info : u_interface::dim,
                r.is_committed( )  ? "COMMIT"
                : r.is_reserved( ) ? "RESERVED"
                                   : "FREE" );
            ImGui::TableSetColumnIndex( 3 );
            ImGui::TextColored( r.protect == PAGE_NOACCESS ? u_interface::error : u_interface::warn, "%s", prot_str( r.protect ) );
            ImGui::TableSetColumnIndex( 4 );
            ImGui::TextColored( u_interface::dim, r.is_image( ) ? "IMAGE" : r.is_mapped( ) ? "MAPPED" : "PRIVATE" );
        }

        ImGui::EndTable( );
    }
}

void u_interface::draw( )
{
    const auto display = ImGui::GetIO( ).DisplaySize;

    ImGui::SetNextWindowPos( { ( display.x - 1060.f ) * 0.5f, ( display.y - 660.f ) * 0.5f }, ImGuiCond_Once );
    ImGui::SetNextWindowSize( { 1060.f, 660.f } );

    ImGui::Begin( "PE Forge", nullptr, ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoCollapse );

    const float h = ImGui::GetContentRegionAvail( ).y;

    ImGui::BeginChild( "##left", { 280.f, h }, true );
    draw_process_panel( );
    draw_options_panel( );
    draw_actions_panel( );
    ImGui::EndChild( );

    ImGui::SameLine( );

    ImGui::BeginChild( "##right", { -1.f, h }, true );
    ImGui::BeginChild( "##tabschild", ImVec2( 0, h * 0.65f ), true );

    if ( ImGui::BeginTabBar( "##tabs" ) )
    {
        auto tab_flags = [ & ]( int idx ) -> ImGuiTabItemFlags
        { return dump::g_state->active_tab == idx ? ImGuiTabItemFlags_SetSelected : ImGuiTabItemFlags_None; };

        auto on_open = [ & ]( int idx )
        {
            if ( dump::g_state->active_tab == idx )
                dump::g_state->active_tab = -1;
        };

        if ( ImGui::BeginTabItem( "Sections", nullptr, tab_flags( 0 ) ) )
        {
            on_open( 0 );
            draw_sections( );
            ImGui::EndTabItem( );
        }
        if ( ImGui::BeginTabItem( "Imports", nullptr, tab_flags( 1 ) ) )
        {
            on_open( 1 );
            draw_imports( );
            ImGui::EndTabItem( );
        }
        if ( ImGui::BeginTabItem( "Exports", nullptr, tab_flags( 2 ) ) )
        {
            on_open( 2 );
            draw_exports( );
            ImGui::EndTabItem( );
        }
        if ( ImGui::BeginTabItem( "Regions", nullptr, tab_flags( 3 ) ) )
        {
            on_open( 3 );
            draw_regions( );
            ImGui::EndTabItem( );
        }

        ImGui::EndTabBar( );
    }

    ImGui::EndChild( );
    ImGui::BeginChild( "##logchild", ImVec2( 0, 0 ), true );

    draw_log( );

    ImGui::EndChild( );
    ImGui::EndChild( );
    ImGui::End( );
}
