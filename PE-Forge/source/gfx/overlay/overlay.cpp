#include <imgui/backends/imgui_impl_dx11.h>
#include <imgui/backends/imgui_impl_win32.h>
#include <imgui/imgui.h>
#include <imgui/imgui_internal.h>
#include <imgui/misc/imgui_freetype.h>

#include <gfx/overlay/overlay.hpp>
#include <gfx/interface/interface.hpp>

#pragma comment( lib, "winmm.lib" )

LRESULT WINAPI wnd_proc( HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam );

void overlay::tick( )
{
    ImGui_ImplWin32_EnableDpiAwareness( );
    float main_scale = ImGui_ImplWin32_GetDpiScaleForMonitor( ::MonitorFromPoint( POINT{ 0, 0 }, MONITOR_DEFAULTTOPRIMARY ) );
    WNDCLASSEX wc = {};

    wc.cbClsExtra = NULL;
    wc.cbSize = sizeof( WNDCLASSEX );
    wc.cbWndExtra = NULL;
    wc.hbrBackground = ( HBRUSH )CreateSolidBrush( RGB( 0, 0, 0 ) );
    wc.hCursor = LoadCursor( nullptr, IDC_ARROW );
    wc.hIcon = LoadIcon( nullptr, IDI_APPLICATION );
    wc.hIconSm = LoadIcon( nullptr, IDI_APPLICATION );
    wc.hInstance = GetModuleHandle( nullptr );
    wc.lpfnWndProc = wnd_proc;
    wc.lpszClassName = "PE-Forge";
    wc.lpszMenuName = nullptr;
    wc.style = CS_VREDRAW | CS_HREDRAW;

    ::RegisterClassEx( &wc );
    const HWND hwnd = ::CreateWindowEx(
        WS_EX_TOPMOST | WS_EX_TRANSPARENT | WS_EX_NOACTIVATE,
        wc.lpszClassName,
        "PE-Forge",
        WS_POPUP,
        0,
        0,
        GetSystemMetrics( SM_CXSCREEN ),
        GetSystemMetrics( SM_CYSCREEN ),
        nullptr,
        nullptr,
        wc.hInstance,
        nullptr );
    g_hwnd = hwnd;

    if ( !create_device_d3d( hwnd ) )
    {
        cleanup_device_d3d( );
        ::UnregisterClass( wc.lpszClassName, wc.hInstance );
        return;
    }

    ::ShowWindow( hwnd, SW_SHOWDEFAULT );
    ::UpdateWindow( hwnd );

    IMGUI_CHECKVERSION( );
    ImGui::CreateContext( );
    ImGuiIO& io = ImGui::GetIO( );
    io.IniFilename = nullptr;

    ImGui_ImplWin32_Init( hwnd );
    ImGui_ImplDX11_Init( g_pd3d_device, g_pd3d_device_context );

    ImGui::StyleColorsDark( );
    ImGui::GetStyle( ).ScaleAllSizes( main_scale );

    const unsigned int freetype_flags = ImGuiFreeTypeLoaderFlags_MonoHinting | ImGuiFreeTypeLoaderFlags_Monochrome;
    io.Fonts->SetFontLoader( ImGuiFreeType::GetFontLoader( ) );
    io.Fonts->FontLoaderFlags = freetype_flags;

    const MARGINS margin = { -1, 0, 0, 0 };
    DwmExtendFrameIntoClientArea( hwnd, &margin );

    bool done = false;
    bool menu_open = true;
    bool insert_key_down_prev = false;

    timeBeginPeriod( 1 );

    while ( !done )
    {
        MSG msg;
        while ( ::PeekMessage( &msg, nullptr, 0U, 0U, PM_REMOVE ) )
        {
            ::TranslateMessage( &msg );
            ::DispatchMessage( &msg );
            if ( msg.message == WM_QUIT )
            {
                done = true;
            }
        }
        if ( done )
        {
            break;
        }

        bool insert_key_down = ( GetAsyncKeyState( VK_INSERT ) & 0x8000 ) != 0;
        if ( insert_key_down && !insert_key_down_prev )
        {
            menu_open = !menu_open;
        }
        insert_key_down_prev = insert_key_down;

        LONG_PTR ex_style = GetWindowLongPtr( hwnd, GWL_EXSTYLE );
        if ( menu_open )
        {
            SetWindowLongPtr( hwnd, GWL_EXSTYLE, ex_style & ~( WS_EX_TRANSPARENT | WS_EX_LAYERED ) );
        }
        else
        {
            SetWindowLongPtr( hwnd, GWL_EXSTYLE, ex_style | WS_EX_TRANSPARENT | WS_EX_LAYERED );
        }

        const float clear_color[ 4 ] = { 0.f, 0.f, 0.f, 0.f };
        g_pd3d_device_context->OMSetRenderTargets( 1, &g_main_render_target_view, nullptr );
        g_pd3d_device_context->ClearRenderTargetView( g_main_render_target_view, clear_color );

        ImGui_ImplDX11_NewFrame( );
        ImGui_ImplWin32_NewFrame( );
        ImGui::NewFrame( );

        if ( menu_open )
        {
            u_interface::draw( );
        }

        ImGui::Render( );
        ImGui_ImplDX11_RenderDrawData( ImGui::GetDrawData( ) );
        g_p_swap_chain->Present( 1, 0 );

        std::this_thread::yield( );
    }
    timeEndPeriod( 1 );

    ImGui_ImplDX11_Shutdown( );
    ImGui_ImplWin32_Shutdown( );
    ImGui::DestroyContext( );
    cleanup_device_d3d( );
    ::DestroyWindow( hwnd );
    ::UnregisterClass( wc.lpszClassName, wc.hInstance );
}

bool overlay::create_device_d3d( HWND hwnd )
{
    DXGI_SWAP_CHAIN_DESC sd;
    ZeroMemory( &sd, sizeof( sd ) );
    sd.BufferCount = 2;
    sd.BufferDesc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
    sd.Flags = DXGI_SWAP_CHAIN_FLAG_ALLOW_MODE_SWITCH;
    sd.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
    sd.OutputWindow = hwnd;
    sd.SampleDesc.Count = 1;
    sd.Windowed = TRUE;
    sd.SwapEffect = DXGI_SWAP_EFFECT_DISCARD;

    D3D_FEATURE_LEVEL feature_level;
    const D3D_FEATURE_LEVEL feature_level_array[] = { D3D_FEATURE_LEVEL_11_0 };
    HRESULT res = D3D11CreateDeviceAndSwapChain(
        nullptr,
        D3D_DRIVER_TYPE_HARDWARE,
        nullptr,
        0,
        feature_level_array,
        1,
        D3D11_SDK_VERSION,
        &sd,
        &g_p_swap_chain,
        &g_pd3d_device,
        &feature_level,
        &g_pd3d_device_context );

    if ( res != S_OK )
    {
        return false;
    }

    create_render_target( );
    return true;
}

void overlay::cleanup_device_d3d( )
{
    cleanup_render_target( );
    if ( g_p_swap_chain )
    {
        g_p_swap_chain->Release( );
        g_p_swap_chain = nullptr;
    }
    if ( g_pd3d_device_context )
    {
        g_pd3d_device_context->Release( );
        g_pd3d_device_context = nullptr;
    }
    if ( g_pd3d_device )
    {
        g_pd3d_device->Release( );
        g_pd3d_device = nullptr;
    }
}

void overlay::create_render_target( )
{
    ID3D11Texture2D* p_back_buffer;
    g_p_swap_chain->GetBuffer( 0, IID_PPV_ARGS( &p_back_buffer ) );
    if ( p_back_buffer )
    {
        g_pd3d_device->CreateRenderTargetView( p_back_buffer, nullptr, &g_main_render_target_view );
        p_back_buffer->Release( );
    }
}

void overlay::cleanup_render_target( )
{
    if ( g_main_render_target_view )
    {
        g_main_render_target_view->Release( );
        g_main_render_target_view = nullptr;
    }
}

extern IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler( HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam );

LRESULT WINAPI wnd_proc( HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam )
{
    if ( ImGui_ImplWin32_WndProcHandler( hwnd, msg, wparam, lparam ) )
    {
        return true;
    }

    switch ( msg )
    {
        case WM_SIZE:
            if ( wparam != SIZE_MINIMIZED )
            {
                overlay::g_resize_width = ( UINT )LOWORD( lparam );
                overlay::g_resize_height = ( UINT )HIWORD( lparam );
            }
            return 0;
        case WM_SYSCOMMAND:
            if ( ( wparam & 0xfff0 ) == SC_KEYMENU )
            {
                return 0;
            }
            break;
        case WM_DESTROY: ::PostQuitMessage( 0 ); return 0;
    }
    return ::DefWindowProcW( hwnd, msg, wparam, lparam );
}