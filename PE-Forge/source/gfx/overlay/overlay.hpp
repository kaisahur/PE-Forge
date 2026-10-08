#pragma once
#define STB_IMAGE_IMPLEMENTATION
#include <d3d11.h>
#include <dwmapi.h>
#include <windows.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <thread>

namespace overlay
{
    inline HWND g_hwnd = nullptr;

    inline ID3D11Device* g_pd3d_device = nullptr;
    inline ID3D11DeviceContext* g_pd3d_device_context = nullptr;
    inline IDXGISwapChain* g_p_swap_chain = nullptr;
    inline UINT g_resize_width = 0, g_resize_height = 0;
    inline ID3D11RenderTargetView* g_main_render_target_view = nullptr;

    void tick( );
    void cleanup_device_d3d( );
    void create_render_target( );
    void cleanup_render_target( );
    bool create_device_d3d( HWND hwnd );
}  // namespace overlay