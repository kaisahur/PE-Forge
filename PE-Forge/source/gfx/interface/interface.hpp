#pragma once

#include <imgui/backends/imgui_impl_dx11.h>
#include <imgui/backends/imgui_impl_win32.h>
#include <imgui/imgui.h>
#include <imgui/imgui_internal.h>
#include <imgui/misc/imgui_freetype.h>

namespace u_interface
{
    inline constexpr ImVec4 info{ 0.90f, 0.90f, 0.90f, 1.0f };
    inline constexpr ImVec4 warn{ 1.00f, 0.85f, 0.10f, 1.0f };
    inline constexpr ImVec4 error{ 1.00f, 0.35f, 0.35f, 1.0f };
    inline constexpr ImVec4 address{ 0.35f, 1.00f, 0.50f, 1.0f };
    inline constexpr ImVec4 module{ 0.45f, 0.75f, 1.00f, 1.0f };
    inline constexpr ImVec4 function{ 1.00f, 0.85f, 0.50f, 1.0f };
    inline constexpr ImVec4 dim{ 0.55f, 0.55f, 0.55f, 1.0f };

    void draw( );
}  // namespace u_interface