# PE Forge
A Windows PE dumper and analyzer with an ImGui overlay UI. Enumerates and dumps PE images from running processes headers, sections, imports, exports, and memory regions using direct NT syscalls.

## Features

- **Overlay UI** — fullscreen transparent D3D11 overlay toggled with `Insert`
- **Process list** — live list of running processes with a filter box and one-click refresh
- **Auto-load** — selecting a process immediately resolves its image base and loads all PE data in a single background pass
- **PE inspection** — sections, imports, exports, and memory regions shown in tabbed tables
- **PE dump** — reconstructs the in-memory image and writes it to disk, with optional import table rebuild and relocation fixup
- **Read modes** — normal, force-read (temp-unprotects pages), and bruteforce (polls until NOACCESS pages become readable)
- **Process control** — optional suspend/resume around the dump pass
- **Direct syscalls** — all NT calls go through hand-rolled MASM stubs (Halo's Gate SSN resolution), bypassing the standard ntdll dispatch

## Requirements

- Windows 10 x64 or Windows 11
- Visual Studio 2022 with the MASM build tool (`ml64`)
- Administrator privileges (required to open process handles)

## Build

1. Open `PE-Forge.vcxproj` in Visual Studio 2022.
2. Select the **Release | x64** configuration.
3. Build (`Ctrl+Shift+B`).

## Usage

1. Run the binary as administrator.
2. Press `Insert` to open the overlay.
3. Select a process from the list (filter by name if needed). Headers, sections, imports, exports, and regions load automatically.
4. Review the tabs on the right panel.
5. Set an output path, configure options, and click **Dump PE** to write the reconstructed image to disk.

## Options

| Option | Effect |
|---|---|
| Rebuild Imports | Rewrites the import table in the dumped file |
| Fix Relocs | Applies base relocation fixups |
| Suspend | Suspends the target process during the dump pass |
| Force Read | Temporarily changes page protection to read otherwise-protected pages |
| Bruteforce | Polls NOACCESS pages until they become readable (for packed/guarded regions) |

## Project Structure

~~~
source/
  entry_point.cpp          — startup: syscall init, overlay loop
  memory/                  — process open/read/write, region query, syscall stubs (MASM)
  pe/                      — PE parsing, reconstruction, import rebuild, reloc fixup
  dump/                    — worker thread state, all background tasks
  gfx/overlay/             — D3D11 window, ImGui setup, render loop
  gfx/interface/           — ImGui layout and all UI panels
  console/                 — debug console output
  utilities/               — string helpers
vendors/
  imgui/                   — Dear ImGui (with FreeType)
  freetype/                — FreeType font rasterizer
~~~
