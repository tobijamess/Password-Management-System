#include "imgui.h"
#include "imgui_impl_dx9.h"
#include "imgui_impl_win32.h"
#include <d3d9.h>

#ifndef UI_H
#define UI_H

#include <d3d9.h>
#include <Windows.h>

// Declare d3d, d3dDevice, and hwnd as extern variables
extern LPDIRECT3D9 d3d;
extern LPDIRECT3DDEVICE9 d3dDevice;
extern HWND hwnd;

// Function declarations for UI initialization, rendering, and cleanup
bool InitializeUI(HWND windowHandle);
void RenderUI();
void CleanupUI();

#endif