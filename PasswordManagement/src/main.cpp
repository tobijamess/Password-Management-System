#include <iostream>
#include <iomanip>
#include <sstream>
#include <vector>
#include <limits>

#include "user.h"
#include "database.h"
#include "pwdManager.h"
#include "pwdStrength.h"
#include "util.h"
#include "recovery.h"

#include <openssl/rand.h>

#include "UI.h"

#define NOMINMAX
#include <Windows.h>

void AttachConsoleOutput() {
    
    AllocConsole();  // Allocate a new console
    FILE* consoleOutput;
    freopen_s(&consoleOutput, "CONOUT$", "w", stdout);  // Redirect standard output to the console
    freopen_s(&consoleOutput, "CONOUT$", "w", stderr);  // Redirect standard error to the console
}

extern IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);

// Window procedure to handle window events
LRESULT WINAPI WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    if (ImGui_ImplWin32_WndProcHandler(hWnd, msg, wParam, lParam))
        return true; // Ensures ImGui handles the input first

    switch (msg) {
    case WM_SIZE:
        if (d3dDevice && wParam != SIZE_MINIMIZED) {
            ImGui_ImplDX9_InvalidateDeviceObjects();
            D3DPRESENT_PARAMETERS d3dpp = {};
            d3dpp.Windowed = TRUE;
            d3dpp.SwapEffect = D3DSWAPEFFECT_DISCARD;
            d3dpp.BackBufferFormat = D3DFMT_UNKNOWN;
            d3dpp.PresentationInterval = D3DPRESENT_INTERVAL_IMMEDIATE;
            d3dDevice->Reset(&d3dpp);
            ImGui_ImplDX9_CreateDeviceObjects();
        }
        break;
    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProc(hWnd, msg, wParam, lParam);
}

// Function to create the main application window
HWND CreateMainWindow(HINSTANCE hInstance) {
    const wchar_t* className = L"MainWindowClass";
    WNDCLASS wc = {};
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInstance;
    wc.lpszClassName = className;

    RegisterClass(&wc);

    return CreateWindowEx(
        0, className, L"Password Manager", WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, CW_USEDEFAULT, 800, 600, nullptr, nullptr, hInstance, nullptr);
}

// WinMain entry point for a Windows application
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    // AttachConsoleOutput();
    HWND hwnd = CreateMainWindow(hInstance);
    if (!hwnd) {
        std::cerr << "Window creation failed." << std::endl;
        return -1;
    }
    ShowWindow(hwnd, nCmdShow);

    // Call your UI initialization with hwnd
    if (!InitializeUI(hwnd)) {
        std::cerr << "UI initialization failed." << std::endl;
        return -1;
    }

    // Main message loop
    MSG msg = {};
    while (msg.message != WM_QUIT) {
        if (PeekMessage(&msg, nullptr, 0, 0, PM_REMOVE)) {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
        }
        else {
            RenderUI();  // Render a frame when there are no messages
        }
    }

    CleanupUI();
    FreeConsole();
    return 0;
}