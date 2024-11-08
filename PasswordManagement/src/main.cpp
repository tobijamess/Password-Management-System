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
#include <Windows.h>
#define NOMINMAX

// Create and redirect output to a console window for debugging
void AttachConsoleOutput() {
    AllocConsole();  // Allocate a new console
    FILE* consoleOutput;
    freopen_s(&consoleOutput, "CONOUT$", "w", stdout);  // Redirect standard output to the console
    freopen_s(&consoleOutput, "CONOUT$", "w", stderr);  // Redirect standard error to the console
}

// Declare function that is defined in separate .cpp to allow ImGui to process windows messages like user inputs from mouse and keyboard
extern IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);

// Window procedure to handle window events
LRESULT WINAPI WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    // Passes each event to the ImGui handler (ImGui_ImplWin32_WndProcHandler) which gives priority to ImGui over other event handling
    // This gives ImGui priority over other event handling to make sure mouse clicks and inputs are handled by ImGui
    if (ImGui_ImplWin32_WndProcHandler(hWnd, msg, wParam, lParam))
        return true; // Returns true if ImGui successfully handles the event

    switch (msg) {
        // WM_SIZE case is triggered when application window is resized
    case WM_SIZE:
        // Checks the direct3d device is initalized and that the window isn't minimized
        if (d3dDevice && wParam != SIZE_MINIMIZED) {
            // Clears any existing direct3d resources
            ImGui_ImplDX9_InvalidateDeviceObjects();
            // Set up direct3d environment
            D3DPRESENT_PARAMETERS d3dpp = {};
            // Start direct3d environment (window) in windowed mode
            d3dpp.Windowed = TRUE;
            // Define how the backbuffer gets discarded once it has been displayed
            d3dpp.SwapEffect = D3DSWAPEFFECT_DISCARD;
            // Let direct3d choose the appropriate back buffer format
            d3dpp.BackBufferFormat = D3DFMT_UNKNOWN;
            // Reduce latency by not waiting for vsync
            d3dpp.PresentationInterval = D3DPRESENT_INTERVAL_IMMEDIATE;
            // Reset and reinitalize the direct3d device with the above settings
            d3dDevice->Reset(&d3dpp);
            // Recreate the ImGui resources after the direct3d device has been reset and reinitalized
            // To make sure the UI is displayed correctly
            ImGui_ImplDX9_CreateDeviceObjects();
        }
        break;
        // WM_DESTROY is triggered when application window is closed
    case WM_DESTROY:
        // Posts WM_QUIT to the message queue to exit the application
        PostQuitMessage(0);
        return 0;
    }
    // If none of these cases match (msg), default windows procedure is called to handle it
    return DefWindowProc(hWnd, msg, wParam, lParam);
}

// Function to create the main application window
HWND CreateMainWindow(HINSTANCE hInstance) {
    // Define className variable to hold the name of the window class to be registered (L prefix because its a unicode string)
    const wchar_t* className = L"MainWindowClass";
    // Initalize instance of WNDCLASS struct to zero
    WNDCLASS wc = {};
    // Choose WndProc as the window procedure for handling events like resizing
    wc.lpfnWndProc = WndProc;
    // Assign hInstance (current instance handle) to wc.hInstance for window management
    wc.hInstance = hInstance;
    // Set the class name so it can be referenced when a window is created
    wc.lpszClassName = className;
    // Register the WNDCLASS structure so a window of this class can be created in the below return function
    RegisterClass(&wc);
    // CreateWindowEx creates the actual window and returns its handle
    // Parameters: 0 = default window style, className = window class, Password Manager = window title, WS_OVERLAPPEDWINDOW = standard window style (borders, titlebar etc.)
    // Parameters: CW_USEDEFAULT = default x, y positions, 800, 600 = window width and height, nullptr = parent window handle (null because this is the main window)
    // Parameters: nullptr = menu handle (null because no menu is defined), hInstance = application instance, nullptr = no more parameters
    return CreateWindowEx(
        0, className, L"Password Manager", WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, CW_USEDEFAULT, 800, 600, nullptr, nullptr, hInstance, nullptr);
}

// WinMain entry point for a Windows application
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    // Create main application window and store its handle in hwnd object
    HWND hwnd = CreateMainWindow(hInstance);
    // If window creation failed, output error
    if (!hwnd) {
        std::cerr << "Window creation failed." << std::endl;
        return -1;
    }
    // Display window with handle (hwnd) and display state (nCmdShow)
    ShowWindow(hwnd, nCmdShow);
    // Call InitalizeUI() to set up ImGui UI environment
    if (!InitializeUI(hwnd)) {
        std::cerr << "UI initialization failed." << std::endl;
        return -1;
    }
    // Create an instance of MSG structure 
    MSG msg = {};
    // Main message loop, runs as long as the msg instance received isn't WM_QUIT
    while (msg.message != WM_QUIT) {
        // Check for a message without blocking
        if (PeekMessage(&msg, nullptr, 0, 0, PM_REMOVE)) {
            // If there is an available message, translate it and dispatch it to WndProc
            TranslateMessage(&msg);
            DispatchMessage(&msg);
        }
        else {
            // If no message was available, render a new frame of the UI (to make sure UI is responsive even when idle)
            RenderUI();
        }
    }
    // Clean up UI resources
    CleanupUI();
    // Release the console output if one was allocated
    FreeConsole();
    // Exit
    return 0;
}