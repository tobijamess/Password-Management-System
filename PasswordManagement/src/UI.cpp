#include "imgui.h"
#include <iostream>
#include <chrono>
#include <algorithm>
#include "imgui_impl_dx9.h"
#include "imgui_impl_win32.h"
#include "d3d9.h"

#include "user.h"
#include "database.h"
#include "encryption.h"
#include "pwdManager.h"
#include "pwdStrength.h"
#include "recovery.h"
#include "smtp.h"
#include "util.h"

LPDIRECT3D9 d3d = NULL;
LPDIRECT3DDEVICE9 d3dDevice = NULL;
HWND hwnd = NULL;

enum Scene {
    MAIN_MENU,
    CREATE_ACCOUNT,
    LOGIN,
    FORGOT_PASSWORD,
    RECOVERY_SENT,
    RESET_PASSWORD,
    PASSWORD_MANAGER,
    ADD_PASSWORD,
    VIEW_PASSWORDS
};

Scene currentScene = MAIN_MENU;
PasswordManager pm("");

bool InitializeUI(HWND windowHandle) {
    d3d = Direct3DCreate9(D3D_SDK_VERSION);
    if (!d3d) {
        std::cerr << "Direct3D initialization failed." << std::endl;
        return false;
    }

    D3DPRESENT_PARAMETERS d3dpp = {};
    d3dpp.Windowed = TRUE;
    d3dpp.SwapEffect = D3DSWAPEFFECT_DISCARD;
    d3dpp.BackBufferFormat = D3DFMT_UNKNOWN;
    d3dpp.PresentationInterval = D3DPRESENT_INTERVAL_IMMEDIATE;

    if (d3d->CreateDevice(D3DADAPTER_DEFAULT, D3DDEVTYPE_HAL, windowHandle,
        D3DCREATE_SOFTWARE_VERTEXPROCESSING, &d3dpp, &d3dDevice) < 0) {
        std::cerr << "Direct3D device creation failed." << std::endl;
        return false;
    }

    ImGui::CreateContext();
    ImGui::StyleColorsDark();
    ImGui_ImplWin32_Init(windowHandle);
    ImGui_ImplDX9_Init(d3dDevice);

    return true;
}

void CheckDeviceLost() {
    HRESULT result = d3dDevice->TestCooperativeLevel();
    if (result == D3DERR_DEVICELOST) {
        return; // Device is lost, wait until it can be reset
    }
    else if (result == D3DERR_DEVICENOTRESET) {
        // Reset the device
        D3DPRESENT_PARAMETERS d3dpp = {};
        d3dpp.Windowed = TRUE;
        d3dpp.SwapEffect = D3DSWAPEFFECT_DISCARD;
        d3dpp.BackBufferFormat = D3DFMT_UNKNOWN;
        d3dpp.PresentationInterval = D3DPRESENT_INTERVAL_IMMEDIATE;
        if (d3dDevice->Reset(&d3dpp) == D3D_OK) {
            ImGui_ImplDX9_InvalidateDeviceObjects();
            ImGui_ImplDX9_CreateDeviceObjects();
        }
    }
}

// Center input fields with labels wrapping them
void CenteredInputField(const char* label, const char* inputID, char* buffer, size_t bufferSize, bool isPassword = false) {
    // Dynamically set width based on window size
    ImGuiIO& io = ImGui::GetIO();
    float windowWidth = io.DisplaySize.x;

    // Widths of label and input field, calculated based on window width for responsiveness
    float labelWidth = min(windowWidth * 0.15f, 150.0f);       // Cap label width at 150 pixels
    float inputFieldWidth = min(windowWidth * 0.35f, 400.0f);  // Cap input field width at 400 pixels

    // Calculate total width and center alignment
    float totalWidth = labelWidth + inputFieldWidth + ImGui::GetStyle().ItemSpacing.x;
    float offsetX = (windowWidth - totalWidth) / 2;

    // Center label and input field with calculated widths
    ImGui::SetCursorPosX(offsetX);
    ImGui::PushItemWidth(labelWidth);
    ImGui::Text("%s", label);
    ImGui::PopItemWidth();

    ImGui::SameLine();
    ImGui::SetCursorPosX(offsetX + labelWidth + ImGui::GetStyle().ItemSpacing.x);
    ImGui::PushItemWidth(inputFieldWidth);

    if (isPassword) {
        ImGui::InputText(inputID, buffer, bufferSize, ImGuiInputTextFlags_Password);
    }
    else {
        ImGui::InputText(inputID, buffer, bufferSize);
    }
    ImGui::PopItemWidth();
}

std::string statusMessage = "";
std::chrono::steady_clock::time_point messageStartTime;
float messageDisplayDuration = 3.0f; // Display message for 3 seconds

void ShowStatusMessage(const std::string& message) {
    statusMessage = message;
    messageStartTime = std::chrono::steady_clock::now();
}

void RenderUI() {
    CheckDeviceLost();

    d3dDevice->Clear(0, nullptr, D3DCLEAR_TARGET, D3DCOLOR_XRGB(59, 47, 47), 1.0f, 0);
    ImGui_ImplDX9_NewFrame();
    ImGui_ImplWin32_NewFrame();
    ImGui::NewFrame();

    ImGuiIO& io = ImGui::GetIO();
    ImVec2 windowSize = io.DisplaySize;

    ImGui::SetNextWindowPos(ImVec2(0, 0));
    ImGui::SetNextWindowSize(windowSize);
    ImGui::SetNextWindowBgAlpha(0.0f);

    ImGui::Begin("Password Manager", nullptr, ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_NoResize);

    static char usernameBuffer[64] = "";
    static char emailBuffer[64] = "";
    static char recoveryCodeBuffer[8] = "";
    static char masterPasswordBuffer[64] = "";
    static char confirmPasswordBuffer[64] = "";

    static bool authenticated = false;
    static User loggedInUser;

    // Show status message if present
    if (!statusMessage.empty()) {
        auto currentTime = std::chrono::steady_clock::now();
        std::chrono::duration<float> elapsedTime = currentTime - messageStartTime;
        if (elapsedTime.count() < messageDisplayDuration) {
            ImGui::TextWrapped("%s", statusMessage.c_str());
        }
        else {
            statusMessage = "";  // Clear the message after the duration
        }
    }

    // Center buttons and input fields with relative sizes
    ImVec2 buttonSize(windowSize.x * 0.2f, windowSize.y * 0.05f);  // Buttons are 20% of width, 5% of height

    switch (currentScene) {
    case MAIN_MENU:
        ImGui::SetCursorPos(ImVec2((windowSize.x - buttonSize.x) / 2, windowSize.y * 0.2f));
        ImGui::Text("Welcome to the Password Manager!");

        ImGui::SetCursorPosX((windowSize.x - buttonSize.x) / 2);  // Center "Create Account" button
        if (ImGui::Button("Create Account", buttonSize)) {
            currentScene = CREATE_ACCOUNT;
        }
        ImGui::SetCursorPosX((windowSize.x - buttonSize.x) / 2);  // Center "Log In" button
        if (ImGui::Button("Log In", buttonSize)) {
            currentScene = LOGIN;
        }
        break;

    case CREATE_ACCOUNT:
        ImGui::Text("Create Account");
        CenteredInputField("Username", "##username", usernameBuffer, IM_ARRAYSIZE(usernameBuffer));
        CenteredInputField("Email", "##email", emailBuffer, IM_ARRAYSIZE(emailBuffer));
        CenteredInputField("Master Password", "##masterPassword", masterPasswordBuffer, IM_ARRAYSIZE(masterPasswordBuffer), true);
        CenteredInputField("Confirm Password", "##confirmPassword", confirmPasswordBuffer, IM_ARRAYSIZE(confirmPasswordBuffer), true);

        ImGui::SetCursorPosX((windowSize.x - buttonSize.x) / 2);  // Center "Confirm" button
        if (ImGui::Button("Confirm", buttonSize)) {
            std::string username(usernameBuffer);
            std::string email(emailBuffer);
            std::string masterPassword(masterPasswordBuffer);

            if (Database::fileExists(username)) {
                ShowStatusMessage("This account already exists.");
            }
            else if (evaluatePasswordStrength(masterPassword) == Weak) {
                ShowStatusMessage("Weak password. Choose another.");
            }
            else {
                User user(username, email);
                if (user.saveUserData(masterPassword)) {
                    ShowStatusMessage("Account Created Successfully!");
                    currentScene = MAIN_MENU;
                }
                else {
                    ShowStatusMessage("Failed to save user data.");
                }
            }
        }
        ImGui::SetCursorPosX((windowSize.x - buttonSize.x) / 2);  // Center "Back" button
        if (ImGui::Button("Back", buttonSize)) {
            currentScene = MAIN_MENU;
        }
        break;

    case LOGIN:
        ImGui::Text("Log In");
        CenteredInputField("Username", "##username", usernameBuffer, IM_ARRAYSIZE(usernameBuffer));
        CenteredInputField("Master Password", "##masterPassword", masterPasswordBuffer, IM_ARRAYSIZE(masterPasswordBuffer), true);

        ImGui::SetCursorPosX((windowSize.x - buttonSize.x) / 2);  // Center "Login" button
        if (ImGui::Button("Login", buttonSize)) {
            std::string username(usernameBuffer);
            std::string masterPassword(masterPasswordBuffer);

            User user(username, masterPassword);
            if (user.loadUserData(masterPassword, false)) {
                loggedInUser = user; // Store the authenticated user
                pm.loadDatabase(Database(loggedInUser.getUsername()).loadPasswordDatabase());
                authenticated = true;
                currentScene = PASSWORD_MANAGER;
            }
            else {
                ShowStatusMessage("Authentication failed.");
            }
            break;
        }
        ImGui::SetCursorPosX((windowSize.x - buttonSize.x) / 2);  // Center "Forgot Password" button
        if (ImGui::Button("Forgot Password", buttonSize)) {
            currentScene = FORGOT_PASSWORD;
        }
        ImGui::SetCursorPosX((windowSize.x - buttonSize.x) / 2);  // Center "Back" button
        if (ImGui::Button("Back", buttonSize)) {
            currentScene = MAIN_MENU;
        }
        break;

    case FORGOT_PASSWORD:
        ImGui::Text("Forgot Password");
        ImGui::Text("WARNING: Resetting your password will cause your stored passwords to be wiped.");
        CenteredInputField("Username", "##username", usernameBuffer, IM_ARRAYSIZE(usernameBuffer));
        ImGui::SetCursorPosX((windowSize.x - buttonSize.x) / 2);

        if (ImGui::Button("Send Recovery Email")) {
            std::string username(usernameBuffer);
            User user(username, "");
            if (user.loadUserData("", true)) {
                std::string email = user.getEmail();
                std::string recoveryCode = generateRecoveryCode();
                Database(username).setRecoveryStatus(username, true, recoveryCode);

                if (sendRecoveryEmail(email, recoveryCode)) {
                    ShowStatusMessage("Recovery email sent.");
                    currentScene = RECOVERY_SENT;
                }
                else {
                    ShowStatusMessage("Failed to send recovery email.");
                }
            }
            else {
                ShowStatusMessage("User not found.");
            }
        }
        ImGui::SetCursorPosX((windowSize.x - buttonSize.x) / 2);
        if (ImGui::Button("Back")) {
            currentScene = LOGIN;
        }
        break;

    case RECOVERY_SENT:
        ImGui::Text("Enter Recovery Code:");
        ImGui::Text("Check your spam folder if you cannot find it.");
        CenteredInputField("Recovery Code", "##recoverycode", recoveryCodeBuffer, IM_ARRAYSIZE(recoveryCodeBuffer));

        ImGui::SetCursorPosX((windowSize.x - buttonSize.x) / 2);
        if (ImGui::Button("Submit")) {
            std::string username(usernameBuffer);
            std::string enteredCode(recoveryCodeBuffer);
            if (Database(username).validateRecoveryCode(username, enteredCode)) {
                currentScene = RESET_PASSWORD;
            }
            else {
                ShowStatusMessage("Invalid recovery code.");
            }
        }
        break;

    case RESET_PASSWORD:
        ImGui::Text("Reset Master Password");
        CenteredInputField("New Master Password", "##newmasterpassword", masterPasswordBuffer, IM_ARRAYSIZE(masterPasswordBuffer), ImGuiInputTextFlags_Password);
        CenteredInputField("Confirm New Password", "##confirmnewpassword", confirmPasswordBuffer, IM_ARRAYSIZE(confirmPasswordBuffer), ImGuiInputTextFlags_Password);

        ImGui::SetCursorPosX((windowSize.x - buttonSize.x) / 2);
        if (ImGui::Button("Reset Password")) {
            if (strcmp(masterPasswordBuffer, confirmPasswordBuffer) == 0) {
                std::string username(usernameBuffer);
                std::string newMasterPassword(masterPasswordBuffer);
                User user(username, "");
                Database(username).clearPasswords();
                user.saveUserData(newMasterPassword);
                Database(username).setRecoveryStatus(username, false);
                ShowStatusMessage("Password reset successfully.");
                currentScene = MAIN_MENU;
            }
            else {
                ShowStatusMessage("Passwords do not match.");
            }
        }
        break;

    case PASSWORD_MANAGER:
        ImGui::Text("--- Password Manager Menu ---");

        ImGui::SetCursorPosX((windowSize.x - buttonSize.x) / 2);
        if (ImGui::Button("Add New Password")) {
            currentScene = ADD_PASSWORD;
        }
        ImGui::SetCursorPosX((windowSize.x - buttonSize.x) / 2);
        if (ImGui::Button("View Stored Passwords")) {
            currentScene = VIEW_PASSWORDS;
        }
        ImGui::SetCursorPosX((windowSize.x - buttonSize.x) / 2);
        if (ImGui::Button("Log Out")) {
            authenticated = false;
            currentScene = MAIN_MENU;
        }
        break;

    case ADD_PASSWORD: {
        static std::string account, password, generatedPassword;
        static char accountBuffer[64] = "";
        static char passwordBuffer[128] = "";
        static int passwordChoice = 0;
        static int length = 12;
        static bool showGeneratedPassword = false;

        ImGui::Text("Add New Password");
        CenteredInputField("Account or App Name", "##accountorappname", accountBuffer, IM_ARRAYSIZE(accountBuffer));

        ImGui::SetCursorPosX((windowSize.x - buttonSize.x) / 2);
        ImGui::RadioButton("Enter your password", &passwordChoice, 1);
        ImGui::SetCursorPosX((windowSize.x - buttonSize.x) / 2);
        ImGui::RadioButton("Generate a secure password", &passwordChoice, 2);

        if (passwordChoice == 1) {
            CenteredInputField("Your Password", "##yourpassword", passwordBuffer, sizeof(passwordBuffer), ImGuiInputTextFlags_Password);
        }
        else if (passwordChoice == 2) {
            ImGui::InputInt("Password Length", &length);

            ImGui::SetCursorPosX((windowSize.x - buttonSize.x) / 2);
            if (ImGui::Button("Generate Password")) {
                generatedPassword = generateSecurePassword(length);
                showGeneratedPassword = true;
            }
            if (showGeneratedPassword) {
                ImGui::Text("Generated Password: %s", generatedPassword.c_str());
                password = generatedPassword;
            }
        }

        ImGui::SetCursorPosX((windowSize.x - buttonSize.x) / 2);
        if (ImGui::Button("Save Password")) {
            account = accountBuffer;
            if (passwordChoice == 1) password = passwordBuffer;

            if (evaluatePasswordStrength(password) == Weak) {
                ShowStatusMessage("Weak password. Choose another.");
            }
            else {
                pm.addPassword(account, password);
                Database db(loggedInUser.getUsername());
                if (db.savePasswordDatabase(pm.getPasswordDatabase())) {
                    ShowStatusMessage("Password added successfully!");
                }
                else {
                    ShowStatusMessage("Failed to save password.");
                }
            }
        }
        ImGui::SetCursorPosX((windowSize.x - buttonSize.x) / 2);
        if (ImGui::Button("Back")) {
            currentScene = PASSWORD_MANAGER;
        }
        break;
    }

    case VIEW_PASSWORDS: {
        ImGui::Text("--- Viewing Stored Passwords ---");

        const auto& db = pm.getPasswordDatabase();
        if (db.empty()) {
            ShowStatusMessage("No passwords stored.");
        }
        else {
            for (const auto& entry : db) {
                std::string decryptedPassword = pm.getPassword(entry.first);
                ImGui::Text("Account: %s, Password: %s", entry.first.c_str(), decryptedPassword.c_str());
            }
        }

        ImGui::SetCursorPosX((windowSize.x - buttonSize.x) / 2);
        if (ImGui::Button("Back")) {
            currentScene = PASSWORD_MANAGER;
        }
        break;
    }
    }

    ImGui::End();
    ImGui::EndFrame();
    ImGui::Render();
    d3dDevice->BeginScene();
    ImGui_ImplDX9_RenderDrawData(ImGui::GetDrawData());
    d3dDevice->EndScene();
    d3dDevice->Present(NULL, NULL, NULL, NULL);
}

void CleanupUI() {
    ImGui_ImplDX9_Shutdown();
    ImGui_ImplWin32_Shutdown();
    ImGui::DestroyContext();
    if (d3dDevice) { d3dDevice->Release(); d3dDevice = NULL; }
    if (d3d) { d3d->Release(); d3d = NULL; }
}
