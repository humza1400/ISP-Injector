#include <windows.h>
#include <tlhelp32.h>
#include <string>
#include "imgui.h"
#include "backends/imgui_impl_dx11.h"
#include "backends/imgui_impl_win32.h"
#include <d3d11.h>
#include <commdlg.h>
#include <windowsx.h>

#pragma comment(lib, "d3d11.lib")
#pragma comment(lib, "dxgi.lib")
#pragma comment(lib, "Comdlg32.lib")

namespace Util {
    //------------------------------------------------------------
    // Helper: Convert a wide string to a UTF-8 encoded narrow string
    std::string ConvertWideToString(const std::wstring& wstr) {
        int size = WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), -1, nullptr, 0, nullptr, nullptr);
        if (size <= 0) return "";
        std::string result(size, 0);
        WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), -1, &result[0], size, nullptr, nullptr);
        result.resize(size - 1);  // Remove the extra null character.
        return result;
    }

    //------------------------------------------------------------
    // Helper: Extract the file name (without path) from a full path
    std::string GetFileName(const std::string& fullPath) {
        size_t pos = fullPath.find_last_of("\\/");
        if (pos != std::string::npos)
            return fullPath.substr(pos + 1);
        return fullPath;
    }
} // namespace Util

//------------------------------------------------------------
// InjectorApp class: Manages DLL injection UI and state
class InjectorApp {
    HWND hwnd;
    char dllPath[MAX_PATH] = { 0 };
    bool dllInjected = false;  // Tracks whether injection has been performed
    bool darkTheme = true;

    // Holds the last detected RotMG process ID (0 if not found)
    DWORD rotmgPid = 0;

    // Scans for rotmg process (case-insensitive)
    DWORD DetectRotMGProcess() {
        DWORD foundPid = 0;
        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snapshot == INVALID_HANDLE_VALUE)
            return 0;

        PROCESSENTRY32 pe;
        pe.dwSize = sizeof(pe);
        if (Process32First(snapshot, &pe)) {
            do {
                std::wstring wname(pe.szExeFile);
                std::string procName = Util::ConvertWideToString(wname);
                if (_stricmp(procName.c_str(), "rotmg exalt.exe") == 0) {
                    foundPid = pe.th32ProcessID;
                    break;
                }
            } while (Process32Next(snapshot, &pe));
        }
        CloseHandle(snapshot);
        return foundPid;
    }

    // Shows the file explorer dialog to let the user choose a DLL
    void ShowBrowseDialog() {
        OPENFILENAMEA ofn;
        char szFile[MAX_PATH] = { 0 };
        ZeroMemory(&ofn, sizeof(ofn));
        ofn.lStructSize = sizeof(ofn);
        ofn.hwndOwner = hwnd;
        ofn.lpstrFile = szFile;
        ofn.nMaxFile = sizeof(szFile);
        ofn.lpstrFilter = "DLL Files\0*.dll\0";
        ofn.nFilterIndex = 1;
        ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST;

        if (GetOpenFileNameA(&ofn)) {
            strcpy_s(dllPath, szFile);
        }
    }

    // Attempt to inject the specified DLL into the process with the given PID
    bool InjectDLL(DWORD pid, const char* path) {
        HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
        if (!hProcess)
            return false;

        size_t pathLen = strlen(path) + 1;
        LPVOID alloc = VirtualAllocEx(hProcess, nullptr, pathLen, MEM_COMMIT, PAGE_READWRITE);
        if (!alloc) {
            CloseHandle(hProcess);
            return false;
        }

        if (!WriteProcessMemory(hProcess, alloc, path, pathLen, nullptr)) {
            VirtualFreeEx(hProcess, alloc, 0, MEM_RELEASE);
            CloseHandle(hProcess);
            return false;
        }

        HANDLE hThread = CreateRemoteThread(hProcess, nullptr, 0,
            (LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA"),
            alloc, 0, nullptr);

        if (!hThread) {
            VirtualFreeEx(hProcess, alloc, 0, MEM_RELEASE);
            CloseHandle(hProcess);
            return false;
        }

        WaitForSingleObject(hThread, INFINITE);
        VirtualFreeEx(hProcess, alloc, 0, MEM_RELEASE);
        CloseHandle(hThread);
        CloseHandle(hProcess);
        return true;
    }

    // Remove the injected DLL by calling its exported UnloadDLL function
    bool UninjectDLL(DWORD processID, const char* dllPath) {
        std::string dllName = Util::GetFileName(dllPath);
        HMODULE hRemoteModule = GetRemoteModuleHandle(processID, dllName.c_str());
        if (!hRemoteModule)
            return false;  // DLL not found in process

        HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processID);
        if (!hProcess)
            return false;

        // Load the DLL locally (without running its DllMain) to compute the function offset.
        HMODULE hLocalModule = LoadLibraryExA(dllPath, NULL, DONT_RESOLVE_DLL_REFERENCES);
        if (!hLocalModule) {
            CloseHandle(hProcess);
            return false;
        }

        FARPROC pLocalUnload = GetProcAddress(hLocalModule, "UnloadDLL");
        if (!pLocalUnload) {
            FreeLibrary(hLocalModule);
            CloseHandle(hProcess);
            return false;
        }

        DWORD_PTR offset = (DWORD_PTR)pLocalUnload - (DWORD_PTR)hLocalModule;
        FARPROC pRemoteUnload = (FARPROC)((DWORD_PTR)hRemoteModule + offset);
        FreeLibrary(hLocalModule);

        HANDLE hThread = CreateRemoteThread(hProcess, nullptr, 0,
            (LPTHREAD_START_ROUTINE)pRemoteUnload, nullptr, 0, nullptr);
        if (!hThread) {
            CloseHandle(hProcess);
            return false;
        }

        WaitForSingleObject(hThread, INFINITE);
        CloseHandle(hThread);
        CloseHandle(hProcess);
        return true;
    }

    // Gets the handle to the module in the remote process
    HMODULE GetRemoteModuleHandle(DWORD processID, const char* moduleName) {
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, processID);
        if (hSnapshot == INVALID_HANDLE_VALUE)
            return nullptr;

        MODULEENTRY32 moduleEntry;
        moduleEntry.dwSize = sizeof(MODULEENTRY32);
        HMODULE result = nullptr;
        if (Module32First(hSnapshot, &moduleEntry)) {
            do {
                std::wstring wModuleName(moduleEntry.szModule);
                std::string narrowModuleName = Util::ConvertWideToString(wModuleName);
                if (_stricmp(narrowModuleName.c_str(), moduleName) == 0) {
                    result = moduleEntry.hModule;
                    break;
                }
            } while (Module32Next(hSnapshot, &moduleEntry));
        }
        CloseHandle(hSnapshot);
        return result;
    }

    // Draws a custom title bar with a close and minimize button.
    void DrawCustomTitleBar() {
        ImVec2 windowPos = ImGui::GetWindowPos();
        ImVec2 windowSize = ImGui::GetWindowSize();

        // Draw the background for the title bar.
        ImGui::GetWindowDrawList()->AddRectFilled(
            windowPos,
            ImVec2(windowPos.x + windowSize.x, windowPos.y + 30),
            IM_COL32(45, 45, 48, 255) // Dark gray background
        );

        // Draw title text.
        ImGui::SetCursorPos(ImVec2(8, 5));
        ImGui::Text("ISP Injector");

        // Position the buttons on the same line on the right.
        float btnSize = 20.0f;
        float spacing = 4.0f;
        float xPos = windowSize.x - (btnSize + spacing) * 2 - 8;
        ImGui::SameLine(xPos);
        ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(0, 0));

        if (ImGui::Button("_", ImVec2(btnSize, btnSize))) {
            PostMessage(hwnd, WM_SYSCOMMAND, SC_MINIMIZE, 0);
        }
        ImGui::SameLine();
        if (ImGui::Button("X", ImVec2(btnSize, btnSize))) {
            PostMessage(hwnd, WM_SYSCOMMAND, SC_CLOSE, 0);
        }
        ImGui::PopStyleVar();

        // Move the cursor below the title bar.
        ImGui::SetCursorPosY(30);
    }

public:
    InjectorApp(HWND window) : hwnd(window) {}

    // Renders the ImGui UI.
    void RenderUI() {
        if (darkTheme)
            ImGui::StyleColorsDark();

        RECT rect;
        GetClientRect(hwnd, &rect);
        float appWidth = static_cast<float>(rect.right - rect.left);
        float appHeight = static_cast<float>(rect.bottom - rect.top);
        ImVec2 windowSize(400, 300);
        ImVec2 centeredPos((appWidth - windowSize.x) * 0.5f, (appHeight - windowSize.y) * 0.5f);
        ImGui::SetNextWindowPos(centeredPos, ImGuiCond_Always);
        ImGui::SetNextWindowSize(windowSize, ImGuiCond_Always);

        ImGui::Begin("ISP Injector", nullptr,
            ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoTitleBar);

        DrawCustomTitleBar();

        // Update process status.
        rotmgPid = DetectRotMGProcess();
        std::string procStatus;
        if (dllInjected)
            procStatus = "DLL Injected";
        else if (rotmgPid != 0)
            procStatus = "RotMG Detected";
        else
            procStatus = "RotMG Not Detected";
        ImGui::Text("Status: %s", procStatus.c_str());

        ImGui::Separator();
        ImGui::Text("DLL");
        {
            std::string fileName = Util::GetFileName(dllPath);
            char fileNameBuffer[256] = { 0 };
            strcpy_s(fileNameBuffer, fileName.c_str());
            ImGui::InputText("##DLLPath", fileNameBuffer, sizeof(fileNameBuffer), ImGuiInputTextFlags_ReadOnly);
        }

        if (ImGui::Button("Browse"))
            ShowBrowseDialog();

        ImGui::Separator();
        bool canInject = (rotmgPid != 0) && (dllPath[0] != '\0') && (!dllInjected);
        bool canUninject = dllInjected;

        ImGui::BeginDisabled(!canInject);
        if (ImGui::Button("Inject")) {
            if (InjectDLL(rotmgPid, dllPath))
                dllInjected = true;
        }
        ImGui::EndDisabled();

        ImGui::SameLine();
        ImGui::BeginDisabled(!canUninject);
        if (ImGui::Button("Uninject")) {
            if (UninjectDLL(rotmgPid, dllPath))
                dllInjected = false;
        }
        ImGui::EndDisabled();

        ImGui::End();
    }
};

//------------------------------------------------------------
// Win32 message procedure. Also passes messages to ImGui.
extern IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(HWND, UINT, WPARAM, LPARAM);
LRESULT CALLBACK WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    if (msg == WM_NCHITTEST) {
        LRESULT hit = DefWindowProc(hWnd, msg, wParam, lParam);
        if (hit == HTCLIENT) {
            POINT pt = { GET_X_LPARAM(lParam), GET_Y_LPARAM(lParam) };
            ScreenToClient(hWnd, &pt);
            RECT rc;
            GetClientRect(hWnd, &rc);
            int reservedWidth = 60;
            if (pt.y < 50 && pt.x < (rc.right - reservedWidth))
                return HTCAPTION;
        }
        return hit;
    }

    if (ImGui_ImplWin32_WndProcHandler(hWnd, msg, wParam, lParam))
        return true;

    switch (msg) {
    case WM_SIZE:
        break;
    case WM_SYSCOMMAND:
        if ((wParam & 0xfff0) == SC_KEYMENU)
            return 0;
        break;
    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProc(hWnd, msg, wParam, lParam);
}

//------------------------------------------------------------
// WinMain: Sets up the OS window, Direct3D, ImGui, and runs the main loop.
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE, LPSTR, int nCmdShow) {
    WNDCLASSEX wc = { sizeof(WNDCLASSEX), CS_CLASSDC, WndProc, 0L, 0L,
                      GetModuleHandle(nullptr), nullptr, nullptr, nullptr, nullptr,
                      L"ImGuiInjector", nullptr };
    ::RegisterClassEx(&wc);

    HWND hwnd = ::CreateWindow(wc.lpszClassName, L"ISP Injector",
        WS_POPUP | WS_VISIBLE,
        100, 100, 400, 300,
        nullptr, nullptr, wc.hInstance, nullptr);

    ShowWindow(hwnd, nCmdShow);
    UpdateWindow(hwnd);

    DXGI_SWAP_CHAIN_DESC sd = {};
    sd.BufferCount = 2;
    sd.BufferDesc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
    sd.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
    sd.OutputWindow = hwnd;
    sd.SampleDesc.Count = 1;
    sd.Windowed = TRUE;
    sd.SwapEffect = DXGI_SWAP_EFFECT_DISCARD;

    ID3D11Device* device = nullptr;
    ID3D11DeviceContext* context = nullptr;
    IDXGISwapChain* swapChain = nullptr;
    D3D_FEATURE_LEVEL featureLevel;

    if (FAILED(D3D11CreateDeviceAndSwapChain(
        nullptr,
        D3D_DRIVER_TYPE_HARDWARE,
        nullptr,
        0,
        nullptr,
        0,
        D3D11_SDK_VERSION,
        &sd,
        &swapChain,
        &device,
        &featureLevel,
        &context))) {
        MessageBoxW(nullptr, L"Failed to create D3D device", L"Error", MB_ICONERROR);
        return 1;
    }

    ID3D11RenderTargetView* mainRenderTarget = nullptr;
    ID3D11Texture2D* backBuffer = nullptr;
    swapChain->GetBuffer(0, IID_PPV_ARGS(&backBuffer));
    if (backBuffer) {
        device->CreateRenderTargetView(backBuffer, nullptr, &mainRenderTarget);
        backBuffer->Release();
    }

    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGuiIO& io = ImGui::GetIO();
    io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;
    io.IniFilename = nullptr;
    ImGui_ImplWin32_Init(hwnd);
    ImGui_ImplDX11_Init(device, context);

    InjectorApp app(hwnd);
    bool running = true;
    while (running) {
        MSG msg;
        while (::PeekMessage(&msg, nullptr, 0U, 0U, PM_REMOVE)) {
            if (msg.message == WM_QUIT)
                running = false;
            ::TranslateMessage(&msg);
            ::DispatchMessage(&msg);
        }

        ImGui_ImplDX11_NewFrame();
        ImGui_ImplWin32_NewFrame();
        ImGui::NewFrame();

        app.RenderUI();

        ImGui::Render();
        const float clearColor[] = { 0.1f, 0.1f, 0.1f, 1.0f };
        context->OMSetRenderTargets(1, &mainRenderTarget, nullptr);
        context->ClearRenderTargetView(mainRenderTarget, clearColor);
        ImGui_ImplDX11_RenderDrawData(ImGui::GetDrawData());
        swapChain->Present(1, 0);
    }

    ImGui_ImplDX11_Shutdown();
    ImGui_ImplWin32_Shutdown();
    ImGui::DestroyContext();

    if (swapChain) swapChain->Release();
    if (mainRenderTarget) mainRenderTarget->Release();
    if (device) device->Release();
    if (context) context->Release();

    ::DestroyWindow(hwnd);
    ::UnregisterClass(wc.lpszClassName, wc.hInstance);
    return 0;
}
