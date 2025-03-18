# ISP Injector

ISP Injector is a lightweight Windows DLL injection tool with a custom GUI built using DirectX 11 and [ImGui](https://github.com/ocornut/imgui). It allows you to inject and uninject DLLs into a target process (by default, **rotmg exalt.exe**) with a few simple clicks.

This was initially created for my Shaders project for the game "Realm of the Mad God" but turns out to be a helpful utility injector for whenever you need to inject DLLs into processes.

> **Note:** The DLL you intend to inject must export an `UnloadDLL` function to allow proper uninjecting. Injecting should work fine with all DLLs.

![ISP-Injector](https://cdn.discordapp.com/attachments/1048373938486526012/1351661173640265789/image.png?ex=67db3010&is=67d9de90&hm=5540fc1b04f94830b0487382d74456c29ddca5e8ef90ff60ebab69dfa225f657&)

## Features

- **DLL Injection/Uninjection:**  
  Easily inject and remove a DLL from a target process.

- **Simple But Clean GUI:**  
  A clutter-free, user-friendly interface built with ImGui.

- **Automatic Process Detection:**  
  Scans for the target process (e.g., "rotmg exalt.exe") and updates the UI status accordingly.

- **DirectX 11 Rendering:**  
  Uses Direct3D 11 for efficient rendering of the UI. Direct3D 11 was chosen because Realm of the Mad God happened to use the same API.

## Requirements

- **Operating System:** Windows 7 or later.
- **Compiler:** Visual Studio 2019/2022 or any C++ compiler that supports C++17.
- **Dependencies:**
  - [ImGui](https://github.com/ocornut/imgui) (included in the repository via the `backends/` folder)
  - DirectX 11 (typically included with the Windows SDK)
  - Windows SDK

## Building the Project

1. **Clone the Repository:**

   ```bash
   git clone https://github.com/humza1400/ISP-Injector.git
   cd ISPInjector
   ```

2. **Configure Dependencies**:
   - Ensure that the ImGui library (and its DirectX 11/Win32 backends) is properly referenced.
   - The project automatically links against DirectX 11 and the required Windows libraries via `#pragma comment`.
3. **Build**
   - Choose your build configuration (Debug/Release) and compile the project.


## Usage

1. **Run the Injector:**
   - Launch the built executable. The custom window will appear with the ISP Injector interface.
2. **Select a DLL:**
   - Click the Browse button to open a file dialog and choose the DLL you want to inject.
3. **Inject/Uninject:**
   - If the target process is detected, the Inject button will be enabled. Click it to inject your DLL.
Once injected, the Uninject button becomes available. Click it to remove the DLL by calling its UnloadDLL export.

## Additional Notes
   - **DLL Requirements:**
The DLL you inject should export an UnloadDLL function. This function is used by the injector to safely remove the DLL from the target process.
   - **Error Handling:**
The code performs basic error checking (e.g., ensuring handles are valid and allocations succeed). In critical failure cases (like a failure to create the Direct3D device), a message box is displayed.

## Contributing
Contributions are welcome! If you have ideas for improvements or bug fixes, please fork the repository and open a pull request. For major changes, feel free to open an issue first to discuss your ideas.
