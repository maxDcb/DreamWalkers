# DreamWalkers

> Reflective shellcode loader inspired by [MemoryModule](https://github.com/fancycode/MemoryModule) and [Donut](https://github.com/TheWover/donut), with advanced call stack spoofing and .NET support.

Check the blog post that is related: [DreamWalkers](https://maxdcb.github.io/DreamWalkers/)

Unlike traditional call stack spoofing, which often fails within reflectively loaded modules due to missing unwind metadata, DreamWalkers introduces a novel approach that enables clean and believable call stacks even during execution of shellcode-mapped payloads. By manually parsing the PE structure and registering custom unwind information via RtlAddFunctionTable, our loader restores proper stack unwinding — a capability that I didn't see achieved in reflective loading contexts. This allows our shellcode to blend in more effectively, even under the scrutiny of modern EDR and debugging tools.

![WithoutSpoofing](./images/WithoutSpoofing.png)

![WithoutRtlAddFunctionTable](./images/WithoutRtlAddFunctionTable.png)

![WithoutMS](./images/WithoutMS.png)

![CleanStack](./images/CleanStack.png)

---

## 🌘 Introduction

DreamWalkers is a research-grade project that blends ideas from Donut and MemoryModule to create a fully position-independent, reflective PE loader capable of clean call stack spoofing and modular payload execution — including .NET assemblies.

My goal was to understand how these components work under the hood, then reimplement and extend them with novel functionality. This includes position independence, command-line argument handling, .NET hosting using C++, and spoofed call stacks even in reflectively loaded code.

Big thanks to [@almounah](https://github.com/almounah) for his early support (even if he fell into the Go trap), and credit due to the original authors of Donut, MemoryModule, and [Being-A-Good-CLR-Host](https://github.com/passthehashbrowns/Being-A-Good-CLR-Host) as well as [SilentMoonwalk](https://github.com/klezVirus/SilentMoonwalk), LoudSunRun and others.

---

## 📦 Features

- 🧬 Position-independent shellcode extracted from a modified `MemoryModule`
- 🛠️ Shellcode generator inspired by Donut's stub generation
- 📝 Custom command-line argument handling for EXEs
- ☁️ .NET loader via intermediate native DLL (.NET logic not directly embedded in shellcode)
- 🎭 Clean and spoofed call stacks, even in reflectively loaded modules
- 🔥 Module stomping + unwind info registration using `RtlAddFunctionTable`

---

## 📁 Project Structure

```
/DreamWalkers
├── bin/                   # Output folder for compiled binaries and shellcode
├── build.ps1              # CMake wrapper for local and CI builds
├── CMakeLists.txt         # MSVC/CMake build graph
├── CMakePresets.json      # x64, x86 and ARM64 configure presets
├── common/                # Shared code or headers
├── dotnetLoader/          # C++ CLR host loader for .NET payloads
├── exe2h/                 # Tool for extracting TEXT section of binaries
├── finalShellcode.bin     # Final compiled shellcode output
├── DreamWalkers.py        # Python script to generate shellcode and input structure
├── memoryModule/          # Modified, position-independent MemoryModule loader
├── shellcodeTester/       # Shellcode testing utilities 
├── testDll/               # Sample DLL payloads for testing loader
├── testExe/               # Sample EXE payloads for testing loader

```

---

## 🚀 How to Use

The project includes a Python script, `DreamWalkers.py`, that bundles your payload (EXE or DLL) together with the position-independent loader, builds the required structure, and outputs a standalone shellcode blob.

### 📦 Basic Usage

```powershell
PS B:\framework\DreamWalkers> python .\DreamWalkers.py -f .\Rubeus.exe -c help
````

* `-f`: Path to the payload (EXE or DLL)
* `-c`: Command-line arguments passed to the loaded module
* `-m`: (Optional) Method name to call if the payload is a DLL
* `-a`: Target architecture (`auto`, `x86`, `x64`, or `arm64`)
* `--module-stomping`: Enable stomping `Windows.Storage.dll` instead of the default private allocation

### 🧠 Example Output

```text
File is a .NET (managed) executable.
Command line argument:  help
padding_length  11
Extracted 4954 bytes.
Instance struct size: 3552 bytes
Loader size: 4954 bytes
final shellcode  591173  bytes
```

The output `finalShellcode.bin` is a standalone, reflectively loadable shellcode. To test it you can use the very simple shellcodeTester.exe provided or use any shellcode injector.

### 📘 Help Menu

```powershell
PS B:\framework\DreamWalkers> python .\DreamWalkers.py
usage: DreamWalkers.py [-h] -f FILE [-m METHOD] [-c CMD] [-a {auto,x86,x64,arm64}] [--module-stomping | --no-module-stomping] [-x {1,2,3}]

Generate shellcode from any given PE.

options:
  -h, --help           show this help message and exit
  -f, --file FILE      PE file path (DLL or EXE)
  -m, --method METHOD  Method name to invoke in case of DLL
  -c, --cmd CMD        Command line arguments
  -a, --arch {auto,x86,x64,arm64}
                        Target loader architecture
  --module-stomping    Enable module stomping into Windows.Storage.dll
  --no-module-stomping
                        Use private allocation instead of module stomping (default)
  -x, --exit {1,2,3}   Exit behavior: 1=exit thread, 2=exit process, 3=block indefinitely
```

Make sure to build the shellcode after any changes to the loader or input structure.

---

## 🚀 How to Build

From PowerShell with Visual Studio 2022 and CMake available:

```powershell
.\build.ps1 -Arch all -Target all -Config Release
```

Build every configured architecture:

```powershell
.\build.ps1 -Arch all -Target all -Config Release
```

Build only the CI smoke artifacts:

```powershell
.\build.ps1 -Arch x64 -Target ci-smoke -Config Release
```

Available targets are `all`, `ci-smoke`, `exe2h`, `memoryModule`, `memoryModuleAsm`, `dotnetLoader`, `shellcodeTester`, `testDll`, `testExe`, and `smoke-payload`.
The native MemoryModule shellcode generation and `dotnetLoader`/`goodClr` builds are wired for x64, x86, and ARM64.

### Architecture Notes

The x64, x86 and ARM64 builds share the same MemoryModule and `goodClr` managed-loading path. Optional `goodClr` behavior is split into independent CMake flags so each feature can be validated in isolation:

- `DW_ENABLE_DOTNET_ETW_PATCH`
- `DW_ENABLE_DOTNET_AMSI_PATCH`
- `DW_ENABLE_DOTNET_SYSCALLS`
- `DW_ENABLE_DOTNET_HOST_MEMORY_MANAGER`
- `DW_ENABLE_DOTNET_TRACE`

The ETW patch, AMSI patch, syscall wrappers, and host memory manager are enabled by default in the CMake presets and in the baseline CMake configuration. `DW_ENABLE_DOTNET_TRACE` stays disabled by default and should only be enabled for diagnostic runs.

Current ARM64 assumption: the managed MemoryModule path should stay stable with the normal `goodClr` compile options. The CI managed ARM64 test repeats this path to catch intermittent CLR startup or early managed invocation failures.

Related architecture docs:

- [memoryModuleLoader build notes](docs/memorymodule-loader-build-notes.md)
- [Python/C `INSTANCE` layout contract](docs/instance-layout-contract.md)
- [shellcode bootstrap](docs/shellcode-bootstrap.md)
- [per-architecture feature matrix](docs/architecture-feature-matrix.md)
- [ARM64 module stomping and unwind metadata](docs/arm64-module-stomping-unwind.md)

---

## 🧠 Credits

- [TheWover](https://github.com/TheWover) [modexp/odzhan](https://modexp.wordpress.com/) – Donut
- [fancycode](https://github.com/fancycode) – MemoryModule
- [passthehashbrowns](https://github.com/passthehashbrowns) – Being-A-Good-CLR-Host
- ChatGPT – For helping with stack unwinding research

---
