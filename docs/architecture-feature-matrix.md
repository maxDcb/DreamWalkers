# Architecture Feature Matrix

This matrix records the current per-architecture contract. Update it when a
loader feature, `INSTANCE` field, CMake option, or validation path becomes
architecture-specific.

Legend:

- `yes`: implemented and expected to work.
- `limited`: implemented, but with an architecture-specific constraint.
- `no`: intentionally absent for this architecture.
- `avoid`: known failing or invalid path.

## Matrix

| Capability | x86 | x64 | ARM64 |
| --- | --- | --- | --- |
| CMake target | yes, `Win32` | yes, `x64` | yes, `ARM64` |
| Generated loader header | yes, `memorymodule_exe_x86.h` | yes, `memorymodule_exe_x64.h` | yes, `memorymodule_exe_arm64.h`; cross-builds can require `DW_EXE2H_HOST_PATH` |
| Shellcode bootstrap ABI | stack argument; cleanup returns with `ret 4` | `RCX` first argument; wrapper aligns `rsp` and reserves shadow space | `x0` first argument with `adr`; branch to `Loader` |
| `INSTANCE` pointer size | 4 bytes | 8 bytes | 8 bytes |
| Current `INSTANCE` size | 3172 bytes | 3432 bytes | 3304 bytes |
| Native EXE payload | yes | yes | yes |
| Native DLL payload | yes; `--method` is required | yes; `--method` is required | yes; `--method` is required |
| .NET payload through `goodClr`, private allocation | yes | yes | yes |
| .NET payload through `goodClr`, module stomping | implemented, but no runtime function table registration path | implemented; retest after loader, mapping, section, or `goodClr` changes | avoid; known to fail the managed loader path |
| Native payload with module stomping | implemented; retest after loader, mapping, section, or `INSTANCE` changes | implemented; retest after loader, mapping, section, or `INSTANCE` changes | implemented for unmanaged smoke; does not validate `goodClr` |
| Runtime function table registration | no; `DW_HAS_RUNTIME_FUNCTION_TABLE=0` | yes; `.pdata` is registered with `RtlAddFunctionTable` | yes; `.pdata` is registered with `RtlAddFunctionTable` |
| Stack spoofing fields and path | no; `DW_HAS_STACK_SPOOFING=0` | yes; only architecture where this path is enabled | no; `DW_HAS_STACK_SPOOFING=0` |
| `goodClr` syscall wrappers | yes, when `DW_ENABLE_DOTNET_SYSCALLS=ON` | yes, when `DW_ENABLE_DOTNET_SYSCALLS=ON` | yes, when `DW_ENABLE_DOTNET_SYSCALLS=ON` |
| `goodClr` ETW/AMSI/host-memory flags | yes | yes | yes; keep module-stomping limitation separate from these flags |
| `memoryModuleLoader` `/FIXED` and `/DYNAMICBASE:NO` | yes | yes | no; currently treated as architecture-sensitive |
| `/SAFESEH:NO` | yes, for x86 linker targets that need it | no; not applicable | no; not applicable |
| CI smoke coverage | build, managed direct, managed loader, native shellcode | build, managed direct, managed loader, native shellcode | build, managed direct, managed loader, native shellcode on ARM64 runner |

## Per-Architecture Notes

### x86

x86 does not use the dynamic unwind registration path. `RtlAddFunctionTable`
fields are absent from `INSTANCE`, and the loader must not assume `.pdata`
registration exists. Stack spoofing is also disabled for x86.

### x64

x64 is the full feature baseline: it has 8-byte pointers, runtime function
table registration, and the stack-spoofing fields. The shellcode bootstrap must
keep the Windows x64 ABI rules: first argument in `RCX`, 16-byte stack alignment,
and 32 bytes of shadow space.

### ARM64

ARM64 has runtime function table registration, but `goodClr` must not be loaded
through module stomping. That path can leave Windows with conflicting unwind
metadata for the same address range: the victim module registered by the normal
loader and the manually mapped `goodClr` image registered by MemoryModule. Use
private allocation for the managed path. The detailed note is in
[`arm64-module-stomping-unwind.md`](arm64-module-stomping-unwind.md).

## Maintenance Rule

When adding or removing an architecture-specific field, update these files
together:

- `common/winapi.h` for feature macros.
- `common/instance.h` for the C layout.
- `DreamWalkers.py` for the Python serializer.
- `tests/test_arch_contract.py` for layout and bootstrap checks.
- This matrix for the expected behavior.
