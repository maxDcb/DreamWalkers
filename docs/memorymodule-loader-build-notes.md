# MemoryModule Loader Build Notes

## Summary

`memoryModuleLoader` is not used as a normal executable in the production path. CMake links it as a PE file so `exe2h` can extract its `.text` section into `bin/memorymodule_exe_<arch>.h`. That extracted byte array is the shellcode loader consumed by `DreamWalkers.py`.

Because only the code section is extracted, the loader must behave like standalone shellcode:

- execution starts at the `Loader` routine,
- required Windows APIs are resolved at runtime from the target process,
- the loader must not depend on CRT startup or external runtime libraries,
- architecture-specific call/unwind assumptions must be validated with the generated shellcode, not only by launching the linked PE.

## Linker Constraints

`/ENTRY:Loader` makes `Loader` the PE entrypoint instead of the default C runtime startup. `memoryModule/order.txt` also keeps `Loader` first in `.text`, which keeps the extracted section aligned with the shellcode entrypoint expectation.

`/NODEFAULTLIB` prevents implicit CRT and default library dependencies. The shellcode path cannot rely on imported runtime startup code because `exe2h` only preserves `.text`.

`/ORDER:@memoryModule/order.txt` keeps the entry routine first in the generated code layout. The order file currently contains only `Loader`; that is intentional.

`/FIXED` and `/DYNAMICBASE:NO` are used for x86 and x64 so the linked image does not rely on normal PE loader ASLR or relocation behavior for the shellcode extraction path. The extracted loader still needs to be position-independent through its own code and runtime API resolution. ARM64 currently omits these flags, so changes here should be treated as architecture-sensitive.

`/SAFESEH:NO` is used on x86 because the loader uses a custom entrypoint and shellcode-oriented layout instead of a normal CRT-linked image. x64 and ARM64 do not use SAFESEH.

## Compile Constraints

The loader compile options favor a compact, shellcode-friendly C image:

- `/Zp8` keeps the expected structure packing.
- `/Gy`, `/Os`, and `/O1` favor small function-level code generation.
- `/GR-` disables RTTI.
- `/Oi` allows intrinsic expansion.
- `/GS-` avoids stack cookie helpers that would add runtime dependencies.
- `/EHa` keeps SEH-compatible exception handling behavior for the test/debug path.

## Validation Rule

After changing these options, regenerate the headers and run the loader tests for each affected architecture. A normal executable launch is not enough validation because the real path executes the extracted `.text` bytes.
