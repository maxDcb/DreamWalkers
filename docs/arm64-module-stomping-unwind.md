# ARM64 Module Stomping and Runtime Unwind Metadata

## Summary

On Windows ARM64, loading `goodClr` through the MemoryModule module-stomping path can break runtime unwind resolution. The failure is not directly caused by the `DW_ENABLE_DOTNET_ETW_PATCH` patch bytes. Enabling that option changes the `goodClr` binary layout enough to expose an existing ARM64 loader/unwind issue.

The validated behavior is:

- `GoodClrDirectTest` succeeds with `DW_ENABLE_DOTNET_ETW_PATCH=ON`.
- `LoaderTest` unmanaged smoke payload succeeds with module stomping enabled.
- `LoaderTest` managed payload fails when `goodClr` is loaded through module stomping.
- The same managed `LoaderTest` path succeeds when `inst->isModuleStompingUsed` is set to `0` for the `goodClr` load.

The failing process exit code observed in CI was `-1073740791`, which is `0xC0000409` (`STATUS_STACK_BUFFER_OVERRUN` / fail-fast).

## What Happens

The MemoryModule module-stomping path loads a victim image, currently `Windows.Storage.dll`, and maps the payload image inside that module's address range:

```text
victimLib + pageSize * 2
```

From MemoryModule's point of view, the bytes at that address are the manually mapped `goodClr` image. From the Windows loader's point of view, however, that address still belongs to the already loaded victim module.

This creates two conflicting views of the same address range:

- The Windows loader has registered the victim module and its original exception directory.
- MemoryModule copies `goodClr` and calls `RtlAddFunctionTable` for `goodClr`'s `.pdata`.

`RtlAddFunctionTable` can return success while the runtime lookup still does not resolve the manually mapped image's unwind metadata as expected. The CI log showed this exact pattern:

```text
RtlAddFunctionTable table=... ret=1
No unwind info found - stack walk won't work.
```

That means the dynamic function table was accepted, but `RtlLookupFunctionEntry` did not find usable unwind information for the address being checked.

## Why ARM64 Is Sensitive

Windows ARM64 relies heavily on table-based unwind metadata. For non-trivial native code, the OS needs correct `.pdata` and unwind information to:

- identify function boundaries,
- restore saved frame and link registers,
- walk stacks,
- handle C++ and SEH transitions,
- support COM and CLR startup paths,
- recover correctly from exceptions and runtime probes.

Simple payloads may run without exercising these paths. `smoke_payload.dll` can succeed even when the unwind metadata is effectively unusable.

`goodClr` is different. It initializes CLR hosting, uses C++ support code, COM interfaces, and runtime startup paths that depend on correct unwind behavior. If Windows resolves unwind metadata against the victim module, or cannot resolve it at all, ARM64 runtime code can fail-fast instead of raising a normal catchable exception.

## Why ETW Appears Related

`DW_ENABLE_DOTNET_ETW_PATCH` changes `goodClr`'s code and section layout. On ARM64, that can move exported functions and change `.pdata` entries enough to expose the module-stomping unwind ambiguity.

The patch itself is not the direct cause when:

- `GoodClrDirectTest` succeeds with ETW patching enabled,
- the failure only happens when `goodClr` is manually mapped by `LoaderTest`,
- disabling module stomping for the `goodClr` load fixes the managed ARM64 path.

In that case, ETW is acting as a layout trigger, not as the root cause.

## Practical Rule

Do not module-stomp `goodClr` on Windows ARM64.

For ARM64 managed payload loading, `goodClr` should be mapped into a dedicated allocation so its dynamic function table is associated with a memory range that does not overlap an already registered Windows loader module.

The unmanaged smoke payload can still pass under module stomping, but that does not validate the managed `goodClr` path. The managed path must be tested separately because it depends much more heavily on runtime unwind correctness.

## Useful Diagnostics

When debugging this area, compare these cases:

- `GoodClrDirectTest` with ETW patching enabled.
- `LoaderTest` managed payload with module stomping enabled.
- `LoaderTest` managed payload with `inst->isModuleStompingUsed = 0`.

Useful runtime checks:

- Print the mapped image base for `goodClr`.
- Print the `.pdata` address and entry count passed to `RtlAddFunctionTable`.
- After adding the function table, call `RtlLookupFunctionEntry` on the exported `go` address.
- Verify that the returned image base matches the manually mapped `goodClr` base.

If `RtlAddFunctionTable` returns success but `RtlLookupFunctionEntry` cannot resolve `go`, or resolves it against the victim module range, the ARM64 unwind metadata is not usable for that mapped image.
