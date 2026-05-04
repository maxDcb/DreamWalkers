# INSTANCE Layout Contract

`DreamWalkers.py` serializes the `INSTANCE` structure consumed by `memoryModule/memoryModule.c`.

Keep these files in lockstep:

- `common/instance.h`
- `DreamWalkers.py`
- `tests/test_arch_contract.py`

## Rules

- `INSTANCE` is packed with `#pragma pack(push, 1)`. Python must not add implicit alignment.
- Field order in `Instance.pack()` must match `common/instance.h` exactly.
- Pointer fields are architecture-sized: 4 bytes on x86, 8 bytes on x64 and ARM64.
- `DW_HAS_RUNTIME_FUNCTION_TABLE` adds `.pdata` and `RtlAddFunctionTable` fields on x64 and ARM64.
- `DW_HAS_STACK_SPOOFING` adds stack-spoofing fields only on x64.
- Fixed string fields must stay bounded and NUL-padded. Oversized values must fail before packing.
- `instanceSize` and `loaderSize` are placeholder values patched after the final instance blob size and loader size are known.

## Change Rule

When changing `common/instance.h`, update `Instance.pack()` in the same change and add or update a test that proves the generated layout still matches the intended architecture contract.
