# Shellcode Bootstrap

`DreamWalkers.py` emits a small architecture-specific bootstrap before the extracted `memoryModuleLoader` bytes. Its only job is to pass the serialized `INSTANCE` pointer as the first argument, then transfer execution to `Loader`.

## x64

The x64 bootstrap uses a `call`/`pop` pattern to discover the inline `INSTANCE` address without an absolute pointer. `call after_instance` pushes the address of the embedded instance blob, `pop rcx` moves it into the first Windows x64 argument register, and the wrapper aligns `rsp` plus reserves 32 bytes of shadow space before calling the loader.

```asm
call after_instance        ; pushes &INSTANCE
db   INSTANCE bytes
after_instance:
pop  rcx                   ; rcx = INSTANCE*
push rbp
mov  rbp, rsp
and  rsp, -16
sub  rsp, 20h              ; Windows x64 shadow space
call Loader
mov  rsp, rbp
pop  rbp
ret
```

## x86

The x86 bootstrap also uses `call`/`pop` to get the inline `INSTANCE` address. The loader expects a normal stack argument at `[esp+4]`, so the bootstrap preserves the caller return address, pushes `INSTANCE*`, then calls the loader. The call return address points to a cleanup stub that removes the synthetic argument and returns with `ret 4`, preserving the thread-start return layout used by the tester path.

```asm
call after_instance        ; pushes &INSTANCE
db   INSTANCE bytes
after_instance:
pop  ecx                   ; ecx = INSTANCE*
pop  edx                   ; save caller return address
push edx                   ; restore caller return address
push ecx                   ; stack arg: INSTANCE*
call Loader                ; return address is cleanup
cleanup:
add  esp, 4                ; drop INSTANCE*
ret  4
```

## ARM64

The ARM64 bootstrap uses fixed-width instructions. `adr x0, instance` computes the inline `INSTANCE` address into the first Windows ARM64 argument register, then `b Loader` branches directly to the extracted loader bytes. The branch is not a link branch, so the loader returns through the link register already provided by the shellcode caller.

```asm
adr x0, instance           ; x0 = INSTANCE*
b   Loader
instance:
db  INSTANCE bytes
Loader:
```
