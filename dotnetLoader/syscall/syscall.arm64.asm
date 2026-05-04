    AREA |.text|, CODE, READONLY, ALIGN=2

    IMPORT getGlobalHash
    IMPORT SW3_GetSyscallAddress

    EXPORT Sw3NtAllocateVirtualMemory
    EXPORT Sw3NtWaitForSingleObject
    EXPORT Sw3NtCreateThreadEx
    EXPORT Sw3NtClose
    EXPORT Sw3NtWriteVirtualMemory
    EXPORT Sw3NtProtectVirtualMemory
    EXPORT Sw3NtOpenProcess
    EXPORT Sw3NtCreateProcess
    EXPORT Sw3NtQueueApcThread
    EXPORT Sw3NtResumeThread
    EXPORT Sw3NtOpenProcessToken
    EXPORT Sw3NtAdjustPrivilegesToken
    EXPORT Sw3NtQueryVirtualMemory
    EXPORT Sw3NtReadVirtualMemory
    EXPORT Sw3NtWriteFile
    EXPORT Sw3NtLoadDriver
    EXPORT Sw3NtDeviceIoControlFile
    EXPORT Sw3NtCreateKey
    EXPORT Sw3NtSetValueKey
    EXPORT Sw3NtCreateFile

Sw3NtAllocateVirtualMemory PROC
    b pipo
Sw3NtAllocateVirtualMemory ENDP

Sw3NtWaitForSingleObject PROC
    b pipo
Sw3NtWaitForSingleObject ENDP

Sw3NtCreateThreadEx PROC
    b pipo
Sw3NtCreateThreadEx ENDP

Sw3NtClose PROC
    b pipo
Sw3NtClose ENDP

Sw3NtWriteVirtualMemory PROC
    b pipo
Sw3NtWriteVirtualMemory ENDP

Sw3NtProtectVirtualMemory PROC
    b pipo
Sw3NtProtectVirtualMemory ENDP

Sw3NtOpenProcess PROC
    b pipo
Sw3NtOpenProcess ENDP

Sw3NtCreateProcess PROC
    b pipo
Sw3NtCreateProcess ENDP

Sw3NtQueueApcThread PROC
    b pipo
Sw3NtQueueApcThread ENDP

Sw3NtResumeThread PROC
    b pipo
Sw3NtResumeThread ENDP

Sw3NtOpenProcessToken PROC
    b pipo
Sw3NtOpenProcessToken ENDP

Sw3NtAdjustPrivilegesToken PROC
    b pipo
Sw3NtAdjustPrivilegesToken ENDP

Sw3NtQueryVirtualMemory PROC
    b pipo
Sw3NtQueryVirtualMemory ENDP

Sw3NtReadVirtualMemory PROC
    b pipo
Sw3NtReadVirtualMemory ENDP

Sw3NtWriteFile PROC
    b pipo
Sw3NtWriteFile ENDP

Sw3NtLoadDriver PROC
    b pipo
Sw3NtLoadDriver ENDP

Sw3NtDeviceIoControlFile PROC
    b pipo
Sw3NtDeviceIoControlFile ENDP

Sw3NtCreateKey PROC
    b pipo
Sw3NtCreateKey ENDP

Sw3NtSetValueKey PROC
    b pipo
Sw3NtSetValueKey ENDP

Sw3NtCreateFile PROC
    b pipo
Sw3NtCreateFile ENDP

pipo PROC
    sub sp, sp, #0x50
    stp x0, x1, [sp, #0x00]
    stp x2, x3, [sp, #0x10]
    stp x4, x5, [sp, #0x20]
    stp x6, x7, [sp, #0x30]
    str lr, [sp, #0x40]

    bl getGlobalHash
    bl SW3_GetSyscallAddress
    mov x11, x0

    ldr lr, [sp, #0x40]
    ldp x6, x7, [sp, #0x30]
    ldp x4, x5, [sp, #0x20]
    ldp x2, x3, [sp, #0x10]
    ldp x0, x1, [sp, #0x00]
    add sp, sp, #0x50

    br x11
pipo ENDP

    END
