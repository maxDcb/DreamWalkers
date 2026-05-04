.686p                       ; x86 target
.model flat, c              ; <-- C calling convention
option casemap:none

EXTERN getGlobalHash: PROC

EXTERN SW3_GetSyscallAddress: PROC


.code

Sw3NtAllocateVirtualMemory PROC
	jmp pipo                               
Sw3NtAllocateVirtualMemory ENDP

Sw3NtWaitForSingleObject PROC
	jmp pipo                                 
Sw3NtWaitForSingleObject ENDP

Sw3NtCreateThreadEx PROC
	jmp pipo                         
Sw3NtCreateThreadEx ENDP

Sw3NtClose PROC
	jmp pipo                              
Sw3NtClose ENDP

Sw3NtWriteVirtualMemory PROC
	jmp pipo                               
Sw3NtWriteVirtualMemory ENDP

Sw3NtProtectVirtualMemory PROC
	jmp pipo                                  
Sw3NtProtectVirtualMemory ENDP

Sw3NtOpenProcess PROC
	jmp pipo                                  
Sw3NtOpenProcess ENDP

Sw3NtCreateProcess PROC
	jmp pipo                                  
Sw3NtCreateProcess ENDP

Sw3NtQueueApcThread PROC
	jmp pipo                                  
Sw3NtQueueApcThread ENDP

Sw3NtResumeThread PROC
	jmp pipo                                  
Sw3NtResumeThread ENDP

Sw3NtOpenProcessToken PROC
	jmp pipo                                  
Sw3NtOpenProcessToken ENDP

Sw3NtAdjustPrivilegesToken PROC
	jmp pipo                                  
Sw3NtAdjustPrivilegesToken ENDP

Sw3NtQueryVirtualMemory PROC
	jmp pipo                                  
Sw3NtQueryVirtualMemory ENDP

Sw3NtReadVirtualMemory PROC
	jmp pipo                                  
Sw3NtReadVirtualMemory ENDP

Sw3NtWriteFile PROC
	jmp pipo  
Sw3NtWriteFile ENDP

Sw3NtLoadDriver PROC
	jmp pipo  
Sw3NtLoadDriver ENDP

Sw3NtDeviceIoControlFile PROC
	jmp pipo  
Sw3NtDeviceIoControlFile ENDP

Sw3NtCreateKey PROC
	jmp pipo  
Sw3NtCreateKey ENDP

Sw3NtSetValueKey PROC
	jmp pipo  
Sw3NtSetValueKey ENDP

Sw3NtCreateFile PROC
	jmp pipo  
Sw3NtCreateFile ENDP

pipo PROC
		push ebp
		mov ebp, esp
		call getGlobalHash		
		push eax
		call SW3_GetSyscallAddress
		lea esp, [esp+4]
		test eax, eax
		jz syscall_not_found
		mov edx, eax
		mov ecx, 0Bh
	push_argument:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument
		call edx
		mov esp, ebp
		pop ebp
		ret
	syscall_not_found:
		mov eax, 0C0000225h
		mov esp, ebp
		pop ebp
		ret
pipo ENDP

end
