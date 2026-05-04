.code

EXTERN getGlobalHash: PROC

EXTERN SW3_GetSyscallNumber: PROC

EXTERN SW3_GetSyscallAddress: PROC


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
	mov [rsp +8], rcx          
	mov [rsp+16], rdx
	mov [rsp+24], r8
	mov [rsp+32], r9
	sub rsp, 28h
	call getGlobalHash		; remove hash
	mov rcx, rax
	call SW3_GetSyscallAddress              
	mov r11, rax        
	call getGlobalHash		; remove hash
	mov rcx, rax                        
	call SW3_GetSyscallNumber              
	add rsp, 28h
	mov rcx, [rsp+8]                      
	mov rdx, [rsp+16]
	mov r8, [rsp+24]
	mov r9, [rsp+32]
	mov r10, rcx
	jmp r11                                
pipo ENDP

end