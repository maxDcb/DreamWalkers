#pragma once

#include <windows.h>
#include <tlhelp32.h>
#include "include.hpp"

#include <vector>
#include <algorithm>
#include <iostream>
#include <cstring>
#include <utility>

extern DWORD GlobalHash;

EXTERN_C DWORD getGlobalHash();
DWORD SW3_HashSyscall(PCSTR FunctionName);
EXTERN_C DWORD SW3_GetSyscallNumber(DWORD FunctionHash);
EXTERN_C PVOID SW3_GetSyscallAddress(DWORD FunctionHash);


EXTERN_C NTSTATUS Sw3NtAllocateVirtualMemory(
IN HANDLE ProcessHandle,
IN OUT PVOID * BaseAddress,
IN ULONG ZeroBits,
IN OUT PSIZE_T RegionSize,
IN ULONG AllocationType,
IN ULONG Protect);


EXTERN_C NTSTATUS Sw3NtWaitForSingleObject(
IN HANDLE ObjectHandle,
IN BOOLEAN Alertable,
IN PLARGE_INTEGER TimeOut OPTIONAL);


EXTERN_C NTSTATUS Sw3NtCreateThreadEx(
OUT PHANDLE ThreadHandle,
IN ACCESS_MASK DesiredAccess,
IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
IN HANDLE ProcessHandle,
IN PVOID StartRoutine,
IN PVOID Argument OPTIONAL,
IN ULONG CreateFlags,
IN SIZE_T ZeroBits,
IN SIZE_T StackSize,
IN SIZE_T MaximumStackSize,
IN PPS_ATTRIBUTE_LIST AttributeList OPTIONAL);


EXTERN_C NTSTATUS Sw3NtClose(
IN HANDLE Handle);


EXTERN_C NTSTATUS Sw3NtWriteVirtualMemory(
IN HANDLE ProcessHandle,
IN PVOID BaseAddress,
IN PVOID Buffer,
IN SIZE_T NumberOfBytesToWrite,
OUT PSIZE_T NumberOfBytesWritten OPTIONAL);


EXTERN_C NTSTATUS Sw3NtProtectVirtualMemory(
IN HANDLE ProcessHandle,
IN OUT PVOID * BaseAddress,
IN OUT PSIZE_T RegionSize,
IN ULONG NewProtect,
OUT PULONG OldProtect);


EXTERN_C NTSTATUS Sw3NtOpenProcess(
OUT PHANDLE ProcessHandle,
IN ACCESS_MASK DesiredAccess,
IN POBJECT_ATTRIBUTES ObjectAttributes,
IN CLIENT_ID* ClientId OPTIONAL);


EXTERN_C NTSTATUS Sw3NtCreateProcess(
OUT PHANDLE ProcessHandle,
IN ACCESS_MASK DesiredAccess,
IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
IN HANDLE ParentProcess,
IN BOOLEAN InheritObjectTable,
IN HANDLE SectionHandle OPTIONAL,
IN HANDLE DebugPort OPTIONAL,
IN HANDLE ExceptionPort OPTIONAL ); 


EXTERN_C NTSTATUS Sw3NtQueueApcThread(
IN HANDLE ThreadHandle,
IN PIO_APC_ROUTINE ApcRoutine,
IN PVOID ApcRoutineContext OPTIONAL,
IN PIO_STATUS_BLOCK ApcStatusBlock OPTIONAL,
IN ULONG pcReserved OPTIONAL );


EXTERN_C NTSTATUS Sw3NtResumeThread(
IN HANDLE ThreadHandle,
OUT PULONG SuspendCount OPTIONAL );


EXTERN_C NTSTATUS Sw3NtOpenProcessToken(
IN HANDLE ProcessHandle,
IN ACCESS_MASK DesiredAccess,
OUT PHANDLE TokenHandle);


EXTERN_C NTSTATUS Sw3NtAdjustPrivilegesToken(
IN HANDLE TokenHandle,
IN BOOLEAN DisableAllPrivileges,
IN PTOKEN_PRIVILEGES NewState OPTIONAL,
IN ULONG BufferLength,
OUT PTOKEN_PRIVILEGES PreviousState OPTIONAL,
OUT PULONG ReturnLength OPTIONAL);


EXTERN_C NTSTATUS Sw3NtQueryVirtualMemory(
IN HANDLE ProcessHandle,
IN PVOID BaseAddress,
IN MEMORY_INFORMATION_CLASS MemoryInformationClass,
OUT PVOID MemoryInformation,
IN SIZE_T MemoryInformationLength,
OUT PSIZE_T ReturnLength OPTIONAL);


EXTERN_C NTSTATUS Sw3NtReadVirtualMemory(
IN HANDLE ProcessHandle,
IN PVOID BaseAddress OPTIONAL,
OUT PVOID Buffer,
IN SIZE_T BufferSize,
OUT PSIZE_T NumberOfBytesRead OPTIONAL);

EXTERN_C NTSTATUS Sw3NtWriteFile(
IN HANDLE FileHandle,
IN HANDLE Event OPTIONAL,
IN PIO_APC_ROUTINE ApcRoutine OPTIONAL,
IN PVOID ApcContext OPTIONAL,
OUT PIO_STATUS_BLOCK IoStatusBlock,
IN PVOID Buffer,
IN ULONG Length,
IN PLARGE_INTEGER ByteOffset OPTIONAL,
IN PULONG Key OPTIONAL
);

EXTERN_C NTSTATUS Sw3NtLoadDriver(
    PUNICODE_STRING DriverServiceName
);

EXTERN_C NTSTATUS Sw3NtDeviceIoControlFile(
    IN HANDLE FileHandle,
    IN HANDLE Event OPTIONAL,
    IN PIO_APC_ROUTINE ApcRoutine OPTIONAL,
    IN PVOID ApcContext OPTIONAL,
    OUT PIO_STATUS_BLOCK IoStatusBlock,
    IN ULONG IoControlCode,
    IN PVOID InputBuffer OPTIONAL,
    IN ULONG InputBufferLength,
    OUT PVOID OutputBuffer OPTIONAL,
    IN ULONG OutputBufferLength
);

EXTERN_C NTSTATUS Sw3NtCreateKey(
    OUT PHANDLE KeyHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes,
    IN ULONG TitleIndex,
    IN PUNICODE_STRING Class OPTIONAL,
    IN ULONG CreateOptions,
    OUT PULONG Disposition OPTIONAL
);

EXTERN_C NTSTATUS Sw3NtSetValueKey(
    IN HANDLE KeyHandle,
    IN PUNICODE_STRING ValueName,
    IN ULONG TitleIndex,
    IN ULONG Type,
    IN PVOID Data,
    IN ULONG DataSize
);

EXTERN_C NTSTATUS Sw3NtCreateFile(
    OUT PHANDLE FileHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes,
    OUT PIO_STATUS_BLOCK IoStatusBlock,
    IN PLARGE_INTEGER AllocationSize OPTIONAL,
    IN ULONG FileAttributes,
    IN ULONG ShareAccess,
    IN ULONG CreateDisposition,
    IN ULONG CreateOptions,
    IN PVOID EaBuffer OPTIONAL,
    IN ULONG EaLength
);


template <typename... Args>
NTSTATUS Sw3NtAllocateVirtualMemory_(Args&&... args) 
{
    // need to put Zw for the syscall
    // char *FunctionName = "ZwAllocateVirtualMemory";
    // GlobalHash = SW3_HashSyscall(FunctionName);
    // std::cout << "ZwAllocateVirtualMemory " << GlobalHash << std::endl;

    GlobalHash = 806327511;
    return Sw3NtAllocateVirtualMemory(std::forward<Args>(args)...);
}


template <typename... Args>
NTSTATUS Sw3NtWaitForSingleObject_(Args&&... args) 
{
    // char *FunctionName = "ZwWaitForSingleObject";
    // GlobalHash = SW3_HashSyscall(FunctionName);
    // std::cout << "ZwWaitForSingleObject " << GlobalHash << std::endl;

    GlobalHash = 3941435821;
    return Sw3NtWaitForSingleObject(std::forward<Args>(args)...);
}


template <typename... Args>
NTSTATUS Sw3NtClose_(Args&&... args) 
{
    //     char *FunctionName = "ZwClose";
    //     GlobalHash = SW3_HashSyscall(FunctionName);
    // std::cout << "ZwClose " << GlobalHash << std::endl;

    GlobalHash = 745328858;
    return Sw3NtClose(std::forward<Args>(args)...);
}


template <typename... Args>
NTSTATUS Sw3NtWriteVirtualMemory_(Args&&... args) 
{
    // char *FunctionName = "ZwWriteVirtualMemory";
    // GlobalHash = SW3_HashSyscall(FunctionName);
    // std::cout << "ZwWriteVirtualMemory " << GlobalHash << std::endl;

    GlobalHash = 4080026747;
    return Sw3NtWriteVirtualMemory(std::forward<Args>(args)...);
}


template <typename... Args>
NTSTATUS Sw3NtProtectVirtualMemory_(Args&&... args) 
{
    // char *FunctionName = "ZwProtectVirtualMemory";
    // GlobalHash = SW3_HashSyscall(FunctionName);
    // std::cout << "ZwProtectVirtualMemory " << GlobalHash << std::endl;

    GlobalHash = 699580991;
    return Sw3NtProtectVirtualMemory(std::forward<Args>(args)...);
}


template <typename... Args>
NTSTATUS Sw3NtOpenProcess_(Args&&... args) 
{
    // char *FunctionName = "ZwOpenProcess";
    // GlobalHash = SW3_HashSyscall(FunctionName);
    // std::cout << "ZwAllocateVirtualMemory " << GlobalHash << std::endl;

    GlobalHash = 3548847587;
    // __debugbreak();
    return Sw3NtOpenProcess(std::forward<Args>(args)...);

}


template <typename... Args>
NTSTATUS Sw3NtCreateThreadEx_(Args&&... args) 
{
    // char *FunctionName = "ZwCreateThreadEx";
    // GlobalHash = SW3_HashSyscall(FunctionName);
    // std::cout << "ZwCreateThreadEx " << GlobalHash << std::endl;

    GlobalHash = 3653557611;
    return Sw3NtCreateThreadEx(std::forward<Args>(args)...);
}


template <typename... Args>
NTSTATUS Sw3NtCreateProcess_(Args&&... args) 
{
    // PCSTR FunctionName = "ZwCreateProcess";
    // GlobalHash = SW3_HashSyscall(FunctionName);
    // std::cout << "ZwCreateProcess " << GlobalHash << std::endl;

    GlobalHash = 1768521463;
    return Sw3NtCreateProcess(std::forward<Args>(args)...);
}


template <typename... Args>
NTSTATUS Sw3NtQueueApcThread_(Args&&... args) 
{
    // PCSTR FunctionName = "ZwQueueApcThread";
    // GlobalHash = SW3_HashSyscall(FunctionName);
    // std::cout << "ZwQueueApcThread " << GlobalHash << std::endl;

    GlobalHash = 735850453;
    return Sw3NtQueueApcThread(std::forward<Args>(args)...);
}


template <typename... Args>
NTSTATUS Sw3NtResumeThread_(Args&&... args) 
{
    // PCSTR FunctionName = "ZwResumeThread";
    // GlobalHash = SW3_HashSyscall(FunctionName);
    // std::cout << "ZwResumeThread " << GlobalHash << std::endl;

    GlobalHash = 4130550557;
    return Sw3NtResumeThread(std::forward<Args>(args)...);
}


template <typename... Args>
NTSTATUS Sw3NtOpenProcessToken_(Args&&... args) 
{
    // PCSTR FunctionName = "ZwOpenProcessToken";
    // GlobalHash = SW3_HashSyscall(FunctionName);
    // std::cout << FunctionName << " " << GlobalHash << std::endl;

    GlobalHash = 2590718720;
    return Sw3NtOpenProcessToken(std::forward<Args>(args)...);
}


template <typename... Args>
NTSTATUS Sw3NtAdjustPrivilegesToken_(Args&&... args) 
{
    // PCSTR FunctionName = "ZwAdjustPrivilegesToken";
    // GlobalHash = SW3_HashSyscall(FunctionName);
    // std::cout << FunctionName << " " << GlobalHash << std::endl;

    GlobalHash = 2243258122;
    return Sw3NtAdjustPrivilegesToken(std::forward<Args>(args)...);
}


template <typename... Args>
NTSTATUS Sw3NtQueryVirtualMemory_(Args&&... args) 
{
    // PCSTR FunctionName = "ZwQueryVirtualMemory";
    // GlobalHash = SW3_HashSyscall(FunctionName);
    // std::cout << FunctionName << " " << GlobalHash << std::endl;

    GlobalHash = 422492770;
    return Sw3NtQueryVirtualMemory(std::forward<Args>(args)...);
}


template <typename... Args>
NTSTATUS Sw3NtReadVirtualMemory_(Args&&... args) 
{
    // PCSTR FunctionName = "ZwReadVirtualMemory";
    // GlobalHash = SW3_HashSyscall(FunctionName);
    // std::cout << FunctionName << " " << GlobalHash << std::endl;

    GlobalHash = 663422542;
    return Sw3NtReadVirtualMemory(std::forward<Args>(args)...);
}


template <typename... Args>
NTSTATUS Sw3NtWriteFile_(Args&&... args) 
{
    // PCSTR FunctionName = "ZwWriteFile";
    // GlobalHash = SW3_HashSyscall(FunctionName);
    // std::cout << FunctionName << " " << GlobalHash << std::endl;

    GlobalHash = 4125819791;
    return Sw3NtWriteFile(std::forward<Args>(args)...);
}

template <typename... Args>
NTSTATUS Sw3NtLoadDriver_(Args&&... args) 
{
    // PCSTR FunctionName = "ZwLoadDriver";
    // GlobalHash = SW3_HashSyscall(FunctionName);
    // std::cout << FunctionName << " " << GlobalHash << std::endl;

    GlobalHash = 910764656;
    return Sw3NtLoadDriver(std::forward<Args>(args)...);
}


template <typename... Args>
NTSTATUS Sw3NtDeviceIoControlFile_(Args&&... args) 
{
    // PCSTR FunctionName = "ZwDeviceIoControlFile";
    // GlobalHash = SW3_HashSyscall(FunctionName);
    // std::cout << FunctionName << " " << GlobalHash << std::endl;

    GlobalHash = 1830534599;
    return Sw3NtDeviceIoControlFile(std::forward<Args>(args)...);
}

template <typename... Args>
NTSTATUS Sw3NtCreateKey_(Args&&... args) 
{
    // PCSTR FunctionName = "ZwCreateKey";
    // GlobalHash = SW3_HashSyscall(FunctionName);
    // std::cout << FunctionName << " " << GlobalHash << std::endl;

    GlobalHash = 1519667297;
    return Sw3NtCreateKey(std::forward<Args>(args)...);
}

template <typename... Args>
NTSTATUS Sw3NtSetValueKey_(Args&&... args) 
{
    // PCSTR FunctionName = "ZwSetValueKey";
    // GlobalHash = SW3_HashSyscall(FunctionName);
    // std::cout << FunctionName << " " << GlobalHash << std::endl;

    GlobalHash = 3718251598;
    return Sw3NtSetValueKey(std::forward<Args>(args)...);
}

template <typename... Args>
NTSTATUS Sw3NtCreateFile_(Args&&... args) 
{
    // PCSTR FunctionName = "ZwCreateFile";
    // GlobalHash = SW3_HashSyscall(FunctionName);
    // std::cout << FunctionName << " " << GlobalHash << std::endl;

    GlobalHash = 2061785324;
    return Sw3NtCreateFile(std::forward<Args>(args)...);
}


class Entry
{
public:
    Entry(DWORD hash, DWORD address, PVOID syscallAddress)
    : m_hash(hash)
    , m_address(address)
    , m_syscallAddress(syscallAddress)
    {
    }

    DWORD getHash()
    {
        return m_hash;
    }

    DWORD getAddress()
    {
        return m_address;
    }

    PVOID getSyscallAddress()
    {
        return m_syscallAddress;
    }


private:
    DWORD m_hash;
    DWORD m_address;
    PVOID m_syscallAddress;
};


bool compareEntry(Entry i1, Entry i2);


#if defined(_M_ARM64)
    #define PEB_OFFSET 0x60
    #define READ_TEB() ((void*)__getReg(18))

#elif defined(_M_X64)
    #define PEB_OFFSET 0x60
    #define READ_TEB() ((void*)__readgsqword(0x30))

#elif defined(_M_IX86)
    #define PEB_OFFSET 0x30
    #define READ_TEB() ((void*)__readfsdword(0x18))

#else
    #error Unsupported architecture
#endif


static void* GetPeb(void)
{
    unsigned char* teb = (unsigned char*)READ_TEB();
    return *(void**)(teb + PEB_OFFSET);
}


class SyscallList
{
private:

    PVOID getNtdllExportDirectory()
    {       
#ifdef _M_IX86 
        PSW3_PEB Peb = (PSW3_PEB)GetPeb();
#else
        PSW3_PEB Peb = (PSW3_PEB)GetPeb();
#endif
        
        PSW3_PEB_LDR_DATA Ldr = Peb->Ldr;
        PIMAGE_EXPORT_DIRECTORY ExportDirectory = NULL;
        m_dllBase = NULL;

        // Get the DllBase address of NTDLL.dll. NTDLL is not guaranteed to be the second
        // in the list, so it's safer to loop through the full list and find it.
        PSW3_LDR_DATA_TABLE_ENTRY LdrEntry;
        for (LdrEntry = (PSW3_LDR_DATA_TABLE_ENTRY)Ldr->Reserved2[1]; LdrEntry->DllBase != NULL; LdrEntry = (PSW3_LDR_DATA_TABLE_ENTRY)LdrEntry->Reserved1[0])
        {
            m_dllBase = LdrEntry->DllBase;
            PIMAGE_DOS_HEADER DosHeader = (PIMAGE_DOS_HEADER)m_dllBase;
            PIMAGE_NT_HEADERS NtHeaders = SW3_RVA2VA(PIMAGE_NT_HEADERS, m_dllBase, DosHeader->e_lfanew);
            PIMAGE_DATA_DIRECTORY DataDirectory = (PIMAGE_DATA_DIRECTORY)NtHeaders->OptionalHeader.DataDirectory;
            DWORD VirtualAddress = DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
            if (VirtualAddress == 0) continue;

            ExportDirectory = (PIMAGE_EXPORT_DIRECTORY)SW3_RVA2VA(ULONG_PTR, m_dllBase, VirtualAddress);

            // If this is NTDLL.dll, exit loop.
            PCHAR DllName = SW3_RVA2VA(PCHAR, m_dllBase, ExportDirectory->Name);

            if ((*(ULONG*)DllName | 0x20202020) != 0x6c64746e) 
                continue;
            if ((*(ULONG*)(DllName + 4) | 0x20202020) == 0x6c642e6c) 
                break;
        }

        if (!ExportDirectory) 
            return NULL;

        return (PVOID)ExportDirectory;
    }

    void fillSyscallEntryList(PVOID add)
    {
        PIMAGE_EXPORT_DIRECTORY ExportDirectory = (PIMAGE_EXPORT_DIRECTORY)add;
        DWORD NumberOfNames = ExportDirectory->NumberOfNames;
        PDWORD Functions = SW3_RVA2VA(PDWORD, m_dllBase, ExportDirectory->AddressOfFunctions);
        PDWORD Names = SW3_RVA2VA(PDWORD, m_dllBase, ExportDirectory->AddressOfNames);
        PWORD Ordinals = SW3_RVA2VA(PWORD, m_dllBase, ExportDirectory->AddressOfNameOrdinals);

        // Populate SW3_SyscallList with unsorted Zw* entries.
        do
        {
            PCHAR FunctionName = SW3_RVA2VA(PCHAR, m_dllBase, Names[NumberOfNames - 1]);

            // Is this a system call?
            // start with Zw
            if (*(USHORT*)FunctionName == 0x775a)
            {
                DWORD Hash = SW3_HashSyscall(FunctionName);

                DWORD Address = Functions[Ordinals[NumberOfNames - 1]];
                PVOID SyscallAddress = SC_Address(SW3_RVA2VA(PVOID, m_dllBase, Address));

                Entry newEntry(Hash, Address, SyscallAddress);
                m_syscallEntry.push_back(std::move(newEntry));

            }
        } while (--NumberOfNames);

        // sort for the getSyscallNumber
        std::sort(m_syscallEntry.begin(), m_syscallEntry.end(), compareEntry); 
    }

    
    PVOID SC_Address(PVOID NtApiAddress)
    {
#if defined(_M_ARM64) || defined(_M_IX86)
        // ARM64 and x86/WOW64 have different transition stubs than the x64
        // `syscall; ret` sequence searched below. Branch to the exported Zw*
        // entrypoint and let ntdll own the platform-specific transition.
        return NtApiAddress;
#else
        DWORD searchLimit = 512;
        PVOID SyscallAddress;

#ifdef _WIN64
        // If the process is 64-bit on a 64-bit OS, we need to search for syscall
        BYTE syscall_code[] = { 0x0f, 0x05, 0xc3 };
        ULONG distance_to_syscall = 0x12;
#else
        // If the process is 32-bit on a 32-bit OS, we need to search for sysenter
        BYTE syscall_code[] = { 0x0f, 0x34, 0xc3 };
        ULONG distance_to_syscall = 0x0f;
#endif

        // we don't really care if there is a 'jmp' between
        // NtApiAddress and the 'syscall; ret' instructions
        SyscallAddress = SW3_RVA2VA(PVOID, NtApiAddress, distance_to_syscall);

        if (!memcmp((PVOID)syscall_code, SyscallAddress, sizeof(syscall_code)))
        {
            // we can use the original code for this system call :)
            return SyscallAddress;
        }

        // the 'syscall; ret' intructions have not been found,
        // we will try to use one near it, similarly to HalosGate
        for (ULONG32 num_jumps = 1; num_jumps < searchLimit; num_jumps++)
        {
            // let's try with an Nt* API below our syscall
            SyscallAddress = SW3_RVA2VA(
                PVOID,
                NtApiAddress,
                distance_to_syscall + num_jumps * 0x20);

            if (!memcmp((PVOID)syscall_code, SyscallAddress, sizeof(syscall_code)))
            {
                return SyscallAddress;
            }

            // let's try with an Nt* API above our syscall
            SyscallAddress = SW3_RVA2VA(
                PVOID,
                NtApiAddress,
                distance_to_syscall - num_jumps * 0x20);

            if (!memcmp((PVOID)syscall_code, SyscallAddress, sizeof(syscall_code)))
            {
                return SyscallAddress;
            }
        }

        return NULL;
#endif
    }

    PVOID m_dllBase;
    std::vector<Entry> m_syscallEntry;

protected:
    SyscallList()
    {
        PVOID add = getNtdllExportDirectory();
        fillSyscallEntryList(add);
    }

    static SyscallList* singleton_;

public:

    SyscallList(SyscallList &other) = delete;
    void operator=(const SyscallList &) = delete;
    static SyscallList *GetInstance();

    // need to be sorted to be able to get the syscall number from the entry index
    DWORD getSyscallNumber(DWORD hash)
    {
        for(int i=0; i<m_syscallEntry.size(); i++)
        {
            if(m_syscallEntry[i].getHash() == hash)
            {
                return i;
            }
        }
        return -1;
    }

    PVOID getSyscallAddress(DWORD hash)
    {
        for(int i=0; i<m_syscallEntry.size(); i++)
        {
            if(m_syscallEntry[i].getHash() == hash)
            {
                return m_syscallEntry[i].getSyscallAddress();
            }
        }
        return NULL;
    }
};
