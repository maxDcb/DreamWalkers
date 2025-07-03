#ifndef INSTANCE_H
#define INSTANCE_H

#include <windows.h>
#include <wincrypt.h>
#include <oleauto.h>
#include <objbase.h>
#include <wininet.h>
#include <shlwapi.h>
#include <stdint.h>

#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "shell32.lib")

#include "peb.h"
#include "winapi.h"

#pragma pack(push, 1)
typedef struct _INSTANCE 
{		
	uint32_t    lenTest;  
	
	// Could be encrypted to avoid detection
	uint8_t sKernel32DLL[32];
	uint8_t sNtDLL[32];
	uint16_t wsKernel32DLL[32];
	uint8_t sKernelBaseDLL[32];  	 // cmdline
	uint8_t sMsvcrtDLL[32];  		 // printf
	
	uint8_t sGetProcAddress[32];
	uint8_t sGetModuleHandleA[32];
	uint8_t sLoadLibraryA[32];
	uint8_t sFreeLibrary[32];
	uint8_t sVirtualAlloc[32];
	uint8_t sVirtualFree[32];
	uint8_t sVirtualProtect[32];
	uint8_t sHeapAlloc[32];
	uint8_t sHeapFree[32];
	uint8_t sGetProcessHeap[32];
	uint8_t sGetLastError[32];
	uint8_t sGetNativeSystemInfo[32];
	uint8_t sIsBadReadPtr[32];
	uint8_t sHeapReAlloc[32];
	uint8_t sWaitForSingleObject[32];
	uint8_t sCreateThread[32];
	uint8_t sRtlLookupFunctionEntry[32];// stack spoofing
	uint8_t sBaseThreadInitThunk[32];	// stack spoofing
	uint8_t sRtlUserThreadStart[32];	// stack spoofing
	uint8_t sPrintf[32];				// printf
	uint8_t sGetCommandLineA[32];		// cmdline
	uint8_t sGetCommandLineW[32];		// cmdline
	uint8_t sRtlAddFunctionTable[32];	// stack spoofing
	
    struct 
    {
        LoadLibraryA_t                   LoadLibraryA;
		FreeLibrary_t					 FreeLibrary;
        GetProcAddress_t                 GetProcAddress;
        GetModuleHandleA_t               GetModuleHandleA;
        VirtualAlloc_t                   VirtualAlloc;
        VirtualFree_t                    VirtualFree;
        VirtualProtect_t                 VirtualProtect;
		WaitForSingleObject_t            WaitForSingleObject;
		CreateThread_t                   CreateThread;
		GetCommandLineA_t             	 GetCommandLineA;				// cmdline
		GetCommandLineW_t              	 GetCommandLineW;				// cmdline
        HeapAlloc_t                      HeapAlloc;
        HeapReAlloc_t                    HeapReAlloc;
        GetProcessHeap_t                 GetProcessHeap;
        HeapFree_t                       HeapFree;
        GetLastError_t                   GetLastError;
		GetNativeSystemInfo_t			 GetNativeSystemInfo;
		IsBadReadPtr_t 					 IsBadReadPtr;
		RtlLookupFunctionEntry_t		 RtlLookupFunctionEntry;		// stack spoofing
		BaseThreadInitThunk_t		 	 BaseThreadInitThunk;			// stack spoofing
		RtlUserThreadStart_t			 RtlUserThreadStart;			// stack spoofing
		printf_t 					 	 Printf;						// printf
		RtlAddFunctionTable_t			 RtlAddFunctionTable;			// stack spoofing
    } api;


	uint32_t moduleSize;

	// option for module stomping
	uint8_t isModuleStompingUsed;
	uint8_t sModuleToStomp[32];

	// find the module that follow the loader
	uint32_t instanceSize;  
	uint32_t loaderSize;
	uint8_t sMagicBytes[8];

	uint8_t sDataSec[8];		// cmdline
	uint8_t sCmdLine[2048];		// cmdline

	uint8_t sPDataSec[8];		// stack spoofing
	uint8_t sGadget[8];			// stack spoofing

	uint8_t isDll;
	uint8_t sdllMethode[256];

	uint8_t isDotNet;
	uint32_t dotnetLoaderSize;
	uint32_t dotnetModuleSize;

	uint8_t sDebug[32];			// debug string

	void* ptrModuleTst;			// LoaderTest
	void* ptrDotNetModuleTst;	// LoaderTest

	
} INSTANCE;
#pragma pack(pop)

#endif