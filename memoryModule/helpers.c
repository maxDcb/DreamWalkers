#include "helpers.h"
#include "../common/PEstructs.h"
#include <intrin.h>

static int hlpStrCmp(const char* s1, const char* s2)
{
	while (*s1 && (*s1 == *s2))
	{
		s1++;
		s2++;
	}
	return *(const unsigned char*)s1 - *(const unsigned char*)s2;
}


static WCHAR hlpUpperW(WCHAR c)
{
	if (c >= L'a' && c <= L'z')
		return c - (L'a' - L'A');

	return c;
}


static int hlpWideStrCmpI(LPCWSTR s1, LPCWSTR s2)
{
	while (*s1 && *s2)
	{
		WCHAR c1 = hlpUpperW(*s1);
		WCHAR c2 = hlpUpperW(*s2);

		if (c1 != c2)
			return (int)c1 - (int)c2;

		s1++;
		s2++;
	}

	return (int)hlpUpperW(*s1) - (int)hlpUpperW(*s2);
}


HMODULE WINAPI hlpGetModuleHandle(LPCWSTR sModuleName)
{
	// get the offset of Process Environment Block
	#ifdef _M_IX86
		PEB * ProcEnvBlk = (PEB *) __readfsdword(0x30);
	#elif defined(_M_ARM64)
		PEB * ProcEnvBlk = *(PEB **)((BYTE *)NtCurrentTeb() + 0x60);
	#else
		PEB * ProcEnvBlk = (PEB *)__readgsqword(0x60);
	#endif
	PEB_LDR_DATA * Ldr = ProcEnvBlk->Ldr;
		
	// return base address of a calling module
	if (sModuleName == NULL) 
		return (HMODULE) (ProcEnvBlk->ImageBaseAddress);
	
	LIST_ENTRY * ModuleList = &Ldr->InMemoryOrderModuleList;
	LIST_ENTRY *  pStartListEntry = ModuleList->Flink;
	LIST_ENTRY *  px;
	for (px  = pStartListEntry;	px != ModuleList; px  = px->Flink)
	{
		LDR_DATA_TABLE_ENTRY * pe = (LDR_DATA_TABLE_ENTRY *) ((BYTE *) px - sizeof(LIST_ENTRY));

		LPCWSTR pbuff = pe->BaseDllName.Buffer;
		if (pbuff && hlpWideStrCmpI(pbuff, sModuleName) == 0)
			return (HMODULE) pe->DllBase;
	}

	// otherwise:
	return NULL;
}


FARPROC WINAPI hlpGetProcAddress(HMODULE hMod, char * sProcName) 
{
	char * pBaseAddr = (char *) hMod;

	// get pointers to main headers/structures
	IMAGE_DOS_HEADER * pDosHdr = (IMAGE_DOS_HEADER *) pBaseAddr;
	IMAGE_NT_HEADERS * pNTHdr = (IMAGE_NT_HEADERS *) (pBaseAddr + pDosHdr->e_lfanew);
	IMAGE_OPTIONAL_HEADER * pOptionalHdr = &pNTHdr->OptionalHeader;
	IMAGE_DATA_DIRECTORY * pExportDataDir = (IMAGE_DATA_DIRECTORY *) (&pOptionalHdr->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]);
	IMAGE_EXPORT_DIRECTORY * pExportDirAddr = (IMAGE_EXPORT_DIRECTORY *) (pBaseAddr + pExportDataDir->VirtualAddress);

	// function address we're looking for
	void *pProcAddr;

	// resolve function by ordinal
	if (((DWORD_PTR)sProcName >> 16) == 0) 
	{
		DWORD * pEAT = (DWORD *) (pBaseAddr + pExportDirAddr->AddressOfFunctions);
		
		WORD ordinal = (WORD) sProcName & 0xFFFF;	// convert to WORD
		DWORD Base = pExportDirAddr->Base;			// first ordinal number

		// check if ordinal is not out of scope
		if (ordinal < Base || ordinal >= Base + pExportDirAddr->NumberOfFunctions)
			return NULL;

		// get the function virtual address = RVA + BaseAddr
		pProcAddr = (FARPROC) (pBaseAddr + (DWORD_PTR) pEAT[ordinal - Base]);
	}
	// resolve function by name
	else 
	{
		pProcAddr = NULL;
		
		DWORD * pFuncNameTbl = (DWORD *) (pBaseAddr + pExportDirAddr->AddressOfNames);
		WORD * pHintsTbl = (WORD *) (pBaseAddr + pExportDirAddr->AddressOfNameOrdinals);

		DWORD * pEAT = (DWORD *) (pBaseAddr + pExportDirAddr->AddressOfFunctions);

		// parse through table of function names
		DWORD ii=254;
		for (ii = 0; ii < pExportDirAddr->NumberOfNames; ii++) 
		{
			char * sTmpFuncName = (char *) pBaseAddr + (DWORD_PTR) pFuncNameTbl[ii];
	
			if (hlpStrCmp(sProcName, sTmpFuncName) == 0)
			{
				// found, get the function virtual address = RVA + BaseAddr
				pProcAddr = (FARPROC) (pBaseAddr + (DWORD_PTR) pEAT[pHintsTbl[ii]]);
				break;
			}
		}
	}

	return (FARPROC) pProcAddr;
}
