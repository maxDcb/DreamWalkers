#pragma once


#include <winternl.h> // for UNICODE_STRING


#define SW3_RVA2VA(Type, DllBase, Rva) (Type)((ULONG_PTR) DllBase + Rva)

typedef struct _SW3_PEB_LDR_DATA {
    BYTE Reserved1[8];
    PVOID Reserved2[3];
    LIST_ENTRY InMemoryOrderModuleList;
} SW3_PEB_LDR_DATA, *PSW3_PEB_LDR_DATA;

typedef struct _SW3_LDR_DATA_TABLE_ENTRY {
    PVOID Reserved1[2];
    LIST_ENTRY InMemoryOrderLinks;
    PVOID Reserved2[2];
    PVOID DllBase;
} SW3_LDR_DATA_TABLE_ENTRY, *PSW3_LDR_DATA_TABLE_ENTRY;

typedef struct _SW3_PEB {
    BYTE Reserved1[2];
    BYTE BeingDebugged;
    BYTE Reserved2[1];
    PVOID Reserved3[2];
    PSW3_PEB_LDR_DATA Ldr;
} SW3_PEB, *PSW3_PEB;

typedef struct _PS_ATTRIBUTE
{
    ULONG  Attribute;
    SIZE_T Size;
    union
    {
        ULONG Value;
        PVOID ValuePtr;
    } u1;
    PSIZE_T ReturnLength;
} PS_ATTRIBUTE, *PPS_ATTRIBUTE;

// typedef struct _UNICODE_STRING
// {
//     USHORT Length;
//     USHORT MaximumLength;
//     PWSTR  Buffer;
// } UNICODE_STRING, *PUNICODE_STRING;

// typedef struct _OBJECT_ATTRIBUTES
// {
//     ULONG           Length;
//     HANDLE          RootDirectory;
//     PUNICODE_STRING ObjectName;
//     ULONG           Attributes;
//     PVOID           SecurityDescriptor;
//     PVOID           SecurityQualityOfService;
// } OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

// typedef struct _CLIENT_ID
// {
//     HANDLE UniqueProcess;
//     HANDLE UniqueThread;
// } CLIENT_ID, *PCLIENT_ID;

typedef struct _PS_ATTRIBUTE_LIST
{
    SIZE_T       TotalLength;
    PS_ATTRIBUTE Attributes[1];
} PS_ATTRIBUTE_LIST, *PPS_ATTRIBUTE_LIST;

typedef enum _MEMORY_INFORMATION_CLASS
{
    MemoryBasicInformation,
    MemoryWorkingSetInformation,
    MemoryMappedFilenameInformation,
    MemoryRegionInformation,
    MemoryWorkingSetExInformation,
    MemorySharedCommitInformation,
    MemoryImageInformation,
    MemoryRegionInformationEx,
    MemoryPrivilegedBasicInformation,
    MemoryEnclaveImageInformation,
    MemoryBasicInformationCapped
} MEMORY_INFORMATION_CLASS, *PMEMORY_INFORMATION_CLASS;


#ifndef InitializeObjectAttributes
#define InitializeObjectAttributes( p, n, a, r, s ) { \
    (p)->Length = sizeof( OBJECT_ATTRIBUTES );        \
    (p)->RootDirectory = r;                           \
    (p)->Attributes = a;                              \
    (p)->ObjectName = n;                              \
    (p)->SecurityDescriptor = s;                      \
    (p)->SecurityQualityOfService = NULL;             \
}
#endif

typedef LPVOID HINTERNET;
#define WINHTTP_ACCESS_TYPE_DEFAULT_PROXY   0
#define WINHTTP_NO_PROXY_NAME               NULL
#define WINHTTP_NO_PROXY_BYPASS             NULL
#define WINHTTP_NO_REFERER   NULL
#define WINHTTP_DEFAULT_ACCEPT_TYPES   NULL
typedef WORD INTERNET_PORT;
#define WINHTTP_FLAG_BYPASS_PROXY_CACHE   0x00000100
#define WINHTTP_FLAG_REFRESH   WINHTTP_FLAG_BYPASS_PROXY_CACHE
#define WINHTTP_FLAG_SECURE   0x00800000
#define SECURITY_FLAG_IGNORE_UNKNOWN_CA   0x00000100
#define SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE   0x00000200
#define SECURITY_FLAG_IGNORE_CERT_CN_INVALID   0x00001000
#define SECURITY_FLAG_IGNORE_CERT_DATE_INVALID   0x00002000
#define WINHTTP_OPTION_SECURITY_FLAGS   31
#define WINHTTP_NO_ADDITIONAL_HEADERS   NULL
#define WINHTTP_NO_REQUEST_DATA   NULL
#define WINHTTP_QUERY_STATUS_CODE   19
#define WINHTTP_QUERY_FLAG_NUMBER   0x20000000
#define WINHTTP_HEADER_NAME_BY_INDEX   NULL
#define WINHTTP_NO_HEADER_INDEX   NULL


typedef HINTERNET (WINAPI *WinHttpOpen_t)(
LPCWSTR pszAgentW,
DWORD   dwAccessType,
LPCWSTR pszProxyW,
LPCWSTR pszProxyBypassW,
DWORD   dwFlags
);

typedef HINTERNET (WINAPI *WinHttpConnect_t)(
HINTERNET     hSession,
LPCWSTR       pswzServerName,
INTERNET_PORT nServerPort,
DWORD         dwReserved
);

typedef HINTERNET (WINAPI *WinHttpOpenRequest_t)(
HINTERNET hConnect,
LPCWSTR   pwszVerb,
LPCWSTR   pwszObjectName,
LPCWSTR   pwszVersion,
LPCWSTR   pwszReferrer,
LPCWSTR   *ppwszAcceptTypes,
DWORD     dwFlags
);

typedef BOOL (WINAPI *WinHttpSetOption_t)(
HINTERNET hInternet,
DWORD     dwOption,
LPVOID    lpBuffer,
DWORD     dwBufferLength
);

typedef BOOL (WINAPI *WinHttpSendRequest_t)(
HINTERNET hRequest,
LPCWSTR   lpszHeaders,
DWORD     dwHeadersLength,
LPVOID    lpOptional,
DWORD     dwOptionalLength,
DWORD     dwTotalLength,
DWORD_PTR dwContext
);

typedef BOOL (WINAPI *WinHttpReceiveResponse_t)(
HINTERNET hRequest,
LPVOID    lpReserved
);

typedef BOOL (WINAPI *WinHttpQueryHeaders_t)(
HINTERNET hRequest,
DWORD     dwInfoLevel,
LPCWSTR   pwszName,
LPVOID    lpBuffer,
LPDWORD   lpdwBufferLength,
LPDWORD   lpdwIndex
);

typedef BOOL (WINAPI *WinHttpQueryDataAvailable_t)(
HINTERNET hRequest,
LPDWORD   lpdwNumberOfBytesAvailable
);

typedef BOOL (WINAPI *WinHttpReadData_t)(
HINTERNET hRequest,
LPVOID    lpBuffer,
DWORD     dwNumberOfBytesToRead,
LPDWORD   lpdwNumberOfBytesRead
);

typedef BOOL (WINAPI *WinHttpCloseHandle_t)(
HINTERNET hInternet
);

typedef FARPROC (WINAPI * GetProcAddress_t)(
HMODULE hModule,
LPCSTR  lpProcName
);

typedef HMODULE (WINAPI * GetModuleHandle_t)(
LPCSTR lpModuleName
);

typedef BOOL    (WINAPI * VirtualProtect_t)( 
LPVOID lpAddress,
SIZE_T dwSize,
DWORD  flNewProtect,
PDWORD lpflOldProtect 
);

typedef LPVOID  (WINAPI * VirtualAllocEx_t)( 
HANDLE hProcess,
LPVOID lpAddress,
SIZE_T dwSize,
DWORD  flAllocationType,
DWORD  flProtect 
);

typedef HANDLE  (WINAPI * CreateRemoteThread_t)( 
HANDLE hProcess,
LPSECURITY_ATTRIBUTES  lpThreadAttributes,
SIZE_T dwStackSize,
LPTHREAD_START_ROUTINE lpStartAddress,
LPVOID lpParameter,
DWORD dwCreationFlags,
LPDWORD lpThreadId 
);

typedef HANDLE  (WINAPI * OpenProcess_t)( 
DWORD dwDesiredAccess,
BOOL bInheritHandle,
DWORD dwProcessId 
);

typedef BOOL    (WINAPI * WriteProcessMemory_t)( 
HANDLE  hProcess,
LPVOID  lpBaseAddress,
LPCVOID lpBuffer,
SIZE_T  nSize,
SIZE_T  *lpNumberOfBytesWritten 
);

typedef HMODULE (WINAPI * LoadLibraryA_t)( 
LPCSTR lpLibFileName
);

typedef DWORD   (WINAPI * WaitForSingleObject_t)( 
HANDLE hHandle,
DWORD  dwMilliseconds
);

typedef BOOL    (WINAPI * CloseHandle_t)( 
HANDLE hObject 
);

typedef BOOL (WINAPI * CryptAcquireContextW_t)(
HCRYPTPROV *phProv,
LPCSTR szContainer,
LPCSTR szProvider,
DWORD dwProvType,
DWORD dwFlags
);

typedef BOOL (WINAPI * CryptCreateHash_t)( 
HCRYPTPROV hProv,
ALG_ID Algid,
HCRYPTKEY  hKey,
DWORD dwFlags,
HCRYPTHASH *phHash 
);

typedef BOOL (WINAPI * CryptHashData_t)( 
HCRYPTHASH hHash,
const BYTE *pbData,
DWORD dwDataLen,
DWORD dwFlags 
);

typedef BOOL (WINAPI * CryptDeriveKey_t)( 
HCRYPTPROV hProv,
ALG_ID Algid,
HCRYPTHASH hBaseData,
DWORD dwFlags,
HCRYPTKEY  *phKey 
);

typedef BOOL (WINAPI * CryptDecrypt_t)( 
HCRYPTKEY  hKey,
HCRYPTHASH hHash,
BOOL Final,
DWORD dwFlags,
BYTE *pbData,
DWORD *pdwDataLen 
);

typedef BOOL (WINAPI * CryptReleaseContext_t)( 
HCRYPTPROV hProv,
DWORD dwFlags 
);

typedef BOOL (WINAPI * CryptDestroyHash_t)( 
HCRYPTHASH hHash 
);

typedef BOOL (WINAPI * CryptDestroyKey_t)(
HCRYPTKEY hKey 
);

typedef HANDLE (WINAPI * CreateToolhelp32Snapshot_t)(
DWORD dwFlags,
DWORD th32ProcessID 
);

typedef BOOL (WINAPI * Process32First_t)(
HANDLE hSnapshot,
LPPROCESSENTRY32 lppe 
);

typedef BOOL (WINAPI * Process32Next_t)(  
HANDLE  hSnapshot,
LPPROCESSENTRY32 lppe 
);

typedef HANDLE (WINAPI * OpenThread_t)( 
DWORD dwDesiredAccess,
BOOL bInheritHandle,
DWORD dwThreadId 
);

typedef DWORD (WINAPI * SuspendThread_t)( 
HANDLE hThread 
);

typedef DWORD (WINAPI * ResumeThread_t)( 
HANDLE hThread 
);

typedef BOOL  (WINAPI * GetThreadContext_t)( 
HANDLE hThread,
LPCONTEXT lpContext 
);

typedef BOOL (WINAPI * SetThreadContext_t)( 
HANDLE hThread,
const CONTEXT *lpContex
);

typedef BOOL (WINAPI * Thread32Next_t)( 
HANDLE hSnapshot,
LPTHREADENTRY32 lpte
);

// typedef struct _IO_STATUS_BLOCK {
//   union {
//     NTSTATUS Status;
//     PVOID    Pointer;
//   };
//   ULONG_PTR Information;
// } IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;


typedef
VOID
(NTAPI *PIO_APC_ROUTINE) (
    IN PVOID ApcContext,
    IN PIO_STATUS_BLOCK IoStatusBlock,
    IN ULONG Reserved
    );