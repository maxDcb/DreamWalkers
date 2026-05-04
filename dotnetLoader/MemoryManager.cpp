#include "MemoryManager.hpp"
#include "HostMalloc.hpp"

#include <algorithm>
#include <new>


MyMemoryManager::MyMemoryManager(void)
{
    count = 1;
    InitializeCriticalSection(&m_allocListLock);
}


MyMemoryManager::~MyMemoryManager(void)
{
    for (auto entry : m_memAllocList)
        delete entry;
    for (auto entry : m_mallocList)
        delete entry;
    DeleteCriticalSection(&m_allocListLock);
}


HRESULT STDMETHODCALLTYPE MyMemoryManager::QueryInterface(REFIID vTableGuid, void** ppv)
{
    if (ppv == NULL)
        return E_POINTER;

    if (!IsEqualIID(vTableGuid, IID_IUnknown) && !IsEqualIID(vTableGuid, IID_IHostMemoryManager))
    {
        *ppv = 0;
        return E_NOINTERFACE;
    }
    *ppv = this;
    this->AddRef();
    return S_OK;
}


ULONG STDMETHODCALLTYPE MyMemoryManager::AddRef()
{
    return static_cast<ULONG>(InterlockedIncrement(&count));
}


ULONG STDMETHODCALLTYPE MyMemoryManager::Release()
{
    ULONG refCount = static_cast<ULONG>(InterlockedDecrement(&count));
    if (refCount == 0)
    {
        delete this;
        return 0;
    }
    return refCount;
}


// This is called when the CLR wants to do heap allocations, it's responsible for returning our implementation of IHostMalloc
HRESULT STDMETHODCALLTYPE MyMemoryManager::CreateMalloc(DWORD dwMallocType, IHostMalloc** ppMalloc)
{
    if (ppMalloc == NULL)
        return E_POINTER;
    *ppMalloc = NULL;

    HANDLE hHeap = NULL;
    if (dwMallocType & MALLOC_EXECUTABLE)
    {
        hHeap = ::HeapCreate(HEAP_CREATE_ENABLE_EXECUTE, 0, 0);
    }
    else
    {
        hHeap = ::HeapCreate(0, 0, 0);
    }
    if (hHeap == NULL)
        return HRESULT_FROM_WIN32(GetLastError());

    MyHostMalloc* mallocManager = new (std::nothrow) MyHostMalloc(hHeap, this, &m_allocListLock, &m_mallocList);
    if (mallocManager == NULL)
    {
        ::HeapDestroy(hHeap);
        return E_OUTOFMEMORY;
    }

    *ppMalloc = mallocManager;
    return S_OK;
}


//The Virtual* API calls are responsible for non-heap memory management, you can just call the Virtual* APIs as intended or implement your own routines
HRESULT STDMETHODCALLTYPE MyMemoryManager::VirtualAlloc(void* pAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect, EMemoryCriticalLevel eCriticalLevel, void** ppMem)
{
    (void)eCriticalLevel;

    if (ppMem == NULL)
        return E_POINTER;
    *ppMem = NULL;

    LPVOID allocAddress = ::VirtualAlloc(pAddress, dwSize, flAllocationType, flProtect);

    if (allocAddress == NULL)
        return HRESULT_FROM_WIN32(GetLastError());

    MemAllocEntry* allocEntry = new (std::nothrow) MemAllocEntry();
    if (allocEntry == NULL)
    {
        ::VirtualFree(allocAddress, 0, MEM_RELEASE);
        return E_OUTOFMEMORY;
    }
    allocEntry->Address = allocAddress;
    allocEntry->size = dwSize;
    allocEntry->type = MEM_ALLOC_VIRTUALALLOC;

    EnterCriticalSection(&m_allocListLock);
    try
    {
        m_memAllocList.push_back(allocEntry);
    }
    catch (...)
    {
        LeaveCriticalSection(&m_allocListLock);
        delete allocEntry;
        ::VirtualFree(allocAddress, 0, MEM_RELEASE);
        return E_OUTOFMEMORY;
    }
    LeaveCriticalSection(&m_allocListLock);

    *ppMem = allocAddress;
    return S_OK;
}


HRESULT STDMETHODCALLTYPE MyMemoryManager::VirtualFree(LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType)
{
    if (lpAddress == NULL)
        return S_OK;

    EnterCriticalSection(&m_allocListLock);
    auto it = std::find_if(m_memAllocList.begin(), m_memAllocList.end(), [lpAddress](const MemAllocEntry* entry) {
        return entry != NULL && entry->Address == lpAddress && entry->type == MEM_ALLOC_VIRTUALALLOC;
    });
    if (!::VirtualFree(lpAddress, dwSize, dwFreeType))
    {
        DWORD lastError = GetLastError();
        LeaveCriticalSection(&m_allocListLock);
        return HRESULT_FROM_WIN32(lastError == ERROR_SUCCESS ? ERROR_INVALID_PARAMETER : lastError);
    }

    if (it != m_memAllocList.end())
    {
        MemAllocEntry* allocEntry = *it;
        m_memAllocList.erase(it);
        delete allocEntry;
    }
    LeaveCriticalSection(&m_allocListLock);

    return S_OK;
}


HRESULT STDMETHODCALLTYPE MyMemoryManager::VirtualQuery(void* lpAddress, void* lpBuffer, SIZE_T dwLength, SIZE_T* pResult)
{
    if (lpBuffer == NULL || pResult == NULL)
        return E_POINTER;

    *pResult = ::VirtualQuery(lpAddress, (PMEMORY_BASIC_INFORMATION)lpBuffer, dwLength);
    if (*pResult == 0)
        return HRESULT_FROM_WIN32(GetLastError());

    return S_OK;
}


HRESULT STDMETHODCALLTYPE MyMemoryManager::VirtualProtect(void* lpAddress, SIZE_T dwSize, DWORD flNewProtect, DWORD* pflOldProtect)
{
    if (pflOldProtect == NULL)
        return E_POINTER;

    if (!::VirtualProtect(lpAddress, dwSize, flNewProtect, pflOldProtect))
        return HRESULT_FROM_WIN32(GetLastError());

    return S_OK;
}


HRESULT STDMETHODCALLTYPE MyMemoryManager::GetMemoryLoad(DWORD* pMemoryLoad, SIZE_T* pAvailableBytes)
{
    if (pMemoryLoad == NULL || pAvailableBytes == NULL)
        return E_POINTER;

    MEMORYSTATUSEX memoryStatus = {};
    memoryStatus.dwLength = sizeof(memoryStatus);
    if (!::GlobalMemoryStatusEx(&memoryStatus))
        return HRESULT_FROM_WIN32(GetLastError());

    *pMemoryLoad = memoryStatus.dwMemoryLoad;
    *pAvailableBytes = static_cast<SIZE_T>(memoryStatus.ullAvailVirtual);
    return S_OK;
}


HRESULT STDMETHODCALLTYPE MyMemoryManager::RegisterMemoryNotificationCallback(ICLRMemoryNotificationCallback* pCallback)
{
    (void)pCallback;
    return S_OK;
}


HRESULT STDMETHODCALLTYPE MyMemoryManager::NeedsVirtualAddressSpace(LPVOID startAddress, SIZE_T size)
{
    (void)startAddress;
    (void)size;
    return S_OK;
}


//
// This is a notification callback that will be triggered whenever a .NET assembly is loaded into the process
//
HRESULT STDMETHODCALLTYPE MyMemoryManager::AcquiredVirtualAddressSpace(LPVOID startAddress, SIZE_T size)
{
    //This is used to track the assemblies that are mapped into the process
    MemAllocEntry* allocEntry = new (std::nothrow) MemAllocEntry();
    if (allocEntry == NULL)
        return E_OUTOFMEMORY;

    allocEntry->Address = startAddress;
    allocEntry->size = size;
    allocEntry->type = MEM_ALLOC_MAPPED_FILE;

    EnterCriticalSection(&m_allocListLock);
    try
    {
        m_memAllocList.push_back(allocEntry);
    }
    catch (...)
    {
        LeaveCriticalSection(&m_allocListLock);
        delete allocEntry;
        return E_OUTOFMEMORY;
    }
    LeaveCriticalSection(&m_allocListLock);

    return S_OK;
}


HRESULT STDMETHODCALLTYPE MyMemoryManager::ReleasedVirtualAddressSpace(LPVOID startAddress)
{
    MemAllocEntry* allocEntry = NULL;
    EnterCriticalSection(&m_allocListLock);
    auto it = std::find_if(m_memAllocList.begin(), m_memAllocList.end(), [startAddress](const MemAllocEntry* entry) {
        return entry != NULL && entry->Address == startAddress && entry->type == MEM_ALLOC_MAPPED_FILE;
    });
    if (it != m_memAllocList.end())
    {
        allocEntry = *it;
        m_memAllocList.erase(it);
    }
    LeaveCriticalSection(&m_allocListLock);

    delete allocEntry;
    return S_OK;
}
