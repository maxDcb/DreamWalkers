#include "HostMalloc.hpp"
#include "MemoryManager.hpp"

#include <algorithm>
#include <new>


MyHostMalloc::MyHostMalloc(HANDLE hHeap, IHostMemoryManager* owner, CRITICAL_SECTION* allocListLock, std::vector<MemAllocEntry*>* allocList)
{
    count = 1;
    m_hHeap = hHeap;
    m_owner = owner;
    if (m_owner != NULL)
        m_owner->AddRef();
    m_allocListLock = allocListLock;
    m_memAllocList = allocList;
}


MyHostMalloc::~MyHostMalloc(void)
{
    if (m_hHeap != NULL)
    {
        ::HeapDestroy(m_hHeap);
        m_hHeap = NULL;
    }
    if (m_owner != NULL)
    {
        m_owner->Release();
        m_owner = NULL;
    }
}


HRESULT STDMETHODCALLTYPE MyHostMalloc::QueryInterface(REFIID vTableGuid, void** ppv)
{
    if (ppv == NULL)
        return E_POINTER;

    if (!IsEqualIID(vTableGuid, IID_IUnknown) && !IsEqualIID(vTableGuid, IID_IHostMalloc))
    {
        *ppv = 0;
        return E_NOINTERFACE;
    }
    *ppv = this;
    this->AddRef();
    return S_OK;
}


ULONG STDMETHODCALLTYPE MyHostMalloc::AddRef()
{
    return static_cast<ULONG>(InterlockedIncrement(&count));
}


ULONG STDMETHODCALLTYPE MyHostMalloc::Release()
{
    ULONG refCount = static_cast<ULONG>(InterlockedDecrement(&count));
    if (refCount == 0)
    {
        delete this;
        return 0;
    }
    return refCount;
}


HRESULT STDMETHODCALLTYPE MyHostMalloc::Alloc(SIZE_T cbSize, EMemoryCriticalLevel eCriticalLevel, void** ppMem)
{
    (void)eCriticalLevel;

    if (ppMem == NULL)
        return E_POINTER;
    *ppMem = NULL;

    LPVOID allocAddress = ::HeapAlloc(m_hHeap, 0, cbSize);

    if (allocAddress == NULL)
        return E_OUTOFMEMORY;

    MemAllocEntry* allocEntry = new (std::nothrow) MemAllocEntry();
    if (allocEntry == NULL)
    {
        ::HeapFree(m_hHeap, 0, allocAddress);
        return E_OUTOFMEMORY;
    }

    allocEntry->Address = allocAddress;
    allocEntry->size = cbSize;
    allocEntry->type = MEM_ALLOC_MALLOC;

    EnterCriticalSection(m_allocListLock);
    try
    {
        m_memAllocList->push_back(allocEntry);
    }
    catch (...)
    {
        LeaveCriticalSection(m_allocListLock);
        delete allocEntry;
        ::HeapFree(m_hHeap, 0, allocAddress);
        return E_OUTOFMEMORY;
    }
    LeaveCriticalSection(m_allocListLock);

    *ppMem = allocAddress;
    return S_OK;
}


HRESULT STDMETHODCALLTYPE MyHostMalloc::DebugAlloc(SIZE_T cbSize, EMemoryCriticalLevel       eCriticalLevel, char* pszFileName, int         iLineNo, void** ppMem)
{
    (void)pszFileName;
    (void)iLineNo;

    return Alloc(cbSize, eCriticalLevel, ppMem);
}


HRESULT STDMETHODCALLTYPE MyHostMalloc::Free(void* pMem)
{
    if (pMem == NULL)
        return S_OK;

    EnterCriticalSection(m_allocListLock);
    auto it = std::find_if(m_memAllocList->begin(), m_memAllocList->end(), [pMem](const MemAllocEntry* entry) {
        return entry != NULL && entry->Address == pMem;
    });
    if (!::HeapFree(m_hHeap, 0, pMem))
    {
        DWORD lastError = GetLastError();
        LeaveCriticalSection(m_allocListLock);
        return HRESULT_FROM_WIN32(lastError == ERROR_SUCCESS ? ERROR_INVALID_PARAMETER : lastError);
    }

    if (it != m_memAllocList->end())
    {
        MemAllocEntry* allocEntry = *it;
        m_memAllocList->erase(it);
        delete allocEntry;
    }
    LeaveCriticalSection(m_allocListLock);

    return S_OK;
}
