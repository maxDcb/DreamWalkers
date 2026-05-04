#pragma once
#include "HostMalloc.hpp"

#include <string>


class MyMemoryManager : public IHostMemoryManager
{
public:
    MyMemoryManager(void);
    ~MyMemoryManager(void);

    virtual HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid,void  **ppv);
    virtual ULONG   STDMETHODCALLTYPE AddRef(void);
    virtual ULONG   STDMETHODCALLTYPE Release(void);

    virtual HRESULT STDMETHODCALLTYPE CreateMalloc(DWORD dwMallocType, IHostMalloc** ppMalloc);
    virtual HRESULT STDMETHODCALLTYPE VirtualAlloc(void* pAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect, EMemoryCriticalLevel eCriticalLevel, void** ppMem);
    virtual HRESULT STDMETHODCALLTYPE VirtualFree(LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType);
    virtual HRESULT STDMETHODCALLTYPE VirtualQuery(void* lpAddress, void* lpBuffer, SIZE_T dwLength, SIZE_T* pResult);
    virtual HRESULT STDMETHODCALLTYPE VirtualProtect(void* lpAddress, SIZE_T dwSize, DWORD flNewProtect, DWORD* pflOldProtect);
    virtual HRESULT STDMETHODCALLTYPE GetMemoryLoad(DWORD* pMemoryLoad, SIZE_T* pAvailableBytes);
    virtual HRESULT STDMETHODCALLTYPE RegisterMemoryNotificationCallback(ICLRMemoryNotificationCallback* pCallback);
    virtual HRESULT STDMETHODCALLTYPE NeedsVirtualAddressSpace(LPVOID startAddress, SIZE_T size);
    virtual HRESULT STDMETHODCALLTYPE AcquiredVirtualAddressSpace(LPVOID startAddress, SIZE_T size);
    virtual HRESULT STDMETHODCALLTYPE ReleasedVirtualAddressSpace(LPVOID startAddress);

    const std::vector<MemAllocEntry*>& getVirtualAllocList()
    {
        return m_memAllocList;
    }

    const std::vector<MemAllocEntry*>& getMallocList()
    {
        return m_mallocList;
    }


protected:
    volatile LONG count;

private:
    CRITICAL_SECTION m_allocListLock;
    std::vector<MemAllocEntry*> m_memAllocList;
    std::vector<MemAllocEntry*> m_mallocList;

};
