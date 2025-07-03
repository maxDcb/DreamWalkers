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

	virtual HRESULT CreateMalloc(DWORD dwMallocType, IHostMalloc** ppMalloc);
	virtual HRESULT VirtualAlloc(void* pAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect, EMemoryCriticalLevel eCriticalLevel, void** ppMem);
	virtual HRESULT VirtualFree(LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType);
	virtual HRESULT VirtualQuery(void* lpAddress, void* lpBuffer, SIZE_T dwLength, SIZE_T* pResult);
	virtual HRESULT VirtualProtect(void* lpAddress, SIZE_T dwSize, DWORD flNewProtect, DWORD* pflOldProtect);
	virtual HRESULT GetMemoryLoad(DWORD* pMemoryLoad, SIZE_T* pAvailableBytes);
	virtual HRESULT RegisterMemoryNotificationCallback(ICLRMemoryNotificationCallback* pCallback);
	virtual HRESULT NeedsVirtualAddressSpace(LPVOID startAddress, SIZE_T size);
	virtual HRESULT AcquiredVirtualAddressSpace(LPVOID startAddress, SIZE_T size);
	virtual HRESULT ReleasedVirtualAddressSpace(LPVOID startAddress);

	const std::vector<MemAllocEntry*>& getVirtualAllocList()
	{
		return m_memAllocList;
	}

	const std::vector<MemAllocEntry*>& getMallocList()
	{
		return m_mallocManager->getMemAllocList();
	}


protected:
	DWORD count;

private:
	MyHostMalloc* m_mallocManager;

	std::vector<MemAllocEntry*> m_memAllocList;

};