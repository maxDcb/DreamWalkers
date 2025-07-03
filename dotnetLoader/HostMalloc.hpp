#pragma once
#include <Windows.h>
#include <mscoree.h>
#include <metahost.h>

#include <vector>


typedef enum 
{
	MEM_ALLOC_LIST_HEAD,
	MEM_ALLOC_MALLOC,
	MEM_ALLOC_VIRTUALALLOC,
	MEM_ALLOC_MAPPED_FILE
} memAllocTracker;


typedef struct _MemAllocEntry 
{
	SLIST_ENTRY allocEntry;
	void* Address;
	SIZE_T size;
	memAllocTracker type;
} MemAllocEntry;


class MyHostMalloc : public IHostMalloc
{
public:
	MyHostMalloc(void);
	~MyHostMalloc(void);

    virtual HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid,void  **ppv);
    virtual ULONG   STDMETHODCALLTYPE AddRef(void);
    virtual ULONG   STDMETHODCALLTYPE Release(void);

	virtual HRESULT Alloc(SIZE_T cbSize, EMemoryCriticalLevel eCriticalLevel, void** ppMem);
	virtual HRESULT DebugAlloc(SIZE_T cbSize, EMemoryCriticalLevel       eCriticalLevel, char* pszFileName, int         iLineNo, void** ppMem);
	virtual HRESULT Free(void* pMem);

	HANDLE hHeap;

	const std::vector<MemAllocEntry*>& getMemAllocList()
	{
		return m_memAllocList;
	}

protected:
	DWORD count;

private:
	std::vector<MemAllocEntry*> m_memAllocList;
};