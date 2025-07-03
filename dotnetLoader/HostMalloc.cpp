#include "HostMalloc.hpp"
#include "MemoryManager.hpp"

#include <iostream>


MyHostMalloc::MyHostMalloc(void)
{
	count = 0;
}


MyHostMalloc::~MyHostMalloc(void)
{
	
}


HRESULT STDMETHODCALLTYPE MyHostMalloc::QueryInterface(REFIID vTableGuid, void** ppv) 
{
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
	return(++((MyHostMalloc*)this)->count);
}


ULONG STDMETHODCALLTYPE MyHostMalloc::Release() 
{
	if (--this->count == 0) 
	{
		GlobalFree(this);
		return 0;
	}
	return this->count;
}


HRESULT MyHostMalloc::Alloc(SIZE_T cbSize, EMemoryCriticalLevel eCriticalLevel, void** ppMem) 
{
	LPVOID allocAddress = ::HeapAlloc(this->hHeap, 0, cbSize);
	// std::cout << "MyHostMalloc::Alloc " << std::hex << allocAddress << std::endl;

	MemAllocEntry* allocEntry = new MemAllocEntry();
	allocEntry->Address = allocAddress;
	allocEntry->size = cbSize;
	allocEntry->type = MEM_ALLOC_MALLOC;
	m_memAllocList.push_back(allocEntry);

	*ppMem = allocAddress;
	if (*ppMem == NULL) 
	{
		return E_OUTOFMEMORY;
	}
	else 
	{
		return S_OK;
	}
}


HRESULT MyHostMalloc::DebugAlloc(SIZE_T cbSize, EMemoryCriticalLevel       eCriticalLevel, char* pszFileName, int         iLineNo, void** ppMem) 
{
	// std::cout << "MyHostMalloc::DebugAlloc" << std::endl;

	*ppMem = ::HeapAlloc(this->hHeap, 0, cbSize);
	if (*ppMem == NULL) 
	{
		return E_OUTOFMEMORY;
	}
	else 
	{
		return S_OK;
	}
}


HRESULT MyHostMalloc::Free(void* pMem) 
{
	// std::cout << "MyHostMalloc::Free" << std::endl;

	if (!::HeapValidate(this->hHeap, 0, pMem)) 
	{
		// std::cout << "Detected corrupted heap" << std::endl;
		return E_OUTOFMEMORY;
	}
	::HeapFree(this->hHeap, 0, pMem);
	pMem = nullptr;

	return S_OK;
}