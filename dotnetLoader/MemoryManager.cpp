#include "MemoryManager.hpp"
#include "HostMalloc.hpp"

#include <iostream>


MyMemoryManager::MyMemoryManager(void)
{
	count = 0;
	m_mallocManager = new MyHostMalloc();
}


MyMemoryManager::~MyMemoryManager(void)
{
	delete m_mallocManager;
}


HRESULT STDMETHODCALLTYPE MyMemoryManager::QueryInterface(REFIID vTableGuid, void** ppv) 
{
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
	return(++((MyMemoryManager*)this)->count);
}


ULONG STDMETHODCALLTYPE MyMemoryManager::Release() 
{
	if (--((MyMemoryManager*)this)->count == 0) 
	{
		GlobalFree(this);
		return 0;
	}
	return ((MyMemoryManager*)this)->count;
}


// This is called when the CLR wants to do heap allocations, it's responsible for returning our implementation of IHostMalloc
HRESULT MyMemoryManager::CreateMalloc(DWORD dwMallocType, IHostMalloc** ppMalloc) 
{
	// std::cout << "MyMemoryManager::CreateMalloc" << std::endl;

	//C reate a heap and add it to our interface struct
	HANDLE hHeap = NULL;
	if (dwMallocType & MALLOC_EXECUTABLE) 
	{
		hHeap = ::HeapCreate(HEAP_CREATE_ENABLE_EXECUTE, 0, 0);
	}
	else 
	{
		hHeap = ::HeapCreate(0, 0, 0);
	}
	m_mallocManager->hHeap = hHeap;

	*ppMalloc = m_mallocManager;
	return S_OK;
}


//The Virtual* API calls are responsible for non-heap memory management, you can just call the Virtual* APIs as intended or implement your own routines
HRESULT MyMemoryManager::VirtualAlloc(void* pAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect, EMemoryCriticalLevel eCriticalLevel, void** ppMem) 
{

	LPVOID allocAddress = ::VirtualAlloc(pAddress, dwSize, flAllocationType, flProtect);

	// std::cout << "MyMemoryManager::VirtualAlloc " << std::hex << allocAddress << std::endl;

	*ppMem = allocAddress;

	MemAllocEntry* allocEntry = new MemAllocEntry();
	allocEntry->Address = allocAddress;
	allocEntry->size = dwSize;
	allocEntry->type = MEM_ALLOC_VIRTUALALLOC;
	m_memAllocList.push_back(allocEntry);

	return S_OK;
}


HRESULT MyMemoryManager::VirtualFree(LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType) 
{
	// std::cout << "MyMemoryManager::VirtualFree" << std::endl;

	::VirtualFree(lpAddress, dwSize, dwFreeType);
	lpAddress = nullptr;

	return S_OK;
}


HRESULT MyMemoryManager::VirtualQuery(void* lpAddress, void* lpBuffer, SIZE_T dwLength, SIZE_T* pResult) 
{
	// std::cout << "MyMemoryManager::VirtualQuery" << std::endl;

	*pResult = ::VirtualQuery(lpAddress, (PMEMORY_BASIC_INFORMATION)lpBuffer, dwLength);
	return S_OK;
}


HRESULT MyMemoryManager::VirtualProtect(void* lpAddress, SIZE_T dwSize, DWORD flNewProtect, DWORD* pflOldProtect) 
{
	// std::cout << "MyMemoryManager::VirtualProtect" << std::endl;

	::VirtualProtect(lpAddress, dwSize, flNewProtect, pflOldProtect);

	return S_OK;
}


HRESULT MyMemoryManager::GetMemoryLoad(DWORD* pMemoryLoad, SIZE_T* pAvailableBytes) 
{
	// std::cout << "MyMemoryManager::GetMemoryLoad" << std::endl;

	//Just returning arbitrary values
	*pMemoryLoad = 30;
	*pAvailableBytes = 100 * 1024 * 1024;
	return S_OK;
}


HRESULT MyMemoryManager::RegisterMemoryNotificationCallback(ICLRMemoryNotificationCallback* pCallback) 
{
	// std::cout << "MyMemoryManager::RegisterMemoryNotificationCallback" << std::endl;
	return S_OK;
}


HRESULT MyMemoryManager::NeedsVirtualAddressSpace(LPVOID startAddress, SIZE_T size) 
{
	// std::cout << "MyMemoryManager::NeedsVirtualAddressSpace" << std::endl;
	return S_OK;
}


//
// This is a notification callback that will be triggered whenever a .NET assembly is loaded into the process
//
HRESULT MyMemoryManager::AcquiredVirtualAddressSpace(LPVOID startAddress, SIZE_T size) 
{
	// std::cout << "MyMemoryManager::AcquiredVirtualAddressSpace" << std::endl;
	// std::cout << "Mapped file with size " << size <<  " bytes into memory at  " << std::hex << startAddress << std::endl;

	//This is used to track the assemblies that are mapped into the process
	MemAllocEntry* allocEntry = new MemAllocEntry();
	allocEntry->Address = startAddress;
	allocEntry->size = size;
	allocEntry->type = MEM_ALLOC_MAPPED_FILE;
	m_memAllocList.push_back(allocEntry);
	

	return S_OK;
}


HRESULT MyMemoryManager::ReleasedVirtualAddressSpace(LPVOID startAddress) 
{
	// std::cout << "MyMemoryManager::ReleasedVirtualAddressSpace" << std::endl;
	return S_OK;
}