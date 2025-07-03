#pragma once
#include <Windows.h>
#include <mscoree.h>
#include <metahost.h>

#include "MemoryManager.hpp"
#include "AssemblyManager.hpp"


static const  GUID xIID_IHostControl = { 0x02CA073C, 0x7079, 0x4860, {0x88, 0x0A, 0xC2, 0xF7, 0xA4, 0x49, 0xC9, 0x91} };


inline void XOREncrypt2(char* address, int size, const std::string& xorKey) 
{
	DWORD start = 0;
	while (start < size) 
	{
		*(address + start) ^= xorKey[start % xorKey.size()];
		start++;
	}
}


class MyHostControl : public IHostControl
{
public:
	MyHostControl(void);
	~MyHostControl(void);

    virtual HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid,void  **ppv);
    virtual ULONG   STDMETHODCALLTYPE AddRef(void);
    virtual ULONG   STDMETHODCALLTYPE Release(void);

	virtual HRESULT STDMETHODCALLTYPE GetHostManager(REFIID riid, void** ppObject);
	virtual HRESULT STDMETHODCALLTYPE SetAppDomainManager(DWORD dwAppDomainID, IUnknown* pUnkAppDomainManager);

	int setTargetAssembly(TargetAssembly * targetAssembly)
	{
		m_assemblyManager->setTargetAssembly(targetAssembly);
		return 0;
	}

	int updateTargetAssembly(ICLRAssemblyIdentityManager* identityManager, const std::string& data)
	{
		m_assemblyManager->updateTargetAssembly(identityManager, data);
		return 0;
	}

	LPWSTR getAssemblyInfo()
	{
		return m_assemblyManager->getAssemblyInfo();
	};


	const std::vector<MemAllocEntry*>& getVirtualAllocList()
	{
		return m_memoryManager->getVirtualAllocList();
	}

	const std::vector<MemAllocEntry*>& getMallocList()
	{
		return m_memoryManager->getMallocList();
	}

	int xorMemory(const std::string& xorKey)
	{
		std::vector<MemAllocEntry*> vitualAllocList = getVirtualAllocList();

		for (auto it = vitualAllocList.begin(); it != vitualAllocList.end(); ++it)
		{
			MemAllocEntry* entry = *it;
			if (entry->Address && entry->type == MEM_ALLOC_MAPPED_FILE)
			{
				XOREncrypt2((char*)entry->Address, entry->size, xorKey);
			}
		}

		MEMORY_BASIC_INFORMATION memInfo;
		DWORD oldProtect;
		std::vector<MemAllocEntry*> mallocList = getMallocList();
		for (auto it = mallocList.begin(); it != mallocList.end(); ++it)
		{
			MemAllocEntry* entry = *it;

			if(entry->Address)
			{
				::VirtualQuery(entry->Address, &memInfo, sizeof(MEMORY_BASIC_INFORMATION));

				if (memInfo.AllocationProtect != 0 && memInfo.State != 0x2000 && memInfo.State != 0x10000) 
				{
					if (memInfo.Protect != PAGE_READWRITE) 
					{
						::VirtualProtect(memInfo.BaseAddress, memInfo.RegionSize, PAGE_READWRITE, &oldProtect);
						XOREncrypt2((char*)memInfo.BaseAddress, memInfo.RegionSize, xorKey);
						::VirtualProtect(memInfo.BaseAddress, memInfo.RegionSize, oldProtect, &oldProtect);
					}
					else 
					{
						XOREncrypt2((char*)memInfo.BaseAddress, memInfo.RegionSize, xorKey);
					}
				}
			}
		}

		return 0;
	}
	
protected:
	DWORD count;

private:
	MyAssemblyManager* m_assemblyManager;
	MyMemoryManager* m_memoryManager;

};
