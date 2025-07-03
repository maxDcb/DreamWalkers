#pragma once
#include "AssemblyStore.hpp"


class MyAssemblyManager : public IHostAssemblyManager
{
public:
	MyAssemblyManager(void);
	~MyAssemblyManager(void);

    virtual HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid,void  **ppv);
    virtual ULONG   STDMETHODCALLTYPE AddRef(void);
    virtual ULONG   STDMETHODCALLTYPE Release(void);

	virtual HRESULT STDMETHODCALLTYPE GetNonHostStoreAssemblies(ICLRAssemblyReferenceList** ppReferenceList);
	virtual HRESULT STDMETHODCALLTYPE GetAssemblyStore(IHostAssemblyStore** ppAssemblyStore);

	int setTargetAssembly(TargetAssembly * targetAssembly)
	{
		m_assemblyStore->setTargetAssembly(targetAssembly);
		return 0;
	}

	int updateTargetAssembly(ICLRAssemblyIdentityManager* identityManager, const std::string& data)
	{
		m_assemblyStore->updateTargetAssembly(identityManager, data);
		return 0;
	}

	LPWSTR getAssemblyInfo()
	{
		return m_assemblyStore->getAssemblyInfo();
	};

protected:	
	DWORD count;

private:
	MyAssemblyStore* m_assemblyStore;

};