#include "AssemblyManager.hpp"


MyAssemblyManager::MyAssemblyManager(void)
{
	count = 0;
	m_assemblyStore = new MyAssemblyStore();
};


MyAssemblyManager::~MyAssemblyManager(void)
{
	delete m_assemblyStore;
};


HRESULT STDMETHODCALLTYPE MyAssemblyManager::QueryInterface(REFIID vTableGuid, void** ppv) 
{
	if (!IsEqualIID(vTableGuid, IID_IUnknown) && !IsEqualIID(vTableGuid, IID_IHostAssemblyManager)) 
	{
		*ppv = 0;
		return E_NOINTERFACE;
	}
	*ppv = this;
	this->AddRef();
	return S_OK;
}


ULONG STDMETHODCALLTYPE MyAssemblyManager::AddRef() 
{
	return(++((MyAssemblyManager*)this)->count);
}


ULONG STDMETHODCALLTYPE MyAssemblyManager::Release() 
{
	if (--((MyAssemblyManager*)this)->count == 0) 
	{
		GlobalFree(this);
		return 0;
	}
	return ((MyAssemblyManager*)this)->count;
}


// This returns a list of assemblies that we are telling the CLR that we want it to handle loading (when/if a load is requested for them)
// We can just return NULL and we will always be asked to load the assembly, but we can tell the CLR to load it in our ProvideAssembly implementation
HRESULT STDMETHODCALLTYPE MyAssemblyManager::GetNonHostStoreAssemblies(ICLRAssemblyReferenceList** ppReferenceList) 
{
	*ppReferenceList = NULL;
	return S_OK;
}


//This is responsible for returning our IHostAssemblyStore implementation
HRESULT STDMETHODCALLTYPE MyAssemblyManager::GetAssemblyStore(IHostAssemblyStore** ppAssemblyStore) 
{
	*ppAssemblyStore = m_assemblyStore;
	return S_OK;
}

