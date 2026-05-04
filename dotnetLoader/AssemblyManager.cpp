#include "AssemblyManager.hpp"


MyAssemblyManager::MyAssemblyManager(void)
{
    count = 1;
    m_assemblyStore = new MyAssemblyStore();
};


MyAssemblyManager::~MyAssemblyManager(void)
{
    if (m_assemblyStore != NULL)
        m_assemblyStore->Release();
};


HRESULT STDMETHODCALLTYPE MyAssemblyManager::QueryInterface(REFIID vTableGuid, void** ppv)
{
    if (ppv == NULL)
        return E_POINTER;

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
    return static_cast<ULONG>(InterlockedIncrement(&count));
}


ULONG STDMETHODCALLTYPE MyAssemblyManager::Release()
{
    ULONG refCount = static_cast<ULONG>(InterlockedDecrement(&count));
    if (refCount == 0)
    {
        delete this;
        return 0;
    }
    return refCount;
}


// This returns a list of assemblies that we are telling the CLR that we want it to handle loading (when/if a load is requested for them)
// We can just return NULL and we will always be asked to load the assembly, but we can tell the CLR to load it in our ProvideAssembly implementation
HRESULT STDMETHODCALLTYPE MyAssemblyManager::GetNonHostStoreAssemblies(ICLRAssemblyReferenceList** ppReferenceList)
{
    if (ppReferenceList == NULL)
        return E_POINTER;

    *ppReferenceList = NULL;
    return S_OK;
}


//This is responsible for returning our IHostAssemblyStore implementation
HRESULT STDMETHODCALLTYPE MyAssemblyManager::GetAssemblyStore(IHostAssemblyStore** ppAssemblyStore)
{
    if (ppAssemblyStore == NULL)
        return E_POINTER;

    m_assemblyStore->AddRef();
    *ppAssemblyStore = m_assemblyStore;
    return S_OK;
}
