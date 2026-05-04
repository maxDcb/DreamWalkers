#include "HostControl.hpp"


MyHostControl::MyHostControl(void)
{
    count = 1;

    m_assemblyManager = new MyAssemblyManager();
#ifdef DW_ENABLE_DOTNET_HOST_MEMORY_MANAGER
    m_memoryManager = new MyMemoryManager();
#else
    m_memoryManager = NULL;
#endif
};

MyHostControl::~MyHostControl(void)
{
    if (m_assemblyManager != NULL)
        m_assemblyManager->Release();
    if (m_memoryManager != NULL)
        m_memoryManager->Release();
};


HRESULT STDMETHODCALLTYPE MyHostControl::QueryInterface(REFIID vTableGuid, void** ppv)
{
    if (ppv == NULL)
        return E_POINTER;

    if (!IsEqualIID(vTableGuid, IID_IUnknown) && !IsEqualIID(vTableGuid, IID_IHostControl))
    {
        *ppv = 0;
        return E_NOINTERFACE;
    }
    *ppv = this;
    this->AddRef();
    return S_OK;
}


ULONG STDMETHODCALLTYPE MyHostControl::AddRef()
{
    return static_cast<ULONG>(InterlockedIncrement(&count));
}


ULONG STDMETHODCALLTYPE MyHostControl::Release()
{
    ULONG refCount = static_cast<ULONG>(InterlockedDecrement(&count));
    if (refCount == 0)
    {
        delete this;
        return 0;
    }
    return refCount;
}


HRESULT STDMETHODCALLTYPE MyHostControl::GetHostManager(REFIID riid, void** ppObject)
{
    if (ppObject == NULL)
        return E_POINTER;

    if (IsEqualIID(riid, IID_IHostMemoryManager))
    {
#ifdef DW_ENABLE_DOTNET_HOST_MEMORY_MANAGER
        m_memoryManager->AddRef();
        *ppObject = m_memoryManager;
        return S_OK;
#else
        *ppObject = NULL;
        return E_NOINTERFACE;
#endif
    }

    if (IsEqualIID(riid, IID_IHostAssemblyManager))
    {
        m_assemblyManager->AddRef();
        *ppObject = m_assemblyManager;
        return S_OK;
    }

    *ppObject = NULL;
    return E_NOINTERFACE;
}


// //This has some fun uses left as an exercise for the reader :)
HRESULT MyHostControl::SetAppDomainManager(DWORD dwAppDomainID, IUnknown* pUnkAppDomainManager)
{
    (void)dwAppDomainID;
    (void)pUnkAppDomainManager;

    return E_NOTIMPL;
}
