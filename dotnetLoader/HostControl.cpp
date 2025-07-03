#include "HostControl.hpp"


MyHostControl::MyHostControl(void)
{
	count = 0;

	m_assemblyManager = new MyAssemblyManager();
	m_memoryManager = new MyMemoryManager();
};

MyHostControl::~MyHostControl(void)
{
	delete m_assemblyManager;
	delete m_memoryManager;
};


HRESULT STDMETHODCALLTYPE MyHostControl::QueryInterface(REFIID vTableGuid, void** ppv) 
{
	// printf("MyHostControl_QueryInterface\n");

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
	// printf("MyHostControl_AddRef\n");

	return(++((MyHostControl*)this)->count);
}


ULONG STDMETHODCALLTYPE MyHostControl::Release() 
{
	// printf("MyHostControl_Release\n");

	if (--((MyHostControl*)this)->count == 0) 
	{
		GlobalFree(this);
		return 0;
	}
	return ((MyHostControl*)this)->count;
}


// This is responsible for returning all of our manager implementations
// If you want to disable an interface just comment out the if statement
HRESULT STDMETHODCALLTYPE MyHostControl::GetHostManager(REFIID riid, void** ppObject)
{
	// printf("MyHostControl_GetHostManager\n");

	if (IsEqualIID(riid, IID_IHostMemoryManager))
	{
		*ppObject = m_memoryManager;
		return S_OK;
	}

	if (IsEqualIID(riid, IID_IHostAssemblyManager))
	{
		*ppObject = m_assemblyManager;
		return S_OK;
	}

	*ppObject = NULL;
	return E_NOINTERFACE;
}


// //This has some fun uses left as an exercise for the reader :) 
HRESULT MyHostControl::SetAppDomainManager(DWORD dwAppDomainID, IUnknown* pUnkAppDomainManager) 
{
	// printf("MyHostControl_SetAppDomainManager\n");

	return E_NOTIMPL;
}

