#include "AssemblyStore.hpp"
#include <objbase.h>

#include <iostream>

#include <shlwapi.h>
#pragma comment(lib, "Shlwapi.lib")


MyAssemblyStore::MyAssemblyStore(void)
{
	count = 0;
	m_targetAssembly = nullptr;
};


MyAssemblyStore::~MyAssemblyStore(void)
{
};


HRESULT STDMETHODCALLTYPE MyAssemblyStore::QueryInterface(REFIID vTableGuid, void** ppv) 
{
	if (!IsEqualIID(vTableGuid, IID_IUnknown) && !IsEqualIID(vTableGuid, IID_IHostAssemblyStore)) 
	{
		*ppv = 0;
		return E_NOINTERFACE;
	}
	*ppv = this;
	this->AddRef();
	return S_OK;
}


ULONG STDMETHODCALLTYPE MyAssemblyStore::AddRef() 
{
	return(++((MyAssemblyStore*)this)->count);
}


ULONG STDMETHODCALLTYPE MyAssemblyStore::Release() 
{
	if (--((MyAssemblyStore*)this)->count == 0) 
	{
		GlobalFree(this);
		return 0;
	}
	return ((MyAssemblyStore*)this)->count;
}


int TargetAssembly::updateTargetAssembly(ICLRAssemblyIdentityManager* identityManager, const std::string& data)
{
	m_assembly=data;

	if(m_assemblyStream!=nullptr)
		m_assemblyStream->Release();

	m_assemblyStream = SHCreateMemStream((BYTE *)m_assembly.data(), m_assembly.size());
	identityManager->GetBindingIdentityFromStream(m_assemblyStream, CLR_ASSEMBLY_IDENTITY_FLAGS_DEFAULT, m_assemblyInfo, &m_identityBufferSize);

	// std::cout << "updateTargetAssembly " << m_assembly.size() << std::endl;
	// std::wcout << "assemblyInfo " << m_assemblyInfo << std::endl;
	m_id++;

	return 0;
}


int MyAssemblyStore::updateTargetAssembly(ICLRAssemblyIdentityManager* identityManager, const std::string& data)
{
	m_targetAssembly->updateTargetAssembly(identityManager, data);

	return 0;
}



HRESULT STDMETHODCALLTYPE MyAssemblyStore::ProvideAssembly(AssemblyBindInfo* pBindInfo, UINT64* pAssemblyId, UINT64* pContext, IStream** ppStmAssemblyImage, IStream** ppStmPDB) 
{
	// std::cout << "MyAssemblyStore::ProvideAssembly " << std::endl;
	// std::wcout << "pBindInfo->lpPostPolicyIdentity     " << pBindInfo->lpPostPolicyIdentity << std::endl;
	// std::wcout << "m_targetAssembly->getAssemblyInfo() " << m_targetAssembly->getAssemblyInfo() << std::endl;

	// Check if the identity of the assembly being loaded is the one we want
	if (m_targetAssembly!=nullptr && wcscmp(m_targetAssembly->getAssemblyInfo(), pBindInfo->lpPostPolicyIdentity) == 0) 
	{
		//This isn't used for anything here so just set it to 0
		*pContext = 0;

		UINT64 id = m_targetAssembly->getId();
		*pAssemblyId = id;

		//Create an IStream using our in-memory assembly bytes and return it to the CLR
		*ppStmAssemblyImage = SHCreateMemStream((BYTE *)m_targetAssembly->getAssembly(), m_targetAssembly->getAssemblySize());
		return S_OK;

	}

	// std::wcout <<" !!!!!!!!!!!!!!!!! FAILLLLLLLLLLLLLLED !!!!!!!!!!!" << std::endl;

	// If it's not our assembly then tell the CLR to handle it
	return HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND);
}


// This shouldn't really get called but if it does we'll just tell the CLR to find it
HRESULT STDMETHODCALLTYPE MyAssemblyStore::ProvideModule(ModuleBindInfo* pBindInfo,	DWORD* pdwModuleId,	IStream** ppStmModuleImage,	IStream** ppStmPDB) 
{
	// std::cout << "MyAssemblyStore::ProvideModule" << std::endl;

	//Tell the CLR to handle this
	return HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND);
}
