#pragma once
#include <Windows.h>
#include <mscoree.h>
#include <metahost.h>

#include <string>

#include <shlwapi.h>


class TargetAssembly
{
public:
	TargetAssembly(void)
	{
		m_assemblyStream = nullptr;

		m_id = 5000;
		m_assemblyInfo = (LPWSTR)malloc(4096);
		m_identityBufferSize = 4096;

	};
	~TargetAssembly(void)
	{
		free(m_assemblyInfo);
	};

	int updateTargetAssembly(ICLRAssemblyIdentityManager* identityManager, const std::string& data);
	
	LPWSTR getAssemblyInfo()
	{
		return m_assemblyInfo;
	};

	int getId()
	{
		return m_id;
	};

	char* getAssembly()
	{
		return (char*)m_assembly.data();
	};

	int getAssemblySize()
	{
		return m_assembly.size();
	};
	
private:
	DWORD m_identityBufferSize;
	LPWSTR m_assemblyInfo;

	std::string m_assembly;

	IStream* m_assemblyStream;

	int m_id;
};


class MyAssemblyStore : public IHostAssemblyStore
{
public:
	MyAssemblyStore(void);
	~MyAssemblyStore(void);

    virtual HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid,void  **ppv);
    virtual ULONG   STDMETHODCALLTYPE AddRef(void);
    virtual ULONG   STDMETHODCALLTYPE Release(void);

	virtual HRESULT STDMETHODCALLTYPE ProvideAssembly(AssemblyBindInfo* pBindInfo, UINT64* pAssemblyId, UINT64* pContext, IStream** ppStmAssemblyImage, IStream** ppStmPDB);
	virtual HRESULT STDMETHODCALLTYPE ProvideModule(ModuleBindInfo* pBindInfo, DWORD* pdwModuleId, IStream** ppStmModuleImage, IStream** ppStmPDB);
	
	int setTargetAssembly(TargetAssembly * targetAssembly)
	{
		m_targetAssembly = targetAssembly;
		return 0;
	}

	int updateTargetAssembly(ICLRAssemblyIdentityManager* identityManager, const std::string& data);

	LPWSTR getAssemblyInfo()
	{
		return m_targetAssembly->getAssemblyInfo();
	};

protected:
	DWORD count;

private:
	TargetAssembly* m_targetAssembly;

};