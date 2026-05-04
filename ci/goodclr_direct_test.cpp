#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <cstdio>
#include <vector>

typedef int(__cdecl* GoodClrGo_t)(void* data, int size, char* argument);

static int PrintSehException(EXCEPTION_POINTERS* exceptionInfo)
{
    if (exceptionInfo && exceptionInfo->ExceptionRecord)
    {
        std::printf("[!] GoodClrDirectTest exception 0x%08lX at %p\n",
            exceptionInfo->ExceptionRecord->ExceptionCode,
            exceptionInfo->ExceptionRecord->ExceptionAddress);
        std::fflush(stdout);
    }

    return EXCEPTION_EXECUTE_HANDLER;
}

static int CallGoodClr(GoodClrGo_t go, void* data, int size, wchar_t* argument)
{
    int result = -1;

    __try
    {
        result = go(data, size, reinterpret_cast<char*>(argument));
    }
    __except (PrintSehException(GetExceptionInformation()))
    {
        result = -1;
    }

    return result;
}

static bool ReadFileBytes(const wchar_t* path, std::vector<unsigned char>& output)
{
    HANDLE file = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE)
    {
        std::printf("[!] CreateFileW failed for %ls: %lu\n", path, GetLastError());
        return false;
    }

    LARGE_INTEGER fileSize = {};
    if (!GetFileSizeEx(file, &fileSize) || fileSize.QuadPart <= 0 || fileSize.QuadPart > 0x7fffffff)
    {
        std::printf("[!] Invalid file size for %ls\n", path);
        CloseHandle(file);
        return false;
    }

    output.resize(static_cast<size_t>(fileSize.QuadPart));

    DWORD bytesRead = 0;
    BOOL readOk = ReadFile(file, output.data(), static_cast<DWORD>(output.size()), &bytesRead, NULL);
    CloseHandle(file);

    if (!readOk || bytesRead != output.size())
    {
        std::printf("[!] ReadFile failed for %ls: %lu\n", path, GetLastError());
        return false;
    }

    return true;
}

int wmain(int argc, wchar_t** argv)
{
    std::setvbuf(stdout, NULL, _IONBF, 0);
    std::setvbuf(stderr, NULL, _IONBF, 0);

    if (argc < 3)
    {
        std::printf("usage: GoodClrDirectTest.exe <goodClr.dll> <managed_payload.exe> [argument]\n");
        return 2;
    }

    const wchar_t* goodClrPath = argv[1];
    const wchar_t* payloadPath = argv[2];
    const wchar_t* argument = argc >= 4 ? argv[3] : L"goodclr-direct";

    std::printf("[ ] GoodClrDirectTest %ls %ls %ls\n", goodClrPath, payloadPath, argument);

    std::vector<unsigned char> payload;
    if (!ReadFileBytes(payloadPath, payload))
        return 1;

    HMODULE goodClr = LoadLibraryW(goodClrPath);
    if (!goodClr)
    {
        std::printf("[!] LoadLibraryW failed for %ls: %lu\n", goodClrPath, GetLastError());
        return 1;
    }

    GoodClrGo_t go = reinterpret_cast<GoodClrGo_t>(GetProcAddress(goodClr, "go"));
    if (!go)
    {
        std::printf("[!] GetProcAddress(go) failed: %lu\n", GetLastError());
        FreeLibrary(goodClr);
        return 1;
    }

    std::printf("[+] goodClr go=%p payload=%p size=%llu\n",
        reinterpret_cast<void*>(go),
        payload.data(),
        static_cast<unsigned long long>(payload.size()));

    std::vector<wchar_t> argumentBuffer;
    size_t argumentLength = lstrlenW(argument);
    argumentBuffer.assign(argument, argument + argumentLength + 1);

    int result = CallGoodClr(go, payload.data(), static_cast<int>(payload.size()), argumentBuffer.data());
    std::printf("[+] GoodClrDirectTest go returned %d\n", result);

    // The process is exiting; unloading a DLL that started the CLR can trigger unrelated shutdown behavior.
    return result == 0 ? 0 : 1;
}
