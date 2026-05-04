#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <cstring>
#include <windows.h>



int testShellCode(const std::string& fileName, bool pauseOnReturn, bool runInThread)
{
	std::ifstream shellcode( fileName, std::ios::binary );
	if(!shellcode)
	{
		std::cout << "Cannot open file!" << std::endl;
		return 1;
	}
	std::vector<unsigned char> buffer(std::istreambuf_iterator<char>(shellcode), {});

	if(buffer.empty())
	{
		std::cout << "Shellcode file is empty!" << std::endl;
		return 1;
	}

	void *exec = VirtualAlloc(0, buffer.size(), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if(!exec)
	{
		std::cout << "VirtualAlloc failed: " << GetLastError() << std::endl;
		return 1;
	}
	memcpy(exec, &buffer[0], buffer.size());

	printf("exec %p\n", exec);
	fflush(stdout);

	// __debugbreak();

	if(runInThread)
	{
		HANDLE thread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)exec, NULL, 0, NULL);
		if(!thread)
		{
			std::cout << "CreateThread failed: " << GetLastError() << std::endl;
			return 1;
		}
		WaitForSingleObject(thread, INFINITE);
		DWORD exitCode = 0;
		if(!GetExitCodeThread(thread, &exitCode))
		{
			std::cout << "GetExitCodeThread failed: " << GetLastError() << std::endl;
			CloseHandle(thread);
			return 1;
		}
		CloseHandle(thread);
		if(exitCode != 0)
		{
			std::cout << "Shellcode thread exited with code: " << exitCode << std::endl;
			return (int)exitCode;
		}
	}
	else
	{
		((void(*)())exec)();
	}


	printf("\nFinished!\n");
	if(pauseOnReturn)
	{
		getchar();
	}

	return 0;
}


int main(int argc, char* argv[]) 
{
    if (argc > 1)
	{
        std::string inputFile = argv[1];
		bool pauseOnReturn = true;
		bool runInThread = false;
		for(int i = 2; i < argc; i++)
		{
			if(std::strcmp(argv[i], "--no-pause") == 0)
			{
				pauseOnReturn = false;
			}
			else if(std::strcmp(argv[i], "--thread") == 0)
			{
				runInThread = true;
			}
		}
        std::cout << "[*] Testing provided file: " << inputFile << std::endl;
        return testShellCode(inputFile, pauseOnReturn, runInThread);
    }
	else
	{
		std::cout << "[*] No file provided..." << std::endl;
		return 1;
	}
}
