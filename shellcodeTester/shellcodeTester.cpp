#include <iostream>
#include <fstream>
#include <vector>
#include <windows.h>



int testShellCode(const std::string& fileName)
{
	std::ifstream shellcode( fileName, std::ios::binary );
	if(!shellcode) 
	{
		std::cout << "Cannot open file!" << std::endl;
		return 1;
	}
	std::vector<unsigned char> buffer(std::istreambuf_iterator<char>(shellcode), {});


	void *exec = VirtualAlloc(0, buffer.size(), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	memcpy(exec, &buffer[0], buffer.size());

	printf("exec %p\n", exec);

	// __debugbreak();

	((void(*)())exec)();


	printf("\nFinished!\n");
	getchar();

	return 0;
}


int main(int argc, char* argv[]) 
{
    if (argc > 1) 
	{
        std::string inputFile = argv[1];
        std::cout << "[*] Testing provided file: " << inputFile << std::endl;
        testShellCode(inputFile);
    } 
	else
	{
		std::cout << "[*] No file provided..." << std::endl;
	}

    return 0;
}