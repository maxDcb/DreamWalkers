#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


extern __declspec(dllexport) int Go(void);
int Go(void) 
{
	MessageBox( NULL, "Hello from exe !", "Hi!", MB_OK );

	return 0;
}

extern __declspec(dllexport) int Gi(const char*, void* inst);
int Gi(const char* str, void* inst) 
{
	MessageBox( NULL, str, "Hi!", MB_OK );
	return 0;
}

extern "C" __declspec(dllexport) int go();
int go() 
{
	MessageBox( NULL, "Hello from go", "Hi!", MB_OK );
	return 0;
}

extern __declspec(dllexport) int Gu(void);
int Gu(void) 
{

	return 2;
}

BOOL WINAPI DllMain( HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved ) {


	switch ( fdwReason ) {
			case DLL_PROCESS_ATTACH:
					// Go();
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