#include <windows.h> 
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


int APIENTRY WinMain( HINSTANCE hInst, HINSTANCE hPrev, LPSTR lpCmdLine, int nCmdShow )
{
	// Check if there is a command-line argument
    if (lpCmdLine != NULL && lpCmdLine[0] != '\0') {
        MessageBox(NULL, lpCmdLine, "Argument Received", MB_OK);
    } else {
        MessageBox(NULL, "Hello from exe!", "Hi!", MB_OK);
    }
	return 0;
}
