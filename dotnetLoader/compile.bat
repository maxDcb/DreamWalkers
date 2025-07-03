


@REM cl /EHsc /W4 /Fe:goodClr.exe AssemblyManager.cpp AssemblyStore.cpp DotnetExec.cpp HostControl.cpp HostMalloc.cpp MemoryManager.cpp shell32.lib

@REM move goodClr.exe bin\goodClr.exe

cl.exe /O2 /D_USRDLL /D_WINDLL AssemblyManager.cpp AssemblyStore.cpp DotnetExec.cpp HostControl.cpp HostMalloc.cpp MemoryManager.cpp /MT /link shell32.lib /DLL /OUT:goodClr.dll

move goodClr.dll bin\goodClr.dll

del *.obj
del *.exp
del *.lib
