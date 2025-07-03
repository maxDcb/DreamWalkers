@ECHO OFF

cl.exe /O2 /D_USRDLL /D_WINDLL implantDLL.cpp implantDLL.def /MT /link User32.lib /DLL /OUT:implantDLL.dll

del *.obj
del *.lib
del *.exp

move implantDLL.dll bin\implantDLL.dll 