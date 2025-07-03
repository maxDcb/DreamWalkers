@ECHO OFF

cl.exe implant.cpp /MT /link User32.lib /OUT:implant.exe

del *.obj

move implant.exe bin\implant.exe 