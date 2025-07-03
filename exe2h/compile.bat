@ECHO OFF

cl /nologo exe2h.c mmap-windows.c

del *.obj

move exe2h.exe bin\exe2h.exe