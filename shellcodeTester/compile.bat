
@ECHO OFF

cl -Zp8 -nologo shellcodeTester.cpp /EHsc


del *.obj
move shellcodeTester.exe bin\shellcodeTester.exe