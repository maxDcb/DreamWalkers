
echo [+] Compiling MemoryModule

ML64 /c test.asm /link /NODEFAULTLIB /RELEASE /MACHINE:X64
cl -Zp8 -c -nologo -Gy -Os -O1 -GR- -EHa -Oi -GS- memoryModule.c helpers.c
link /OUT:MemoryModule.exe -nologo -order:@order.txt -entry:Loader -fixed -subsystem:console -nodefaultlib helpers.obj memoryModule.obj test.obj

echo [+] Compiling LoaderTest

:: Compile debug
cl -DDEBUG_OUTPUT -Zp8 -c -nologo -Gy -Os -O1 -GR- -EHa -Oi -GS- helpers.c memoryModule.c 
link /OUT:LoaderTest.exe -nologo libvcruntime.lib libcmt.lib kernel32.lib -subsystem:console helpers.obj memoryModule.obj test.obj


del *.obj

move MemoryModule.exe bin\MemoryModule.exe
move LoaderTest.exe bin\LoaderTest.exe