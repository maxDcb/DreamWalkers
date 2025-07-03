
cd testDll
call compile.bat
cd ..
move testDll\bin\implantDLL.dll bin\implantDLL.dll

cd testExe
call compile.bat
cd ..
move testExe\bin\implant.exe bin\implant.exe

cd exe2h
call compile.bat
cd ..
move exe2h\bin\exe2h.exe bin\exe2h.exe

cd memoryModule
call compile.bat
cd ..
move memoryModule\bin\MemoryModule.exe bin\MemoryModule.exe
move memoryModule\bin\LoaderTest.exe bin\LoaderTest.exe

cd bin
exe2h MemoryModule.exe
cd ..

cd dotnetLoader
call compile.bat
cd ..
move dotnetLoader\bin\goodClr.dll bin\goodClr.dll

cd shellcodeTester
call compile.bat
cd ..
move shellcodeTester\bin\shellcodeTester.exe bin\shellcodeTester.exe




