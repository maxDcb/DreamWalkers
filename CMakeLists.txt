cmake_minimum_required(VERSION 3.25)

if(POLICY CMP0091)
  cmake_policy(SET CMP0091 NEW)
endif()

project(DreamWalkers LANGUAGES C CXX)

if(NOT WIN32 OR NOT MSVC)
  message(FATAL_ERROR "DreamWalkers CMake builds currently require MSVC on Windows.")
endif()

set(CMAKE_CONFIGURATION_TYPES "Debug;Release" CACHE STRING "" FORCE)

set(_dw_platform "${CMAKE_GENERATOR_PLATFORM}")
if(DEFINED CMAKE_VS_PLATFORM_NAME AND NOT "${CMAKE_VS_PLATFORM_NAME}" STREQUAL "")
  set(_dw_platform "${CMAKE_VS_PLATFORM_NAME}")
endif()

if(_dw_platform STREQUAL "Win32")
  set(DW_ARCH "x86")
elseif(_dw_platform STREQUAL "x64")
  set(DW_ARCH "x64")
elseif(_dw_platform STREQUAL "ARM64")
  set(DW_ARCH "arm64")
else()
  message(FATAL_ERROR "Unsupported or missing Visual Studio platform: ${_dw_platform}")
endif()

message(STATUS "DreamWalkers target architecture: ${DW_ARCH}")

set(DW_BIN_DIR "${CMAKE_SOURCE_DIR}/bin")
set(DW_EXE2H_HOST_PATH "" CACHE FILEPATH "Path to a host-runnable exe2h tool for cross-architecture header generation.")
option(DW_ENABLE_DOTNET_TRACE "Enable goodClr diagnostic traces." OFF)
option(DW_ENABLE_DOTNET_ETW_PATCH "Enable goodClr EtwEventWrite patching." ON)
option(DW_ENABLE_DOTNET_AMSI_PATCH "Enable goodClr CLR AMSI string patching." ON)
option(DW_ENABLE_DOTNET_SYSCALLS "Enable goodClr syscall wrappers for patch memory protection changes." ON)
option(DW_ENABLE_DOTNET_HOST_MEMORY_MANAGER "Expose goodClr custom IHostMemoryManager to the CLR." ON)

if(DW_ARCH STREQUAL "x64")
  set(DW_MEMORYMODULE_ASM memoryModule/test-x64.asm)
  set(DW_DOTNET_SYSCALL_ASM dotnetLoader/syscall/syscall.x64.asm)
elseif(DW_ARCH STREQUAL "x86")
  set(DW_MEMORYMODULE_ASM memoryModule/test-x86.asm)
  set(DW_DOTNET_SYSCALL_ASM dotnetLoader/syscall/syscall.x86.asm)
elseif(DW_ARCH STREQUAL "arm64")
  set(DW_MEMORYMODULE_ASM memoryModule/test-arm64.asm)
  set(DW_DOTNET_SYSCALL_ASM dotnetLoader/syscall/syscall.arm64.asm)
endif()

message(STATUS "goodClr options: trace=${DW_ENABLE_DOTNET_TRACE}, etw=${DW_ENABLE_DOTNET_ETW_PATCH}, amsi=${DW_ENABLE_DOTNET_AMSI_PATCH}, syscalls=${DW_ENABLE_DOTNET_SYSCALLS}, hostMemoryManager=${DW_ENABLE_DOTNET_HOST_MEMORY_MANAGER}")

function(dw_set_output_dirs target)
  set_target_properties(${target} PROPERTIES
    ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/out/$<CONFIG>"
    LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/out/$<CONFIG>"
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/out/$<CONFIG>"
  )
endfunction()

function(dw_use_static_runtime target)
  set_property(TARGET ${target} PROPERTY
    MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
endfunction()

function(dw_stage_runtime target)
  add_custom_command(TARGET ${target} POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E make_directory "${DW_BIN_DIR}/${DW_ARCH}"
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "$<TARGET_FILE:${target}>"
            "${DW_BIN_DIR}/${DW_ARCH}/$<TARGET_FILE_NAME:${target}>"
  )
endfunction()

if(DW_ARCH STREQUAL "arm64")
  enable_language(ASM_MARMASM)
  set(_dw_memorymodule_asm_language ASM_MARMASM)
else()
  enable_language(ASM_MASM)
  set(_dw_memorymodule_asm_language ASM_MASM)
endif()

add_library(memoryModuleAsm OBJECT
  ${DW_MEMORYMODULE_ASM}
)
set_source_files_properties("${DW_MEMORYMODULE_ASM}" PROPERTIES
  LANGUAGE ${_dw_memorymodule_asm_language}
)

set(_goodclr_sources
  dotnetLoader/AssemblyManager.cpp
  dotnetLoader/AssemblyStore.cpp
  dotnetLoader/DotnetExec.cpp
  dotnetLoader/HostControl.cpp
  dotnetLoader/HostMalloc.cpp
  dotnetLoader/MemoryManager.cpp
)

if(DW_ENABLE_DOTNET_SYSCALLS)
  add_library(dotnetSyscallAsm OBJECT
    ${DW_DOTNET_SYSCALL_ASM}
  )
  set_source_files_properties("${DW_DOTNET_SYSCALL_ASM}" PROPERTIES
    LANGUAGE ${_dw_memorymodule_asm_language}
  )
  list(APPEND _goodclr_sources
    dotnetLoader/syscall/syscall.cpp
    $<TARGET_OBJECTS:dotnetSyscallAsm>
  )
endif()

add_executable(exe2h
  exe2h/exe2h.c
  exe2h/mmap-windows.c
)
target_link_libraries(exe2h PRIVATE shlwapi)
dw_set_output_dirs(exe2h)
dw_stage_runtime(exe2h)

add_executable(shellcodeTester
  shellcodeTester/shellcodeTester.cpp
)
target_compile_options(shellcodeTester PRIVATE /Zp8 /EHsc)
dw_set_output_dirs(shellcodeTester)
dw_stage_runtime(shellcodeTester)

add_library(smoke_payload SHARED
  ci/smoke_payload_dll.cpp
)
target_compile_options(smoke_payload PRIVATE /O2)
dw_use_static_runtime(smoke_payload)
set_target_properties(smoke_payload PROPERTIES
  OUTPUT_NAME "smoke_payload"
)
dw_set_output_dirs(smoke_payload)

add_library(implantDLL SHARED
  testDll/implantDLL.cpp
  testDll/implantDLL.def
)
target_compile_definitions(implantDLL PRIVATE _USRDLL _WINDLL)
target_compile_options(implantDLL PRIVATE /O2)
target_link_libraries(implantDLL PRIVATE User32)
dw_use_static_runtime(implantDLL)
set_target_properties(implantDLL PROPERTIES
  OUTPUT_NAME "implantDLL"
)
dw_set_output_dirs(implantDLL)
dw_stage_runtime(implantDLL)

add_executable(implant
  testExe/implant.cpp
)
target_link_libraries(implant PRIVATE User32)
dw_use_static_runtime(implant)
set_target_properties(implant PROPERTIES
  OUTPUT_NAME "implant"
  WIN32_EXECUTABLE TRUE
)
dw_set_output_dirs(implant)
dw_stage_runtime(implant)

add_library(goodClr SHARED ${_goodclr_sources})
target_compile_definitions(goodClr PRIVATE _USRDLL _WINDLL)
target_compile_options(goodClr PRIVATE /O2)
target_link_libraries(goodClr PRIVATE shell32 shlwapi oleaut32)
if(DW_ENABLE_DOTNET_TRACE)
  target_compile_definitions(goodClr PRIVATE DW_GOODCLR_TRACE)
endif()
if(DW_ENABLE_DOTNET_ETW_PATCH)
  target_compile_definitions(goodClr PRIVATE DW_ENABLE_DOTNET_ETW_PATCH)
endif()
if(DW_ENABLE_DOTNET_AMSI_PATCH)
  target_compile_definitions(goodClr PRIVATE DW_ENABLE_DOTNET_AMSI_PATCH)
endif()
if(DW_ENABLE_DOTNET_SYSCALLS)
  target_compile_definitions(goodClr PRIVATE DW_ENABLE_DOTNET_SYSCALLS)
  target_include_directories(goodClr PRIVATE "${CMAKE_SOURCE_DIR}/dotnetLoader/syscall")
endif()
if(DW_ENABLE_DOTNET_HOST_MEMORY_MANAGER)
  target_compile_definitions(goodClr PRIVATE DW_ENABLE_DOTNET_HOST_MEMORY_MANAGER)
endif()
if(DW_ARCH STREQUAL "x86")
  target_link_options(goodClr PRIVATE /SAFESEH:NO)
endif()
dw_use_static_runtime(goodClr)
set_target_properties(goodClr PROPERTIES
  OUTPUT_NAME "goodClr"
)
dw_set_output_dirs(goodClr)
dw_stage_runtime(goodClr)

add_executable(GoodClrDirectTest
  ci/goodclr_direct_test.cpp
)
target_compile_options(GoodClrDirectTest PRIVATE /O2 /EHsc)
dw_use_static_runtime(GoodClrDirectTest)
dw_set_output_dirs(GoodClrDirectTest)
dw_stage_runtime(GoodClrDirectTest)
add_dependencies(GoodClrDirectTest goodClr)

set(_memorymodule_sources
  memoryModule/helpers.c
  memoryModule/memoryModule.c
)

add_executable(memoryModuleLoader
  ${_memorymodule_sources}
  $<TARGET_OBJECTS:memoryModuleAsm>
)
set_property(TARGET memoryModuleLoader PROPERTY MSVC_RUNTIME_LIBRARY "")
target_compile_options(memoryModuleLoader PRIVATE
  $<$<COMPILE_LANGUAGE:C>:/Zp8>
  $<$<COMPILE_LANGUAGE:C>:/Gy>
  $<$<COMPILE_LANGUAGE:C>:/Os>
  $<$<COMPILE_LANGUAGE:C>:/O1>
  $<$<COMPILE_LANGUAGE:C>:/GR->
  $<$<COMPILE_LANGUAGE:C>:/EHa>
  $<$<COMPILE_LANGUAGE:C>:/Oi>
  $<$<COMPILE_LANGUAGE:C>:/GS->
)
# memoryModuleLoader is converted to shellcode from its .text section.
# Keep these linker constraints aligned with docs/memorymodule-loader-build-notes.md.
target_link_options(memoryModuleLoader PRIVATE
  /ORDER:@${CMAKE_SOURCE_DIR}/memoryModule/order.txt
  /ENTRY:Loader
  /SUBSYSTEM:CONSOLE
  /NODEFAULTLIB
)
if(NOT DW_ARCH STREQUAL "arm64")
  target_link_options(memoryModuleLoader PRIVATE
    /FIXED
    /DYNAMICBASE:NO
  )
endif()
if(DW_ARCH STREQUAL "x86")
  target_link_options(memoryModuleLoader PRIVATE /SAFESEH:NO)
endif()
set_target_properties(memoryModuleLoader PROPERTIES
  OUTPUT_NAME "MemoryModule"
)
dw_set_output_dirs(memoryModuleLoader)
dw_stage_runtime(memoryModuleLoader)

add_executable(LoaderTest
  ${_memorymodule_sources}
  $<TARGET_OBJECTS:memoryModuleAsm>
)
target_compile_definitions(LoaderTest PRIVATE DEBUG_OUTPUT)
target_compile_options(LoaderTest PRIVATE
  $<$<COMPILE_LANGUAGE:C>:/Zp8>
  $<$<COMPILE_LANGUAGE:C>:/Gy>
  $<$<COMPILE_LANGUAGE:C>:/Os>
  $<$<COMPILE_LANGUAGE:C>:/O1>
  $<$<COMPILE_LANGUAGE:C>:/GR->
  $<$<COMPILE_LANGUAGE:C>:/EHa>
  $<$<COMPILE_LANGUAGE:C>:/Oi>
  $<$<COMPILE_LANGUAGE:C>:/GS->
)
target_link_libraries(LoaderTest PRIVATE libvcruntime libcmt kernel32)
target_link_options(LoaderTest PRIVATE /SUBSYSTEM:CONSOLE)
if(DW_ARCH STREQUAL "x86")
  target_link_options(LoaderTest PRIVATE /SAFESEH:NO)
endif()
dw_use_static_runtime(LoaderTest)
dw_set_output_dirs(LoaderTest)
dw_stage_runtime(LoaderTest)

set(_loader_header "${DW_BIN_DIR}/memorymodule_exe_${DW_ARCH}.h")
set(_exe2h_for_header "$<TARGET_FILE:exe2h>")
set(_exe2h_header_deps exe2h memoryModuleLoader)
# ARM64 cross-builds can produce an exe2h binary the host cannot execute.
# DW_EXE2H_HOST_PATH lets those builds reuse a host-runnable exe2h for header generation.
if(DW_ARCH STREQUAL "arm64" AND NOT "${DW_EXE2H_HOST_PATH}" STREQUAL "")
  if(NOT EXISTS "${DW_EXE2H_HOST_PATH}")
    message(FATAL_ERROR "DW_EXE2H_HOST_PATH does not exist: ${DW_EXE2H_HOST_PATH}")
  endif()
  set(_exe2h_for_header "${DW_EXE2H_HOST_PATH}")
  set(_exe2h_header_deps "${DW_EXE2H_HOST_PATH}" memoryModuleLoader)
endif()
add_custom_command(
  OUTPUT "${_loader_header}"
  COMMAND ${CMAKE_COMMAND} -E make_directory "${DW_BIN_DIR}"
  COMMAND "${_exe2h_for_header}" "$<TARGET_FILE:memoryModuleLoader>"
  WORKING_DIRECTORY "${DW_BIN_DIR}"
  DEPENDS ${_exe2h_header_deps}
  VERBATIM
)
add_custom_target(memorymodule_header ALL
  DEPENDS "${_loader_header}"
)

add_custom_target(loader
  DEPENDS memoryModuleLoader LoaderTest memorymodule_header
)

add_custom_target(ci_smoke
  DEPENDS shellcodeTester smoke_payload GoodClrDirectTest
)
add_dependencies(ci_smoke memorymodule_header)
