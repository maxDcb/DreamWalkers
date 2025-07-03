#pragma once

#ifdef __linux__ 

#elif _WIN32

#include <windows.h>
#include <comdef.h>
#include <mscoree.h>
#include <metahost.h>

#include "HostControl.hpp"

// Import mscorlib.tlb (Microsoft Common Language Runtime Class Library).
#import "mscorlib.tlb" auto_rename raw_interfaces_only				\
    high_property_prefixes("_get","_put","_putref")					\
    rename("ReportEvent", "InteropServices_ReportEvent")

#endif

#ifdef _WIN32
struct AssemblyModule
{
	mscorlib::_AssemblyPtr spAssembly;
	std::string name;
	std::string type;
};
#endif
