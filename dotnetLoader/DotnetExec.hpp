#pragma once

#ifdef _WIN32

#include <windows.h>
#include <comdef.h>
#include <mscoree.h>
#include <metahost.h>

#include <string>

#include "HostControl.hpp"

#include "mscorlib.tlh"

struct AssemblyModule
{
    mscorlib::_AssemblyPtr spAssembly;
    std::string name;
    std::string type;
};

#endif
