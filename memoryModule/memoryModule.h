/*
 * Memory DLL loading code
 * Version 0.0.4
 *
 * Copyright (c) 2004-2015 by Joachim Bauch / mail@joachim-bauch.de
 * http://www.joachim-bauch.de
 *
 * The contents of this file are subject to the Mozilla Public License Version
 * 2.0 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 * http://www.mozilla.org/MPL/
 *
 * Software distributed under the License is distributed on an "AS IS" basis,
 * WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License
 * for the specific language governing rights and limitations under the
 * License.
 *
 * The Original Code is MemoryModule.h
 *
 * The Initial Developer of the Original Code is Joachim Bauch.
 *
 * Portions created by Joachim Bauch are Copyright (C) 2004-2015
 * Joachim Bauch. All Rights Reserved.
 *
 */

#ifndef __MEMORY_MODULE_HEADER
#define __MEMORY_MODULE_HEADER

#include <windows.h>

typedef void *HMEMORYMODULE;
typedef void *HMEMORYRSRC;
typedef void *HCUSTOMMODULE;

#ifdef __cplusplus
extern "C" {
#endif

#include "../common/instance.h"


HMEMORYMODULE MemoryLoadLibrary(INSTANCE* inst, const void *, size_t);

int MemoryCallEntryPoint(HMEMORYMODULE);

FARPROC MemoryGetProcAddress(INSTANCE* inst, HMEMORYMODULE mod, LPCSTR name);


#ifdef __cplusplus
}
#endif

#endif  // __MEMORY_MODULE_HEADER