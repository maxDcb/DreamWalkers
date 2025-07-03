import struct
import re
import argparse
import os


def read_exe_to_buffer(exe_path):
    if not os.path.isfile(exe_path):
        raise FileNotFoundError(f"Executable not found: {exe_path}")
    
    with open(exe_path, 'rb') as f:
        buffer = f.read()
    
    return buffer


def extract_byte_array_from_header(header_path, array_name):
    with open(header_path, "r") as f:
        content = f.read()

    # Match the array by name: MEMORYMODULE_EXE_X64[] = { ... };
    pattern = re.compile(
        rf"{array_name}\s*\[\s*\]\s*=\s*\{{(.*?)\}};",
        re.DOTALL
    )
    match = pattern.search(content)
    if not match:
        raise ValueError(f"Array {array_name} not found in the header.")

    array_content = match.group(1)

    # Extract all hex values
    hex_values = re.findall(r"0x[0-9a-fA-F]{2}", array_content)
    byte_array = bytes(int(h, 16) for h in hex_values)
    return byte_array


# Define the INSTANCE struct layout in Python
class Instance:
    def __init__(self, moduleSize, isDll, sdllMethode, isDotNet, dotnetLoaderSize, dotnetModuleSize, args=""):
        # Allocate space for string fields (32 bytes each)
        self.sKernel32DLL = b"kernel32.dll".ljust(32, b"\x00")
        self.sNtDLL = b"ntdll.dll".ljust(32, b"\x00")
        self.wsKernel32DLL = "KERNEL32.DLL".encode("utf-16le").ljust(64, b"\x00")
        self.sKernelBaseDLL = b"kernelbase.dll".ljust(32, b"\x00")                      # cmd line arguments   
        self.sMsvcrtDLL = b"msvcrt.dll".ljust(32, b"\x00")

        self.sGetProcAddress = b"GetProcAddress".ljust(32, b"\x00")
        self.sGetModuleHandleA = b"GetModuleHandleA".ljust(32, b"\x00")
        self.sLoadLibraryA = b"LoadLibraryA".ljust(32, b"\x00")
        self.sFreeLibrary = b"".ljust(32, b"\x00")
        self.sVirtualAlloc = b"VirtualAlloc".ljust(32, b"\x00")
        self.sVirtualFree = b"VirtualFree".ljust(32, b"\x00")
        self.sVirtualProtect = b"VirtualProtect".ljust(32, b"\x00")
        self.sHeapAlloc = b"".ljust(32, b"\x00")
        self.sHeapFree = b"".ljust(32, b"\x00")
        self.sGetProcessHeap = b"".ljust(32, b"\x00")
        self.sGetLastError = b"".ljust(32, b"\x00")
        self.sGetNativeSystemInfo = b"".ljust(32, b"\x00")
        self.sIsBadReadPtr = b"".ljust(32, b"\x00")
        self.sHeapReAlloc = b"".ljust(32, b"\x00")
        self.sWaitForSingleObject = b"".ljust(32, b"\x00")
        self.sCreateThread = b"".ljust(32, b"\x00")
        self.sRtlLookupFunctionEntry = b"RtlLookupFunctionEntry".ljust(32, b"\x00")
        self.sBaseThreadInitThunk = b"BaseThreadInitThunk".ljust(32, b"\x00")
        self.sRtlUserThreadStart = b"RtlUserThreadStart".ljust(32, b"\x00")
        self.sPrintf = b"printf".ljust(32, b"\x00")
        self.sGetCommandLineA = b"GetCommandLineA".ljust(32, b"\x00") 
        self.sGetCommandLineW = b"".ljust(32, b"\x00") 
        self.sRtlAddFunctionTable = b"RtlAddFunctionTable".ljust(32, b"\x00")

        self.moduleSize = moduleSize 

        self.isModuleStompingUsed = 1
        self.sModuleToStomp = b"Windows.Storage.dll".ljust(32, b"\x00")

        self.instanceSize = 0x69696969
        self.loaderSize = 0x70707070

        self.sMagicBytes = b"\x4D\x5A".ljust(8, b"\x00")
        self.sGadget = b"\xFF\x23".ljust(8, b"\x00")

        self.sDataSec = b".data".ljust(8, b"\x00") 
        self.sPDataSec = b".pdata".ljust(8, b"\x00") 

        if isDotNet:
            cmdLine = args
        else:
            cmdLine = "e " + args
            
        print("Command line argument: ", cmdLine)
        
        self.sCmdLine = cmdLine.encode("utf-16le").ljust(2048, b"\x00") 
        

        self.isDll = isDll
        self.sdllMethode = sdllMethode.encode("utf-8").ljust(256, b"\x00")

        self.isDotNet = isDotNet
        self.dotnetLoaderSize = dotnetLoaderSize
        self.dotnetModuleSize = dotnetModuleSize

        self.sDebug = b"debug\n".ljust(32, b"\x00") 

    def pack(self):
        parts = [
            struct.pack("<I", 0),  # lenTest
            self.sKernel32DLL,
            self.sNtDLL,
            self.wsKernel32DLL,
            self.sKernelBaseDLL,
            self.sMsvcrtDLL,
            
            self.sGetProcAddress,
            self.sGetModuleHandleA,
            self.sLoadLibraryA,
            self.sFreeLibrary,
            self.sVirtualAlloc,
            self.sVirtualFree,
            self.sVirtualProtect,
            self.sHeapAlloc,
            self.sHeapFree,
            self.sGetProcessHeap,
            self.sGetLastError,
            self.sGetNativeSystemInfo,
            self.sIsBadReadPtr,
            self.sHeapReAlloc,
            self.sWaitForSingleObject,
            self.sCreateThread,
            self.sRtlLookupFunctionEntry,
            self.sBaseThreadInitThunk,
            self.sRtlUserThreadStart,
            self.sPrintf,
            self.sGetCommandLineA,
            self.sGetCommandLineW,
            self.sRtlAddFunctionTable,
            # Simulate function pointer struct with nulls (16 ptrs x 8 bytes each if 64-bit)
            b"\x00" * (23 * 8),

            struct.pack("<I", self.moduleSize),

            struct.pack("B", self.isModuleStompingUsed),
            self.sModuleToStomp,

            struct.pack("<I", self.instanceSize ),  
            struct.pack("<I", self.loaderSize),
            self.sMagicBytes,
            self.sDataSec,
            self.sCmdLine,

            self.sPDataSec,
            self.sGadget,

            struct.pack("B", self.isDll),
            self.sdllMethode,
            struct.pack("B", self.isDotNet),
            struct.pack("<I", self.dotnetLoaderSize),
            struct.pack("<I", self.dotnetModuleSize),
            self.sDebug,
            struct.pack("B", 0), # ptrModuleTst
            struct.pack("B", 0), # ptrDotNetModuleTst
            
        ]
        blob = b"".join(parts)
        self.instanceSize = len(blob)
        return blob


def buildLoaderShellcode(fileName, methodeDll, args):

    peBinary = read_exe_to_buffer(fileName)

    isDotNet = is_dotnet_executable(peBinary)
    print("File is a .NET (managed) executable." if isDotNet else "File is a native (unmanaged) executable.")

    # TODO
    # if the file is a .NET executable, we need to get the dotnetLoader and append the exe file after
    if isDotNet:
        isDotNet=1
        dotnetLoader_path = "./bin/goodClr.dll"
        dotnetLoader = read_exe_to_buffer(dotnetLoader_path)
    else:
        isDotNet=0

    peIsDll = is_dll_manual(peBinary)

    #
    # Create and pack the instance structure
    #
    moduleSize = len(dotnetLoader) if isDotNet else len(peBinary)
    isDll = peIsDll
    if isDotNet:
        sdllMethode = "go"
    elif isDll:
        sdllMethode = methodeDll
    else:
        sdllMethode = ""
    dotnetLoaderSize = len(dotnetLoader) if isDotNet else 0
    dotnetModuleSize = len(peBinary) if isDotNet else 0

    inst = Instance(moduleSize, isDll, sdllMethode, isDotNet, dotnetLoaderSize, dotnetModuleSize, args)
    blob = inst.pack()

    # Compute the required padding length
    padding_length = (16 - (len(blob) % 16)) % 16  # result is 0 if already aligned

    print("padding_length ", padding_length);

    # Add padding
    blob += b'\x00' * padding_length

    #
    # Get the loader_size and instance_size
    #
    header_file = "./bin/memorymodule_exe_x64.h"
    array_name = "MEMORYMODULE_EXE_X64"

    try:
        MEMORYMODULE_EXE_X64 = extract_byte_array_from_header(header_file, array_name)
        print(f"Extracted {len(MEMORYMODULE_EXE_X64)} bytes.")
    except Exception as e:
        print("Error:", e)


    instance_size = len(blob)
    loader_size = len(MEMORYMODULE_EXE_X64)

    print(f"Instance struct size: {instance_size} bytes")
    print(f"Loader size: {loader_size} bytes")

    #
    # Step 2: Find the offsets of the placeholder patterns
    #
    offset_instance_size = blob.find(struct.pack("<I", 0x69696969))
    offset_loader_size   = blob.find(struct.pack("<I", 0x70707070))

    if offset_instance_size == -1 or offset_loader_size == -1:
        raise ValueError("Placeholder values not found in blob")

    #
    # Step 3: Overwrite the placeholders with actual values
    #
    blob = (
        blob[:offset_instance_size] +
        struct.pack("<I", instance_size) +
        blob[offset_instance_size + 4:]
    )

    blob = (
        blob[:offset_loader_size] +
        struct.pack("<I", loader_size) +
        blob[offset_loader_size + 4:]
    )

    #
    # Shellcode generation
    #
    shellcode = bytearray()

    # call next: E8 + offset
    shellcode += b'\xE8' + struct.pack("<I", instance_size)

    # instance structure
    shellcode += blob

    # pop rcx
    shellcode += b'\x59'

    # and rsp, -0x10
    shellcode += b'\x48\x83\xE4\xF0'

    # push rcx (for alignment)
    shellcode += b'\x51'

    # loader shellcode
    shellcode += MEMORYMODULE_EXE_X64

    if isDotNet:
        # If it's a .NET executable, append the dotnetLoader
        shellcode += dotnetLoader

    shellcode += peBinary

    print("final shellcode ", len(shellcode), " bytes");

    # Write final shellcode
    with open("finalShellcode.bin", "wb") as f:
        f.write(shellcode)


def is_dll_manual(data):
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    pe_offset = e_lfanew + 4  # skip 'PE\0\0' signature
    characteristics_offset = pe_offset + 18
    characteristics = struct.unpack_from("<H", data, characteristics_offset)[0]
    
    IMAGE_FILE_DLL = 0x2000
    return (characteristics & IMAGE_FILE_DLL) != 0


def is_dotnet_executable(buffer):
    # IMAGE_DOS_HEADER: 64 bytes, e_magic at offset 0, e_lfanew at 0x3C
    if buffer[0:2] != b'MZ':
        return False

    e_lfanew = struct.unpack_from('<I', buffer, 0x3C)[0]

    # IMAGE_NT_HEADERS Signature check
    if buffer[e_lfanew:e_lfanew+4] != b'PE\0\0':
        return False

    # Go to OptionalHeader (after FileHeader: 20 bytes)
    optional_header_offset = e_lfanew + 4 + 20

    # Determine if it's PE32 or PE32+ (magic is 0x10b or 0x20b)
    magic = struct.unpack_from('<H', buffer, optional_header_offset)[0]
    is_pe32_plus = magic == 0x20B

    # DataDirectory for COM Descriptor is at offset:
    # PE32: OptionalHeader + 0x60 + 8 * 14 = 0xE8
    # PE32+: OptionalHeader + 0x70 + 8 * 14 = 0xF8
    com_desc_offset = optional_header_offset + (0x70 if is_pe32_plus else 0x60) + 8 * 14

    virtual_address, size = struct.unpack_from('<II', buffer, com_desc_offset)

    return virtual_address != 0


def main():

    parser = argparse.ArgumentParser(description="Generate shellcode from any given PE.")

    parser.add_argument("-f", "--file", required=True, help="PE file path (DLL or EXE)")
    parser.add_argument("-m", "--method", default="", help="Method name to invoke in case of DLL")
    parser.add_argument("-c", "--cmd", default="", help="Command line arguments")

    args = parser.parse_args()

    buildLoaderShellcode(args.file, args.method, args.cmd)


if __name__ == "__main__":
    main()