import os
import struct
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from DreamWalkers import (
    COMIMAGE_FLAGS_ILONLY,
    IMAGE_FILE_MACHINE_AMD64,
    IMAGE_FILE_MACHINE_ARM64,
    IMAGE_FILE_MACHINE_I386,
    Instance,
    build_shellcode_blob,
    parse_pe_info,
    resolve_target_arch,
)


REPO_ROOT = Path(__file__).resolve().parents[1]
DREAMWALKERS_SCRIPT = REPO_ROOT / "DreamWalkers.py"

ARCH_MACHINES = {
    "x86": IMAGE_FILE_MACHINE_I386,
    "x64": IMAGE_FILE_MACHINE_AMD64,
    "arm64": IMAGE_FILE_MACHINE_ARM64,
}


def make_minimal_pe(arch, *, is_dll=False, dotnet_anycpu=False):
    machine = ARCH_MACHINES[arch]
    is_pe32 = arch == "x86"
    optional_size = 0xE0 if is_pe32 else 0xF0
    optional_magic = 0x10B if is_pe32 else 0x20B

    buffer = bytearray(0x800)
    buffer[0:2] = b"MZ"
    struct.pack_into("<I", buffer, 0x3C, 0x80)
    buffer[0x80:0x84] = b"PE\0\0"

    file_header = 0x84
    struct.pack_into("<H", buffer, file_header, machine)
    struct.pack_into("<H", buffer, file_header + 2, 1)
    struct.pack_into("<H", buffer, file_header + 16, optional_size)
    characteristics = 0x0002
    if is_dll:
        characteristics |= 0x2000
    struct.pack_into("<H", buffer, file_header + 18, characteristics)

    optional = file_header + 20
    struct.pack_into("<H", buffer, optional, optional_magic)
    struct.pack_into("<I", buffer, optional + 0x3C, 0x200)
    if is_pe32:
        struct.pack_into("<I", buffer, optional + 0x5C, 16)
        data_directory = optional + 0x60
    else:
        struct.pack_into("<I", buffer, optional + 0x6C, 16)
        data_directory = optional + 0x70

    section = optional + optional_size
    buffer[section:section + 8] = b".text\0\0\0"
    struct.pack_into("<I", buffer, section + 8, 0x100)
    struct.pack_into("<I", buffer, section + 12, 0x2000)
    struct.pack_into("<I", buffer, section + 16, 0x200)
    struct.pack_into("<I", buffer, section + 20, 0x400)

    if dotnet_anycpu:
        if arch != "x86":
            raise ValueError("AnyCPU test PE must use the PE32 CLR header shape")
        com_descriptor = data_directory + 14 * 8
        struct.pack_into("<II", buffer, com_descriptor, 0x2000, 0x48)
        struct.pack_into("<I", buffer, 0x400 + 16, COMIMAGE_FLAGS_ILONLY)

    return bytes(buffer)


class ArchContractTests(unittest.TestCase):
    def _arch_under_test(self):
        return os.environ.get("DREAMWALKERS_TEST_ARCH")

    def test_parse_supported_machines(self):
        arch_filter = self._arch_under_test()
        arches = [arch_filter] if arch_filter else ["x86", "x64", "arm64"]

        for arch in arches:
            with self.subTest(arch=arch):
                info = parse_pe_info(make_minimal_pe(arch))
                self.assertEqual(info.arch, arch)
                self.assertFalse(info.is_dll)
                self.assertFalse(info.is_dotnet)
                self.assertFalse(info.is_dotnet_anycpu)
                self.assertEqual(resolve_target_arch("auto", info), arch)

    def test_dotnet_anycpu_arch_resolution(self):
        info = parse_pe_info(make_minimal_pe("x86", dotnet_anycpu=True))

        self.assertTrue(info.is_dotnet)
        self.assertTrue(info.is_dotnet_anycpu)
        self.assertEqual(resolve_target_arch("auto", info), "x64")
        self.assertEqual(resolve_target_arch("x86", info), "x86")
        self.assertEqual(resolve_target_arch("x64", info), "x64")
        self.assertEqual(resolve_target_arch("arm64", info), "arm64")

    def test_x86_shellcode_bootstrap_preserves_thread_return_layout(self):
        instance = b"INST"
        loader = b"LOAD"

        shellcode = build_shellcode_blob("x86", instance, loader)

        self.assertEqual(shellcode[:5], b"\xE8\x04\x00\x00\x00")
        self.assertEqual(shellcode[5:9], instance)
        self.assertEqual(shellcode[9:13], b"\x59\x5A\x52\x51")
        self.assertEqual(shellcode[13:18], b"\xE8\x06\x00\x00\x00")
        self.assertEqual(shellcode[18:24], b"\x83\xC4\x04\xC2\x04\x00")
        self.assertEqual(shellcode[24:28], loader)
        self.assertEqual(shellcode[28:], b"\x00" * 32)

    def test_instance_rejects_oversized_command_line(self):
        with self.assertRaisesRegex(ValueError, "sCmdLine"):
            Instance(1, 0, "", 0, 0, 0, "x64", "A" * 1024)

    def test_instance_rejects_oversized_dll_method(self):
        with self.assertRaisesRegex(ValueError, "sdllMethode"):
            Instance(1, 1, "A" * 256, 0, 0, 0, "x64")

    def test_instance_layout_size_matches_arch_contract(self):
        expected_sizes = {
            "x86": 3172,
            "x64": 3432,
            "arm64": 3304,
        }

        for arch, expected_size in expected_sizes.items():
            with self.subTest(arch=arch):
                instance = Instance(1, 0, "", 0, 0, 0, arch)
                self.assertEqual(len(instance.pack()), expected_size)

    def test_cli_missing_file_reports_clean_error(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir_path = Path(tmpdir)
            missing_payload = tmpdir_path / "missing.exe"

            result = subprocess.run(
                [
                    sys.executable,
                    str(DREAMWALKERS_SCRIPT),
                    "--file",
                    str(missing_payload),
                    "--arch",
                    "x64",
                ],
                cwd=tmpdir_path,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )

            combined_output = result.stdout + result.stderr
            self.assertNotEqual(result.returncode, 0, combined_output)
            self.assertIn("error: Executable not found:", combined_output)
            self.assertNotIn("Traceback", combined_output)
            self.assertFalse((tmpdir_path / "finalShellcode.bin").exists())

    def test_cli_native_dll_requires_method(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir_path = Path(tmpdir)
            payload = tmpdir_path / "payload.dll"
            payload.write_bytes(make_minimal_pe("x64", is_dll=True))

            result = subprocess.run(
                [
                    sys.executable,
                    str(DREAMWALKERS_SCRIPT),
                    "--file",
                    str(payload),
                    "--arch",
                    "x64",
                ],
                cwd=tmpdir_path,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )

            combined_output = result.stdout + result.stderr
            self.assertNotEqual(result.returncode, 0, combined_output)
            self.assertIn("error: Native DLL payloads require --method", combined_output)
            self.assertNotIn("Traceback", combined_output)
            self.assertFalse((tmpdir_path / "finalShellcode.bin").exists())

    def test_cli_generation_contract_for_matrix_arch(self):
        arch = self._arch_under_test() or "x64"
        expected_status = os.environ.get(
            "DREAMWALKERS_EXPECTED_ARCH_STATUS",
            "supported",
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir_path = Path(tmpdir)
            payload = tmpdir_path / f"payload_{arch}.exe"
            payload.write_bytes(make_minimal_pe(arch))

            result = subprocess.run(
                [
                    sys.executable,
                    str(DREAMWALKERS_SCRIPT),
                    "--file",
                    str(payload),
                    "--arch",
                    arch,
                ],
                cwd=tmpdir_path,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )

            final_shellcode = tmpdir_path / "finalShellcode.bin"
            combined_output = result.stdout + result.stderr

            if expected_status == "supported":
                self.assertEqual(result.returncode, 0, combined_output)
                self.assertTrue(final_shellcode.is_file())
                self.assertGreater(final_shellcode.stat().st_size, 0)
                self.assertIn(f"Target architecture: {arch}", combined_output)
            elif expected_status == "unsupported":
                self.assertNotEqual(result.returncode, 0, combined_output)
                self.assertFalse(final_shellcode.exists())
                self.assertIn(
                    f"Target architecture {arch} is valid, but shellcode generation is still",
                    combined_output,
                )
            else:
                self.fail(f"Unknown DREAMWALKERS_EXPECTED_ARCH_STATUS={expected_status!r}")


if __name__ == "__main__":
    unittest.main()
