from androcorn_native_tools.library.scanner import ELFScanner
from androcorn_native_tools.library.patcher import ELFPatcher

from androidemu.internal.elf_reader import ELFReader
from androidemu.const.emu_const import ARCH_ARM64, ARCH_ARM32

reader = ELFReader(r"path", demangle=False)
scanner = ELFScanner(reader, ARCH_ARM64)
patcher = ELFPatcher(reader, ARCH_ARM64)

results_adrp = scanner.search_instructions("adrp", ["x0", None])

print("\n--- ADRP X0, ANY ---")
for addr, mnem, op_str in results_adrp:
    print(f"Found at {addr}: {mnem} {op_str}")
    patcher.patch_instruction(addr, "mov x0, #0")

patcher.save("libc_patched.so")

del reader, scanner
reader = ELFReader("libc_patched.so", demangle=False)
scanner = ELFScanner(reader, ARCH_ARM64)

results_adrp = scanner.search_instructions("adrp", ["x0", None])

print("\n--- ADRP X0, ANY ---")
for addr, mnem, op_str in results_adrp:
    print(f"Found at {addr}: {mnem} {op_str}")
