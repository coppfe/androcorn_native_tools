from androcorn_native_tools.library.scanner import ELFScanner

from androidemu.internal.elf_reader import ELFReader
from androidemu.const.emu_const import ARCH_ARM64, ARCH_ARM32

reader = ELFReader(r"C:\Users\Kirill\Desktop\androidemu\vfs\system\lib64\libc.so", demangle=False)
scanner = ELFScanner(reader, ARCH_ARM64)

results_x0 = scanner.search_instructions("mrs", ["x0", None])

print("--- MRS X0, ANY ---")
for addr, mnem, op_str in results_x0:
    print(f"Found at {addr}: {mnem} {op_str}")

results_tls = scanner.search_instructions("mrs", [None, "tpidr_el0"])

print("\n--- MRS ANY, TPIDR_EL0 ---")
for addr, mnem, op_str in results_tls:
    print(f"Found at {addr}: {mnem} {op_str}")

results_adrp = scanner.search_instructions("adrp", ["x0", None])

print("\n--- ADRP X0, ANY ---")
for addr, mnem, op_str in results_adrp:
    print(f"Found at {addr}: {mnem} {op_str}")