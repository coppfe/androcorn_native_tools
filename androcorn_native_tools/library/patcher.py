import logging
from keystone import *
from androidemu.const.emu_const import ARCH_ARM64

from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from androidemu.utils.parsers.elf import ELFReader

logger = logging.getLogger(__name__)

class ELFPatcher:
    def __init__(self, elf_reader: 'ELFReader', arch: int, is_thumb: bool = True):
        self.reader = elf_reader
        self.arch = arch
        
        if arch == ARCH_ARM64:
            self.ks = Ks(KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN)
            self.nop_insn = "nop"
            self.insn_size_unit = 4
        else:
            mode = KS_MODE_THUMB if is_thumb else KS_MODE_ARM
            self.ks = Ks(KS_ARCH_ARM, mode)
            self.nop_insn = "nop"
            self.insn_size_unit = 2 if is_thumb else 4

    def patch(self, address: int, asm_string: str, original_size: int = 4):
        try:
            encoding, count = self.ks.asm(asm_string)
            patch_bytes = bytearray(encoding)

            if len(patch_bytes) > original_size:
                raise ValueError(f"New code size ({len(patch_bytes)}) exceeds original size ({original_size})")

            while len(patch_bytes) < original_size:
                nop_bytes, _ = self.ks.asm(self.nop_insn)
                if len(patch_bytes) + len(nop_bytes) <= original_size:
                    patch_bytes.extend(nop_bytes)
                else:
                    patch_bytes.append(0x00)

            section = self.reader.binary.section_from_virtual_address(address)
            if not section:
                raise ValueError(f"Address {hex(address)} not found in any section")

            offset = address - section.virtual_address
            content = list(section.content)
            content[offset : offset + len(patch_bytes)] = list(patch_bytes)
            section.content = content
            
            logger.info("PATCH OK: [%s] at %s | Raw: %s", asm_string, hex(address), patch_bytes.hex())
            return True

        except Exception as e:
            logger.error("Patching failed at %s: %s", hex(address), e)
            return False

    def save(self, output_filename: str):
        self.reader.binary.write(output_filename)