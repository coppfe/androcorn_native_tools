import logging

from keystone import *

from androidemu.internal.elf_reader import ELFReader
from androidemu.const.emu_const import ARCH_ARM64

logger = logging.getLogger(__name__)

class ELFPatcher:
    def __init__(self, elf_reader: 'ELFReader', arch: int):
        self.reader = elf_reader
        self.ks = Ks(KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN) if arch == ARCH_ARM64 else Ks(KS_ARCH_ARM, KS_MODE_ARM)

    def patch_instruction(self, address: int, asm_string: str):
        if isinstance(address, str):
            address = int(address, 16)
        try:
            encoding, count = self.ks.asm(asm_string)
            patch_bytes = bytes(encoding)
            section = self.reader.binary.section_from_virtual_address(address)
            if not section:
                raise ValueError(f"Address {hex(address)} not found in any section")

            offset = address - section.virtual_address
            
            content = list(section.content)
            content[offset : offset + len(patch_bytes)] = list(patch_bytes)
            section.content = content
            
            logger.info("Patched %s at %s with bytes %s", asm_string, hex(address), patch_bytes.hex())
            return True
            
        except KsError as e:
            logger.error("Keystone Error: %s", e)
        except Exception as e:
            logger.error("Patching failed: %s", e)
        return False

    def save(self, output_filename: str):
        self.reader.binary.write(output_filename)

