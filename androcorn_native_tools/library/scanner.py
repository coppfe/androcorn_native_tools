import logging

from typing import Optional, List

from capstone import *
from capstone.arm64 import *

from androidemu.internal.elf_reader import ELFReader
from androidemu.const.emu_const import ARCH_ARM64

logger = logging.getLogger(__name__)

class ELFScanner:
    def __init__(self, elf_reader: 'ELFReader', arch: int):
        self.reader = elf_reader
        self.md = Cs(CS_ARCH_ARM64, CS_MODE_ARM) if arch == ARCH_ARM64 else Cs(CS_ARCH_ARM, CS_MODE_ARM)
        self.md.detail = True

    def search_instructions(self, mnemonic: str, operand_filters: List[Optional[str]]):
        results = []
        text_section = self.reader.binary.get_section(".text")
        code = bytes(text_section.content)
        
        for insn in self.md.disasm(code, text_section.virtual_address):
            if insn.mnemonic == mnemonic:
                match = True
                for i, f in enumerate(operand_filters):
                    if f is None: continue # Wildcard
                    
                    if i < len(insn.operands):
                        curr_op_str = insn.op_str.split(',')[i].strip()
                        if f not in curr_op_str:
                            match = False
                            break
                
                if match:
                    results.append((hex(insn.address), insn.mnemonic, insn.op_str))
        return results