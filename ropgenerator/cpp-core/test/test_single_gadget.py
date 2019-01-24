from ropgenerator.core.Symbolic import raw_to_IRBlock, raw_to_REIL
from ropgenerator.core.Architecture import ArchType, set_arch
from ropgenerator.core.Gadget import Gadget, print_gadget

from barf.core.reil import ReilMnemonic, ReilImmediateOperand, ReilRegisterOperand
from barf.arch import ARCH_X86_MODE_32
from barf.arch import ARCH_X86_MODE_64
from barf.arch.x86.x86translator import X86Translator
from barf.arch.x86.x86disassembler import X86Disassembler
from barf.arch.x86.x86base import *


# X64 
set_arch(ArchType.ARCH_X64)
disassembler = X86Disassembler(architecture_mode=ARCH_X86_MODE_64)
ir_translator = X86Translator(architecture_mode=ARCH_X86_MODE_64)
alias_mapper = X86ArchitectureInformation(ARCH_X86_MODE_64).alias_mapper

#raw = "\x48\x89\xD8" # MOV RAX,RBX
raw = "\x04\x0f\x96\xc3"

raw_input("waiting...")

(irblock, asm_instr_list) = raw_to_IRBlock(raw)
gadget = Gadget(irblock)
gadget.set_asm_str('; '.join(str(i) for i in asm_instr_list) )
gadget.set_hex_str("\\x" + '\\x'.join("{:02x}".format(ord(c)) for c in raw))


print_gadget(gadget)
