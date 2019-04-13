from ropgenerator.core.IO import *
from ropgenerator.core.Architecture import *
from ropgenerator.core.Symbolic import raw_to_IRBlock
from ropgenerator.core.Gadget import *
from ropgenerator.core.Database import *
from ropgenerator.core.ChainingEngine import *

from barf.core.reil import ReilMnemonic, ReilImmediateOperand, ReilRegisterOperand
from barf.arch import ARCH_X86_MODE_32
from barf.arch import ARCH_X86_MODE_64
from barf.arch.x86.translator import X86Translator
from barf.arch.x86.disassembler import X86Disassembler
from barf.arch.x86.x86 import *


# X64 
set_bin_type(BinType.ELF32)
set_arch(ArchType.ARCH_X86)

#raw = "\x48\x89\xD8" # MOV RAX,RBX
#raw = b'\x01\xF8\x30\xED\x01\xC8\x5F\xC3'
raw = b'\x30\xED\x01\xC8\xC3'

init_gadget_db();

input("waiting...")
(irblock, asm_instr_list) = raw_to_IRBlock(raw)
if( irblock is None ):
    print("Error IRBLOCK")
    exit(0)
print("Try " + '; '.join(str(i) for i in asm_instr_list))
gadget = Gadget(irblock)
asm_str = '; '.join(str(i) for i in asm_instr_list)
gadget.set_asm_str(asm_str)
gadget.set_hex_str("\\x" + '\\x'.join("{:02x}".format(c) for c in raw))
# Manually check for call (ugly but no other solution for now)
if( str(asm_instr_list[-1]).split(" ")[0] == "call" and gadget.ret_type() == RetType.JMP):
    gadget.set_ret_type(RetType.CALL)


print_gadget(gadget)
