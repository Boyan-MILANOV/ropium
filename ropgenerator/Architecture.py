# -*- coding: utf-8 -*- 
# Architecture module : manage working architecture and interface with BARF 

from barf.arch import ARCH_X86_MODE_32
from barf.arch import ARCH_X86_MODE_64
from barf.arch.x86.x86translator import FULL_TRANSLATION
from barf.arch.x86.x86translator import X86Translator
from barf.arch.x86.x86disassembler import X86Disassembler
from barf.arch.x86.x86base import *


class ArchException(Exception):
    """
    Custom Exception type for this module
    """
    def __init__(self, msg):
        self.msg = msg
        
    def __str__(self):
        return self.msg

##############
# Arch class #
##############

class Architecture: 
    def __init__(self):
        name = None
        archInfo = None
        ip = None
        sp = None
        bits = None
        octets = None
        
        # BARF Information 
        archMode = None
        disassembler = None
        irTranslator = None
        
    def asmToREIL(self, asmStr):
        """
        Translate assembly into REIL
        """
        index = 0
        instr = []
        while( index < len(asmStr)):
            asm = disassembler.disassemble(asmStr[index:], index)
            if( asm is None ):
                bad = "\\x"+"\\x".join("{:02x}".format(ord(c))\
                                    for c in asmStr[index:])
                total = "\\x"+"\\x".join("{:02x}".format(ord(c))\
                                    for c in asmStr)
                raise ArchException("BARF unable to translate {} instructions\
                {} in gadget {}".format(self.name, bad, total))
            instr.append(asm)
            index += asm.size
        irsb = [self.irTranslator.translate(i) for i in ins]
        return (irsb,ins)

#####################
# Register handling #
#####################

ssaRegCount = 0 # Index for register translation during gadget analysis
regNumToName = dict() # Dictionnary <reg number> --> <reg name>
regNameToNum = dict() # Dictionnary <reg name> --> <reg number> 

def r2n(num):
    global regNumToName
    return regNumToName[num]
    
def n2r(name):
    global regNameToNum
    return regNameToNum[name]
    
###########################
# Supported architectures #
###########################

currentArch = None

# X86 
ArchX86 = Architecture()
ArchX86.name = "X86" 
ArchX86.archInfo = X86ArchitectureInformation(ARCH_X86_MODE_32)
ArchX86.ip = "eip"
ArchX86.sp = "esp"
ArchX86.bits = 32
ArchX86.octets = 4
ArchX86.archMode = ARCH_X86_MODE_32
ArchX86.disassembler = X86Disassembler(architecture_mode=ARCH_X86_MODE_32)
ArchX86.irTranslator = X86Translator(architecture_mode=ARCH_X86_MODE_32)
    
# X86-64
ArchX64 = Architecture()
ArchX64.name = "X64" 
ArchX64.archInfo = X86ArchitectureInformation(ARCH_X86_MODE_64)
ArchX64.ip = "rip"
ArchX64.sp = "rsp"
ArchX64.bits = 64
ArchX64.octets = 8
ArchX64.archMode = ARCH_X86_MODE_64
ArchX64.disassembler = X86Disassembler(architecture_mode=ARCH_X86_MODE_64)
ArchX64.irTranslator = X86Translator(architecture_mode=ARCH_X86_MODE_64)
