# -*- coding: utf-8 -*- 
# Architecture module : manage working architecture and interface with BARF 

from barf.arch import ARCH_X86_MODE_32
from barf.arch import ARCH_X86_MODE_64
from barf.arch.x86.x86translator import X86Translator
from barf.arch.x86.x86disassembler import X86Disassembler
from barf.arch.x86.x86base import *
from enum import Enum

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
        self.name = None
        self.archInfo = None
        self.ip = None
        self.sp = None
        self.bits = None
        self.octets = None
        
        # BARF Information 
        self.archMode = None
        
    def asmToREIL(self, asmStr):
        """
        Translate assembly into REIL
        """
        index = 0
        instr = []
        try:
            while( index < len(asmStr)):
                asm = self.disassembler.disassemble(asmStr[index:], index)
                if( asm is None ):
                    bad = '\\x' + '\\x'.join("{:02x}".format(ord(c) for c in asmStr[index:]))
                    raise ArchException("Unable to translate instructions {}".format(bad))
                instr.append(asm)
                index += asm.size
            irsb = [a for i in instr for a in self.irTranslator.translate(i) ]
            return (irsb,instr)
        except:
            raise ArchException("Couldn't translate gadget")

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


available = [ArchX86.name, ArchX64.name]

# Some functions
def currentIsIntel():
    return currentArch in [ArchX64, ArchX86]

def bits():
    return currentArch.bits

def octets():
    return currentArch.octets

def spNum():
    return n2r(currentArch.sp)
    
def ipNum():
    return n2r(currentArch.ip)
    
def registers():
    return range(0, ssaRegCount)
    
def current():
    return currentArch
    
#####################
# Types of binaries #
##################### 
class BinaryType(Enum):
    X86_ELF="X86 ELF"
    X64_ELF="X86-64 ELF"
    X86_PE ="X86 Windows PE"
    X64_PE ="X86-64 Windows PE"
    UNKNOWN = "UNKNOWN"

currentBinType = None

def currentIsELF():
    global currentBinType
    return currentBinType in [BinaryType.X86_ELF, BinaryType.X64_ELF]
    
#############################
# Reinitialisation function #
#############################
def reinit():
    global ssaRegCount, regNumToName, regNameToNum, currentArch, currentBinType
    ssaRegCount = 0
    regNumToName = dict()
    regNameToNum = dict()
    currentArch = None
    currentBinType = None
