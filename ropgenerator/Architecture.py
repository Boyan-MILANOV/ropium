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
        self.minPageSize = None
        self.endianness = None
        self.regs = None
        
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
    
##############
# Endianness # 
##############
class EndiannessType(Enum):
    BIG = "BIG"
    LITTLE = "LITTLE"
    
###########################
# Supported architectures #
###########################

currentArch = None
def setArch(arch):
    global currentArch, ssaRegCount, regNumToName, regNameToNum
    currentArch = arch
    ssaRegCount = 0
    regNumToName = dict()
    regNameToNum = dict()
    for reg in arch.regs:
        regNumToName[ssaRegCount] = reg
        regNameToNum[reg] = ssaRegCount
        ssaRegCount += 1


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
ArchX86.minPageSize = 0x1000
ArchX86.endianness = EndiannessType.LITTLE
Arch.X86.regs = ['eax','ebx','ecx','edx','esi','edi','esp','eip'\
                , 'cf', 'pf', 'af', 'zf', 'sf']

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
ArchX64.minPageSize = 0x1000
ArchX64.endianness = EndiannessType.LITTLE
ArchX64.regs = ['rax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi', 'rsp', 'rbp', 'rip'\
                , 'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15', 'sf', 'zf'\
                , 'af','cf','df','es', 'fs']


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
    
def minPageSize():
    return currentArch.minPageSize
    
def isLittleEndian():
    return currentArch.endianness == EndiannessType.LITTLE

def isBigEndian():
    return currentArch.endianness == EndiannessType.BIG
    
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
