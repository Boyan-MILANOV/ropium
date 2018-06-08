"""
ROPGenerator - Analysis.py module
Gathers information about the analysis being run
"""

from ropgenerator.Expr import REGSIZE
from ropgenerator.Logs import log

from barf.arch import ARCH_X86_MODE_32
from barf.arch import ARCH_X86_MODE_64 
from barf.arch.x86.x86translator import FULL_TRANSLATION
from barf.arch.x86.x86translator import X86Translator
from barf.arch.x86.x86disassembler import X86Disassembler
from barf.arch.x86.x86base import *
from barf.arch.arm import *

############################
# ARCHITECTURE INFORMATION #
############################
class FiletypeInfo:
    filetype = None


class ArchInfo:
    currentArch = None
    currentArchInfo = None
    ip = None # Name of the instruction pointer in current architecture
    sp = None # Name of the stack pointer in current architecture
    bits = 0

#####################
# REGISTER HANDLING #
#####################

# The index for register translation kept for the whole analysis to run on multiple gadgets
ssaRegCount = 0
# This is a hashtable in which a string corresponds to an unique integer
# Example regNamesTable{'ecx'} = 3 means ECX <-> R3 in IR
 # Keys are str, values are integers
regNamesTable = {}
# Keys are integers, values are str. This is the invert of regNamesTable
revertRegNamesTable = {}

def r2n(reg):
    global revertRegNamesTable
    return revertRegNamesTable[reg]
    
def n2r(name):
	global regNamesTable
	return regNamesTable[name]

def printRegTranslation():
    """
    Prints the translation of registers ( eax, esp, ... ) into intern
    representation ( R0, R1, R2, ... )
    The correspondence is stored in the regNamesTable dictionnary
    Example : 
        eax <---> R1
        ebx <---> R0
        esi <---> R3
        eip <---> R2
    """
    print "[-] Register translation :"
    for initId in regNamesTable.keys():
        print "\t" + initId + " <---> R" + str(regNamesTable[initId])
    print "\n"

###########################
# CONFIGURATION FUNCTIONS #
###########################

supportedArchs = ["X86", "X86-64"]
archs32bits = ["X86"]
archs64bits = ["X86-64"]

supportedFiletypes = ["ELF", "PE"]

def setArch(arch):
    """
    Sets the architecture that must be worked with
    Available architectures can be displayed using function helpArch()
    """
    if arch in supportedArchs:
        ArchInfo.currentArch = arch
        if arch == "X86":
            ArchInfo.bits = 32
            REGSIZE.size = 32
            ArchInfo.ip = "eip"
            ArchInfo.sp = "esp"
            ArchInfo.currentArchInfo = X86ArchitectureInformation(ARCH_X86_MODE_32)
        elif arch == "X86-64":
            ArchInfo.bits = 64
            REGSIZE.size = 64
            ArchInfo.ip = "rip"
            ArchInfo.sp = "rsp"
            ArchInfo.currentArchInfo = X86ArchitectureInformation(ARCH_X86_MODE_64)
    else:
        raise AnalysisException("Architecture {} is not supported. Sorry ! ".format(str(arch)))    
    
def helpArch():
    """
    Dsplays available architectures
    """
    print "[-] Available architectures"
    for arch in supportedArchs:
        print "\t"+arch

def setFiletype(filetype):
    if( filetype in supportedFiletypes ):
        FiletypeInfo.filetype = filetype
    else:
        raise Exception("Unknown filetype in Analysis.setFiletype")

######################################################
# GENERAL PURPOSE & ARCHITECTURE DEPENDENT FUNCTIONS #
######################################################

def getIR(opCodeStr, address):
    """
    Get the Intermediate Representation of a piece of assembly code
    Parameters :
        (opCodeStr) - The string of the opcodes in hex
        (address) - The address at which the first instruction is located
    Return value : 
        (instr, ins ) - Where 'instr' in an array of BARF instructions
                And 'ins' is the list of the assembly instructions
    """
    arch = ArchInfo.currentArch
    # Getting the translators and disassemblers for the requested architecture
    if arch == "X86":
        arch_mode =  ARCH_X86_MODE_32
        disassembler = X86Disassembler(architecture_mode=arch_mode)
        ir_translator = X86Translator(architecture_mode=arch_mode)
    elif arch == "X86-64":
        arch_mode =  ARCH_X86_MODE_64
        disassembler = X86Disassembler(architecture_mode=arch_mode)
        ir_translator = X86Translator(architecture_mode=arch_mode)
    else:
        raise AnalysisException("Architecture %s not yet supported" % arch)
    # Translating into IR 
    index = 0
    ins = []
    # disasemble -> return only one instr, so we need to iterate over the 
    #string gadget, using the size of the ins disassembled
    while(index < len(opCodeStr)):
        asm = disassembler.disassemble(opCodeStr[index:],index+address)
        if asm is None:
            bad_instructions = "\\x"+ "\\x".join("{:02x}".format(ord(c)) for c in opCodeStr[index:])
            all_instructions = "\\x"+ "\\x".join("{:02x}".format(ord(c)) for c in opCodeStr)
            raise AnalysisException("BARF unable to translate {} instructions {} in gadget {}".format(arch, bad_instructions, all_instructions))
        ins.append(asm)
        index = index+asm.size
    irsb = []
    for i in ins:
        for r in ir_translator.translate(i):
            irsb.append(r)
    return (irsb, ins)

#############################
# CUSTOM EXCEPTION HANDLING #
#############################

class AnalysisException(Exception):
    def __init__(self, msg):
        self.msg = msg
        log(msg)
    def __str__(self, msg):
        return str(msg)
        
        
#############################
# REINITIALIZATION FUNCTION #
#############################
def reinit():
    global ssaRegCount
    global regNamesTable
    global revertRegNamesTable
    ssaRegCount = 0
    regNamesTable = dict()
    revertRegNamesTable = dict()
