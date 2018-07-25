# -*- coding:utf-8 -*- 
# Load module: load a binary and extract gadgets from it 

import os
import subprocess
from ropgenerator.Database import build, initDB
from ropgenerator.semantic.Engine import initEngine
from ropgenerator.exploit.Scanner import initScanner
import ropgenerator.Architecture as Arch
from ropgenerator.IO import string_bold, info, string_special, banner, notify, error
from magic import from_file
from base64 import b16decode
from random import shuffle, random

# Command options
OPTION_ARCH = '--arch'
OPTION_ARCH_SHORT = '-a'
OPTION_HELP = '--help'
OPTION_HELP_SHORT = '-h'

# Help for the load command
helpStr = banner([string_bold("'load' command"),
    string_special("(Load gadgets from a binary file)")])
helpStr += "\n\n\t"+string_bold("Usage")+":\tload [OPTIONS] <filename>"
helpStr += "\n\n\t"+string_bold("Options")+":"
helpStr += "\n\t\t"+string_special(OPTION_ARCH_SHORT)+","+string_special(OPTION_ARCH)+\
" <arch>"+"\tmanualy specify architecture.\n\t\t\t\t\tAvailable: 'X86', 'X64'"
helpStr += "\n\n\t"+string_bold("Examples")+":\n\t\tload /bin/ls\t\t(load gadgets from /bin/ls program)\n\t\tload ../test/vuln_prog\t(load gadgets from own binary)"
 

def print_help():
    print(helpStr)

def getPlatformInfo(filename):
    """
    Checks the binary type of the file
    Precondition: the file exists ! 
    
    Effects: set the Arch.currentBinType variable
    Return : the architecture 
    """
    INTEL_strings = ["x86", "x86-64", "X86", "X86-64", "Intel", "80386"]
    ELF32_strings = ["ELF 32-bit"]
    ELF64_strings = ["ELF 64-bit"]
    PE32_strings = ["PE32 "]
    PE64_strings = ["PE32+"]
    
    output = from_file(os.path.realpath(filename))
    if( [sub for sub in INTEL_strings if sub in output]):
        if( [sub for sub in ELF32_strings if sub in output]):
            notify("ELF 32-bits detected")
            Arch.currentBinType = Arch.BinaryType.X86_ELF
            return Arch.ArchX86
        elif( [sub for sub in ELF64_strings if sub in output]):
            notify("ELF 64-bits detected")
            Arch.currentBinType = Arch.BinaryType.X64_ELF
            return Arch.ArchX64
        elif( [sub for sub in PE32_strings if sub in output]):
            notify("PE 32-bits detected")
            Arch.currentBinType = Arch.BinaryType.X86_PE
            return Arch.ArchX86
        elif( [sub for sub in PE64_strings if sub in output]):
            notify("PE 64-bits detected")
            Arch.currentBinType = Arch.BinaryType.X64_PE
            return Arch.ArchX64
        else:
            notify("Unknown binary type")
            Arch.currentBinType = Arch.BinaryType.UNKNOWN
            return None
    else:
        return None 

def getGadgets(filename):
    """
    Returns a list of gadgets extracted from a file 
    Precondition: the file exists 
    
    Returns
    -------
    list of pairs (addr, asm) if succesful
    None if failure 
    """    
   
    ropgadget = "ROPgadget4ROPGenerator"
    notify("Executing ROPgadget as: " + ropgadget )
    try:
        p = subprocess.Popen([ropgadget,"--binary",filename,"--dump", "--all"],stdout=subprocess.PIPE)
    except Exception as e:
        error("Could not execute '" +ropgadget+ " --binary " + filename + " --dump --all'")
        print("\tError message is: " + str(e))
        print("\n\t(Maybe check/update your config with the 'config' command,\n\t or make sure you have the last ROPgadget version installed)")
        return None

    # Get the gadget list 
    # Pairs (address, raw_asm)
    first = True
    count = 0
    res = []
    for l in p.stdout.readlines():
        if("0x" in l):
            arr = l.split(' ')
            addr = arr[0]
            raw = b16decode(arr[-1].upper().strip())
            res.append((int(addr,16), raw))
            count += 1 
    notify("Finished : %d gadgets generated" % (count))
    return res
    
def load(args):
    global helpStr
    global loaded
    # Parse arguments and filename 
    filename = None
    user_arch = None
    i = 0
    seenArch = False
    if( not args ):
        print(helpStr)
        return 

    while i < len(args):
        if( args[i] in [OPTION_ARCH, OPTION_ARCH_SHORT] ):
            if( seenArch ):
                error("Option {} can be used only one time"\
                .format(args[i]))
                return 
            seenArch = True
            if( i+1 == len(args)):
                error("Missing argument after {}.\n\tType 'load -h' for help"\
                .format(args[i]))
                return 
            elif( args[i+1] == Arch.ArchX86.name ):
                user_arch = Arch.ArchX86
            elif( args[i+1] == Arch.ArchX64.name ):
                user_arch = Arch.ArchX64
            else:
                error("Unknown architecture: {}".format(args[i+1]))
                return 
            i += 2
        elif( args[i] in [OPTION_HELP, OPTION_HELP_SHORT] ):
            print(helpStr)
            return 
        else:
            filename = args[i]
            break
    if( not filename ):
        error("Missing filename.\n\tType 'load help' for help")
        return 
    
    # Test if the file exists 
    if( not os.path.isfile(filename)):
        error("Error. Could not find file '{}'".format(filename))
        return 
        
    print('')
    info(string_bold("Extracting gadgets from file")+ " '" + filename + "'\n")
    
    # Cleaning the data structures
    initDB()
    Arch.reinit()
    
    # Get architecture and OS info  
    arch = getPlatformInfo(filename)
    if(arch == user_arch == None):
        error("Error. Could not determine architecture")
        return 
    elif( arch and user_arch and (arch != user_arch) ):
        error("Error. Conflicting architectures")
        print("\tUser supplied: " + user_arch.name)
        print("\tFound: " + arch.name)
        return 
    elif( arch ):
        Arch.currentArch = arch
    else:
        Arch.currentArch = user_arch
        
    # Init the binary scanner
    initScanner(filename)
    
    # Extract the gadget list 
    gadgetList = getGadgets(filename)
    if( not gadgetList ):
        return 
        
    # Build the gadget database
    # (we mix the list so that charging bar
    # appears to grow steadily )
    r = random()
    shuffle(gadgetList, lambda: r)
    build(gadgetList)
    # Init engine 
    initEngine()
    loaded = True


# Module wide
loaded = False
def loadedBinary():
    global loaded
    return loaded
