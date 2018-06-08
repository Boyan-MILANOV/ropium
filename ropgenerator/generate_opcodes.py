import subprocess
import os
import sys
import ropgenerator.Config as Config
from ropgenerator.Colors import notify, error_colored, string_bold
from enum import Enum
from magic import from_file
import ropgenerator.Analysis as Analysis

opcodes_file = Config.ROPGENERATOR_DIRECTORY + "generated_opcodes"

# Types of binaries
class binaryType(Enum):
    X86_ELF="X86 ELF"
    X64_ELF="X86-64 ELF"
    X86_PE ="X86 Windows PE"
    X64_PE ="X86-64 Windows PE"

def check_binaryType(filename):
    """
    Checks the binary type of the file
    Precondition: the file exists ! 
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
            Analysis.setFiletype("ELF")
            return "X86"
        elif( [sub for sub in ELF64_strings if sub in output]):
            notify("ELF 64-bits detected")
            Analysis.setFiletype("ELF")
            return "X86-64"
        elif( [sub for sub in PE32_strings if sub in output]):
            notify("PE 32-bits detected")
            Analysis.setFiletype("PE")
            return "X86"
        elif( [sub for sub in PE64_strings if sub in output]):
            notify("PE 64-bits detected")
            Analysis.setFiletype("PE")
            return "X86-64"
        else:
            notify("Unknown binary type")
            return None
    else:
        notify("Unknown architecture")
        return None 

def generate(filename):
    """
    Returns true if success, false otherwise 
    """    
    global opcodes_file
    
    if( not os.path.isfile(filename)):
        print(string_bold("\n\tError. Could not find file '{}'".format(filename)))
        return False
         
    binType = check_binaryType(filename)
    if( not binType):
        error_colored("Could not determine architecture for binary: " + filename+"\n")
        return False
    else:
        Config.set_arch(binType, quiet=True)
    
    ropgadget = Config.PATH_ROPGADGET
    notify("Executing ROPgadget as: " + ropgadget )
    try:
        p = subprocess.Popen([ropgadget,"--binary",filename,"--dump", "--all"],stdout=subprocess.PIPE)
    except Exception as e:
        error_colored("Could not execute ' " +ropgadget+ " --binary " + filename + " --dump '")
        print("\tError message is: " + str(e))
        print("\n\t(Maybe check/update your config with the 'config' command, or make sure you have the last ROPgadget version installed)")
        return False
         
    
    f = open(opcodes_file,"w")

    # Write gadgets 
    first = True
    count = 0
    for l in p.stdout.readlines():
        if("0x" in l):
            arr = l.split(' ')
            addr = arr[0]
            gadget = arr[-1]
            it = iter(gadget)
            gadget = ''.join(a+b for a,b in zip(it,it))
            f.write(addr+'#')
            f.write(gadget+'\n')
            count += 1 
    f.close()
        
    notify("Finished : %d gadgets generated" % (count))
    
    return ( count > 0)
