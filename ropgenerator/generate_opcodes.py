import subprocess
import os
import sys
import ropgenerator.Config as Config
from ropgenerator.Colors import error_colored
from enum import Enum
from magic import from_file

opcodes_file = Config.ROPGENERATOR_DIRECTORY + "generated_opcodes"

# Types of binaries
class binaryType(Enum):
    ELF32="ELF 32 bits"
    ELF64="ELF 64 bits"
    

def check_binaryType(filename):
    """
    Checks the binary type of the file
    Precondition: the file exists ! 
    """
    ELF32_strings = ["ELF 32-bit"]
    ELF64_strings = ["ELF 64-bit", "x86-64"]
    
    output = from_file(os.path.realpath(filename))
    if( [sub for sub in ELF32_strings if sub in output]):
        print("\tELF 32-bit detected")
        return "X86"
    elif( [sub for sub in ELF64_strings if sub in output]):
        print("\tELF 64-bit detected")
        return "X86_64"
    else:
        print("\tUnknown binary type")
        return None

def generate(filename):
    """
    Returns true if success, false otherwise 
    """    
    global opcodes_file
    
    if( not os.path.isfile(filename)):
        print("Error. Could not find file '{}'".format(filename))
        return False
         
    binType = check_binaryType(filename)
    if( not binType):
        error_colored("Could not determine architecture for binary: " + filename+"\n")
        return False
    else:
        Config.set_arch(binType, quiet=True)
    
    ropgadget = Config.PATH_ROPGADGET
    print("\tExecuting ROPgadget as: " + ropgadget )
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
        
    print "\tFinished : %d gadgets generated" % (count)
    
    return ( count > 0)
