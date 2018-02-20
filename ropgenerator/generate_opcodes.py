import subprocess
import os
import sys
import ropgenerator.Config as Config
from ropgenerator.Colors import error_colored

opcodes_file = Config.ROPGENERATOR_DIRECTORY + "generated_opcodes"

def generate(filename):
    """
    Returns true if success, false otherwise 
    """    
    global opcodes_file
    
    if( not os.path.isfile(filename)):
        print("Error. Could not find file '{}'".format(filename))
        return False
         
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
