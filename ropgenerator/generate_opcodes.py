import subprocess
import os
import sys
import ropgenerator.Config as Config


def generate(filename):
    """
    Returns true if success, false otherwise 
    
    """
    #if(not "PATH_ROPGADGET" in os.environ):
    #    print "Need to set PATH_ROPGADGET"
    #    print "export PATH_ROPGADGET=..."
    #    exit()

    #if(len(sys.argv)!=2):
    #    print "Use ./generate_opcode.py BINARY"
    #    exit()

    #ropgadget = os.environ["PATH_ROPGADGET"]+"/ROPgadget.py"
    
    if( not os.path.isfile(filename)):
        print("Error. Could not find file '{}'".format(filename))
        return False
         
    ropgadget = Config.PATH_ROPGADGET+"/ROPgadget.py"
    print("Executing ROPgadget as: " + ropgadget )
    try:
        p = subprocess.Popen([ropgadget,"--binary",filename,"--dump", "--all"],stdout=subprocess.PIPE)
    except Exception as e:
        print("Error. Could not execute ' " +ropgadget+ " --binary " + filename + " --dump '")
        print("Error message is: " + str(e))
        print("\n(Maybe check/update your config with the 'config' command)")
        return False
          
    f = open(".generated_opcodes","w")

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
        
    print "Finished : %d gadgets generated" % (count)
    
    return ( count > 0)
