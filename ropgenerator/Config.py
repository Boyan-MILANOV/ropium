# ROPGenerator - Config.py module
# Stores the configuration for the tool 
import ropgenerator.Analysis as Analysis
from ropgenerator.Colors import info_colored, error_colored
import os 

# Help for the config command
CMD_CONFIG_HELP =  "\n\t------------------------------"
CMD_CONFIG_HELP += "\n\tROPGenerator 'config' command\n\t(Configure ROPGenerator)"
CMD_CONFIG_HELP += "\n\t------------------------------"
CMD_CONFIG_HELP += "\n\n\tUsage:\tconfig show\n\t\tconfig <parameter>=<value> [<parameter>=<value> ...]"
CMD_CONFIG_HELP += "\n\n\tParameters:\n\t\tarch:\t\tarchitecture (available " + ','.join(Analysis.supportedArchs) + ')\n\t\tropgadget:\tcommand to run ROPgadget tool (typically\n\t\t\t\t"ROPgadget" or "/path/to/ROPgadget.py")\n\t\tlimit:\t\tnumber of matching gadgets to find for a query'
CMD_CONFIG_HELP += "\n\n\tExamples:\n\t\tconfig arch=X86\n\t\tconfig arch=X86_64 ropgadget=/usr/ROPgadget.py limit=4"





# ROPGENERATOR CONIGURATION DEFAULT 
DEFAULT_ARCH = "X86_64"
DEFAULT_PATH_ROPGADGET = "ROPgadget"
DEFAULT_LIMIT = 3

ARCH = DEFAULT_ARCH
PATH_ROPGADGET = DEFAULT_PATH_ROPGADGET
LIMIT = DEFAULT_LIMIT
ROPGENERATOR_DIRECTORY = "/var/ropgenerator/"
ROPGENERATOR_CONFIG_FILE = ROPGENERATOR_DIRECTORY + "ROPGenerator-conf"

def print_help():
    print(CMD_CONFIG_HELP)

def print_config():
    global ARCH
    global PATH_ROPGADGET
    global LIMIT
    
    
    print("\n\tROPGenerator's current configuration:\n")
    print("\tarch:\t\t" + ARCH)
    print("\tropgadget:\t" + PATH_ROPGADGET)
    print("\tlimit:\t\t" + str(LIMIT))
    print("")    

def update_config(args):
    """
    Update config with user supplied args
    """
    if( len(args) == 1 and args[0] == 'show' ):
        print_config()
        return 
    
    info_colored("Updating configuration\n")
    for arg in args:
        arg_list = arg.split('=')
        left = arg_list[0]
        if( len(arg_list) < 2 ):
            print("\tError. Missing right part in argument " + arg)
            return 
        else:
            right = arg_list[1]
            if( left == "arch"):
                set_arch(right)
            elif( left == "ropgadget" ):
                set_ropgadget(right)
            elif( left == "limit" ):
                set_limit(right)
            else:
                print("\tIgnored unknown parameter '"+left+"'. Type 'config help' for help")


def set_arch(arch):
    global ARCH
    if( arch in Analysis.supportedArchs ):
        ARCH = arch
        Analysis.setArch(arch)
        print("\tNow working under architecture: " + arch)
    else:
        print("\tArchitecture '" + arch + "' is not supported. Available architectures are: " + ','.join(Analysis.supportedArchs)) 
    
def set_ropgadget(path):
    global DEFAULT_PATH_ROPGADGET
    global PATH_ROPGADGET
    if( (os.path.isfile(path) and path[:-3] == ".py") or path == DEFAULT_PATH_ROPGADGET):
        PATH_ROPGADGET = path
        print("\tNew ropgadget location : " + path)
    else:
        print("\tError. '" + path+"' could not be found")

def set_limit(limit):
    global LIMIT
    if( isinstance(limit, int)):
        LIMIT = limit
    else:
        try:
            limit = int(limit, 10)
            LIMIT = limit
            print("\tNow looking for up to {} gadgets by request".format(str(LIMIT)))
        except:
            print("\tError. 'limit' parameter should be a base 10 integer")
         

def save_config():
    global ARCH
    global PATH_ROPGADGET
    global LIMIT
    try:        
        f = open(ROPGENERATOR_CONFIG_FILE, "w")
        f.write(ARCH + '\n')
        f.write(PATH_ROPGADGET + '\n')
        f.write(str(LIMIT) + '\n')
        f.close()
    except:
        error_colored("Error while saving the last ROPGenerator configuration\n")
        
def load_config():
    global ARCH
    global PATH_ROPGADGET
    try:
        f = open(ROPGENERATOR_CONFIG_FILE, "r" )
        ARCH = f.readline()[:-1]
        PATH_ROPGADGET = f.readline()[:-1]
        LIMIT = int(f.readline()[:-1], 10)
        f.close()
        #info_colored("Loaded configuration\n")
    except:
        if( os.path.isfile(ROPGENERATOR_CONFIG_FILE)):
            info_colored("Couldn't load custom configuration, using the default one\n")
        default_config()
    Analysis.setArch(ARCH)
    
def default_config():
    global ARCH
    global PATH_ROPGADGET
    global DEFAULT_ARCH
    global DEFAULT_PATH_ROPGADGET
    ARCH = DEFAULT_ARCH
    PATH_ROPGADGET = DEFAULT_PATH_ROPGADGET
    LIMIT = DEFAULT_LIMIT
    Analysis.setArch(ARCH)
    

    
    
    
