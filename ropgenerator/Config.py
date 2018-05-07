# ROPGenerator - Config.py module
# Stores the configuration for the tool 
import ropgenerator.Analysis as Analysis
from ropgenerator.Colors import notify, string_special, string_bold,info_colored, error_colored, BOLD_COLOR_ANSI, END_COLOR_ANSI
import os 

# Help for the config command
CMD_CONFIG_HELP =  string_bold("\n\t------------------------------")
CMD_CONFIG_HELP += string_bold("\n\tROPGenerator 'config' command\n\t")
CMD_CONFIG_HELP += string_special("(Configure ROPGenerator)")
CMD_CONFIG_HELP += string_bold("\n\t------------------------------")
CMD_CONFIG_HELP += "\n\n\t"+string_bold("Usage")+":\tconfig show\n\t\tconfig <parameter>=<value> [<parameter>=<value> ...]"
CMD_CONFIG_HELP += "\n\n\t"+string_bold("Parameters")+":\n\t\t"+string_special("ropgadget")+':\tcommand to run ROPgadget tool (typically\n\t\t\t\t"ROPgadget" or "/path/to/ROPgadget.py")\n\t\t'+string_special("limit")+':\t\tnumber of matching gadgets to find for a query'
CMD_CONFIG_HELP += "\n\n\t"+string_bold("Examples")+":\n\t\tconfig ropgadget=ROPgadget\n\t\tconfig ropgadget=/usr/ROPgadget.py limit=4"


# ROPGENERATOR CONIGURATION DEFAULT 
DEFAULT_ARCH = "X86-64"
DEFAULT_PATH_ROPGADGET = "ROPgadget4ROPGenerator"
DEFAULT_LIMIT = 3

ARCH = DEFAULT_ARCH
PATH_ROPGADGET = DEFAULT_PATH_ROPGADGET
LIMIT = DEFAULT_LIMIT
ROPGENERATOR_DIRECTORY = os.path.expanduser('~')+"/ROPGenerator/"
ROPGENERATOR_CONFIG_FILE = ROPGENERATOR_DIRECTORY + "ROPGenerator-conf"

def print_help():
    print(CMD_CONFIG_HELP)

def print_config():
    global ARCH
    global PATH_ROPGADGET
    global LIMIT
    
    
    print(string_bold("\n\tROPGenerator's current configuration:\n"))
    print(string_bold("\tropgadget:\t") + PATH_ROPGADGET)
    print(string_bold("\tlimit:\t\t") + str(LIMIT))
    print("")    

def update_config(args):
    """
    Update config with user supplied args
    """
    if( len(args) == 1 and args[0] == 'show' ):
        print_config()
        return 
    
    info_colored(string_bold("Updating configuration\n"))
    for arg in args:
        arg_list = arg.split('=')
        left = arg_list[0]
        if( len(arg_list) < 2 ):
            notify("Error. Missing right part in argument " + arg)
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
                notify("Ignored unknown parameter '"+left+"'")


def set_arch(arch, quiet=False):
    global ARCH
    if( arch in Analysis.supportedArchs ):
        ARCH = arch
        Analysis.setArch(arch)
        if( not quiet ):
            notify("Now working under architecture: " + arch)
    else:
        if( not quiet) :
            notify("Architecture '" + arch + "' not supported. Available architectures: " + ','.join(Analysis.supportedArchs)) 
    
def set_ropgadget(path):
    global DEFAULT_PATH_ROPGADGET
    global PATH_ROPGADGET
    if( (os.path.isfile(path) and path[:-3] == ".py") or path == DEFAULT_PATH_ROPGADGET or path == "ROPgadget"):
        PATH_ROPGADGET = path
        notify("New ropgadget command : " + path)
    else:
        notify("Error. '" + path+"' could not be found")

def set_limit(limit):
    global LIMIT
    if( isinstance(limit, int)):
        LIMIT = limit
    else:
        try:
            limit = int(limit, 10)
            LIMIT = limit
            notify("Now looking for up to {} gadgets by request".format(str(LIMIT)))
        except:
            notify("Error. 'limit' parameter should be a base 10 integer")
         

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
    global LIMIT 
    # Check if the ROPGenerator director exists 
    if( not os.path.isdir(ROPGENERATOR_DIRECTORY) ):
        try:
            os.system('mkdir '+ROPGENERATOR_DIRECTORY)
        except:
            pass
    try:
        f = open(ROPGENERATOR_CONFIG_FILE, "r" )
        ARCH = f.readline()[:-1]
        PATH_ROPGADGET = f.readline()[:-1]
        LIMIT = int(f.readline()[:-1], 10)
        f.close()
        #info_colored("Loaded configuration\n")
    except:
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
    

    
    
    
