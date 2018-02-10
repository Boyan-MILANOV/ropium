# ROPGenerator - Config.py module
# Stores the configuration for the tool 
import Analysis
import os 

# Help for the config command
CMD_CONFIG_HELP =  "\n\t------------------------------"
CMD_CONFIG_HELP += "\n\tROPGenerator 'config' command\n\t(Configure ROPGenerator)"
CMD_CONFIG_HELP += "\n\t------------------------------"
CMD_CONFIG_HELP += "\n\n\tUsage:\tconfig show\t(Show the current configuration)\n\t\tconfig <parameter>=<value> [<parameter>=<value> ...]\t(Change the configuration)"
CMD_CONFIG_HELP += "\n\n\tParameters:\n\t\tarch:\t\tarchitecture (available " + ','.join(Analysis.supportedArchs) + ')\n\t\tropgadget:\tpath to the folder containing ROPgadget.py tool'
CMD_CONFIG_HELP += "\n\n\tExamples:\n\t\tconfig arch=X86\n\t\tconfig arch=X86_64 ropgadget=/usr/bin/ROPGadget"



config_file = "./.ROPGenerator-conf"

# ROPGENERATOR CONIGURATION DEFAULT 
ARCH = "X86_64"
PATH_ROPGADGET = "/usr/bin/ROPgadget"


def print_help():
	print(CMD_CONFIG_HELP)

def print_config():
	global ARCH
	print("\n\tROPGenerator's current configuration:\n")
	print("\tarch:\t\t" + ARCH)
	print("\tropgadget:\t" + PATH_ROPGADGET)
	print("")	

def update_config(args):
	"""
	Update config with user supplied args
	"""
	if( len(args) == 1 and args[0] == 'show' ):
		print_config()
		return 
	
	for arg in args:
		arg_list = arg.split('=')
		left = arg_list[0]
		if( len(arg_list) < 2 ):
			print("Error. Missing right part in argument " + arg)
			return 
		else:
			right = arg_list[1]
			if( left == "arch"):
				set_arch(right)
			elif( left == "ropgadget" ):
				set_ropgadget(right)
			else:
				print("Ignored unknown parameter '"+left+"'. Type 'config help' for help")


def set_arch(arch):
	global ARCH
	if( arch in Analysis.supportedArchs ):
		ARCH = arch
		Analysis.setArch(arch)
		print("Now working under architecture: " + arch)
	else:
		print("Architecture '" + arch + "' is not supported. Available architectures are: " + ','.join(Analysis.supportedArchs)) 
	
def set_ropgadget(path):
	global PATH_ROPGADGET
	if( os.path.isfile(path+'/ROPgadget.py')):
		PATH_ROPGADGET = path
		print("New ropgadget location : " + path+'/ROPgadget.py')
	else:
		print("Error. '" + path+"/ROPgadget.py' could not be found")

def save_config():
	global ARCH
	global PATH_ROPGADGET
	try:
		f = open(config_file, "w")
		f.write(ARCH + '\n')
		f.write(PATH_ROPGADGET + '\n')
		f.close()
	except:
		print("Error saving the last ROPGenerator configuration")
		
def load_config():
	global ARCH
	global PATH_ROPGADGET
	try:
		f = open(config_file, "r" )
		ARCH = f.readline()[:-1]
		PATH_ROPGADGET = f.readline()[:-1]
		f.close()
	except:
		if( os.path.isfile(config_file)):
			print("Couldn't load custom configuration, using the default one")
		default_config()
	Analysis.setArch(ARCH)
	
def default_config():
	global ARCH
	global PATH_ROPGADGET
	ARCH = "X86_64"
	PATH_ROPGADGET = "usr/bin/ROPgadget"
	Analysis.setArch(ARCH)
	

	
	
	
