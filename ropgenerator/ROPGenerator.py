# ROPGenerator - ROPGenerator module
# Central module to run, prompts for commands and execute them ;) 
import Database
import Analysis
import Gadget_finder
import Load
import Config 

from prompt_toolkit import prompt
from prompt_toolkit.history import InMemoryHistory
from prompt_toolkit.contrib.completers import WordCompleter



ASCII_art = """
   ___  ____  ___  _____                     __          
  / _ \/ __ \/ _ \/ ______ ___ ___ _______ _/ /____  ________
 / , _/ /_/ / ___/ (_ / -_/ _ / -_/ __/ _ `/ __/ _ \/ ______/
/_/|_|\____/_/   \___/\__/_//_\__/_/  \_,_/\__/\___/_/ v0.2 
	
 
""" 


# Definitions of commands 
CMD_HELP = "help"
CMD_LOAD = "load"
CMD_REGISTERS = "registers"
CMD_FIND = "find" 
CMD_CONFIG = "config"
CMD_EXIT = "exit"

command_list = [CMD_HELP, CMD_LOAD, CMD_REGISTERS, CMD_FIND, CMD_CONFIG, CMD_EXIT]
command_completer = WordCompleter(command_list)
command_history = InMemoryHistory()


def main():
	# Launching ROPGenerator 
	print(ASCII_art)
	Config.load_config()
	quit = False
	while( not quit ):
		user_input = prompt(u">>> ", history=command_history)
		args = user_input.split()
		argslen = len(args)
		if( argslen > 0 ):
			command = args[0]
		else:
			command = None
	
		if( command == None):
			pass
		elif( command == CMD_HELP ):
			print("\n\t-----------------------------------------------------------")
			print("\tROPGenerator commands")
			print("\t(For more information about a command type '<command> help')")
			print("\t-----------------------------------------------------------\n")
			print('\t\t' + CMD_HELP + ': \t\tprint available commands')
			print('\t\t' + CMD_LOAD + ': \t\tload usable gadgets from a binary file')
			print('\t\t' + CMD_FIND + ': \t\tfind gadgets that execute specific operations')
			print('\t\t' + CMD_REGISTERS + ': \tprint available registers for the current architecture')
			print('\t\t' + CMD_CONFIG + ': \tconfigure ROPGenerator')
			print('\t\t' + CMD_EXIT + ': \t\texit ROPGenerator')
		elif( command == CMD_FIND ):
			if( argslen > 1 ):
				if( args[1] == CMD_HELP ):
					Gadget_finder.print_help()
				else:
					Gadget_finder.find_gadgets(args[1:])
			else:
				print("Missing arguments. Type 'find help' for help")
		elif( command == CMD_LOAD ):
			# Thi should be in a Load.py module 
			if( argslen > 1 ):
				if( args[1] == CMD_HELP):
					Load.print_help()
				else:
					Load.load(args[1:])
			else:
				print("Missing arguments. Type 'load help' for help")
	
		elif( command == CMD_REGISTERS ):
			Database.pretty_print_registers()
		elif( command == CMD_CONFIG):
			if( argslen > 1 ):
				if( args[1] == CMD_HELP ):
					Config.print_help()
				else:
					Config.update_config(args[1:])
			else:
				print("Missing arguments. Type 'config help' for help")
			
		elif( command == CMD_EXIT ):
			quit = True
			Config.save_config()
		else:
			print("Unknown command '" + command+"'. Type 'help' for available commands")
		# New line
		if( command != None):
			print("")
	exit()

# Run it !	
main()
		
		
