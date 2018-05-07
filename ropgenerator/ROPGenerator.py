# ROPGenerator - ROPGenerator module
# Central module to run, prompts for commands and execute them ;) 
from ropgenerator.Database import pretty_print_registers
from ropgenerator.Colors import string_special, string_bold, write_colored, error_colored, info_colored, BOLD_COLOR_ANSI, END_COLOR_ANSI
import ropgenerator.Analysis as Analysis
import ropgenerator.SearchEngine as SearchEngine
import ropgenerator.Load as Load
import ropgenerator.Config as Config
import ropgenerator.payload.Payload as Payload 
import ropgenerator.Context as Context
import ropgenerator.exploit.Exploit as Exploit
import ropgenerator.Logs as Logs

from prompt_toolkit import prompt
from prompt_toolkit.history import InMemoryHistory
from prompt_toolkit.contrib.completers import WordCompleter
import sys
import cProfile, pstats

ASCII_art = string_bold("""
   ___  ____  ___  _____                     __          
  / _ \/ __ \/ _ \/ ______ ___ ___ _______ _/ /____  ________
 / , _/ /_/ / ___/ (_ / -_/ _ / -_/ __/ _ `/ __/ _ \/ ______/
/_/|_|\____/_/   \___/\__/_//_\__/_/  \_,_/\__/\___/_/ v0.5 
    
 
""")


# Definitions of commands 
CMD_HELP = "help"
CMD_LOAD = "load"
CMD_REGISTERS = "registers"
CMD_FIND = "find" 
CMD_PAYLOAD = "payload"
CMD_CONTEXT = "context"
CMD_CONFIG = "config"
CMD_EXPLOIT = "exploit"
CMD_EXIT = "exit"

command_list = [CMD_HELP, CMD_LOAD, CMD_REGISTERS, CMD_FIND, CMD_CONFIG, CMD_EXIT]
command_completer = WordCompleter(command_list)
command_history = InMemoryHistory()

def main(time_mesure=False):
    
    if( time_mesure ):
        pr = cProfile.Profile()
        pr.enable()
        
    #try:
    # Launching ROPGenerator 
    write_colored(ASCII_art)
    Config.load_config()
    Logs.init()
    quit = False
    while( not quit ):
        try:
            write_colored(">>> ")
            user_input = prompt(u"", history=command_history)
            args = user_input.split()
            argslen = len(args)
            if( argslen > 0 ):
                command = args[0]
            else:
                command = None

            if( command == None):
                pass
            elif( command == CMD_HELP ):
                print(string_bold("\n\t-----------------------------------------------------------\n\tROPGenerator commands"))
                print(string_special("\t(For more information about a command type '<command> help')"))
                print(string_bold("\t-----------------------------------------------------------\n"))
                print('\t' + string_bold(CMD_LOAD) + ': \t\tload usable gadgets from a binary file')
                print('\t' + string_bold(CMD_FIND) + ': \t\tsemantic search for gadgets/ropchains')
                print('\t' + string_bold(CMD_PAYLOAD) + ': \tmanage payloads to use in your exploit')
                print('\t' + string_bold(CMD_EXPLOIT) + ':\tbuild an exploit')
                print('\t' + string_bold(CMD_REGISTERS) + ': \tprint available registers for the current architecture')
                print('\t' + string_bold(CMD_CONFIG) + ': \tconfigure ROPGenerator')
                print('\t' + string_bold(CMD_HELP) + ': \t\tprint available commands')
                print('\t' + string_bold(CMD_EXIT) + ': \t\texit ROPGenerator')
            elif( command == CMD_FIND ):
                if( argslen > 1 ):
                    if( args[1] == CMD_HELP ):
                        SearchEngine.print_help()
                    else:
                        SearchEngine.set_user_input(user_input[len(CMD_FIND):])
                        SearchEngine.find_gadgets(args[1:])
                else:
                    SearchEngine.print_help()
                    #print("Missing arguments. Type 'find help' for help")
            elif( command == CMD_EXPLOIT ):
                if( argslen > 1 ):
                    if( args[1] == CMD_HELP ):
                        Exploit.print_help()
                    else:
                        Exploit.exploit(args[1:])
                else:
                    Exploit.print_help()
            
            elif( command == CMD_PAYLOAD ):
                if( argslen > 1 ):
                    if( args[1] == CMD_HELP):
                        Payload.print_help()
                    else:
                        Payload.payload(args[1:])
                else:
                    Payload.print_help()
                    #print("Missing arguments. Type 'payload help' for help")
            elif( command == CMD_LOAD ):
                if( argslen > 1 ):
                    if( args[1] == CMD_HELP):
                        Load.print_help()
                    else:
                        Load.load(args[1:])
                else:
                    Load.print_help()
                    #print("Missing arguments. Type 'load help' for help")
        
            elif( command == CMD_REGISTERS ):
                pretty_print_registers()
            elif( command == CMD_CONFIG):
                if( argslen > 1 ):
                    if( args[1] == CMD_HELP ):
                        Config.print_help()
                    else:
                        Config.update_config(args[1:])
                else:
                    Config.print_help()
                    #print("Missing arguments. Type 'config help' for help")
            elif( command == CMD_CONTEXT ):    
                if( argslen > 1 ):
                    if( args[1] == CMD_HELP ):
                        Context.print_help()
                    else:
                        Context.context(args[1:])
                else:
                    Context.print_help()
                     
            elif( command == CMD_EXIT ):
                quit = True
                Config.save_config()
                Payload.save_payloads()
            else:
                print(string_bold("\n\tUnknown command '" + command+\
                    "'. Type 'help' for available commands"))
            # New line
            if( command != None):
                print("")
        except KeyboardInterrupt:
            pass
            
    info_colored(string_bold("Closing ROPGenerator...\n"))
    
    #except KeyboardInterrupt:
    #    pass
    #except Exception as e:
    #    print("")
    #    error_colored("ROPGenerator failed unexpectedly\n")
    #    print(e)
        
    if( time_mesure ):
        pr.disable()
        s = pstats.Stats(pr).sort_stats('tottime')
        s.print_stats(0.02)
        
    exit(0)
    
# Run it !
main()
        
        
