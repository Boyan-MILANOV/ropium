# -*- coding: utf-8 -*- 
# Main module: run ROPGenerator 


from prompt_toolkit import prompt
from prompt_toolkit.history import InMemoryHistory
from prompt_toolkit.contrib.completers import WordCompleter

from ropgenerator.IO import string_ropg, string_bold, banner 

import sys

ASCII_art = """
▒▒▒▒▒▒▒╗░▒▒▒▒▒▒╗░▒▒▒▒▒▒░░░▒░▒▒ ░ ▒░▒ ░▒░▒▓▒░▒▒▓░▒▓░▓▒░           
▒▒╔══▒▒║▒▒╔═══▒▒╗▒▒╔══▒╗
▒▒▒▒▒▒╔╝▒▒║   ▒▒║▒▒▒▒▒▒║ G  E  N  E  R  A  T  O  R 
▒▒╔══▒▒╗╚▒▒▒▒▒▒╔╝▒▒╔═══╝ 
╚═╝  ╚═╝ ╚═════╝ ╚═╝                    
▓▒░ ░░ ░ ░▒▒ ░░▒░▒░  ░▒▓░ ░░░ ▒ ▓░▒ ░ ▒░▒░▒░ ░ ▒▓▒░▒▓░
▒ ░     ░   ░░ ░░ ░░▒ ░ ▒░▒░ ░   ░▒▒    ░ ▒░   ░▒ ░ ▒░
   ░ ░░ ░ ░   ░      ░    ░   ░ ░ ░ ░    ░░   ░ ░ ░
         ░    ░   ░ ░   ░    ░  ░ ░        ░ ░     ░

"""


# Definitions of commands 
CMD_HELP = "help"
CMD_LOAD = "load"
CMD_CONFIG = "config"
CMD_EXIT = "exit"

CMD_SEARCH = "search-mode" 
CMD_EXPLOIT = "exploit-mode"


command_list = [CMD_HELP, CMD_LOAD, CMD_CONFIG, CMD_EXIT, CMD_SEARCH, CMD_EXPLOIT]
command_completer = WordCompleter(command_list)
command_history = InMemoryHistory()

helpStr = banner('ROPGenerator main commands')

def main():
    print(string_ropg(string_bold(ASCII_art)))
    
    finish = False
    while( not finish ):
        try:
            sys.stdout.write("("+ string_ropg('main') +")> ")
            user_input = prompt(u"", history=command_history)
            args = user_input.split()
            argslen = len(args)
            if( argslen > 0 ):
                command = args[0]
            else:
                command = None

            if( command == CMD_EXIT ):
                finish = True
            elif( command == CMD_HELP ):
                print(helpStr)
            
            if( command != None ):
                print('')
                
            
                
        except KeyboardInterrupt:
            pass
    exit(0)












