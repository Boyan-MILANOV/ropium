# -*- coding: utf-8 -*- 
# Main module: run ROPGenerator 


from prompt_toolkit import prompt
from prompt_toolkit.history import InMemoryHistory
from prompt_toolkit.contrib.completers import WordCompleter

from ropgenerator.IO import string_ropg, string_bold, string_special, banner 
from ropgenerator.Load import load
from ropgenerator.Logs import init

import sys

ASCII_art = """
▒▒▒▒▒▒▒╗░▒▒▒▒▒▒╗░▒▒▒▒▒▒  ░░░░░░░░░░░░░░░░░░░░░░░░░       
▒▒╔══▒▒║▒▒╔═══▒▒╗▒▒╔══▒╗
▒▒▒▒▒▒╔╝▒▒║   ▒▒║▒▒▒▒▒▒║ G  E  N  E  R  A  T  O  R 
▒▒╔══▒▒╗╚▒▒▒▒▒▒╔╝▒▒╔═══╝ 
╠═╝  ╚═╝ ╚═════╝ ╚═╝  ╔═════╗    ╔═══╗  ╔══╗ ╔═╗╔╗                
║░░░░░░░░░░░░░░░░░░░░░║░░░░░░░░░░║░░░░░░║░░░░║░░║░
╚═════════════════════╝     ╚════╝   ╚══╝  ╚═╝ ╚╝

"""


# Definitions of commands 
CMD_HELP = "help"
CMD_LOAD = "load"
CMD_CONFIG = "config"
CMD_EXIT = "exit"

CMD_SEARCH = "semantic-mode" 
CMD_EXPLOIT = "exploit-mode"


command_list = [CMD_HELP, CMD_LOAD, CMD_CONFIG, CMD_EXIT, CMD_SEARCH, CMD_EXPLOIT]
command_completer = WordCompleter(command_list)
command_history = InMemoryHistory()

helpStr = banner([string_bold('Main Commands'),
    string_special('(For more info about a command type <cmd -h>)')])
helpStr += '\n\t' + string_bold(CMD_LOAD) + ': \t\tload gadgets from a binary file'
helpStr += '\n\n\t' + string_bold(CMD_SEARCH) + ': \tsemantic search for Gadgets/ROPChains'
helpStr += '\n\t' + string_bold(CMD_EXPLOIT) + ': \tautomated exploit generation'
helpStr += '\n\n\t' + string_bold(CMD_CONFIG) + ': \tconfigure ROPGenerator'
helpStr += '\n\t' + string_bold(CMD_HELP) + ': \t\tprint available commands'
helpStr += '\n\t' + string_bold(CMD_EXIT) + ': \t\texit ROPGenerator'

def main():
    print(string_ropg(string_bold(ASCII_art)))
    init()
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

            if( command == CMD_LOAD ):
                load(args[1:])
            if( command == CMD_EXIT ):
                finish = True
            elif( command == CMD_HELP ):
                print(helpStr)
            
            if( command != None ):
                print('')
                
            
                
        except KeyboardInterrupt:
            pass
    exit(0)












