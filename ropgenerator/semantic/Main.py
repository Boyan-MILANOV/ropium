# -*- coding: utf-8 -*- 
# Main module:  semantic-mode 

from prompt_toolkit import prompt
from prompt_toolkit.history import InMemoryHistory
from prompt_toolkit.contrib.completers import WordCompleter

from ropgenerator.IO import string_ropg, string_bold, string_special, banner

import sys

# Definitions of commands 
CMD_HELP = "help"
CMD_ASSERT = "assert"
CMD_FIND = "find"
CMD_MAIN = "main"
CMD_EXIT = "exit"


command_list = [CMD_HELP, CMD_FIND, CMD_EXIT]
command_completer = WordCompleter(command_list)
command_history = InMemoryHistory()

helpStr = banner([string_bold('Semantic-Mode Commands'),
    string_special('(For more info about a command type <cmd -h>)')])
helpStr += '\n\t' + string_bold(CMD_FIND) + ': \t\tfind gadgets/ropchains'
helpStr += '\n\n\t' + string_bold(CMD_HELP) + ': \t\tshow this help'
helpStr += '\n\t' + string_bold(CMD_MAIN) + ': \t\treturn to the main menu'
helpStr += '\n\t' + string_bold(CMD_EXIT) + ': \t\texit ROPGenerator'

def semantic_mode():
    """
    Returns
    -------
    True if ROPGenerator must continue
    False if ROPGenerator must be closed 
    """
    
    finish = False
    while( not finish ):
        try:
            sys.stdout.write("("+ string_ropg('semantic') +")> ")
            user_input = prompt(u"", history=command_history)
            args = user_input.split()
            argslen = len(args)
            if( argslen > 0 ):
                command = args[0]
            else:
                command = None

            if( command == CMD_FIND ):
                pass
            elif( command == CMD_EXIT ):
                return False
            elif( command == CMD_HELP ):
                print(helpStr)
            elif( command == CMD_MAIN ):
                finish = True
            if( command != None ):
                print('')
        except KeyboardInterrupt:
            pass
    return True












