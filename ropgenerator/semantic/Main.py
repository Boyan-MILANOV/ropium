# -*- coding: utf-8 -*- 
# Main module:  semantic-mode 

from prompt_toolkit import PromptSession, ANSI

from ropgenerator.core.IO import *
from ropgenerator.semantic.Find import find
from ropgenerator.core.Architecture import *
from ropgenerator.main.Load import loaded_binary

import sys

# Definitions of commands 
CMD_HELP = "help"
CMD_ASSERT = "assert"
CMD_FIND = "find"
CMD_MAIN = "main"
CMD_REGS = "registers"
CMD_EXIT = "exit"


helpStr = banner([str_bold('Semantic-Mode Commands'),
    str_special('(For more info about a command type <cmd -h>)')])
helpStr += '\n\t' + str_bold(CMD_FIND) + ': \t\tfind gadgets/ropchains'
helpStr += '\n\t' + str_bold(CMD_REGS) + ': \tshow available registers'
helpStr += '\n\n\t' + str_bold(CMD_HELP) + ': \t\tshow this help'
helpStr += '\n\t' + str_bold(CMD_MAIN) + ': \t\treturn to the main menu'
helpStr += '\n\t' + str_bold(CMD_EXIT) + ': \t\texit ROPGenerator'

promptSession = PromptSession(ANSI(u"("+ str_semantic(u'semantic') +u")> "))

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
            user_input = promptSession.prompt()
            args = user_input.split()
            argslen = len(args)
            if( argslen > 0 ):
                command = args[0]
            else:
                command = None
                continue

            if( command == CMD_FIND ):
                find(args[1:])
            elif( command == CMD_EXIT ):
                return False
            elif( command == CMD_HELP ):
                print(helpStr)
            elif( command == CMD_MAIN ):
                finish = True
            elif( command == CMD_REGS ):
                registers_cmd()
            else:
                error("Unknown command '{}'".format(command))
            if( command != None ):
                print('')
        except KeyboardInterrupt:
            pass
    return True


def registers_cmd():
    """
    print available regs in current architecture
    """
    if( not loaded_binary()):
        error("You must load a binary before listing available registers")
        return 
    print(banner([str_bold("Available registers")]))
    for name,num in get_curr_reg_map().items():
        if( num == curr_arch_ip() ):
            print("\t"+str_special(name)+" - instruction pointer")
        elif( num == curr_arch_sp() ):
            print("\t"+str_special(name)+" - stack pointer")
        elif( is_ignored_reg(num) ):
            print("\t"+str_special(name)+" - (ignored)")
        else:
            print("\t"+str_special(name))
