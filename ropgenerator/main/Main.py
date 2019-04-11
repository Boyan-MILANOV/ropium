#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
from ropgenerator.core.IO import *
from ropgenerator.main.Load import load, loaded_binary
from ropgenerator.core.Database import *
from ropgenerator.core.Gadget import *
from ropgenerator.semantic.Main import semantic_mode
from ropgenerator.exploit.Main import exploit_mode
from prompt_toolkit import PromptSession, ANSI
from ropgenerator.core.Log import *


ASCII_art = """
▒▒▒▒▒▒▒╗░▒▒▒▒▒▒╗░▒▒▒▒▒▒  ═════════════════════════       
▒▒╔══▒▒║▒▒╔═══▒▒╗▒▒╔══▒╗
▒▒▒▒▒▒╔╝▒▒║   ▒▒║▒▒▒▒▒▒║ G  E  N  E  R  A  T  O  R
▒▒╔══▒▒╗╚▒▒▒▒▒▒╔╝▒▒╔═══╝ 
╚═╝  ╚═╝ ╚═════╝ ╚═╝     ════════════════════ v2.0          

"""

ROPGenerator_dir = os.path.expanduser('~')+"/.ROPGenerator/"
log_file = ".ROPGenerator.log"

# Definitions of commands 
CMD_HELP = "help"
CMD_LOAD = "load"
CMD_EXIT = "exit"
CMD_SEARCH = "semantic" 
CMD_EXPLOIT = "exploit"


helpStr = banner([str_bold('Main Commands'),
    str_special('(For more info about a command type <cmd -h>)')])
helpStr += '\n\t' + str_bold(CMD_LOAD) + ': \t\tload gadgets from a binary file'
helpStr += '\n\n\t' + str_semantic(str_bold(CMD_SEARCH)) + \
    ': \tEnter semantic-mode (Search for'+'\n\t\t\tgadgets and ROPChains)'
helpStr += '\n\n\t' + str_exploit(str_bold(CMD_EXPLOIT)) + \
    ': \tEnter exploit-mode (Automated exploit'+'\n\t\t\tgeneration features)'
helpStr += '\n\n\t' + str_bold(CMD_HELP) + ': \t\tprint available commands'
helpStr += '\n\t' + str_bold(CMD_EXIT) + ': \t\texit ROPGenerator'


def main():
    #print(str_ropg(str_bold(ASCII_art)))
    init_logs(ROPGenerator_dir+log_file)
    finish = False
    promptSession = PromptSession(ANSI(u"("+ str_ropg(u'main') +u")> "))
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

            if( command == CMD_LOAD ):
                load(args[1:])
            elif( command == CMD_EXIT ):
                finish = True
            elif( command == CMD_HELP ):
                print(helpStr)
            elif( command == CMD_SEARCH ):
                if( loaded_binary() ):
                    print('')
                    finish = not semantic_mode()
                else:
                    error("You have to load a binary before entering semantic mode")
            elif( command == CMD_EXPLOIT ):
                print('')
                finish = not exploit_mode()
            elif( command == "test" ):
                print_gadget(gadget_db_get(int(args[1])))
            else:
                error("Unknown command '{}'".format(command))
            if( command != None and command != CMD_SEARCH and command != CMD_EXPLOIT):
                print('')
        except KeyboardInterrupt:
            pass
    close_logs()
    #save_shellcodes()
    return 


