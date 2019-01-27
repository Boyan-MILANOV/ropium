#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from ropgenerator.core.IO import *
from ropgenerator.main.Load import load 
from ropgenerator.core.Database import *
from ropgenerator.core.Gadget import *
from ropgenerator.semantic.Main import semantic_mode
from prompt_toolkit import PromptSession, ANSI


ASCII_art = """
▒▒▒▒▒▒▒╗░▒▒▒▒▒▒╗░▒▒▒▒▒▒  ═════════════════════════       
▒▒╔══▒▒║▒▒╔═══▒▒╗▒▒╔══▒╗
▒▒▒▒▒▒╔╝▒▒║   ▒▒║▒▒▒▒▒▒║ G  E  N  E  R  A  T  O  R
▒▒╔══▒▒╗╚▒▒▒▒▒▒╔╝▒▒╔═══╝ 
╚═╝  ╚═╝ ╚═════╝ ╚═╝     ════════════════════ v2.0          

"""

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
    #initLogs()
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
                finish = not semantic_mode()
            elif( command == CMD_EXPLOIT ):
                #if( not exploit_mode()):
                #    finish = True
                print(str_special("Work in progess... ;)"))
            elif( command == "test" ):
                print_gadget(gadget_db_get(int(args[1])))
            else:
                error("Unknown command '{}'".format(command))
            if( command != None ):
                print('')
        except KeyboardInterrupt:
            pass
    #closeLogs()
    #save_shellcodes()
    # DEBUG exit(0)
    return 


