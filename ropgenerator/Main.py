# -*- coding: utf-8 -*- 
# Main module: run ROPGenerator 


from prompt_toolkit import PromptSession, ANSI

from ropgenerator.IO import string_ropg, string_bold, string_special, banner, error\
    , string_exploit, string_semantic
from ropgenerator.Load import load
from ropgenerator.Logs import initLogs, closeLogs
from ropgenerator.semantic.Main import semantic_mode
from ropgenerator.exploit.Main import exploit_mode
from ropgenerator.exploit.Shellcode import save_shellcodes
import ropgenerator.Database as Database

import sys

ASCII_art = """
▒▒▒▒▒▒▒╗░▒▒▒▒▒▒╗░▒▒▒▒▒▒  ═════════════════════════       
▒▒╔══▒▒║▒▒╔═══▒▒╗▒▒╔══▒╗
▒▒▒▒▒▒╔╝▒▒║   ▒▒║▒▒▒▒▒▒║ G  E  N  E  R  A  T  O  R
▒▒╔══▒▒╗╚▒▒▒▒▒▒╔╝▒▒╔═══╝ 
╚═╝  ╚═╝ ╚═════╝ ╚═╝     ════════════════════ v1.1          
  

"""


# Definitions of commands 
CMD_HELP = "help"
CMD_LOAD = "load"
CMD_CONFIG = "config"
CMD_EXIT = "exit"

CMD_SEARCH = "semantic" 
CMD_EXPLOIT = "exploit"


helpStr = banner([string_bold('Main Commands'),
    string_special('(For more info about a command type <cmd -h>)')])
helpStr += '\n\t' + string_bold(CMD_LOAD) + ': \t\tload gadgets from a binary file'
helpStr += '\n\n\t' + string_semantic(string_bold(CMD_SEARCH)) + \
    ': \tEnter semantic-mode (Search for'+'\n\t\t\tgadgets and ROPChains)'
helpStr += '\n\n\t' + string_exploit(string_bold(CMD_EXPLOIT)) + \
    ': \tEnter exploit-mode (Automated exploit'+'\n\t\t\tgeneration features)'
helpStr += '\n\n\t' + string_bold(CMD_HELP) + ': \t\tprint available commands'
helpStr += '\n\t' + string_bold(CMD_EXIT) + ': \t\texit ROPGenerator'

def main():
    print(string_ropg(string_bold(ASCII_art)))
    initLogs()
    finish = False
    promptSession = PromptSession(ANSI(u"("+ string_ropg(u'main') +u")> "))
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
                if( not Database.gadgets ):
                    error("You have to load gadgets before entering semantic-mode")
                elif( not semantic_mode()):
                    finish = True
            elif( command == CMD_EXPLOIT ):
                if( not exploit_mode()):
                    finish = True
            else:
                error("Unknown command '{}'".format(command))
            if( command != None ):
                print('')
                
        except KeyboardInterrupt:
            pass
    closeLogs()
    save_shellcodes()
    exit(0)












