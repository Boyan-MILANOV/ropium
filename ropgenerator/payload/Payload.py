# ROPGenerator - PAYLOAD module 
# Building PAYLOADs 
from ropgenerator.Colors import BOLD_COLOR_ANSI, END_COLOR_ANSI, string_bold, info_colored, string_special, ROPGENERATOR_COLOR_ANSI
from ropgenerator.payload.Shellcode import show_shellcodes, save_shellcodes, add_shellcode
from prompt_toolkit import prompt
import ropgenerator.Analysis as Analysis
import sys
import string

CMD_PAYLOAD_HELP = BOLD_COLOR_ANSI
CMD_PAYLOAD_HELP +=    "\n\t-----------------------------------------------"
CMD_PAYLOAD_HELP += "\n\tROPGenerator 'payload' command\n\t(building payloads and exploits)"
CMD_PAYLOAD_HELP += "\n\t-----------------------------------------------"
CMD_PAYLOAD_HELP += END_COLOR_ANSI
CMD_PAYLOAD_HELP += "\n\n\t"+string_bold("Usage")+":\tpayload show <arch>"


def print_help():
    print(CMD_PAYLOAD_HELP)
    
def payload(args):
    # Parsing arguments
    if( args[0] == 'show' ):
        if( len(args) == 1 ):
            print("Error. Missing architecture after 'show'")
        else:
            show_shellcodes(args[1])
            
    elif( args[0] == 'add' ):
        add_payload()
    else:
        print("Error. Subcommand '{}' is not supported yet".format(args[0]))
    return 

def save_payloads():
    save_shellcodes()

def add_payload():
    print(string_bold('\n\t----------------------\n\tAdding a new payload\n\t----------------------\n'))
    
    arch_input = ''
    while( not arch_input in Analysis.supportedArchs ):
        sys.stdout.write('\t'+ROPGENERATOR_COLOR_ANSI+'> '+END_COLOR_ANSI+'Enter the target architecture ({}):\n\t'.format\
            (','.join([string_special(s) for s in Analysis.supportedArchs])))
        arch_input = prompt(u"")
    
    shellcode = ''
    ok = False
    while( not ok ):
        sys.stdout.write('\t'+ROPGENERATOR_COLOR_ANSI+'> '+END_COLOR_ANSI+'Enter your payload as a string in hex format:\n\t')
        shellcode_input = prompt(u"")
        try:
            shellcode = shellcode_input.replace('\\x','').decode('hex')
            ok = True
        except:
            ok = False
        if( not ok ):
            print(string_special("\tError. Your payload input is in wrong format or invalid"))

    sys.stdout.write('\t'+ROPGENERATOR_COLOR_ANSI+'> '+END_COLOR_ANSI+'Enter short payload description:\n\t')
    info = prompt(u"")
    info =  filter( lambda x: x in set(string.printable), info)
    add_shellcode(arch_input, shellcode, info)
    
    
