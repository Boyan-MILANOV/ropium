# ROPGenerator - PAYLOAD module 
# Building PAYLOADs 
from ropgenerator.Colors import BOLD_COLOR_ANSI, END_COLOR_ANSI, string_bold, info_colored, string_special, ROPGENERATOR_COLOR_ANSI, notify
from ropgenerator.payload.Shellcode import remove_shellcode, show_shellcodes, save_shellcodes, add_shellcode, select_shellcode, show_selected
from prompt_toolkit import prompt
import ropgenerator.Analysis as Analysis
import sys
import string
import ropgenerator.Database as Database

CMD_PAYLOAD_HELP =  string_bold("\n\t------------------------------------")
CMD_PAYLOAD_HELP += string_bold("\n\tROPGenerator 'payload' command\n\t")
CMD_PAYLOAD_HELP += string_special("(Manage payloads for your exploit)")
CMD_PAYLOAD_HELP += string_bold("\n\t------------------------------------")
CMD_PAYLOAD_HELP += "\n\n\t"+string_bold("Usage")+\
":\tpayload current \t(" + string_special('show currently selected payload') + ")" +\
"\n\t\tpayload list [<arch>]\t(" + string_special('list available payloads') + ")" +\
"\n\t\tpayload select \t\t(" + string_special('select a payload for your exploit') + ")" +\
"\n\t\tpayload add\t\t("+ string_special('add a payload to your exploit') + ")"+\
"\n\t\tpayload remove\t\t("+string_special('remove a previously added payload') + ")"
CMD_PAYLOAD_HELP += "\n\n\t"+string_bold("Supported architectures")+": "+','.join([string_special(arch) for arch in Analysis.supportedArchs])

def print_help():
    print(CMD_PAYLOAD_HELP)
    
def payload(args):
    # Parsing arguments
    if( args[0] == 'current' ):
        show_selected()
    elif( args[0] == 'list' ):
        list_payloads(args[1:])
    elif( args[0] == 'add' ):
        add_payload()
    elif( args[0] == 'select'):
        select_payload()
    elif( args[0] == 'remove' ):
        remove_payload()
    else:
        print(string_bold("\n\tError. Unknown sub-command '{}'".format(args[0])))
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

def list_payloads(args):
    if( not args ):
        for arch in Analysis.supportedArchs:
            show_shellcodes(arch)
        return
    else:
        show_shellcodes(args[0])

def select_payload():
    
    if( Database.gadgetDB ):
        arch_input = Analysis.ArchInfo.currentArch
        print("")
        notify('Detected architecture from loaded binary: ' + string_special(arch_input))
    else:
        print(string_bold('\n\tOops! You should load a binary before selecting a payload'))
        return 
    
    show_shellcodes(arch_input)
    print("")
    
    choice = ''
    ok = False
    while( not ok ):
        sys.stdout.write('\t'+ROPGENERATOR_COLOR_ANSI+'> '+END_COLOR_ANSI+'Select a payload number:\n\t')
        choice_input = prompt(u"")
        try:
            choice = int(choice_input)
            ok = select_shellcode(arch_input, choice)
        except:
            ok = False
        if( not ok ):
            print(string_special("\tError. Invalid payload number\n"))
    show_selected()
    
def remove_payload():
    print(string_bold('\n\t--------------------\n\tRemoving a payload\n\t--------------------\n'))
    
    arch_input = ''
    while( not arch_input in Analysis.supportedArchs ):
        sys.stdout.write('\t'+ROPGENERATOR_COLOR_ANSI+'> '+END_COLOR_ANSI+'Enter the payload architecture ({}):\n\t'.format\
            (','.join([string_special(s) for s in Analysis.supportedArchs])))
        arch_input = prompt(u"")
    
    show_shellcodes(arch_input)
    print("")
    
    choice = ''
    ok = False
    while( not ok ):
        sys.stdout.write('\t'+ROPGENERATOR_COLOR_ANSI+'> '+END_COLOR_ANSI+'Select a payload to remove:\n\t')
        choice_input = prompt(u"")
        try:
            choice = int(choice_input)
            ok = remove_shellcode(arch_input, choice)
        except:
            ok = False

    print("")
    notify('Payload removed')
