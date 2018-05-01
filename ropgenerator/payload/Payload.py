# ROPGenerator - PAYLOAD module 
# Building PAYLOADs 
from ropgenerator.Colors import BOLD_COLOR_ANSI, END_COLOR_ANSI, string_bold
from ropgenerator.payload.Shellcode import show_shellcodes, save_shellcodes


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
    else:
        print("Error. Subcommand '{}' is not supported yet".format(args[0]))
    return 

def save_payloads():
    save_shellcodes()
