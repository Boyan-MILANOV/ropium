# ROPGenerator - Context module 
# Manage the context for exploit development
from ropgenerator.Colors import string_special, string_bold, notify, info_colored

# Context parameters
ASLR='ASLR'
NX='NX'
BAD_BYTES='BAD-BYTES'

# Default values 
values = dict()
values[ASLR]=True
values[NX]=True
values[BAD_BYTES]=[]

# Help for the context command
CMD_CONTEXT_HELP =  string_bold("\n\t-----------------------------------")
CMD_CONTEXT_HELP += string_bold("\n\tROPGenerator 'context' command\n\t")
CMD_CONTEXT_HELP += string_special("(Set a security context for your exploit)")
CMD_CONTEXT_HELP += string_bold("\n\t-----------------------------------")
CMD_CONTEXT_HELP += "\n\n\t"+string_bold("Usage")+":\tcontext show\n\t\tcontext <parameter>=<value> [<parameter>=<value> ...]"
CMD_CONTEXT_HELP += "\n\n\t"+string_bold("Parameters")+\
":\n\t\t"+string_bold('Name'+"\t\tValues")+\
"\n\t\t"+string_special(ASLR)+":\t\t'yes'/'no'"+\
"\n\t\t"+string_special(NX)+":\t\t'yes'/'no'"+\
"\n\t\t"+string_special(BAD_BYTES)+':\tlist of bad bytes'
CMD_CONTEXT_HELP += "\n\n\t"+string_bold("Examples")+":\n\t\tcontext ASLR=yes\n\t\tcontext ASLR=no NX=yes"


def print_help():
    print(CMD_CONTEXT_HELP)


def b2s(value):
    if( value):
        return 'yes'
    else:
        return 'no'

def s2b(string):
    if( string == 'yes' ):
        return True
    else:
        return False

def show_context():
    
    print(string_bold("\n\tROPGenerator's current context:\n"))
    print(string_bold("\t{}:\t\t".format(ASLR)) + b2s(values[ASLR]))
    print(string_bold("\t{}:\t\t".format(NX)) + b2s(values[NX]))
    print(string_bold("\t{}:\t\t".format(BAD_BYTES)) + \
        ','.join([string_special(b) for b in values[BAD_BYTES]]))
    print("")
    
def check_context():
    info_colored(string_bold('Checking exploit context\n'))
    notify('NX stack: ' + b2s(values[NX]))
    notify('ASLR: ' + b2s(values[NX]))
    notify('Forbidden bytes in exploit: ' +\
            ','.join([string_special(b) for b in values[BAD_BYTES]]))
    
    
def set_context(args):
    for arg in args:
        try:
            (left,right)=arg.split('=')
            if( not left or not right ):
                print("Error. Invalid parameter {}".format(arg))
                return 
        except:
            print("Error. Invalid parameter {}".format(arg))
            return
        if( left in [ASLR, NX] ):
            if( right not in ['yes', 'no']):
                print("Error. Invalid {} value: {}".format(left, right))
                return 
            values[left]= s2b(right)
        elif( left == BAD_BYTES ):
            print("Error. Bad bytes not supported yet for context. Comming soon ;) ".format(left, right))
            return
        else:
            print("Error. Unknown parameter: {}".format(left))
            return 

def context(args):
    if( args[0] == 'show' ):
        show_context()
    else:
        set_context(args)
