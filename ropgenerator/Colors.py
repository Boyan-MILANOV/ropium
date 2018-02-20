import sys


ROPGENERATOR_COLOR_ANSI = '\033[92m'    # Default color 
ERROR_COLOR_ANSI = '\033[91m' 
END_COLOR_ANSI = '\033[0m'

def write_colored(text):
    """
    Prints a text with the ropgenerator custom color
    """
    sys.stdout.write(ROPGENERATOR_COLOR_ANSI + text + END_COLOR_ANSI)
    
def info_colored(text):
    """
    Prints a text with a colored '[+] ' before 
    """
    sys.stdout.write(ROPGENERATOR_COLOR_ANSI + '[+] ' + END_COLOR_ANSI + text)
    
def error_colored(text):
    """
    Prints a text with the error color
    """
    sys.stdout.write(ERROR_COLOR_ANSI + '[!] ' + text + END_COLOR_ANSI)
    
