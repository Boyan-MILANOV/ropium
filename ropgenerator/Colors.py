import sys


ROPGENERATOR_COLOR_ANSI = '\033[92m'    # Default color 
ERROR_COLOR_ANSI = '\033[91m' 
BOLD_COLOR_ANSI = '\033[1m'
SPECIAL_COLOR_ANSI = '\033[93m'
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
    
def string_bold(text):
    """
    Returns a string in bold
    """
    return BOLD_COLOR_ANSI+text+END_COLOR_ANSI

def string_special(text):
    """
    Returns a string with special color 
    """
    return SPECIAL_COLOR_ANSI+text+END_COLOR_ANSI
