import sys


ROPGENERATOR_COLOR_ANSI = '\033[92m'    # Default color 
ERROR_COLOR_ANSI = '\033[91m' 
BOLD_COLOR_ANSI = '\033[1m'
SPECIAL_COLOR_ANSI = '\033[93m'
PAYLOAD_COLOR_ANSI = '\033[96m'
EXPLOIT_COLOR_ANSI = '\033[95m'
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
    
def string_payload(text):
    """
    Returns a string with special color for payload
    """
    return ROPGENERATOR_COLOR_ANSI+text+END_COLOR_ANSI

def string_ropg(text):
    return ROPGENERATOR_COLOR_ANSI+text+END_COLOR_ANSI

def string_exploit(text):
    return EXPLOIT_COLOR_ANSI + text + END_COLOR_ANSI

def notify(text):
    """
    prints a string with a tab and special colored char in front 
    """  
    sys.stdout.write('\t'+ROPGENERATOR_COLOR_ANSI + '% ' + END_COLOR_ANSI + text+'\n')
    
# Custom charging bar :) 
last_percent = -1 
def charging_bar( nb_iter, curr_iter, bar_len, msg="", char=u"\u2588"):
    """
    Print a charging bar 
    """
    global last_percent
    percent = (100*curr_iter)/nb_iter
    if( curr_iter == nb_iter ):
        sys.stdout.write('\r'+' '*(bar_len+len(msg)+30)+'\r')
        last_percent = -1
    elif( last_percent != percent):
        last_percent = percent
        bar = '\r\t'+ROPGENERATOR_COLOR_ANSI + '% ' + END_COLOR_ANSI
        bar += str(msg)
        bar += ' |'
        full_part = char * (curr_iter/(nb_iter/bar_len))
        empty_part = " "*(bar_len-len(full_part))
        bar += full_part + empty_part + '| '
        bar += '{:03d}%'.format(100*curr_iter/nb_iter)
        sys.stdout.write(bar)
    sys.stdout.flush()
