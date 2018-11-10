# -*- coding:utf-8 -*- 

import re
import sys


DEFAULT_ROPGENERATOR_COLOR_ANSI = '\033[92m'    # Default color 
DEFAULT_SEMANTIC_MODE_ANSI = '\033[96m'
DEFAULT_EXPLOIT_MODE_ANSI = '\033[91m'
DEFAULT_ERROR_COLOR_ANSI = '\033[91m' 
DEFAULT_BOLD_COLOR_ANSI = '\033[1m'
DEFAULT_SPECIAL_COLOR_ANSI = '\033[93m'
DEFAULT_PAYLOAD_COLOR_ANSI = '\033[96m'
DEFAULT_EXPLOIT_DESCRIPTION_ANSI = '\033[95m'
DEFAULT_END_COLOR_ANSI = '\033[0m'

ROPGENERATOR_COLOR_ANSI = DEFAULT_ROPGENERATOR_COLOR_ANSI
SEMANTIC_MODE_ANSI = DEFAULT_SEMANTIC_MODE_ANSI
EXPLOIT_MODE_ANSI = DEFAULT_EXPLOIT_MODE_ANSI
ERROR_COLOR_ANSI = DEFAULT_ERROR_COLOR_ANSI
BOLD_COLOR_ANSI = DEFAULT_BOLD_COLOR_ANSI
SPECIAL_COLOR_ANSI = DEFAULT_SPECIAL_COLOR_ANSI
PAYLOAD_COLOR_ANSI = DEFAULT_PAYLOAD_COLOR_ANSI
EXPLOIT_DESCRIPTION_ANSI = DEFAULT_EXPLOIT_DESCRIPTION_ANSI
END_COLOR_ANSI = DEFAULT_END_COLOR_ANSI
    
    
# Info and errors 
    
def notify(text):
    """
    prints a string with a tab and special colored char in front 
    """  
    sys.stdout.write('\t'+ROPGENERATOR_COLOR_ANSI + '% ' + END_COLOR_ANSI + text+'\n')    

def info(text):
    """
    Prints a text with a colored '[+] ' before 
    """
    sys.stdout.write('['+ROPGENERATOR_COLOR_ANSI+'+'+ END_COLOR_ANSI+ '] ' + text)
    
def error(text):
    """
    Prints a text with the error color
    """
    print(string_bold('\n\t'+text))
    
def fatal(text):
    sys.stdout.write(ERROR_COLOR_ANSI + '[!] ' + text + END_COLOR_ANSI)
    
VERBOSE = False   # For verbose info support 
def verbose_mode(mode):
    """
    mode = True or False
    """
    global VERBOSE
    VERBOSE = mode
 
def verbose(msg):
    if( VERBOSE ):
        print(string_ropg('\t\t> ')+msg)
        
        
def banner(msgList):
    c = '_'
    ansi_escape = re.compile(r'\x1B\[[0-?]*[-/]*[@-~]')
    chars = [u'\u2591', u'\u2592', u'\u2593']
    width = max([len(ansi_escape.sub('',m)) for m in msgList])
    res = string_bold('\n\t'+ c*width)+'\n\n\t'+\
        '\n\t'.join(msgList)+'\n\t'+ string_bold(c*width+'\n')
    return res 
    
# Coloring strings 

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
    return EXPLOIT_MODE_ANSI + text+END_COLOR_ANSI

def string_semantic(text):
    return SEMANTIC_MODE_ANSI+text+END_COLOR_ANSI
    
# Custom charging bar :) 
last_percent = -1 
def charging_bar( nb_iter, curr_iter, bar_len=30, msg="", char=u"\u2588"):
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
        div = (nb_iter/bar_len)
        if( div == 0 ):
            div = 1
        full_part = char * (curr_iter/div)
        empty_part = " "*(bar_len-len(full_part))
        bar += full_part + empty_part + '| '
        if( nb_iter == 0 ):
            nb_iter = 1
            
        bar += '{:03d}%'.format(100*curr_iter/nb_iter)
        sys.stdout.write(bar)
    sys.stdout.flush()


# Enable / Disable ANSI output colors 

def disable_colors():
    global ROPGENERATOR_COLOR_ANSI, SEMANTIC_MODE_ANSI, EXPLOIT_MODE_ANSI, ERROR_COLOR_ANSI,BOLD_COLOR_ANSI,\
        SPECIAL_COLOR_ANSI,PAYLOAD_COLOR_ANSI,EXPLOIT_DESCRIPTION_ANSI,END_COLOR_ANSI
    
    ROPGENERATOR_COLOR_ANSI = ''
    SEMANTIC_MODE_ANSI = ''
    EXPLOIT_MODE_ANSI = ''
    ERROR_COLOR_ANSI = ''
    BOLD_COLOR_ANSI = ''
    SPECIAL_COLOR_ANSI = ''
    PAYLOAD_COLOR_ANSI = ''
    EXPLOIT_DESCRIPTION_ANSI = ''
    END_COLOR_ANSI = '' 
        
def enable_colors():
    global ROPGENERATOR_COLOR_ANSI, SEMANTIC_MODE_ANSI, EXPLOIT_MODE_ANSI, ERROR_COLOR_ANSI,BOLD_COLOR_ANSI,\
        SPECIAL_COLOR_ANSI,PAYLOAD_COLOR_ANSI,EXPLOIT_DESCRIPTION_ANSI,END_COLOR_ANSI
    
    ROPGENERATOR_COLOR_ANSI = DEFAULT_ROPGENERATOR_COLOR_ANSI
    SEMANTIC_MODE_ANSI = DEFAULT_SEMANTIC_MODE_ANSI
    EXPLOIT_MODE_ANSI = DEFAULT_EXPLOIT_MODE_ANSI
    ERROR_COLOR_ANSI = DEFAULT_ERROR_COLOR_ANSI
    BOLD_COLOR_ANSI = DEFAULT_BOLD_COLOR_ANSI
    SPECIAL_COLOR_ANSI = DEFAULT_SPECIAL_COLOR_ANSI
    PAYLOAD_COLOR_ANSI = DEFAULT_PAYLOAD_COLOR_ANSI
    EXPLOIT_DESCRIPTION_ANSI = DEFAULT_EXPLOIT_DESCRIPTION_ANSI
    END_COLOR_ANSI = DEFAULT_END_COLOR_ANSI
    
def remove_colors(string):
    """
    Removes colors from a string 
    """
    colors = [ROPGENERATOR_COLOR_ANSI, SEMANTIC_MODE_ANSI, EXPLOIT_MODE_ANSI, ERROR_COLOR_ANSI,BOLD_COLOR_ANSI,\
        SPECIAL_COLOR_ANSI,PAYLOAD_COLOR_ANSI,EXPLOIT_DESCRIPTION_ANSI,END_COLOR_ANSI]
    res = string
    for color in colors:
        res = res.replace(color, '')
    return res

