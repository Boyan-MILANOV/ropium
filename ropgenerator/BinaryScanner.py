# ROPGenerator - Constraints module 
# Scanning binaries to find symbols
import subprocess


binary_name = None
binary = None

def open_binary(filename):
    """
    Open a binary 
    """
    try:
        binary = open(filename)
    except:
        return False
    return True
    
    
def close_binary():
    """
    Close the openend binary
    """
    if( binary != None ):
        binary.close()
    
def find_function(function):
    """
    Looks for the function 'function' in the PLT of a binary 
    """
    global binary_name
    
    output = subprocess.check_output(['readelf', '-r', binary_name])
    offset = output.find(function+'@')
    if( offset == -1 ):
        return None
    function_line  = output[output.rfind('\n', offset-300, offset)+1:output.find('\n', offset)]
    function_line_split = filter(lambda x: x!= '', function_line.split(' '))
    function_offset = function_line_split[0]
    function_symbol = function_line_split[4]

    res = (function_offset, function_symbol) 
    #DEBUG
    print(res)
    return res
    
