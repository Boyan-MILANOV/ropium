# ROPGenerator - Constraints module 
# Scanning binaries to find symbols
import subprocess
from pwnlib.elf.elf import ELF
import mmap 

binary_name = None
binary_pwn = None

def set_binary(filename):
    global binary_name
    global binary_pwn
    binary_name = filename
    binary_pwn = ELF(binary_name)
    
def find_function(function):
    """
    Looks for the function 'function' in the PLT of a binary 
    """
    global binary_name
    global binary_pwn
    
    # using pwntools
    try:
        function_offset = binary_pwn.plt[function]
        function_symbol = function+'@PLT'
        res = (function_offset, function_symbol) 
        #DEBUG
        print("[*] DEBUG hidden functionnality for function search:") 
        print(res)
    except:
        print("[*] DEBUG find_function found nothing ") 
        res = [None, None]
    return res
    
    # Using custom search 
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
    print("[*] DEBUG hidden functionnality for function search:") 
    print(res)
    return res
    
def find_bytes(byte_string, addr_not_null=False):
    """
    Find a string in a file + additionnal null byte at the end
    If addr_not_null set to True, discard addresses with null bytes 
    
    Example: 
        byte_string = 'abc' then result is the address of a string 'abc\x00'
        or a list of addresses s.t elements form 'abc' like 'ab\x00' 'c\x00' 
    """
    
    def _find_substr(m, string):
        if( not string ):
            return [-1,0]
        # Initialize
        offset = -1
        index = len(string)
        last_is_null = (string[-1] == '\x00')
        if( not last_is_null ):
            substring = string + '\x00'
        else:
            substring = string
        # Search biggest substring 
        while( offset == -1 ):
            if( len(substring) <= 0 ):
                return [-1,0]
            offset = m.find(substring)
            if( offset != -1 ):
                print("DEBUG Found att offset " + str(offset) + " index " + str(index))
                return [offset, index]
            else:
                substring = substring[:-2]
                last_is_null = (substring[-1] == '\x00')
                if( not last_is_null ):
                    substring = substring + '\x00'
            index = index -1
        
    global binary_name
    global binary_pwn
    
    f = open(binary_name)
    m = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
    substring = str(byte_string)
    if( addr_not_null ):
        print("[!] DEBUG, in find_bytes(): addr_not_null not supported yet")
        return []
    base_addr = binary_pwn.address
    
    res = []
    while( substring ):
        (offset, index ) = _find_substr(m, substring)
        if( index == 0 ):
            # We didn't find any match, return empty list 
            return []
        else:
            # We add the best substring we found 
            res.append([base_addr+offset,substring[:index]])
            substring = substring[index:]
    return res
        
def bss_address():
    """
    Return the base address of the .bss section
    """
    global binary_pwn
    try:
        return binary_pwn.bss()
    except:
        return None
