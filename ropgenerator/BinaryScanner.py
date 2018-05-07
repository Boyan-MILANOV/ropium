# ROPGenerator - Constraints module 
# Scanning binaries to find symbols
import subprocess
from pwnlib.elf.elf import ELF
from elftools.elf.elffile import ELFFile 
import mmap
import re
from ropgenerator.Gadget import Gadget

binary_name = None
binary_ELF = None

def set_binary(filename):
    global binary_name
    global binary_ELF
    global binary_ELF
    binary_name = filename
    binary_ELF = ELF(binary_name)
    
def find_function(function):
    """
    Looks for the function 'function' in the PLT of a binary 
    """
    global binary_name
    global binary_ELF
    
    # using pwntools
    try:
        function_offset = binary_ELF.plt[function]
        function_symbol = function+'@PLT'
        res = (function_offset, function_symbol) 
        #DEBUG
        #print("[*] DEBUG hidden functionnality for function search:") 
        #print(res)
    except:
        #print("[*] DEBUG find_function found nothing ") 
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
    return res
    
def find_bytes(byte_string, addr_not_null=False, add_null=True ):
    """
    Find a string in a file + additionnal null byte at the end
    If addr_not_null set to True, discard addresses with null bytes 
    If add_null = True then add terminaison null bytes in the end of the substrings 
    
    Example: 
        byte_string = 'abc' then result is the address of a string 'abc\x00'
        or a list of addresses s.t elements form 'abc' like 'ab\x00' 'c\x00' 
    """
    
    def _find_substr(m,string):
        if( not string ):
            return [-1,0]
        # Initialize
        offset = -1
        index = len(string)
        substring = string
        # Search biggest substring 
        while( offset == -1 ):
            if( len(substring) <= 0 ):
                return [-1,0]
            offset = m.find(substring)
            if( offset != -1 ):
                return [offset, index]
            else:
                substring = substring[:-1]
            index = index -1
    
    def _find_substr_add_null(m, string):
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
                return [offset, index]
            else:
                substring = substring[:-2]
                last_is_null = (substring[-1] == '\x00')
                if( not last_is_null ):
                    substring = substring + '\x00'
            index = index -1
        
    global binary_name
    global binary_ELF
   
    if( addr_not_null ):
        print("[!] DEBUG, in find_bytes(): addr_not_null not supported yet")
        return []
        
    text_addr = binary_ELF.get_section_by_name('.text').header.sh_addr
    m = binary_ELF.get_section_by_name('.text').data()
    
    res = []
    substring = str(byte_string)
    while( substring ):
        if( add_null ):
            (offset, index ) = _find_substr_add_null(m, substring)
        else:
            (offset, index ) = _find_substr(m, substring)
        if( index == 0 ):
            # We didn't find any match, return empty list 
            return []
        else:
            # We add the best substring we found 
            res.append([text_addr+offset,substring[:index]])
            substring = substring[index:]
    return res
        
def bss_address():
    """
    Return the base address of the .bss section
    """
    global binary_ELF
    try:
        return binary_ELF.bss()
    except:
        return None
        
def find_syscalls():
    """
    Find all syscall instructions in the binary .text
    """
    global binary_ELF
    
    text_addr = binary_ELF.get_section_by_name('.text').header.sh_addr
    text_data = binary_ELF.get_section_by_name('.text').data()
    
    addresses = [text_addr + pos.start() for pos in re.finditer('\x0f\x05', text_data)]
    return addresses
    
