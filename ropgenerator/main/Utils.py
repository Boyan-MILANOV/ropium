# -*- coding: utf-8 -*- 

########################
#   Parsing functions  #
########################

def parseFunction(string):
    def seek(char, string):
        for i in range(0, len(string)):
            if string[i] == char:
                return (string[:i], i)
        return ([],-1)
        
    if( not string ):
        error("Missing fuction to call")
        return (None, None)
    
    # COmpress the string
    string = "".join(string.split())
    
    # Get the function name 
    (funcName, index) = seek("(", string)
    if( not funcName ):
        error("Invalid function call")
        return (None, None)
    rest = string[index+1:]
    args = []
    arg = ''
    i = 0
    end = False
    while(i < len(rest)):
        c = rest[i]
        # No args
        if( c == ")" and not args):
            end = True
            i += 1
        # String
        elif( c == '"' or c == "'" ):
            (s, index)= seek(c, rest[i+1:])
            if( s == 0 ):
                error("Error. Empty string argument ?")
                return (None, None)
            elif( not s ):
                error("Missing closing {} for string".format(c))
                return (None, None)
            # Parse the string 
            j = 0
            s = str(s)
            parsed_string = ""
            while( j < len(s)):
                if( s[j:j+2] == "\\x" ):
                    if( j + 3 < len(s)):
                        try:
                            char = int(s[j+2:j+4], 16) 
                        except:
                            error("Invalid byte: '{}'".format(s[j:j+4]))
                            return (None, None)
                    else:
                        error("Invalid byte: '{}'".format(s[j:j+4]))
                        return (None, None)
                    parsed_string += chr(char)
                    j+= 4
                else:
                    parsed_string += s[j]
                    j += 1
            args.append(str(parsed_string))
            
            i += index +2
            if( i >= len(rest)):
                error("Error. Missing ')'")
                return (None, None)
            elif( rest[i] == ')' ):
                end = True
                i += 1
            elif( rest[i] == "," ):
                i += 1
            else:
                error("Error. Missing ',' or ')' after string")
                return (None, None)
        # Constant
        else:
            # Get the constant 
            arg = ''
            ok = False
            for j in range(i, len(rest)):
                if( rest[j] == ")" ):
                    end = True
                    ok = True
                    break
                elif( rest[j] == ','):
                    ok = True
                    break
                else:
                    arg += rest[j]
            if( not ok ):
                error("Missing ')' after argument")
                return (None, None)
            if( (not arg) and args):
                error("Missing argument")
                return (None, None)
            # Convert to int 
            try:
                value = int(arg)
            except:
                try:
                    value = int(arg, 16)
                except:
                    try:
                        value = int(arg, 2)
                    except:
                        error("Invalid operand: " + arg )
                        return (None, None)
            args.append(value)
            i = j+1
        if( end):
            break
    
    if( not end ):
        error("Error. Missing ')'")
        return    (None, None)     
    if( i < len(rest)):
        error("Error. Extra argument: {}".format(rest[i:]))
        return (None, None)

    # str() to set its type to str ;) 
    return (str(funcName), args)
    
    
def parse_bad_bytes(string):
    """
    Parses a bad bytes string into a list of bad bytes
    Input: a string of format like "00,0A,FF,32,C7"
    Ouput if valid string : (True, list) where list = 
        ['00', '0a', 'ff', '32', 'c7'] (separate them in individual strings
        and force lower case)
    Output if invalid string (False, error_message)
    """
    hex_chars = '0123456789abcdefABCDEF'
    i = 0
    bad_bytes = []
    user_bad_bytes = [b.lower() for b in string.split(',')]
    for user_bad_byte in user_bad_bytes:
        if( not user_bad_byte ):
            return (False, "Error. Missing bad byte after ','")
        elif( len(user_bad_byte) != 2 ):
            return (False, "Error. '{}' is not a valid byte".format(user_bad_byte))
        elif( not ((user_bad_byte[i] in hex_chars) and (user_bad_byte[i+1] in hex_chars))):
            return (False, "Error. '{}' is not a valid byte".format(user_bad_byte))
        else:
            bad_bytes.append(user_bad_byte)
    return (True, bad_bytes)
    
def parse_keep_regs(string):
    """
    Parses a 'keep registers' string into a list of register uids
    Input: a string of format like "rax,rcx,rdi"
    Output if valid string (True, list) where list = 
        [1, 3, 4] (R1 is rax, R3 is RCX, ... )
    Output if invalid string (False, error_message)
    """
    user_keep_regs = string.split(',')
    keep_regs = set()
    for reg in user_keep_regs:
        if( is_supported_reg(reg) ):
            keep_regs.add(Arch.n2r(reg))
        else:
            return (False, "Error. '{}' is not a valid register".format(reg))
    return (True, list(keep_regs))
