# -*- coding: utf-8 -*- 

from ropgenerator.core.Expression import *
from ropgenerator.core.Architecture import *
from ropgenerator.core.ChainingEngine import *
from ropgenerator.main.Load import biggest_gadget_address

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
            bad_bytes.append(int(user_bad_byte, 16))
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
        if( not reg ):
            return (False, "Error. Missing register after ','")
        elif( is_supported_reg(reg) ):
            keep_regs.add(reg_str_to_num(reg))
        else:
            return (False, "Error. '{}' is not a valid register".format(reg))
    return (True, list(keep_regs))
    
def parse_offset(string):
    try:
        offset = int(string)
    except:
        try: 
            offset = int(string, 16)
        except:
            return (False, "Error. '" + args[i+1] +"' is not a valid offset")
    # Check if not negative
    if( offset < 0 ):
        return (False, "Error. Offset must be positive")
    # Check if not too big
    elif(  biggest_gadget_address() + offset >= 2**curr_arch_bits() ):
        return (False, "Error. Offset is too big!")
    # OK, return
    return (True, offset)
    
def parse_lmax(string):
    try:
        lmax = int(string)
    except:
        try:
            lmax = int(string, 16)
        except:
            return (False, "Error. '" + string +"' is not a valid number of bytes")
    # Check minimal length 
    if( lmax < curr_arch_bits()//8 ):
            return (False, "Error. '" + string +"' is too little :'(")
    # Ok - Convert number of bytes into number of ropchain elements
    lmax = lmax // (curr_arch_bits()//8)
    return (True, lmax)

def parse_query(req):
    """
    Parses a user request for a gadget
    Request is of the form  expression=expression
    Returns either a tuple (success, dest, assign), or, if not supported or invalid 
        arguments, returns a tuple (False, msg, None)
    dest is a DestArg
    assign is an AssignArg
    """
    # Check for int80 and syscall
    if( req == 'int80' ):
        return (True, None, (AssignType.INT80, None))
    elif( req == 'syscall' ):
        return (True, None, (AssignType.SYSCALL, None))
    
    # Check for Regular query 
    args = [x for x in req.split('=',1) if x]
    if( len(args) != 2):
        return (False, "\n\tInvalid semantic query: " + str(req), None)
          
    # Normal request with '=' 
    left = args[0]
    right = args[1]
    # Test destination
    (success, assign_type, dest_tuple) = parse_expr(left)
    if( not success ):
        return (False, assign_type, None)
    if( assign_type == AssignType.REG_BINOP_CST and dest_tuple[1] == Binop.ADD
            and dest_tuple[2] == 0):
        dest_res = DestArg(DestType.REG, dest_tuple[0])
    elif( assign_type == AssignType.MEM_BINOP_CST and dest_tuple[1] == Binop.ADD 
            and dest_tuple[2] == 0):
        dest_res = DestArg(DestType.MEM, dest_tuple[0][0], dest_tuple[0][1], dest_tuple[0][2])
    elif( assign_type == AssignType.CSTMEM_BINOP_CST and dest_tuple[1] == Binop.ADD
            and dest_tuple[2] == 0):
        dest_res = DestArg(DestType.CSTMEM, dest_tuple[0])
    else:
        return (False, "\n\tLeft operand '" +left+"' is invalid or not yet supported :(", None)
        
    # Test assigned value
    (success, assign_type, assign_tuple) = parse_expr(right)
    if( not success ):
        return (False, assign_type)
    if( assign_type == AssignType.CST ):
        assign_res = AssignArg(AssignType.CST, assign_tuple[0])
    elif( assign_type == AssignType.REG_BINOP_CST):
        assign_res = AssignArg(AssignType.REG_BINOP_CST, assign_tuple[0],assign_tuple[1],assign_tuple[2])
    elif( assign_type == AssignType.MEM_BINOP_CST):
        assign_res = AssignArg(AssignType.MEM_BINOP_CST, assign_tuple[0][0],assign_tuple[0][1],assign_tuple[0][2], assign_tuple[1])
    elif( assign_type == AssignType.CSTMEM_BINOP_CST):
        assign_res = AssignArg(AssignType.CSTMEM_BINOP_CST, assign_tuple[0],assign_tuple[1])
    elif( assign_type == AssignType.SYSCALL):
        assign_res = AssignArg(AssignType.SYSCALL)
    elif( assign_type == AssignType.INT80):
        assign_res = AssignArg(AssignType.INT80)
    else:
        raise Exception("Missing assign type when parsing")
    return (True, dest_res, assign_res)


def parse_expr( string ):
    """
    Parses a string into an Expr
    Returns a tuple (True, AssignType, tuple) or (False, ErrorMessage/str, None)
    The tuple depends on the AssignType:
        cst : (cst,)
        reg binop cst : (reg, binop, cst)
        mem binop cst : ((mem_reg, mem_binop, mem_cst), cst)
        cstmem binop cst : (mem_cst, cst)
    
    ! -> We return AssignType even when parsing DestType because it is included in 
    AssignType
    """
    
    binop_map = {
        "+":Binop.ADD,
        "-":Binop.SUB,
        "*":Binop.MUL,
        "/":Binop.DIV,
        "^":Binop.AND,
        "|":Binop.OR,
        "&":Binop.AND
    }

    if( not string ):
        return (False, "Invalid query", None)

    # Is it a mem ? 
    if( string[:4] == "mem(" and string[-1] == ")"):
        if( len(string.split(")", 1)) < 2 ):
            return (False, "Missing parenthesis after " + string, None)
        mem_string = string[4:-1]
        # Get the mem part 
        parsed_mem = parse_expr(mem_string)
        if( not parsed_mem[0] ):
            # cstmem ? 
            if( parse_cst(mem_string) is None ):
                 return (False, "Invalid or unsupported address: " + mem_string, None)
            else:
                tmp_res = [True, AssignType.CSTMEM_BINOP_CST, (parse_cst(mem_string),)]
        # normal mem ? 
        elif( parsed_mem[1] == AssignType.REG_BINOP_CST):
            tmp_res = [True, AssignType.MEM_BINOP_CST, parsed_mem[2:5]]
        else:
            return (False, "Address not supported: " + mem_string, None)
        
        return (tmp_res[0], tmp_res[1], tmp_res[2]+(Binop.ADD, 0,))

    # Or a X binop CST ? 
    for i in reversed(range(0,len(string))):
        # Look for binop 
        if( string[i] in binop_map.keys()):
            binop = binop_map[string[i]]
            # Check for both operands 
            if( i+1 < len(string)):
                right = string[i+1:]
            else:
                return (False, "Missing right operand", None)
            if( i-1 >= 0 ):
                left = string[:i]
            else:
                return (False, "Missing left operand", None)
            # Check if right is a constant
            cst = parse_cst(right)
            if( cst is None ):
                return (False, "Only constants can be used as right operands (got '{}')".format(right), None)
            elif( cst >= 2**curr_arch_bits() ):
                return (False, "Constant {} is too big".format(right), None)
            # Parse left as X binop cst
            if( is_supported_reg(left) ):
                # reg binop cst 
                return (True, AssignType.REG_BINOP_CST, (reg_str_to_num(left), binop, cst,),)
            elif( left[:4] == "mem(" ):
                # mem binop cst 
                if( left[-1] != ")" ):
                    return (False, "Missing parenthesis after " + left, None)
                parsed_mem = parse_expr(left[4:-1])
                if( not parsed_mem[0] ):
                    return parsed_mem
                # check if the const is added/subbed
                if( binop != Binop.ADD and binop != Binop.SUB ):
                    return (False, "Operand '{}' not supported for constant".format(string[i]), None)
                else:
                    adjusted_cst = cst*(1 if binop == Binop.ADD else -1)
                if( parsed_mem[1] == AssignType.REG_BINOP_CST):
                    return (True, AssignType.MEM_BINOP_CST, (parsed_mem[2:5] + (adjusted_cst,)),)
                elif( parsed_mem[1] == AssignType.CST ):
                    return (True, AssignType.CSTMEM_BINOP_CST, (parsed_mem[2], adjusted_cst))
                else:
                    return (False, "Address not supported: " + left[4:-1], None)
            else:
                return (False, "Left operand not supported: " + left, None)
    
    # If didn't find binop, maybe just a reg ?  
    if( is_supported_reg(string) ):
        return (True, AssignType.REG_BINOP_CST, (reg_str_to_num(string), Binop.ADD, 0),)
    # Or a const ? 
    else:
        value = parse_cst(string)
        if( value is None ):
            return (False, "Expression not supported: " + string, None)
        else:
            return (True, AssignType.CST, (value,))

def parse_cst(string):
    # DEBUG TODO: verify that it fits the arch size ??
    try:
        cst = int(string, 10)
    except:
        try:
            cst = int(string, 16)
        except:
            try:
                cst = int(string,2)
            except:
                return None
    return cst

