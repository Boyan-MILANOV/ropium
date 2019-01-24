from ropgenerator_core_ import \
ArgType, ArgEmpty, ArgCst, ArgReg, ArgTmp, \
IROperation, IRInstruction, IRBlock, print_irblock

from ropgenerator.core.Architecture import *

from barf.core.reil import ReilMnemonic, ReilImmediateOperand, ReilRegisterOperand
from barf.arch import ARCH_X86_MODE_32
from barf.arch import ARCH_X86_MODE_64
from barf.arch.x86.x86translator import X86Translator
from barf.arch.x86.x86disassembler import X86Disassembler
from barf.arch.x86.x86base import *

import sys

def raw_to_REIL(asmStr, disassembler, ir_translator):
    """
    Translate assembly into REIL
    """
    
    index = 0
    instr = []
    try:
        while( index < len(asmStr)):
            asm = disassembler.disassemble(asmStr[index:], index)
            if( asm is None ):
                bad = '\\x' + '\\x'.join("{:02x}".format(ord(c) for c in asmStr[index:]))
                #raise ArchException("Unable to translate instructions {}".format(bad))
            instr.append(asm)
            index += asm.size
        irsb = [a for i in instr for a in ir_translator.translate(i) ]
        return (irsb,instr)
    except:
        return (None, None)

def is_calculation_instr( mnemonic ):
    return mnemonic > 0 and mnemonic < 10
    
def is_load_instr( mnemonic ):
    return mnemonic == ReilMnemonic.LDM
    
def is_store_instr( mnemonic ):
    return mnemonic == ReilMnemonic.STM
    
def is_put_instr( mnemonic ):
    return mnemonic == ReilMnemonic.STR

map_op_to_IR = {
ReilMnemonic.ADD: IROperation.ADD,
ReilMnemonic.SUB: IROperation.SUB,
ReilMnemonic.MUL: IROperation.MUL,
ReilMnemonic.BSH: IROperation.BSH,
ReilMnemonic.AND: IROperation.AND,
ReilMnemonic.OR: IROperation.OR,
ReilMnemonic.XOR: IROperation.XOR,
ReilMnemonic.MOD: IROperation.MOD,
ReilMnemonic.DIV: IROperation.DIV
}

def barf_operation_to_IR(mnemonic):
    return map_op_to_IR.get(mnemonic, None)

class RegNotSupported(Exception):
    def __init__(self, msg):
        self.msg = msg
        
    def __str__(self):
        return msg

def barf_operand_to_IR(operand, alias_mapper):
    if( isinstance(operand, ReilImmediateOperand )):
        if( operand._immediate > sys.maxint ): # DEBUG 
            print("[DEBUG] Python2 Error ? ReilImmediateOperand is too big to fit in an int")
            value = sys.maxint
        else:
            value = operand._immediate
        return ArgCst(value, operand.size)
    elif( isinstance( operand, ReilRegisterOperand)):
        if( operand._name[0] == "t" ):
            return ArgTmp(int(operand._name[1:]), operand.size)
        else:
            #Find full reg 
            reg_str = operand._name
            full_reg = (reg_str, 0)
            if( alias_mapper.get(reg_str) != None ):
                if( alias_mapper[reg_str][0] != "rflags" and alias_mapper[reg_str][0] != "eflags" ):
                    full_reg = alias_mapper[reg_str] # Couple (reg, offset)
                    reg_str = full_reg[0]
                    
            # Get reg num
            if( curr_arch_type() == ArchType.ARCH_X86 ):
                reg_num = map_x86_reg_names.get(reg_str, None)
            elif( curr_arch_type() == ArchType.ARCH_X64 ):
                reg_num = map_x64_reg_names.get(reg_str, None)
            else:
                raise Exception("Error")
            if( reg_num is None ):
                raise RegNotSupported("Error, could not get register: " + reg_str)
            # Return the right operand 
            if( operand.size == curr_arch_bits() ):
                return ArgReg(reg_num, operand.size)
            else:
                return ArgReg(reg_num, curr_arch_bits(), operand.size+full_reg[1]-1, full_reg[1])
    else:
        raise("Unsupported reil type")
        
def raw_to_IRBlock(raw):
    # Check for Architecture    
    if( curr_arch_type() == ArchType.ARCH_X86):
        disassembler = X86Disassembler(architecture_mode=ARCH_X86_MODE_32)
        ir_translator = X86Translator(architecture_mode=ARCH_X86_MODE_32)
        alias_mapper = X86ArchitectureInformation(ARCH_X86_MODE_32).alias_mapper
    elif( curr_arch_type() == ArchType.ARCH_X64 ):
        disassembler = X86Disassembler(architecture_mode=ARCH_X86_MODE_64)
        ir_translator = X86Translator(architecture_mode=ARCH_X86_MODE_64)
        alias_mapper = X86ArchitectureInformation(ARCH_X86_MODE_64).alias_mapper
    else:
        pass 
    (irsb,string) = raw_to_REIL(raw, disassembler, ir_translator)
    if( irsb is None ):
        return (None, string) 
    
    res = IRBlock()
    # Translate instruction by instruction 
    # TODO 
    try:
        for instr in irsb:
            #print(instr) # DEBUG 
            i = None
            if( instr.mnemonic == ReilMnemonic.NOP):
                pass
            elif( is_calculation_instr(instr.mnemonic)):
                i = IRInstruction(barf_operation_to_IR(instr.mnemonic),
                                            barf_operand_to_IR(instr.operands[0], alias_mapper),
                                            barf_operand_to_IR(instr.operands[1], alias_mapper),
                                            barf_operand_to_IR(instr.operands[2], alias_mapper));
                                            
            elif( is_load_instr(instr.mnemonic)):
                i = IRInstruction(IROperation.LDM,
                                            barf_operand_to_IR(instr.operands[0], alias_mapper),
                                            ArgEmpty(),
                                            barf_operand_to_IR(instr.operands[2], alias_mapper));
                                            
            elif( is_store_instr(instr.mnemonic)):
                i = IRInstruction(IROperation.STM,
                                            barf_operand_to_IR(instr.operands[0], alias_mapper),
                                            ArgEmpty(),
                                            barf_operand_to_IR(instr.operands[2], alias_mapper));
            elif( is_put_instr(instr.mnemonic)):
                i = IRInstruction(IROperation.STR, 
                                            barf_operand_to_IR(instr.operands[0], alias_mapper),
                                            ArgEmpty(),
                                            barf_operand_to_IR(instr.operands[2], alias_mapper));
            elif( instr.mnemonic == ReilMnemonic.BISZ ):
                i = IRInstruction(IROperation.UNKNOWN,
                                            ArgEmpty(),
                                            ArgEmpty(),
                                            barf_operand_to_IR(instr.operands[2], alias_mapper));
            elif( instr.mnemonic == ReilMnemonic.JCC ):
                if( isinstance(instr.operands[0], ReilImmediateOperand) and 
                        instr.operands[0]._immediate != 0):
                            
                    if( instr.operands[2].size > curr_arch_bits() ):
                        i = IRInstruction(IROperation.BSH,
                                            barf_operand_to_IR(instr.operands[2], alias_mapper),
                                            ArgCst(curr_arch_bits() - instr.operands[2].size, curr_arch_bits()),
                                            ArgReg(curr_arch_ip(), curr_arch_bits()));
                    else:
                        i = IRInstruction(IROperation.STR,
                                            barf_operand_to_IR(instr.operands[2], alias_mapper),
                                            ArgEmpty(),
                                            ArgReg(curr_arch_ip(), curr_arch_bits()));
                    
                else:
                    i = IRInstruction(IROperation.UNKNOWN,
                                            ArgEmpty(),
                                            ArgEmpty(),
                                            ArgReg(curr_arch_ip(), curr_arch_bits()));
                    break
            else:
                return (None, string) 
            if( i ):
                res.add_instr(i)
    except RegNotSupported:
        return (None, string)
    return (res, string)
