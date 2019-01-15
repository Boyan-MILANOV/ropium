from ropgenerator_core_ import \
ArgType, ArgEmpty, ArgCst, ArgReg, ArgTmp, \
IROperation, IRInstruction, IRBlock

from barf.core.reil import ReilMnemonic, ReilImmediateOperand, ReilRegisterOperand

def asm_to_REIL(asmStr, disassembler, ir_translator):
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
        return None

def is_calculation_instr( mnemonic ):
    return mnemonic > 0 and mnemonic < 10
    
def is_load_instr( mnemonic ):
    return mnemonic == ReilMnemonic.LDM
    
def is_store_instr( mnemonic ):
    return mnemonic == ReilMnemonic.STM
    
def is_put_instr( mnemonic ):
return mnemonic == ReilMnemonic.STR

map_op_to_IR = {
ReilMnemonic.ADD: IROperation.ADD
ReilMnemonic.SUB: IROperation.SUB
ReilMnemonic.MUL: IROperation.MUL
ReilMnemonic.BSH: IROperation.BSH
ReilMnemonic.AND: IROperation.AND
ReilMnemonic.OR: IROperation.OR
ReilMnemonic.XOR: IROperation.XOR
ReilMnemonic.MOD: IROperation.MOD
ReilMnemonic.:DIV: IROperation.DIV
}

def barf_operation_to_IR(mnemonic):
    return map_op_to_IR.get(mnemonic, None)

def barf_operand

def REIL_to_IRBlock(irsb):
    for instr in irsb:
        if( instr.mnemonic == ReilMnemonic.NOP):
            pass
        elif( is_calculation_instr(instr.mnemonic)):
            
        elif( is_load_instr(instr.mnemonic)):
            
        elif( is_store_instr(instr.mnemonic)):
            
        elif( is_put_instr(instr.mnemonic)):
            
        elif( instr.mnemonic == ReilMnemonic.BISZ ):
            
        elif( instr.mnemonic == ReilMnemonic.JCC ):
            
        else:
