# -*- coding:utf-8 -*- 
# ROPChains module: representation of rop chains 
import ROPGenerator.Database as DB
from ropgenerator.Gadget import Gadget

class ROPChain:
    def __init__(self):
        """
        chain - list of Gadget or int (index of the padding in self.paddings)
        paddings - list of pairs (int, string)
        """
        self.chain = []
        self.paddings = []
        self.nbGadgets = 0
        self.nbInstr = 0
        self.nbInstrREIL = 0 
        
    def __cmp__(self, other):
        if( self.nbGadgets > other.nbGadgets):
            return 1
        elif( self.nbGadgets < other.nbGadgets):
            return -1
        else:
            if( self.nbInstr > other.nbInstr ):
                return 1
            elif( self.nbInstr < other.nbInstr ):
                return -1
            else:
                if( self.nbInstrREIL > other.nbInstrREIL ):
                    return 1
                elif( self.nbInstrREIL > other.nbInstrREIL ):
                    return -1 
                else:
                    return 0 

    def addGadget(self, gadget):
        self.chain.append(gadget)
        self.nbGadgets += 1
        self.nbInstr += gadget.nbInstr
        self.nbInstrREIL += gadget.nbInstrREIL
        
    def addPadding(self, value, comment="Padding"):
        index = len(self.paddings)
        self.chain.append(index)
        self.paddings.append((value, comment))
        

    def strConsole(self, bits, badBytes = []): 
        res = ''
        for element in self.chain:
            if( not isinstance(element, Gadget):
                padding_str = string_special('0x'+format(self.paddings[element][0], '0'+str(bits/4)+'x'))
                padding_str += '(' + self.paddings[element][1] + ')'
            else:
                padding_str += string_special(validAddrStr(element, badBytes, bits)) +\
                        " (" + string_bold(element.asmStr) + ")"
            if (res != ''):
                res += "\n\t"+padding_str
            else:
                res += "\t"+padding_str
        return res
        
    def strPython(self, bits, badBytes = []):
        # Getting endianness to pack values 
        if( bits == 32 ):
            endianness_str = '<I'
        elif( bits == 64 ):
            endianness_str = '<Q'
        else:
            raise Exception("{}-bits architecture not supported".format(bits))
        pack_str = "p += pack("+endianness_str+","
        res = "\tfrom struct import pack"
        res += "\n\tp = ''"
        for element in self.chain:
            if( not isinstance(element, Gadget)):
                padding_str = pack_str
                padding_str += string_special('0x'+format(self.paddings[element][0], '0'+str(bits/4)+'x'))+")"
                padding_str += "# " + self.paddings[element][1]
                res += "\t"+padding_str
            else:
                res += "\t"+pack_str+string_special(validAddrStr(element, badBytes, bits)) +\
                        ") # " + string_bold(element.asmStr))
        return res

def validAddrStr(gadget, badBytes, bits):
    """
    Find one address for 'gadget' without bad bytes
    Precondition :  there is such address ! 
    """
    for addr in gadget.addrList:
        addrStr = format(self.paddings[element][0], '0'+str(bits/4)+'x'
        ok = True
        for i in range(2, len(addrStr), 2):
            hex_addr_byte = gadget.addrStr[i:i+2]
            if( hex_addr_byte in bad_bytes_list):
                ok = False
                break
        if( ok):
            return "0x"+addrStr

