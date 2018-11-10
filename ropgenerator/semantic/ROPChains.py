# -*- coding:utf-8 -*- 
# ROPChains module: representation of rop chains 
from ropgenerator.Gadget import Gadget
from ropgenerator.IO import string_special, string_bold, string_exploit, string_ropg, error, disable_colors, enable_colors
import ropgenerator.Architecture as Arch

class ROPChain:
    def __init__(self, gadget_chain=[]):
        """
        chain - list of Gadget or int (index of the padding in self.paddings)
        paddings - list of pairs (int, string)
        """
        self.chain = []
        self.paddings = []
        self.nbGadgets = 0
        self.nbInstr = 0
        self.nbInstrREIL = 0
        for g in gadget_chain:
            self.addGadget(g) 
        
    def __str__(self):
        res = ''
        for g in self.chain:
            if( isinstance(g, Gadget)):
                res += '\n\t'+g.asmStr
            else:
                res += '\n\t'+str(g)
        return res
    
    def __cmp__(self, other):
        if( len(self) > len(other)):
            return 1
        elif( len(self) < len(other)):
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

    def __len__(self):
        return len(self.chain)
    
    def addGadget(self, gadget):
        self.chain.append(gadget)
        self.nbGadgets += 1
        self.nbInstr += gadget.nbInstr
        self.nbInstrREIL += gadget.nbInstrREIL
        return self
        
    def addPadding(self, value, comment="Padding", n=1):
        if( n == 0 ):
            return self
        index = len(self.paddings)
        self.paddings.append((value, comment))
        while( n > 0 ):
            self.chain.append(index)
            n -= 1
        return self
        
    def addChain(self, other, new=False):
        if( new ):
            new = ROPChain()
            new.chain = list(self.chain)
            new.paddings = list(self.paddings)
        else:
            new = self
        new.nbGadgets = self.nbGadgets + other.nbGadgets
        new.nbInstr = self.nbInstr + other.nbInstr
        new.nbInstrREIL = self.nbInstrREIL + other.nbInstrREIL
        # Merge chains 
        for element in other.chain:
            if( isinstance(element, Gadget)):
                new.chain.append(element)
            else:
                # Manage paddings ;) 
                index = len(new.paddings)
                new.paddings.append(other.paddings[element])
                new.chain.append(index)
        return new
    
    def strConsole(self, bits, badBytes = []): 
        res = ''
        for element in self.chain:
            if( not isinstance(element, Gadget)):
                element_str = string_special('0x'+format(self.paddings[element][0], '0'+str(bits/4)+'x'))
                element_str += ' (' + self.paddings[element][1] + ')'
            else:
                valid_addr_str = validAddrStr(element, badBytes, bits)
                if( not valid_addr_str ):
                    error("Error! ROP-Chain gadget with no valid address. THIS SHOULD NOT HAPPEND (please report the bug for fixes)")
                    return ''
                element_str = string_special(valid_addr_str) +\
                        " (" + string_bold(element.asmStr) + ")"
            if (res != ''):
                res += "\n\t"+element_str
            else:
                res += "\t"+element_str
        return res
        
    def strPython(self, bits, badBytes = [], init=True, noTab=False):
        if( noTab ):
            tab = ''
        else:
            tab = '\t'
        
        # Getting endianness to pack values 
        if( bits == 32 ):
            endianness_str = "'<I'"
        elif( bits == 64 ):
            endianness_str = "'<Q'"
        else:
            raise Exception("{}-bits architecture not supported".format(bits))
        pack_str = "p += pack("+endianness_str+","
        res = ''
        if( init ):
            res += tab + "from struct import pack\n"
            res += tab + "p = ''"
        for element in self.chain:
            if( not isinstance(element, Gadget)):
                padding_str = pack_str
                padding_str += string_special('0x'+format(self.paddings[element][0], '0'+str(bits/4)+'x'))+")"
                padding_str += " # " + self.paddings[element][1]
                res += "\n"+tab+padding_str
            else:
                res += "\n"+tab+pack_str+string_special(validAddrStr(element, badBytes, bits)) +\
                        ") # " + string_bold(element.asmStr)
        return res

def validAddrStr(gadget, badBytes, bits):
    """
    Find one address for 'gadget' without bad bytes
    Precondition :  there is such address ! 
    """
    for addr in gadget.addrList:
        addrStr = format(addr, '0'+str(bits/4)+'x')
        ok = True
        for i in range(2, len(addrStr), 2):
            hex_addr_byte = addrStr[i:i+2]
            if( hex_addr_byte in badBytes):
                ok = False
                break
        if( ok):
            return "0x"+addrStr


#########################
#########################
## Structure for a full exploit 
# (ROPChain + description )
class PwnChain:
    def __init__(self):
        self.ROPChains = []
        self.info = []
        self.len_bytes = 0
        
    def add( self, chain, descr):
        self.ROPChains.append(chain)
        self.info.append(descr)
        self.len_bytes += len(chain)*Arch.octets()
        
    def strConsole(self, bits, badBytes):
        res = ""
        for i in range(0, len(self.ROPChains)):
            info_string = "\t"+'-'*len(self.info[i])+'\n'\
                            +string_exploit('\t'+self.info[i]+'\n')\
                            +"\t"+'-'*len(self.info[i])+'\n'
            chain_string = self.ROPChains[i].strConsole(bits, badBytes)+'\n'
            res += info_string + chain_string
        return res 
        
    def strPython(self, bits, badBytes, noTab=False):
        if( noTab ):
            tab = ''
        else:
            tab = '\t' 
        res = ""
        res += tab+"# -------------------\n"
        res += tab+"# "+string_exploit("Padding goes there\n")
        res += tab+"# -------------------\n"
        res += tab+"from struct import pack\n"
        res += tab+"p = ''\n"
        
        for i in range(0, len(self.ROPChains)):
            info_string = tab + "# "+'-'*len(self.info[i])+'\n'\
                            + tab + "# "+string_exploit(self.info[i]+'\n')\
                            +tab+"# "+'-'*len(self.info[i])
            chain_string = self.ROPChains[i].strPython(bits, badBytes, init=False, noTab=noTab)+"\n"
            res += info_string + chain_string
        
        return res 
    
