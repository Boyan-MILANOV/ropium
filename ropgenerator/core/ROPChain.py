from ropgenerator_core_ import ROPChain
from ropgenerator.core.IO import *

### PwnChain -> list of ROP-chains wuth comments :)
class PwnChain:
    def __init__(self):
        self.chains = []
        self.comments = []
        
    def add_chain(self, ropchain, comment=""):
        self.chains.append(ropchain)
        self.comments.append(comment)
        
    def to_str_console(self, octets, bad_bytes):
        if( not self.chains ):
            return ""
        tab = "\t"
        sep = "-"
        info_str = tab + sep*len(self.comments[0]) + '\n' + str_exploit('\t'+self.comments[0]+'\n') + tab + sep*len(self.comments[0]) + '\n'
        chain_str = self.chains[0].to_str_console(octets, bad_bytes) + '\n'
        res = info_str + chain_str
        for i in range(1, len(self.chains)):
            info_str = tab + sep*len(self.comments[i]) + '\n' + str_exploit('\t'+self.comments[i]+'\n') + tab + sep*len(self.comments[i]) + '\n'
            chain_str = self.chains[i].to_str_console(octets, bad_bytes) + '\n'
            res += info_str + chain_str
        return res
        
    def to_str_python(self, octets, bad_bytes, no_tab=False):
        if( not self.chains ):
            return ""
        tab = "" if no_tab else "\t"
        sep = "-"
        padding_message = "Padding goes here"
        res = ""
        res += tab+"# " +sep*len(padding_message) + "\n"
        res += tab+"# "+str_exploit("Padding goes there\n")
        res += tab+"# " +sep*len(padding_message) + "\n"
        res += tab+"from struct import pack\n"
        res += tab+"p = ''\n\n"
        for i in range(0, len(self.chains)):
            info_str = tab + "# " + sep*len(self.comments[i]) + '\n\t# ' + str_exploit(self.comments[i]+'\n') + tab + "# " + sep*len(self.comments[i]) + '\n'
            chain_str = self.chains[i].to_str_python(octets, bad_bytes, False, no_tab) + '\n'
            res += info_str + chain_str
        return res
