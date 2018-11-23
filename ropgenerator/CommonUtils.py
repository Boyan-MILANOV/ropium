# -*- coding:utf-8 -*-  
# CommonUtils module: useful functions 
import ropgenerator.Database as Database
import ropgenerator.exploit.Scanner as Scanner


def set_offset(offset):
    if( not Database.set_gadgets_offset(offset)):
        return False
    elif( not Scanner.set_offset(offset)):
        return False
    return True
    
def reset_offset():
    Database.reset_gadgets_offset()
    Scanner.reset_offset()
