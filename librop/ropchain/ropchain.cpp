#include "ropchain.hpp"
#include "utils.hpp"
#include <iostream>
#include <sstream>


ROPChain::ROPChain(Arch* a):arch(a){}

void ROPChain::add_gadget(addr_t addr, Gadget* gadget){
    items.push_back(ROPItem(addr, gadget));
}

int ROPChain::len(){
    return items.size();
}

void ROPChain::print_pretty(ostream& os, string tab){
    for(ROPItem& item : items){
        if( item.type == ROPItemType::GADGET ){
            os << tab << str_special(value_to_hex_str(arch->octets, item.addr)) << " (" << str_bold(item.gadget->asm_str) << ")" << std::endl;
        }else if( item.type == ROPItemType::CST ){
            os << tab << str_special(value_to_hex_str(arch->octets, item.value)) << item.msg << std::endl;
        }else if( item.type == ROPItemType::PADDING ){
            os << tab << str_special(value_to_hex_str(arch->octets, item.value)) << item.msg << std::endl;
        }else{
            os << tab << "Unsupported " << std::endl;
        }
    }
}


void ROPChain::print_python(ostream& os, string tab){
    os << "Unsupported" << std::endl;
}

ostream& operator<<(ostream& os, ROPChain& ropchain){
    ropchain.print_pretty(os);
    return os;
}
