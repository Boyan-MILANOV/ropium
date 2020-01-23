#include "ropchain.hpp"
#include "utils.hpp"
#include <iostream>
#include <sstream>


ROPChain::ROPChain(Arch* a):arch(a){}

void ROPChain::add_gadget(addr_t addr, Gadget* gadget){
    items.push_back(ROPItem(addr, gadget));
}

void ROPChain::add_padding(cst_t value){
    items.push_back(ROPItem(ROPItemType::PADDING, value));
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
    string pack, endian, p; 
    addr_t gadgets_offset = 0;
    // Set packing strings, endianness, etc
    p = "p"; 
    if( arch->octets == 4 )
        endian = "'<I'";
    else if( arch->octets == 8 )
        endian = "'<Q'";
    else
        throw runtime_exception("ROPChain::print_python(): Doesn't support printing for non 4 or 8 octets address size");
    pack = p + " += pack(" + endian + ", "; 
    // Init chain
    os << tab << "from struct import pack" ;
    os << "\n" << tab << "off = 0x" << std::hex << gadgets_offset;
    os << "\n" << tab << p << " = ''" << std::endl; 

    for(ROPItem& item : items){
        if( item.type == ROPItemType::GADGET ){
            os << tab << pack << str_special(value_to_hex_str(arch->octets, item.addr)) << ") # " << str_bold(item.gadget->asm_str) << std::endl;
        }else if( item.type == ROPItemType::CST ){
            os << tab << pack << str_special(value_to_hex_str(arch->octets, item.value)) << ")";
            if( !item.msg.empty())
                os << " # " << item.msg;
            os << std::endl;
        }else if( item.type == ROPItemType::PADDING ){
            os << tab << pack << str_special(value_to_hex_str(arch->octets, item.value)) << ")";
            if( !item.msg.empty())
                os << " # " << item.msg;
            os << std::endl;
        }else{
            os << tab << "[Unsupported item]" << std::endl;
        }
    }
}

void append_value_to_bytes(vector<uint8_t>& bytes, addr_t val, int nb_octets){
    // Assume little endian
    for( int i = 0; i < nb_octets; i++){
        bytes.push_back((uint8_t)(val & 0xff));
        val >>= 8;
    }
}

void ROPChain::dump_raw(vector<uint8_t>& bytes){
    for(ROPItem& item : items){
        if( item.type == ROPItemType::GADGET ){
            append_value_to_bytes(bytes, item.addr, arch->octets);
        }else if( item.type == ROPItemType::CST ){
            append_value_to_bytes(bytes, item.value, arch->octets);
        }else if( item.type == ROPItemType::PADDING ){
            append_value_to_bytes(bytes, item.value, arch->octets);
        }else{
            throw runtime_exception("ROPChain::print_raw() got unsupported item type");
        }
    }
}

ostream& operator<<(ostream& os, ROPChain& ropchain){
    ropchain.print_pretty(os);
    return os;
}
