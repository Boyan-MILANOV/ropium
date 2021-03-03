#include "ropchain.hpp"
#include "utils.hpp"
#include <iostream>
#include <sstream>


ROPChain::ROPChain(Arch* a):arch(a){}

void ROPChain::add_gadget(addr_t addr, Gadget* gadget){
    items.push_back(ROPItem(addr, gadget));
}

void ROPChain::add_padding(cst_t value, string msg){
    items.push_back(ROPItem(ROPItemType::PADDING, value, msg));
}

void ROPChain::add_gadget_address(cst_t value, string msg){
    items.push_back(ROPItem(ROPItemType::GADGET_ADDRESS, value, msg));
}

void ROPChain::add_chain(ROPChain& other){
    for( ROPItem& item : other.items ){
        items.push_back(item);
    }
}

int ROPChain::len(){
    return items.size();
}

void ROPChain::print_pretty(ostream& os, string tab){
    for(ROPItem& item : items){
        if( item.type == ROPItemType::GADGET ){
            os << tab << str_special(value_to_hex_str(arch->octets, item.addr)) << " (" << str_bold(item.gadget->asm_str) << ")" << std::endl;
        }else if( item.type == ROPItemType::PADDING ){
            os << tab << str_special(value_to_hex_str(arch->octets, item.value));
            if( !item.msg.empty() )
                os << " (" << str_bold(item.msg) << ")";
            os << std::endl;
        }else if( item.type == ROPItemType::GADGET_ADDRESS ){
            os << tab << str_special(value_to_hex_str(arch->octets, item.value));
            if( !item.msg.empty() )
                os << " (" << str_bold(item.msg) << ")";
            os << std::endl;
        }else{
            os << tab << "Unsupported: " << std::endl;
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
            os << tab << pack << str_special(value_to_hex_str(arch->octets, item.addr)) << " + off) # " << str_bold(item.gadget->asm_str) << std::endl;
        }else if( item.type == ROPItemType::PADDING ){
            os << tab << pack << str_special(value_to_hex_str(arch->octets, item.value)) << ")";
            if( !item.msg.empty())
                os << " # " << str_bold(item.msg);
            os << std::endl;
        }else if( item.type == ROPItemType::GADGET_ADDRESS ){
            os << tab << pack << str_special(value_to_hex_str(arch->octets, item.value)) << " + off)";
            if( !item.msg.empty())
                os << " # " << str_bold(item.msg);
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
        }else if( item.type == ROPItemType::PADDING ){
            append_value_to_bytes(bytes, item.value, arch->octets);
        }else if( item.type == ROPItemType::GADGET_ADDRESS ){
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
