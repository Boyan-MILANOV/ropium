#include "ROPChain.hpp"
#include "Database.hpp"
#include "CommonUtils.hpp"
#include "Exception.hpp"
#include "Gadget.hpp"
#include "IO.hpp"
#include <algorithm>
#include <iomanip>

ROPChain::ROPChain():_len(0), _nb_gadgets(0), _nb_instr(0), _nb_instr_ir(0){}

// Accessors
int ROPChain::len(){return _len;}
int ROPChain::nb_gadgets(){return _nb_gadgets;}
int ROPChain::nb_instr(){return _nb_instr;}
int ROPChain::nb_instr_ir(){return _nb_instr_ir;}
vector<int>& ROPChain::chain(){return _chain;}
vector<addr_t>& ROPChain::padding_values(){return _padding_values;}
vector<string>& ROPChain::padding_comments(){return _padding_comments;}
vector<bool>& ROPChain::padding_offsets(){return _padding_offsets;}

// Modifiers
void ROPChain::add_gadget(int g){
    _chain.push_back(g);
    _len++; 
    _nb_instr += gadget_db()->get(g)->nb_instr();
    _nb_instr_ir += gadget_db()->get(g)->nb_instr_ir();
    _nb_gadgets++; 
}

void ROPChain::add_padding(addr_t value, int n,  string comment, bool offset){
    int num; 
    if( n == 0 )
        return;
    // Get padding number 
    num = _padding_values.size()+1;
    // Add padding 
    _padding_values.push_back(value);
    _padding_comments.push_back(comment);
    _padding_offsets.push_back(offset);
    // Add to the chain 
    _len += n; 
    for( ;n>0; n--)
        _chain.push_back(-1*num);
}

void ROPChain::add_chain(ROPChain* other){
    vector<int>::iterator it; 
    int num; 
    _len += other->len(); 
    _nb_gadgets += other->nb_gadgets(); 
    _nb_instr += other->nb_instr(); 
    _nb_instr_ir += other->nb_instr_ir();
    
    for( it = other->chain().begin(); it != other->chain().end(); it++){
        // Gadget
        if( *it >= 0 ){
            _chain.push_back(*it);
        }else {
        // Padding 
            // Get padding number 
            num = _padding_values.size()+1;
            // Add padding 
            _padding_values.push_back(other->padding_values().at(-1*(*it) -1));
            _padding_comments.push_back(other->padding_comments().at(-1*(*it) -1));
            _padding_offsets.push_back(other->padding_offsets().at(-1*(*it) -1));
            _chain.push_back(-1*num);
        }
    }
}

// Sort
bool ROPChain::lthan(ROPChain* other){
    if( _len == other->len() ){
        if( _nb_instr == other->nb_instr() ){
            if( _nb_instr_ir >= other->nb_instr_ir() )
                return false; 
        }
        return _nb_instr < other->nb_instr(); 
    }
    return _len < other->len(); 
}

// String representation 
string valid_addr_str(int octets, shared_ptr<Gadget> g, vector<unsigned char> bad_bytes, bool offset=false, bool color=false){
    int i=0;
    vector<addr_t>::iterator it; 
    vector<addr_t>* addr_list = g->addresses();
    addr_t address=0;
    addr_t off = get_gadgets_offset();
    for( it = addr_list->begin(); it != addr_list->end(); it++){
        // Test if bad bytes inside 
        for( i=0; i < octets; i++)
            if (std::find( bad_bytes.begin(), bad_bytes.end(), (unsigned char)( ((*it) >> i*8) & 0xff)) != bad_bytes.end())
                break;
        if( i == octets ){
            address = *it;
            break;
        }
    }
    delete addr_list;
    if( i == octets ){
        if( offset ){
            if( color )
                return str_special(value_to_hex_str(octets, address-off)) + " + off";
            else
                return value_to_hex_str(octets, address-off) + " + off";
        }else{
            if( color )
                return str_special(value_to_hex_str(octets, address));
            else
                return value_to_hex_str(octets, address);
        }
    }else{
        throw_exception("In valid_addr_str: Error, No valid address found for the gadget to print ! :( ");
    }
}

string ROPChain::to_str_console(int octets, vector<unsigned char> bad_bytes){
    stringstream ss;
    vector<int>::iterator it; 
    int padd_num; 
    
    for(it = _chain.begin(); it != _chain.end(); it++){
        if( *it >= 0 ){
            // Gadget 
            ss << "\t" << str_special(valid_addr_str(octets, gadget_db()->get(*it), bad_bytes)) << " (" << 
                str_bold(gadget_db()->get(*it)->asm_str()) << ")\n";
        }else{
            // Padding 
            padd_num = -1*(*it)-1;
            ss << "\t" << str_special(value_to_hex_str(octets, (addr_t)_padding_values.at(padd_num))) << " (" << 
            _padding_comments.at(padd_num) << ")\n"; 
        }
    } 
    return ss.str(); 
}

string ROPChain::to_str_python(int octets, vector<unsigned char> bad_bytes, bool init=true, bool no_tab=false){
    stringstream ss;
    vector<int>::iterator it; 
    int padd_num; 
    string tab, pack, endian, p; 
    
    tab = no_tab ? "" : "\t"; 
    p = "p"; 
    if( octets == 4 )
        endian = "'<I'";
    else if( octets == 8 )
        endian = "'<Q'";
    else
        return string("Doesn't support printing for non 4 or 8 octets address size");
    pack = p + " += pack(" + endian + ", "; 
    
    if( init ){
        ss << tab << "from struct import pack" ;
        ss << "\n" << tab << "off = 0x" << std::hex << get_gadgets_offset();
        ss << "\n" << tab << p << " = ''" << endl; 
    }
    for(it = _chain.begin(); it != _chain.end(); it++){
        if( *it >= 0 ){
            // Gadget
            ss <<  tab << pack << valid_addr_str(octets, gadget_db()->get(*it), bad_bytes, true, true) <<
                ") # " << str_bold(gadget_db()->get(*it)->asm_str()) << "\n";
        }else{
            // Padding 
            padd_num = -1*(*it)-1;
            if( _padding_offsets.at(padd_num))
                /* We substract the offset because we'll print '+off', that's an ugly hack but fuck it it's 
                 * working */ 
                ss << tab << pack << str_special(value_to_hex_str(octets, (addr_t)_padding_values.at(padd_num) - get_gadgets_offset())) << " + off) # " << 
                _padding_comments.at(padd_num) << "\n" ; 
            else
                ss << tab << pack << str_special(value_to_hex_str(octets, (addr_t)_padding_values.at(padd_num))) << ") # " << 
                _padding_comments.at(padd_num) << "\n"; 
        }
    }
    return ss.str(); 
}

// Assign 
void ROPChain::copy_from(ROPChain* other){
    _len = other->len(); 
    _nb_gadgets = other->nb_gadgets(); 
    _nb_instr = other->nb_instr(); 
    _nb_instr_ir = other->nb_instr_ir();
    
    _chain = other->chain();
    _padding_values = other->padding_values();
    _padding_comments = other->padding_comments();
    _padding_offsets = other->padding_offsets();
    return;
}
