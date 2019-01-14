#include "ROPChain.hpp"
#include "Database.hpp"
#include "CommonUtils.hpp"
#include "IO.hpp"
#include <algorithm>

ROPChain::ROPChain(){}
// Accessors
int ROPChain::len(){return _len;}
int ROPChain::nb_gadgets(){return _nb_gadgets;}
int ROPChain::nb_instr(){return _nb_instr;}
int ROPChain::nb_instr_ir(){return _nb_instr_ir;}

// Modifiers
void ROPChain::add_gadget(int g){
    _chain.push_back(g);
    _len++; 
    _nb_instr += gadget_db()->get(g)->nb_instr();
    _nb_instr_ir += gadget_db()->get(g)->nb_instr_ir();
    _nb_gadgets++; 
}

void ROPChain::add_padding(cst_t value, string comment="Padding", int n=1){
    int num; 
    if( n == 0 )
        return; 
    // Get padding number 
    num = _padding_values.size()+1;
    // Add padding 
    _padding_values.push_back(value);
    _padding_comments.push_back(comment); 
    // Add to the chain 
    _len += n; 
    for( ;n--; n>0)
        _chain.push_back(-1*num);
}

void ROPChain::add_chain(ROPChain* other){
    vector<int>::iterator it; 
    int num; 
    _len += other->len(); 
    _nb_gadgets += other->nb_gadgets(); 
    _nb_instr += other->nb_instr(); 
    _nb_instr_ir += other->nb_instr_ir(); 
    
    for( it = other->_chain.begin(); it != other->_chain.end(); it++){
        // Gadget
        if( *it >= 0 ){
            _chain.push_back(*it);
        }else {
        // Padding 
            // Get padding number 
            num = _padding_values.size()+1;
            // Add padding 
            _padding_values.push_back(other->_padding_values.at(-1*(*it) -1));
            _padding_comments.push_back(other->_padding_comments.at(-1*(*it) -1)); 
            _chain.push_back(-1*num);
        }
    }
}

// Sort
bool ROPChain::lthan(ROPChain* other){
    if( _len == other->len() )
        if( _nb_instr == other->nb_instr() )
            if( _nb_instr_ir >= other->nb_instr_ir() )
                return false; 
        return _nb_instr < other->nb_instr(); 
    return _len < other->len(); 
}

// String representation 
string valid_addr_str(int octets, Gadget* g, vector<unsigned char> bad_bytes){
    int i;
    vector<addr_t>::iterator it; 
    for( it = g->addresses().begin(); it != g->addresses().end(); it++){
        // Test if bad bytes inside 
        for( i=0; i < octets; i++)
            if (std::find( bad_bytes.begin(), bad_bytes.end(), (unsigned char)( ((*it) >> i) & 0xff)) != bad_bytes.end())
                break;
        if( i == octets ){
            return value_to_hex_str(octets, *it);
        }
    }
    throw "Error, No valid address found for the gadget to print ! :( ";
}

string ROPChain::to_str_console(int octets, vector<unsigned char> bad_bytes){
    stringstream ss;
    vector<int>::iterator it; 
    int padd_num; 
    
    for(it = _chain.begin(); it != _chain.end(); it++){
        if( *it >= 0 ){
            // Gadget 
            ss << "\n\t" << str_special(valid_addr_str(octets, gadget_db()->get(*it), bad_bytes)) << " (" << 
                str_bold(gadget_db()->get(*it)->asm_str()) << ")";
        }else{
            // Padding 
            padd_num = -1*(*it)-1; 
            ss << "\n\t" << value_to_hex_str(octets, _padding_values.at(padd_num)) << " (" << 
            _padding_comments.at(padd_num) << ")"; 
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
        return string("Doesn't support printing for non 4 or 8 octets");
    pack = p + " += pack(" + endian + ","; 
    
    if( init )
        ss << tab << "from struct import pack\n" << tab << p << "+= ''";   
    
    for(it = _chain.begin(); it != _chain.end(); it++){
        if( *it >= 0 ){
            // Gadget 
            ss << "\n" << tab << pack << str_special(valid_addr_str(octets, gadget_db()->get(*it), bad_bytes)) <<
                ") # " << str_bold(gadget_db()->get(*it)->asm_str());
        }else{
            // Padding 
            padd_num = -1*(*it)-1; 
            ss << "\n" << tab << pack << value_to_hex_str(octets, _padding_values.at(padd_num)) << ") # " << 
            _padding_comments.at(padd_num); 
        }
    }
    return ss.str(); 
}
