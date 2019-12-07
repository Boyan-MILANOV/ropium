#include "utils.hpp"
#include "exception.hpp"
#include <iostream>
#include <fstream>

using std::ifstream;
using std::ios;

/* ======== Raw gadgets interface ======== */
// Read gadgets from file
vector<RawGadget>* raw_gadgets_from_file(string filename){
    vector<RawGadget>* res = new vector<RawGadget>();
    RawGadget raw;
    bool got_addr;
    ifstream file;
    string line;
    string addr_str;
    file.open(filename, ios::in | ios::binary );
    while( getline(file, line)){
        raw = RawGadget();
        got_addr = false;
        for( char& c : line ){
            // First the gadget address
            if( c == '$' ){
                try{
                    raw.addr = std::stoi(addr_str);
                    got_addr = true;
                }catch(std::invalid_argument const& e){
                    throw runtime_exception("raw_gadgets_from_file: error, bad address string");
                }
            }else if( !got_addr){
                addr_str += c;
            }else{
                raw.raw += c;
            }
        }
        res->push_back(raw);
    }
    
    file.close();
    return res;
}
