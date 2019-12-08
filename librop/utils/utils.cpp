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
    string byte;
    
    file.open(filename, ios::in | ios::binary );
    while( getline(file, line)){
        raw = RawGadget();
        got_addr = false;
        addr_str = "";
        byte = "";
        for( char& c : line ){
            // First the gadget address
            if( c == '$' ){
                try{
                    raw.addr = std::stoi(addr_str, 0, 16);
                    if( raw.addr == 0 )
                        throw runtime_exception("");
                    got_addr = true;
                }catch(std::exception& e){
                    throw runtime_exception(QuickFmt() << "raw_gadgets_from_file: error, bad address string: " << addr_str >> QuickFmt::to_str);
                }
            }else if( !got_addr){
                addr_str += c;
            }else{
                byte += c;
                if( byte.size() == 2 ){
                    raw.raw += (char)(std::stoi(byte, 0, 16));
                    byte = "";
                }
            }
        }
        res->push_back(raw);
    }
    
    file.close();
    return res;
}

