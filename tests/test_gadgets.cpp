#include "database.hpp"
#include "exception.hpp"
#include <string>
#include <sstream>
#include <tuple>
#include <iostream>
#include <iomanip>

using std::cout;
using std::endl; 
using std::string;

namespace test{
    namespace gadgets{
        unsigned int _assert(bool val, const string& msg){
            if( !val){
                cout << "\nFail: " << msg << endl << std::flush; 
                throw test_exception();
            }
            return 1; 
        }
        
        unsigned int basic(){
            Arch* arch = new ArchX86();
            
            ropgadget_to_file("/tmp/gadgets.ropg", "/usr/bin/nmap");
            
            vector<RawGadget>* raw = raw_gadgets_from_file("/tmp/gadgets.ropg");
            std::cout << raw->at(0).raw << " and " << raw->at(0).addr << std::endl;
            
            vector<Gadget*> g = gadgets_from_raw(*raw, arch);
            std::cout << *(g[0]) << std::endl;
            std::cout << "DEBUG TOTAL GADGETS : " << g.size() << std::endl;
            
            delete raw;
            delete arch;
            return 1;
        }
    }
}

using namespace test::gadgets; 
// All unit tests 
void test_gadgets(){
    unsigned int total = 0;
    string green = "\033[1;32m";
    string def = "\033[0m";
    string bold = "\033[1m";
    
    // Start testing 
    cout << bold << "[" << green << "+" << def << bold << "]" << def << std::left << std::setw(34) << " Testing gadget analysis... " << std::flush;  
    // DEBUG total += basic();
    // Return res
    cout << "\t" << total << "/" << total << green << "\t\tOK" << def << endl;
}
