#include "database.hpp"
#include "exception.hpp"
#include <string>
#include <sstream>
#include <tuple>
#include <iostream>
#include <iomanip>
#include <algorithm>

using std::cout;
using std::endl; 
using std::string;
using std::make_tuple;
using std::tuple;

namespace test{
    namespace database{
        unsigned int _assert(bool val, const string& msg){
            if( !val){
                cout << "\nFail: " << msg << endl << std::flush; 
                throw test_exception();
            }
            return 1; 
        }
        
        unsigned int base_db(){
            BaseDB<tuple<int, int>> db;
            int nb = 0;
            Gadget *g1 = new Gadget(), *g2 = new Gadget();
            vector<Gadget*> all;
            g1->id = 0; g2->id = 1;
            all.push_back(g1);
            all.push_back(g2);
            
            db.add(make_tuple(1,2), g1);
            nb += _assert(db.get(make_tuple(1,2))[0] == g1, "BaseDB, failed to add then get gadget");
            db.add(make_tuple(1,4456), g2);
            nb += _assert(db.get(make_tuple(1,4456))[0] == g2, "BaseDB, failed to add then get gadget");

            return nb; 
        }
        
        unsigned int _assert_db(addr_t addr, vector<Gadget*>& list){
            for( Gadget* g : list ){
                if( std::find(g->addresses.begin(), g->addresses.end(), addr) != g->addresses.end() )
                    return 1;
            }
            cout << "\nFail: " << "GadgetDB: failed to classify/return gadget correctly" << endl << std::flush; 
                throw test_exception();
        }
        
        unsigned int classification(){
            unsigned int nb = 0;
            Arch* arch = new ArchX86();
            GadgetDB db;

            vector<RawGadget> raw;
            raw.push_back(RawGadget(string("\xb8\x03\x00\x00\x00\xc3", 8), 0)); // mov eax, 3; ret
            raw.push_back(RawGadget(string("\x89\xf9\xbb\x01\x00\x00\x00\xc3", 8), 1)); // mov ecx, edi; mov ebx, 1; ret
            
            vector<Gadget*> gadget_list = gadgets_from_raw(raw, arch);
            
            for( Gadget* gadget : gadget_list ){
                db.add(gadget);
            }

            // Test gadget classification
            nb += _assert_db(0, db.get_mov_cst(X86_EAX, 3));
            nb += _assert_db(1, db.get_mov_cst(X86_EBX, 1));
            nb += _assert_db(1, db.get_mov_reg(X86_ECX, X86_EDI));
            
            
            delete arch;
            return nb;
        }
    }
}

using namespace test::database; 
// All unit tests 
void test_database(){
    unsigned int total = 0;
    string green = "\033[1;32m";
    string def = "\033[0m";
    string bold = "\033[1m";
    
    // Start testing 
    cout << bold << "[" << green << "+" << def << bold << "]" << def << std::left << std::setw(34) << " Testing gadget database... " << std::flush;  
    total += base_db();
    total += classification();
    // Return res
    cout << "\t" << total << "/" << total << green << "\t\tOK" << def << endl;
}
