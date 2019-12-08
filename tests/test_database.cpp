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
            
            db.add(make_tuple(1,2), g1, all);
            nb += _assert(db.get(make_tuple(1,2))[0] == g1->id, "BaseDB, failed to add then get gadget");
            db.add(make_tuple(1,4456), g2, all);
            nb += _assert(db.get(make_tuple(1,4456))[0] == g2->id, "BaseDB, failed to add then get gadget");

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
    // Return res
    cout << "\t" << total << "/" << total << green << "\t\tOK" << def << endl;
}
