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
        
        unsigned int set_and_get(){
            BaseDB<tuple<int, int>> db;
            int nb = 0;
            db.add(make_tuple(1,2), 10);
            nb += _assert(db.get(make_tuple(1,2)) == 10, "BaseDB, failed to add then get gadget");
            db.add(make_tuple(1,2), 12);
            nb += _assert(db.get(make_tuple(1,2)) == 12, "BaseDB, failed to add then get gadget");
            db.add(make_tuple(0,456789), 7);
            nb += _assert(db.get(make_tuple(0,456789)) == 7, "BaseDB, failed to add then get gadget");

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
    total += set_and_get();
    // Return res
    cout << "\t" << total << "/" << total << green << "\t\tOK" << def << endl;
}
