#include "ir.hpp"
#include "exception.hpp"
#include <cassert>
#include <iostream>
#include <string>
#include <sstream>
#include <iomanip>

using std::cout;
using std::endl; 
using std::string;

namespace test{
    namespace ir{
        unsigned int _assert(bool val, const string& msg){
            if( !val){
                cout << "\nFail: " << msg << endl << std::flush; 
                throw test_exception();
            }
            return 1; 
        }
        
        unsigned int ir_context(){
            IRContext ctx = IRContext(4);
            Expr    e1 = exprcst(32, 56),
                    e2 = exprvar(64, "var1"),
                    e3 = exprvar(16, "var2");
            unsigned int nb = 0;
            ctx.set(0, e1);
            ctx.set(1, e1);
            ctx.set(2, e2);
            ctx.set(3, e3);
            nb += _assert(ctx.get(0)->eq(e1), "IRContext failed to update then get variable");
            nb += _assert(ctx.get(1)->eq(e1), "IRContext failed to update then get variable");
            nb += _assert(ctx.get(2)->eq(e2), "IRContext failed to update then get variable");
            nb += _assert(ctx.get(3)->eq(e3), "IRContext failed to update then get variable");
            return nb; 
        }
    }
    
    
}

using namespace test::ir; 
// All unit tests 
void test_ir(){
    unsigned int total = 0;
    string green = "\033[1;32m";
    string def = "\033[0m";
    string bold = "\033[1m";
    
    // Start testing 
    cout << bold << "[" << green << "+" << def << bold << "]" << def << std::left << std::setw(34) << " Testing ir module... " << std::flush;  
    total += ir_context();
    // Return res
    cout << "\t" << total << "/" << total << green << "\t\tOK" << def << endl;
}
