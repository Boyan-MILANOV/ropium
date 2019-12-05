#include "expression.hpp"
#include "simplification.hpp"
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
    namespace expression{
        // Individual unit tests
        unsigned int basic(){
            Expr e1, e2, e3, e4, e5, e6, e7, e8; 
            for( int i = 0; i < 10; i++){
                e1 = exprcst(32, -1);
                e2 = exprcst(32, 1048567);
                e3 = exprmem(32, e2);
                e4 = -e1;
                e5 = e2 - e1;
                e6 = extract(e1, 31, 23);
                e7 = e6;
            }
            return 0;
        }

        /* Expression hashing */
        unsigned int _assert_hash_eq(Expr e1, Expr e2){
            if( e1->hash() != e2->hash() ){
                cout << endl << "Fail: _assert_hash_eq: " << e1 << " == " << e2 << endl;
                throw test_exception();  
            }
            return 1; 
        }
        
        unsigned int _assert_hash_neq(Expr e1, Expr e2){
            if( e1->hash() == e2->hash() ){
                cout << endl << "Fail: _assert_hash_eq: " << e1 << " == " << e2 << endl;
                throw test_exception();  
            }
            return 1; 
        }
        unsigned hashing(){
            Expr    e1 = exprcst(32,1),
                    e2 = exprvar(32, "var1"),
                    e3 = exprmem(32, e2),
                    e4 = -e1,
                    e5 = e2 & e3,
                    e6 = exprmem(32, e5),
                    e7 = exprmem(32, e6),
                    e8 = bisz(32, e5, 1),
                    e9 = e3 % e5;;
            unsigned int nb = 0;
            // Hash equality 
            nb += _assert_hash_eq(e1, exprcst(32,1));
            nb += _assert_hash_eq(e2, exprvar(32, "var1"));
            nb += _assert_hash_eq(e3, exprmem(32, e2));
            nb += _assert_hash_eq(e4, (-e1));
            nb += _assert_hash_eq(e5, (e2 & e3));
            nb += _assert_hash_eq(e6, exprmem(32, e5));
            nb += _assert_hash_eq(e7, exprmem(32,e6));
            nb += _assert_hash_eq(e8, bisz(32, e5, 1));
            nb += _assert_hash_eq(e9, e3%e5);
            // Hash inequality
            nb += _assert_hash_neq(e1, e2);
            nb += _assert_hash_neq(e2,e3);
            nb += _assert_hash_neq(e3,e4);
            nb += _assert_hash_neq(e4,e5);
            nb += _assert_hash_neq(e5,e6);
            nb += _assert_hash_neq(e6,e7);
            nb += _assert_hash_neq(e8, bisz(32, e5, 0));
            nb += _assert_hash_neq(e9, e5%e3);
            return nb;
        }
        
        /* Expression Canonization */
        unsigned int _assert_canonize_eq(Expr e1, Expr e2 ){
            Expr tmp1 = expr_canonize(e1), tmp2 = expr_canonize(e2);
            if(!(tmp1->eq(tmp2))){
                cout << endl << "Fail:  _assert_canonize_eq: " << e1 << " <==> " << e2 << endl
                << "Note: canonized as : " << tmp1 << " <==> " << tmp2 << endl << std::flush;
                throw test_exception(); 
            }
            return 1;
        }
        unsigned int _assert_canonize_neq(Expr e1, Expr e2 ){
            Expr tmp1 = expr_canonize(e1), tmp2 = expr_canonize(e2);
            if(!tmp1->neq(tmp2)){
                cout << endl << "Fail:  _assert_canonize_neq: " << e1 << " <=/=> " << e2 << endl
                << "Note: canonized as : " << tmp1 << " <==> " << tmp2 << endl << std::flush;
                throw test_exception(); 
            }
            return 1;
        }
        unsigned int canonize(){
            Expr    cst1 = exprcst(32, 1),
                    cst2 = exprcst(32, 567),
                    var1 = exprvar(32, "var1"),
                    var2 = exprvar(32, "var2"),
                    var3 = exprvar(32, "var3"),
                    un1 = -var2,
                    bin1 = var1+var2,
                    bin2 = var3/var2,
                    bin3 = sdiv(var3,var2); 
            unsigned int nb = 0;
            // a+b == b+a 
            nb += _assert_canonize_eq((cst1+cst2), (cst2+cst1));
            nb += _assert_canonize_eq((cst1+var1), (var1+cst1));
            nb += _assert_canonize_eq((bin3+var1), (var1+bin3));
            nb += _assert_canonize_eq((bin1+bin2), (bin2+bin1));
            nb += _assert_canonize_eq((bin1+bin1), (bin1+bin1)); 
            // a*b == b*a
            nb += _assert_canonize_eq((cst1*cst2), (cst2*cst1));
            nb += _assert_canonize_eq((cst1*var1), (var1*cst1));
            // (a^b)^c == (c^b)^a
            nb += _assert_canonize_eq( cst1^var1^bin3, cst1^bin3^var1);
            // a/b/c == a/c/b
            nb += _assert_canonize_eq( var2/var3/un1, var2/un1/var3);
            // a/b != b/a 
            nb += _assert_canonize_neq(var3/cst1, cst1/var3);
            // a<<b != b<<a
            nb += _assert_canonize_neq(shl(bin1,bin2), shl(bin2, bin1));
            // a-b-c == a-c-b
            nb += _assert_canonize_eq(cst1-var1-bin3, cst1-bin3-var1);
            // a-b != b-a
            nb += _assert_canonize_neq(cst2-un1, un1-cst2);
            // Concat reordering
            nb += _assert_canonize_eq(concat(var1, concat(var2, var3)), concat(concat(var1, var2), var3));
            return nb;  
        };
        

        unsigned int _assert(bool val, const string& msg){
            if( !val){
                cout << "\nFail: " << msg << endl << std::flush; 
                throw test_exception();
            }
            return 1; 
        }
        
    }
}

using namespace test::expression; 
// All unit tests 
void test_expression(){
    unsigned int total = 0;
    string green = "\033[1;32m";
    string def = "\033[0m";
    string bold = "\033[1m";
    
    // Start testing 
    cout << bold << "[" << green << "+" << def << bold << "]" << def << std::left << std::setw(34) << " Testing expression module... " << std::flush;  
    total += basic();
    total += canonize();
    total += hashing();
    // Return res
    cout << "\t" << total << "/" << total << green << "\t\tOK" << def << endl;
}
