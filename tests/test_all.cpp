#include "exception.hpp"
#include <string>
#include <cstring>
#include <iostream>
#include <exception>

using std::cout;
using std::endl;
using std::string;

void test_expression();
void test_simplification();
void test_ir();
void test_database();
void test_gadgets();
void test_strategy();
void test_il();
void test_compiler();

int main(int argc, char ** argv){
    string bold = "\033[1m";
    string def = "\033[0m";
    string red = "\033[1;31m";
    string green = "\033[1;32m";
    
    cout << bold << "\nRunnning ROPGenerator unit-tests" << def << endl
                 <<   "================================" << endl << endl;
     for(int i = 0; i < 1; i++){
        try{
            if( argc == 1 ){
            /* If no args specified, test all */
                test_expression();
                test_simplification();
                test_ir();
                test_gadgets();
                test_database();
                test_strategy();
                test_il();
                test_compiler();
            }else{
            /* Iterate through all options */
                for( int i = 1; i < argc; i++){
                    if( !strcmp(argv[i], "expr"))
                        test_expression();
                    else if (!strcmp(argv[i], "simp"))
                        test_simplification();
                    else if (!strcmp(argv[i], "ir"))
                        test_ir();
                    else if( !strcmp(argv[i], "db"))
                        test_database();
                    else if( !strcmp(argv[i], "gadgets"))
                        test_gadgets();
                    else if( !strcmp(argv[i], "strategy"))
                        test_strategy();
                    else if( !strcmp(argv[i], "il"))
                        test_il();
                    else if( !strcmp(argv[i], "compiler"))
                        test_compiler();
                    else
                        std::cout << "[" << red << "!" << def << "] Skipping unknown test: " << argv[i] << std::endl;
                }
            }
        }catch(test_exception& e){
            cout << red << "Fatal: Unit test failed" << def << endl << endl;
            return 1; 
        }
    }
    cout << endl;
    return 0;
}
