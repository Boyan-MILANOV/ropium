#include "strategy.hpp"
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
    namespace strategy{        

        
        unsigned int _assert(bool val, const string& msg){
            if( !val){
                cout << "\nFail: " << msg << endl << std::flush; 
                throw test_exception();
            }
            return 1; 
        }
        
        unsigned int basic(){
            unsigned int nb = 0;
            StrategyGraph sgraph;
            node_t n1 = sgraph.new_node(GadgetType::MOV_REG);
            node_t n2 = sgraph.new_node(GadgetType::MOV_REG);
            Node& node1 = sgraph.nodes[n1];
            Node& node2 = sgraph.nodes[n2];
            node1.params[PARAM_MOVREG_SRC_REG].make_reg(X86_EAX);
            node1.params[PARAM_MOVREG_DST_REG].make_reg(n2, PARAM_MOVREG_SRC_REG);
            node2.params[PARAM_MOVREG_SRC_REG].make_reg(-1, false);
            node2.params[PARAM_MOVREG_DST_REG].make_reg(X86_ECX);
            sgraph.add_strategy_edge(n1, n2);
            sgraph.add_param_edge(n1, n2);
            // std::cout << sgraph;
            
            sgraph.rule_mov_reg_transitivity(n1);
            // std::cout << sgraph;
            return nb;
        }

    }
}

using namespace test::strategy;
// All unit tests 
void test_strategy(){    
    unsigned int total = 0;
    string green = "\033[1;32m";
    string def = "\033[0m";
    string bold = "\033[1m";
    
    // Start testing 
    cout << bold << "[" << green << "+" << def << bold << "]" << def << " Testing strategy graphs... " << std::flush;
    for( int i = 0; i < 1; i++){
        total += basic();
    }

    // Return res
    cout << "\t\t" << total << "/" << total << green << "\t\tOK" << def << endl;
}
