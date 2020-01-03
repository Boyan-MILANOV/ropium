#include "strategy.hpp"
#include "exception.hpp"
#include "utils.hpp"
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
        
        unsigned int _assert_ropchain(ROPChain* ropchain, const string& msg){
            if( ropchain == nullptr){
                cout << "\nFail: " << msg << endl << std::flush; 
                throw test_exception();
            }
            delete ropchain;
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
            //std::cout << sgraph;
            
            sgraph.rule_mov_reg_transitivity(n1);
            sgraph.compute_dfs_params();
            sgraph.compute_dfs_strategy();
            //std::cout << sgraph;
            return nb;
        }
        
        unsigned int rules(){
            unsigned int nb = 0;
            Arch* arch = new ArchX86();
            GadgetDB db;
            ROPChain* ropchain;

            vector<RawGadget> raw;
            raw.push_back(RawGadget(string("\x89\xf9\xbb\x01\x00\x00\x00\xc3", 8), 1)); // mov ecx, edi; mov ebx, 1; ret
            raw.push_back(RawGadget(string("\x89\xC8\xC3", 3), 2)); // mov eax, ecx; ret
            raw.push_back(RawGadget(string("\x89\xC3\xC3", 3), 3)); // mov ebx, eax; ret
            raw.push_back(RawGadget(string("\x89\xCB\xC3", 3), 4)); // mov ebx, ecx; ret
            raw.push_back(RawGadget(string("\xbb\x04\x00\x00\x00\xc3", 6), 5)); // mov ebx, 4; ret
            raw.push_back(RawGadget(string("\xb8\x05\x00\x00\x00\xc3", 6), 6)); // mov eax, 5; ret
            raw.push_back(RawGadget(string("\x89\xc2\xc3", 3), 7)); // mov edx, eax; ret
            raw.push_back(RawGadget(string("\x5f\x5e\x59\xc3", 4), 8)); // pop edi; pop esi; pop ecx; ret

            db.fill_from_raw_gadgets(raw, arch);
            
            // Test register transitivity
            StrategyGraph sgraph;
            node_t n1 = sgraph.new_node(GadgetType::MOV_REG);
            node_t n2 = sgraph.new_node(GadgetType::MOV_REG);
            Node& node1 = sgraph.nodes[n1];
            Node& node2 = sgraph.nodes[n2];
            node1.params[PARAM_MOVREG_SRC_REG].make_reg(X86_EDI);
            node1.params[PARAM_MOVREG_DST_REG].make_reg(n2, PARAM_MOVREG_SRC_REG);
            node2.params[PARAM_MOVREG_SRC_REG].make_reg(0, false);
            node2.params[PARAM_MOVREG_DST_REG].make_reg(X86_EBX);
            sgraph.add_strategy_edge(n1, n2);
            sgraph.add_param_edge(n1, n2);
            // Apply strat
            sgraph.rule_mov_reg_transitivity(n2);
            sgraph.select_gadgets(db);
            ropchain = sgraph.get_ropchain(arch);
            nb += _assert_ropchain(ropchain, "Basic application of strategy rule failed");

            // Test constant param resolving
            StrategyGraph graph2;
            n1 = graph2.new_node(GadgetType::MOV_CST);
            n2 = graph2.new_node(GadgetType::MOV_CST);
            Node& node1a = graph2.nodes[n1];
            Node& node2a = graph2.nodes[n2];
            node1a.params[PARAM_MOVCST_SRC_CST].make_cst(n2, PARAM_MOVCST_SRC_CST, exprvar(32, "cst1")+1, "cst2");
            node1a.params[PARAM_MOVCST_DST_REG].make_reg(X86_EAX);
            node2a.params[PARAM_MOVCST_SRC_CST].make_cst(0, "cst1", false); // free
            node2a.params[PARAM_MOVCST_DST_REG].make_reg(-1, false); // free
            graph2.add_strategy_edge(n1, n2);
            graph2.add_param_edge(n1, n2);

            graph2.select_gadgets(db);
            ropchain = graph2.get_ropchain(arch);
            nb += _assert_ropchain(ropchain, "Basic application of strategy rule failed");

            // Test MovCst transitivity
            StrategyGraph graph3;
            n1 = graph3.new_node(GadgetType::MOV_CST);
            Node& node1b = graph3.nodes[n1];
            node1b.params[PARAM_MOVCST_SRC_CST].make_cst(5, "cst_1");
            node1b.params[PARAM_MOVCST_DST_REG].make_reg(X86_EDX);
            // Apply strat
            graph3.rule_mov_cst_transitivity(n1);
            graph3.select_gadgets(db);
            ropchain = graph3.get_ropchain(arch);
            nb += _assert_ropchain(ropchain, "Basic application of strategy rule failed");
            
            // Test MovCst transitivity
            StrategyGraph graph4;
            n1 = graph4.new_node(GadgetType::MOV_CST);
            Node& node1c = graph4.nodes[n1];
            node1c.params[PARAM_MOVCST_SRC_CST].make_cst(0x1234, "cst_2");
            node1c.params[PARAM_MOVCST_DST_REG].make_reg(X86_ESI);
            // Apply strat
            graph4.rule_mov_cst_pop(n1, arch);
            graph4.select_gadgets(db);
            ropchain = graph4.get_ropchain(arch);
            nb += _assert_ropchain(ropchain, "Basic application of strategy rule failed");

            delete arch;
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
        total += rules();
    }

    // Return res
    cout << "\t\t" << total << "/" << total << green << "\t\tOK" << def << endl;
}
