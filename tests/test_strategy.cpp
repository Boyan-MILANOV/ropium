#include "strategy.hpp"
#include "compiler.hpp"
#include "il.hpp"
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
            
            sgraph.rule_generic_transitivity(n1);
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
            
            raw.push_back(RawGadget(string("\x89\xF5\xFF\xE0", 4), 9)); // mov ebp, esi; jmp eax
            raw.push_back(RawGadget(string("\xB8\x09\x00\x00\x00\xC3", 6), 10)); // mov eax, 9; ret
            raw.push_back(RawGadget(string("\x8B\x4F\x04\xFF\xE0", 5), 11)); // mov ecx, [edi+4]; jmp eax
            
            db.analyse_raw_gadgets(raw, arch);
            
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
            sgraph.rule_generic_transitivity(n2);
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
            graph3.rule_generic_transitivity(n1);
            graph3.select_gadgets(db);
            ropchain = graph3.get_ropchain(arch);
            nb += _assert_ropchain(ropchain, "Basic application of strategy rule failed");
            
            // Test MovCst pop
            StrategyGraph graph4;
            n1 = graph4.new_node(GadgetType::MOV_CST);
            Node& node1c = graph4.nodes[n1];
            node1c.params[PARAM_MOVCST_SRC_CST].make_cst(0x1234, "cst_2");
            node1c.params[PARAM_MOVCST_DST_REG].make_reg(X86_ESI);
            // Apply strat
            graph4.rule_mov_cst_pop(n1, arch);
            graph4.select_gadgets(db, nullptr, arch);
            ropchain = graph4.get_ropchain(arch);
            nb += _assert_ropchain(ropchain, "Basic application of strategy rule failed");

            // Test generic adjust jmp
            StrategyGraph graph5;
            n1 = graph5.new_node(GadgetType::MOV_REG);
            Node& node1d = graph5.nodes[n1];
            node1d.params[PARAM_MOVREG_SRC_REG].make_reg(X86_ESI);
            node1d.params[PARAM_MOVREG_DST_REG].make_reg(X86_EBP);
            node1d.branch_type = BranchType::RET; // So the rule applies
            // Apply strat
            graph5.rule_generic_adjust_jmp(n1, arch);
            graph5.select_gadgets(db, nullptr, arch);
            ropchain = graph5.get_ropchain(arch);
            nb += _assert_ropchain(ropchain, "Basic application of strategy rule failed");
            
            StrategyGraph graph6;
            n1 = graph6.new_node(GadgetType::LOAD);
            Node& node1e = graph6.nodes[n1];
            node1e.params[PARAM_LOAD_SRC_ADDR_REG].make_reg(X86_EDI);
            node1e.params[PARAM_LOAD_SRC_ADDR_OFFSET].make_cst(4, "cstlalal");
            node1e.params[PARAM_LOAD_DST_REG].make_reg(X86_ECX);
            node1e.branch_type = BranchType::RET; // So the rule applies
            // Apply strat
            graph6.rule_generic_adjust_jmp(n1, arch);
            graph6.select_gadgets(db, nullptr, arch);
            ropchain = graph6.get_ropchain(arch);
            nb += _assert_ropchain(ropchain, "Basic application of strategy rule failed");

            delete arch;
            return nb;
        }
        
        
        unsigned int test_generic_adjust_jmp(){
            unsigned int nb = 0;
            Arch* arch = new ArchX86();
            GadgetDB db;
            ROPChain* ropchain;

            vector<RawGadget> raw;
            raw.push_back(RawGadget(string("\x89\xC8\xC3", 3), 1)); // mov eax, ecx; ret
            raw.push_back(RawGadget(string("\xc3", 1), 2)); // ret
            raw.push_back(RawGadget(string("\x89\xF1\xFF\xE0", 4), 3)); // mov ecx, esi; jmp eax
            raw.push_back(RawGadget(string("\x5A\x59\xC3", 3), 4)); // pop edx; pop ecx; ret
            db.analyse_raw_gadgets(raw, arch);

            // Test on more advanced example (eax = esi)
            StrategyGraph sgraph;
            node_t n1 = sgraph.new_node(GadgetType::MOV_REG);
            Node& node1 = sgraph.nodes[n1];
            node1.params[PARAM_MOVREG_DST_REG].make_reg(X86_EAX);
            node1.params[PARAM_MOVREG_SRC_REG].make_reg(X86_ESI);
            // Apply strat
            sgraph.rule_generic_transitivity(n1);
            sgraph.rule_generic_adjust_jmp(1, arch);
            sgraph.rule_generic_transitivity(3);
            sgraph.rule_mov_cst_pop(5, arch);
            sgraph.select_gadgets(db, nullptr, arch);
            ropchain = sgraph.get_ropchain(arch);
            nb += _assert_ropchain(ropchain, "Basic application of strategy rule failed");

            delete arch;
            return nb;
        }
        
        
        unsigned int test_adjust_load(){
            unsigned int nb = 0;
            Arch* arch = new ArchX86();
            GadgetDB db;
            ROPChain* ropchain;

            vector<RawGadget> raw;
            raw.push_back(RawGadget(string("\x8B\x41\x08\xC3", 4), 1)); // mov eax, [ecx + 8]; ret
            raw.push_back(RawGadget(string("\x8D\x4B\x08\xC3", 4), 2)); // lea ecx, [ebx + 8]; ret

            raw.push_back(RawGadget(string("\x23\x56\xF8\xC3", 4), 3)); // and edx, [esi - 8]; ret
            raw.push_back(RawGadget(string("\x8D\x77\x10\xC3", 4), 4)); // lea esi, [edi + 16]; ret
            db.analyse_raw_gadgets(raw, arch);

            // Test adjust load on LOAD type
            StrategyGraph sgraph;
            node_t n1 = sgraph.new_node(GadgetType::LOAD);
            Node& node1 = sgraph.nodes[n1];
            node1.params[PARAM_LOAD_DST_REG].make_reg(X86_EAX);
            node1.params[PARAM_LOAD_SRC_ADDR_REG].make_reg(X86_EBX);
            node1.params[PARAM_LOAD_SRC_ADDR_OFFSET].make_cst(0x10, "cst_0");
            // Apply strat
            sgraph.rule_adjust_load(n1, arch);
            sgraph.select_gadgets(db, nullptr, arch);
            ropchain = sgraph.get_ropchain(arch);
            nb += _assert_ropchain(ropchain, "Basic application of strategy rule failed");

            // Test adjust load on ALOAD type
            StrategyGraph sgraph2;
            node_t n2 = sgraph2.new_node(GadgetType::ALOAD);
            Node& node2 = sgraph2.nodes[n2];
            node2.params[PARAM_ALOAD_DST_REG].make_reg(X86_EDX);
            node2.params[PARAM_ALOAD_OP].make_op(Op::AND);
            node2.params[PARAM_ALOAD_SRC_ADDR_REG].make_reg(X86_EDI);
            node2.params[PARAM_ALOAD_SRC_ADDR_OFFSET].make_cst(8, "cst_0");
            // Apply strat
            sgraph2.rule_adjust_load(n2, arch);
            sgraph2.select_gadgets(db, nullptr, arch);
            ropchain = sgraph2.get_ropchain(arch);
            nb += _assert_ropchain(ropchain, "Basic application of strategy rule failed");
            delete arch;
            return nb;
        }
        
        unsigned int test_generic_src_transitivity(){
            unsigned int nb = 0;
            Arch* arch = new ArchX86();
            GadgetDB db;
            ROPChain* ropchain;

            vector<RawGadget> raw;
            raw.push_back(RawGadget(string("\x89\x51\xEC\xC3", 4), 1)); // mov [ecx - 20], edx; ret
            raw.push_back(RawGadget(string("\x89\xC2\xC3", 3), 2)); // mov edx, eax; ret
            raw.push_back(RawGadget(string("\x31\x51\xEC\xC3", 4), 3)); // xor [ecx - 20], edx; ret
            db.analyse_raw_gadgets(raw, arch);

            // Test src transitivity on STORE
            StrategyGraph sgraph;
            node_t n1 = sgraph.new_node(GadgetType::STORE);
            Node& node1 = sgraph.nodes[n1];
            node1.params[PARAM_STORE_DST_ADDR_REG].make_reg(X86_ECX);
            node1.params[PARAM_STORE_DST_ADDR_OFFSET].make_cst(-20, "cst_0");
            node1.params[PARAM_STORE_SRC_REG].make_reg(X86_EAX);
            // Apply strat
            sgraph.rule_generic_src_transitivity(n1);
            sgraph.select_gadgets(db, nullptr, arch);
            ropchain = sgraph.get_ropchain(arch);
            nb += _assert_ropchain(ropchain, "Basic application of strategy rule failed");
            
            // Test src transitivity on ASTORE
            StrategyGraph sgraph2;
            node_t n2 = sgraph2.new_node(GadgetType::ASTORE);
            Node& node2 = sgraph2.nodes[n2];
            node2.params[PARAM_ASTORE_DST_ADDR_REG].make_reg(X86_ECX);
            node2.params[PARAM_ASTORE_DST_ADDR_OFFSET].make_cst(-20, "cst_0");
            node2.params[PARAM_ASTORE_SRC_REG].make_reg(X86_EAX);
            node2.params[PARAM_ASTORE_OP].make_op(Op::XOR);
            // Apply strat
            sgraph2.rule_generic_src_transitivity(n2);
            sgraph2.select_gadgets(db, nullptr, arch);
            ropchain = sgraph2.get_ropchain(arch);
            nb += _assert_ropchain(ropchain, "Basic application of strategy rule failed");

            return nb;
        }
        
        unsigned int test_adjust_store(){
            unsigned int nb = 0;
            Arch* arch = new ArchX86();
            GadgetDB db;
            ROPChain* ropchain;

            vector<RawGadget> raw;
            raw.push_back(RawGadget(string("\x89\x41\x08\xC3", 4), 1)); // mov [ecx + 8], eax; ret
            raw.push_back(RawGadget(string("\x8D\x4B\x08\xC3", 4), 2)); // lea ecx, [ebx + 8]; ret

            raw.push_back(RawGadget(string("\x21\x56\xF8\xC3", 4), 3)); // and [esi - 8], edx; ret
            raw.push_back(RawGadget(string("\x8D\x77\x10\xC3", 4), 4)); // lea esi, [edi + 16]; ret
            
            raw.push_back(RawGadget(string("\x89\xC8\xC3", 3), 5)); // mov eax, ecx; ret
            raw.push_back(RawGadget(string("\x89\xC3\xC3", 3), 6)); // mov ebx, eax; ret
            raw.push_back(RawGadget(string("\x89\x43\x08\xC3", 4), 7)); // mov [ebx + 8], eax; ret

            db.analyse_raw_gadgets(raw, arch);

            // Test adjust store on STORE type
            StrategyGraph sgraph;
            node_t n1 = sgraph.new_node(GadgetType::STORE);
            Node& node1 = sgraph.nodes[n1];
            node1.params[PARAM_STORE_DST_ADDR_REG].make_reg(X86_EBX);
            node1.params[PARAM_STORE_DST_ADDR_OFFSET].make_cst(16, "cst_0");
            node1.params[PARAM_STORE_SRC_REG].make_reg(X86_EAX);
            // Apply strat
            sgraph.rule_adjust_store(n1, arch);
            sgraph.select_gadgets(db, nullptr, arch);
            ropchain = sgraph.get_ropchain(arch);
            nb += _assert_ropchain(ropchain, "Basic application of strategy rule failed");

            // Test adjust store on ASTORE type
            StrategyGraph sgraph2;
            node_t n2 = sgraph2.new_node(GadgetType::ASTORE);
            Node& node2 = sgraph2.nodes[n2];
            node2.params[PARAM_ASTORE_DST_ADDR_REG].make_reg(X86_EDI);
            node2.params[PARAM_ASTORE_DST_ADDR_OFFSET].make_cst(8, "cst_0");
            node2.params[PARAM_ASTORE_SRC_REG].make_reg(X86_EDX);
            node2.params[PARAM_ASTORE_OP].make_op(Op::AND);
            // Apply strat
            sgraph2.rule_adjust_store(n2, arch);
            sgraph2.select_gadgets(db, nullptr, arch);
            ropchain = sgraph2.get_ropchain(arch);
            nb += _assert_ropchain(ropchain, "Basic application of strategy rule failed");

            // ANother adjust store on STORE mixed with src_transitivity
            StrategyGraph sgraph3;
            node_t n3 = sgraph3.new_node(GadgetType::STORE);
            Node& node3 = sgraph3.nodes[n3];
            node3.params[PARAM_STORE_DST_ADDR_REG].make_reg(X86_EAX);
            node3.params[PARAM_STORE_DST_ADDR_OFFSET].make_cst(8, "cst_0");
            node3.params[PARAM_STORE_SRC_REG].make_reg(X86_ECX);
            // Apply strat
            sgraph3.rule_adjust_store(n3, arch);
            sgraph3.rule_generic_src_transitivity(2);

            sgraph3.select_gadgets(db, nullptr, arch);
            ropchain = sgraph3.get_ropchain(arch);
            nb += _assert_ropchain(ropchain, "Basic application of strategy rules failed");

            delete arch;
            return nb;
        }
        
        unsigned int test_cst_pop(){
            unsigned int nb = 0;
            /*
            Arch* arch = new ArchX86();
            GadgetDB db;
            ROPChain* ropchain;
            
            vector<RawGadget> raw;
            raw.push_back(RawGadget(string("\x59\x58\x5B\xFF\xE0", 5), 1)); // pop ecx; pop eax; pop ebx; jmp eax
            raw.push_back(RawGadget(string("\xC3", 1), 2)); // ret
            db.analyse_raw_gadgets(raw, arch);

            // Test cst_pop on a function call strategy graph 
            vector<StrategyGraph*> graphs;
            ROPCompiler* comp = new ROPCompiler(arch, &db);
            vector<ILInstruction> instrs = comp->parse("0x1234()");
            comp->il_to_strategy(graphs, instrs[0], NULL, ABI::X86_CDECL);

            // Apply strat
            graphs[0]->rule_mov_cst_pop(1, arch);
            
            graphs[0]->select_gadgets(db);
            ropchain = graphs[0]->get_ropchain(arch);
            // nb += _assert_ropchain(ropchain, "Basic application of strategy rule failed");

            delete arch;
            delete comp;
            */
            return nb;
        }
        
        // Buggy X64 syscall...
        unsigned int test_x64_syscall(){
            unsigned int nb = 0;
            /*  DOESN'T WORK ANYMORE WITH NEW COMPILER MECANISM
            
            Arch* arch = new ArchX64();
            GadgetDB db;
            ROPChain* ropchain = nullptr;
            
            vector<RawGadget> raw;
            raw.push_back(RawGadget(string("\x58\xC3", 2), 1)); // pop rax; ret
            raw.push_back(RawGadget(string("\x5F\xC3", 2), 2)); // pop rdi; ret
            raw.push_back(RawGadget(string("\x83\xC5\x20\x0F\x05", 5), 3)); // add ebp, 32; syscall
            raw.push_back(RawGadget(string("\x5E\xC3", 2), 4)); // pop rsi; ret
            raw.push_back(RawGadget(string("\x59xC3", 2), 5)); // pop rcx; ret
            raw.push_back(RawGadget(string("\x41\x5F\xC3", 3), 6)); // pop r15; ret
            raw.push_back(RawGadget(string("\x48\x89\xC2\x41\xFF\xD7", 6), 7)); // mov rdx, rax; call r15
            db.analyse_raw_gadgets(raw, arch);
            

            // Test cst_pop on a function call strategy graph 
            vector<StrategyGraph*> graphs;
            ROPCompiler* comp = new ROPCompiler(arch, &db);
            string query = "sys_11(1,2,3)";
            vector<ILInstruction> instrs = comp->parse(query);
            comp->il_to_strategy(graphs, instrs[0], nullptr, ABI::NONE, System::LINUX);

            // Apply strat
            graphs[0]->rule_mov_cst_pop(1, arch);
            graphs[0]->rule_mov_cst_pop(2, arch);
            // Adjust rdx 
            graphs[0]->rule_generic_adjust_jmp(3, arch);
            graphs[0]->rule_mov_cst_pop(7, arch);
            graphs[0]->rule_generic_transitivity(3);
            graphs[0]->rule_mov_cst_pop(10, arch);
            // Adjust eax
            graphs[0]->rule_mov_cst_pop(4, arch);

            graphs[0]->select_gadgets(db, nullptr, arch);
            ropchain = graphs[0]->get_ropchain(arch);
            nb += _assert_ropchain(ropchain, "Applications of rules to get syscall ropchain failed");

            for( auto g : graphs ){
                delete g;
            }
            
            delete arch;
            delete comp;
            
            */

            
            
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
        total += test_generic_adjust_jmp();
        total += test_adjust_load();
        total += test_generic_src_transitivity();
        total += test_adjust_store();
        total += test_cst_pop();
        total += test_x64_syscall();
    }

    // Return res
    cout << "\t\t" << total << "/" << total << green << "\t\tOK" << def << endl;
}
