#include "compiler.hpp"
#include "arch.hpp"
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
    namespace compiler{
        unsigned int _assert_ropchain(ROPChain* ropchain, const string& msg){
            if( ropchain == nullptr){
                cout << "\nFail: " << msg << endl << std::flush; 
                throw test_exception();
            }
            delete ropchain;
            return 1; 
        }

        unsigned int direct_match(){
            unsigned int nb = 0;
            ArchX86 arch;
            GadgetDB db;
            ROPCompiler comp = ROPCompiler(&arch, &db);
            ROPChain* ropchain;
            
            // Available gadgets
            vector<RawGadget> raw;
            raw.push_back(RawGadget(string("\x89\xf9\xbb\x01\x00\x00\x00\xc3", 8), 1)); // mov ecx, edi; mov ebx, 1; ret
            raw.push_back(RawGadget(string("\x89\xC8\xC3", 3), 2)); // mov eax, ecx; ret
            raw.push_back(RawGadget(string("\x89\xC3\xC3", 3), 3)); // mov ebx, eax; ret
            raw.push_back(RawGadget(string("\x01\xf0\x89\xc3\xc3", 5), 4)); // add eax, esp; mov ebx, eax; ret
            raw.push_back(RawGadget(string("\xbb\x04\x00\x00\x00\xc3", 6), 5)); // mov ebx, 4; ret
            raw.push_back(RawGadget(string("\x83\xc0\x04\x89\xc3\xc3", 6), 6)); // add eax, 4; mov ebx, eax; ret
            raw.push_back(RawGadget(string("\x8b\x59\xf7\x89\xd8\xc3", 6), 7)); // mov ebx, [ecx-9]; mov eax, ebx; ret
            raw.push_back(RawGadget(string("\x03\x39\xc3", 3), 8)); // add edi, [ecx]; ret
            raw.push_back(RawGadget(string("\xb9\x0a\x00\x00\x00\xc3", 6), 9)); // mov ecx, 10; ret
            raw.push_back(RawGadget(string("\x89\x0f\x89\x5e\xfd\xc3", 6), 10)); // mov [edi], ecx; mov [esi-3], ebx; ret
            raw.push_back(RawGadget(string("\xbe\x16\x00\x00\x00\xc3", 6), 11)); // mov esi, 22; ret
            raw.push_back(RawGadget(string("\xbf\x78\x56\x34\x12\xc3", 6), 12)); // mov edi, 0x12345678; ret
            raw.push_back(RawGadget(string("\x01\x21\xc3", 3), 13)); // add [ecx], esp; ret
            raw.push_back(RawGadget(string("\x33\x79\xf6\xc3", 4), 14)); // xor edi, [ecx-10]; ret
            raw.push_back(RawGadget(string("\x83\xc9\xff\xc3", 4), 15)); // or ecx, 0xffffffff; ret
            raw.push_back(RawGadget(string("\x21\x49\xf7\xc3", 4), 16)); // and [ecx-9], ecx; ret
            

            db.fill_from_raw_gadgets(raw, &arch);

            // Test basic queries
            ropchain = comp.compile("eax = ecx");
            nb += _assert_ropchain(ropchain, "Failed to find ropchain");
            ropchain = comp.compile(" ebx = 4");
            nb += _assert_ropchain(ropchain, "Failed to find ropchain");
            ropchain = comp.compile(" ebx = eax + 4");
            nb += _assert_ropchain(ropchain, "Failed to find ropchain");
            ropchain = comp.compile(" ebx = eax + esi ");
            nb += _assert_ropchain(ropchain, "Failed to find ropchain");
            ropchain = comp.compile(" ebx = mem( ecx - 0x9) ");
            nb += _assert_ropchain(ropchain, "Failed to find ropchain");
            ropchain = comp.compile(" ebx = mem( 1) ");
            nb += _assert_ropchain(ropchain, "Failed to find ropchain");
            ropchain = comp.compile(" mem(edi) = ecx");
            nb += _assert_ropchain(ropchain, "Failed to find ropchain");
            ropchain = comp.compile(" mem(  esi-   0x3) = ebx");
            nb += _assert_ropchain(ropchain, "Failed to find ropchain");
            ropchain = comp.compile(" mem(19) = ebx");
            nb += _assert_ropchain(ropchain, "Failed to find ropchain");
            ropchain = comp.compile(" mem(0x12345678) = ecx");
            nb += _assert_ropchain(ropchain, "Failed to find ropchain");
            ropchain = comp.compile(" edi += mem(ecx)");
            nb += _assert_ropchain(ropchain, "Failed to find ropchain");
            ropchain = comp.compile(" edi ^= mem(0)");
            nb += _assert_ropchain(ropchain, "Failed to find ropchain");
            ropchain = comp.compile(" mem(ecx+0x000) += esp  \t\t\n\t  ");
            nb += _assert_ropchain(ropchain, "Failed to find ropchain");
            ropchain = comp.compile(" ecx = -1");
            nb += _assert_ropchain(ropchain, "Failed to find ropchain");
            ropchain = comp.compile(" mem(0xffffffff) += esp  \t\t\n\t  ");
            nb += _assert_ropchain(ropchain, "Failed to find ropchain");
            ropchain = comp.compile(" mem(-1) += esp  \t\t\n\t  ");
            nb += _assert_ropchain(ropchain, "Failed to find ropchain");

            return nb;
        }
        
        unsigned int indirect_match(){
            unsigned int nb = 0;
            ArchX86 arch;
            GadgetDB db;
            ROPCompiler comp = ROPCompiler(&arch, &db);
            ROPChain* ropchain;
            
            // Available gadgets
            vector<RawGadget> raw;
            raw.push_back(RawGadget(string("\x89\xf9\xbb\x01\x00\x00\x00\xc3", 8), 1)); // mov ecx, edi; mov ebx, 1; ret
            raw.push_back(RawGadget(string("\x89\xC8\xC3", 3), 2)); // mov eax, ecx; ret
            raw.push_back(RawGadget(string("\x89\xC3\xC3", 3), 3)); // mov ebx, eax; ret
            raw.push_back(RawGadget(string("\xb9\xad\xde\x00\x00\xc3", 6), 4)); // mov ecx, 0xdead; ret
            db.fill_from_raw_gadgets(raw, &arch);

            // Test mov_reg_transitivity
            ropchain = comp.compile("eax = edi");
            nb += _assert_ropchain(ropchain, "Failed to find ropchain");
            ropchain = comp.compile("ebx = edi");
            nb += _assert_ropchain(ropchain, "Failed to find ropchain");

            // Test mov_cst_transitivity
            ropchain = comp.compile("eax = 0xdead");
            nb += _assert_ropchain(ropchain, "Failed to find ropchain");
            ropchain = comp.compile("ebx = 0xdead");
            nb += _assert_ropchain(ropchain, "Failed to find ropchain");

            return nb;
        }
    }
}

using namespace test::compiler; 
// All unit tests 
void test_compiler(){
    unsigned int total = 0;
    string green = "\033[1;32m";
    string def = "\033[0m";
    string bold = "\033[1m";
    
    // Start testing 
    cout << bold << "[" << green << "+" << def << bold << "]" << def << std::left << std::setw(34) << " Testing ROP compiler... " << std::flush;  
    total += direct_match();
    total += indirect_match();
    // Return res
    cout << "\t" << total << "/" << total << green << "\t\tOK" << def << endl;
}
