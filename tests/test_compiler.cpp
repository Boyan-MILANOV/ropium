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
        
        unsigned int _assert_no_ropchain(ROPChain* ropchain, const string& msg){
            if( ropchain != nullptr){
                cout << "\nFail: " << msg << endl << std::flush; 
                throw test_exception();
            }
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
            raw.push_back(RawGadget(string("\x01\x1E\xC3", 3), 17)); // add [esi], ebx; ret

            db.analyse_raw_gadgets(raw, &arch);

            // Test basic queries
            ropchain = comp.compile("eax = ecx");
            nb += _assert_ropchain(ropchain, "Failed to find ropchain");
            ropchain = comp.compile(" ebx = 4");
            nb += _assert_ropchain(ropchain, "Failed to find ropchain");
            ropchain = comp.compile(" ebx = eax + 4");
            nb += _assert_ropchain(ropchain, "Failed to find ropchain");
            ropchain = comp.compile(" ebx = eax + esi ");
            nb += _assert_ropchain(ropchain, "Failed to find ropchain");
            ropchain = comp.compile(" ebx = [ ecx - 0x9] ");
            nb += _assert_ropchain(ropchain, "Failed to find ropchain");
            ropchain = comp.compile(" ebx = [ 1] ");
            nb += _assert_ropchain(ropchain, "Failed to find ropchain");
            ropchain = comp.compile(" [edi] = ecx");
            nb += _assert_ropchain(ropchain, "Failed to find ropchain");
            ropchain = comp.compile(" [ esi-   0x3] = ebx");
            nb += _assert_ropchain(ropchain, "Failed to find ropchain");
            ropchain = comp.compile(" [19] = ebx");
            nb += _assert_ropchain(ropchain, "Failed to find ropchain");
            ropchain = comp.compile(" [0x12345678] = ecx");
            nb += _assert_ropchain(ropchain, "Failed to find ropchain");
            ropchain = comp.compile(" edi += [ecx]");
            nb += _assert_ropchain(ropchain, "Failed to find ropchain");
            ropchain = comp.compile(" edi ^= [0]");
            nb += _assert_ropchain(ropchain, "Failed to find ropchain");
            ropchain = comp.compile(" [ecx+0x000 ] += esp  \t\t\n\t  ");
            nb += _assert_ropchain(ropchain, "Failed to find ropchain");
            ropchain = comp.compile(" ecx = -1");
            nb += _assert_ropchain(ropchain, "Failed to find ropchain");
            ropchain = comp.compile(" [22] += 4");
            nb += _assert_ropchain(ropchain, "Failed to find ropchain");

            return nb;
        }

        unsigned int indirect_match(){
            unsigned int nb = 0;
            ArchX86 arch;
            GadgetDB db;
            ROPCompiler comp = ROPCompiler(&arch, &db);
            ROPChain* ropchain;
            Constraint constr;
            constr.bad_bytes.add_bad_byte(0xff);

            // Available gadgets
            vector<RawGadget> raw;
            raw.push_back(RawGadget(string("\x89\xf9\xbb\x01\x00\x00\x00\xc3", 8), 1)); // mov ecx, edi; mov ebx, 1; ret
            raw.push_back(RawGadget(string("\x89\xC8\xC3", 3), 2)); // mov eax, ecx; ret
            raw.push_back(RawGadget(string("\x89\xC3\xC3", 3), 3)); // mov ebx, eax; ret
            raw.push_back(RawGadget(string("\xb9\xad\xde\x00\x00\xc3", 6), 4)); // mov ecx, 0xdead; ret
            raw.push_back(RawGadget(string("\x5f\x5e\x59\xc3", 4), 5)); // pop edi; pop esi; pop ecx; ret
            raw.push_back(RawGadget(string("\x89\xE8\xFF\xE6", 4), 6)); // mov eax, ebp; jmp esi
            raw.push_back(RawGadget(string("\x89\xF1\xFF\xE0", 4), 7)); // mov ecx, esi; jmp eax
            raw.push_back(RawGadget(string("\x5A\x59\xC3", 3), 8)); // pop edx; pop ecx; ret
            raw.push_back(RawGadget(string("\x8B\x40\x08\xC3", 4), 9)); // mov eax, [eax + 8]; ret
            raw.push_back(RawGadget(string("\x8D\x4B\x08\xC3", 4), 10)); // lea ecx, [ebx + 8]; ret
            raw.push_back(RawGadget(string("\x8D\x40\x20\xFF\xE1", 5), 11)); // lea eax, [eax + 32]; jmp ecx;
            raw.push_back(RawGadget(string("\x89\x43\x08\xC3", 4), 12)); // mov [ebx + 8], eax; ret

            db.analyse_raw_gadgets(raw, &arch);

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
            
            // Test mov_cst pop
            ropchain = comp.compile(" edi =   -2");
            nb += _assert_ropchain(ropchain, "Failed to find ropchain");
            ropchain = comp.compile(" eax = 0x12345678  ");
            nb += _assert_ropchain(ropchain, "Failed to find ropchain");
            
            // Test generic adjust jmp
            ropchain = comp.compile(" ebx =  ebp");
            nb += _assert_ropchain(ropchain, "Failed to find ropchain");
            ropchain = comp.compile(" eax =  esi");
            nb += _assert_ropchain(ropchain, "Failed to find ropchain");
            
            // Test adjust load
            ropchain = comp.compile(" eax =  [ebx+16]");
            nb += _assert_ropchain(ropchain, "Failed to find ropchain");
            ropchain = comp.compile(" eax =  [eax+40]");
            nb += _assert_ropchain(ropchain, "Failed to find ropchain");

            // Test src transitivity
            ropchain = comp.compile(" [ebx+8] =  ebp");
            nb += _assert_ropchain(ropchain, "Failed to find ropchain");
            return nb;
        }
        
        unsigned int incorrect_match(){
            unsigned int nb = 0;
            ArchX86 arch;
            GadgetDB db;
            ROPCompiler comp = ROPCompiler(&arch, &db);
            ROPChain* ropchain;
            Constraint constr;
            constr.bad_bytes.add_bad_byte(0xff);

            // Test when adjust gadget clobbers reg that must be set
            // Here gadget 2 and 3 both modify ecx
            vector<RawGadget> raw;
            raw.push_back(RawGadget(string("\x89\xF1\xFF\xE0", 4), 1)); // mov ecx, esi; jmp eax
            raw.push_back(RawGadget(string("\x59\xC3", 2), 2)); // pop ecx; ret
            raw.push_back(RawGadget(string("\x58\x59\xC3", 3), 3)); // pop eax; pop ecx; ret
            db.analyse_raw_gadgets(raw, &arch);
            ropchain = comp.compile(" ecx =  esi");
            nb += _assert_no_ropchain(ropchain, "Found ropchain but no ropchain should exist");
            
            // Test when adjust gadget clobbers input register
            // Here gadget 2 can set eax but modifies esi
            db.clear();
            raw.clear();
            raw.push_back(RawGadget(string("\x89\xF1\xFF\xE0", 4), 1)); // mov ecx, esi; jmp eax
            raw.push_back(RawGadget(string("\x5E\x58\xC3", 3), 2)); // pop esi; pop eax; ret
            raw.push_back(RawGadget(string("\xC3", 1), 3)); // ret
            db.analyse_raw_gadgets(raw, &arch);
            ropchain = comp.compile(" ecx =  esi");
            nb += _assert_no_ropchain(ropchain, "Found ropchain but no ropchain should exist");

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
    total += incorrect_match();
    // Return res
    cout << "\t" << total << "/" << total << green << "\t\tOK" << def << endl;
}
