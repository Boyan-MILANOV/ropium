#include "database.hpp"
#include "exception.hpp"
#include <string>
#include <sstream>
#include <tuple>
#include <iostream>
#include <iomanip>
#include <algorithm>

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
            
            db.add(make_tuple(1,2), g1);
            nb += _assert(db.get(make_tuple(1,2))[0] == g1, "BaseDB, failed to add then get gadget");
            db.add(make_tuple(1,4456), g2);
            nb += _assert(db.get(make_tuple(1,4456))[0] == g2, "BaseDB, failed to add then get gadget");

            delete g1; delete g2;
            return nb; 
        }
        
        unsigned int _assert_db(addr_t addr, const vector<Gadget*>& list){
            for( Gadget* g : list ){
                if( std::find(g->addresses.begin(), g->addresses.end(), addr) != g->addresses.end() )
                    return 1;
            }
            cout << "\nFail: " << "GadgetDB: failed to classify/return gadget correctly" << endl << std::flush; 
                throw test_exception();
        }
        
        unsigned int classification(){
            unsigned int nb = 0;
            Arch* arch = new ArchX86();
            GadgetDB db;

            vector<RawGadget> raw;
            raw.push_back(RawGadget(string("\xb8\x03\x00\x00\x00\xc3", 6), 0)); // mov eax, 3; ret
            raw.push_back(RawGadget(string("\x89\xf9\xbb\x01\x00\x00\x00\xc3", 8), 1)); // mov ecx, edi; mov ebx, 1; ret
            raw.push_back(RawGadget(string("\xb8\x03\x00\x00\x00\xc3", 6), 2)); // mov eax, 3; ret
            raw.push_back(RawGadget(string("\x83\xc0\x02\x89\xc6\xc3", 6), 3)); // add eax, 2; mov esi, eax; ret
            raw.push_back(RawGadget(string("\x81\xea\x34\x12\x00\x00\xc3", 7), 4)); // sub edx, 0x1234; ret
            raw.push_back(RawGadget(string("\x01\xe5\xc3", 3), 5)); // add ebp, esp; ret
            raw.push_back(RawGadget(string("\x58\x5e\xc3", 3), 6)); // pop eax; pop esi; ret
            raw.push_back(RawGadget(string("\x8b\x59\xf7\x89\xd8\xc3", 6), 7)); // mov ebx, [ecx-9]; mov eax, ebx; ret
            raw.push_back(RawGadget(string("\x03\x39\xc3", 3), 8)); // add edi, [ecx]; ret
            raw.push_back(RawGadget(string("\x33\x79\xf6\xc3", 4), 9)); // xor edi, [ecx-10]; ret
            raw.push_back(RawGadget(string("\xff\xe0", 2), 10)); // jmp eax;
            raw.push_back(RawGadget(string("\x89\x0f\x89\x5e\xfd\xc3", 6), 11)); // mov [edi], ecx; mov [esi-3], ebx; ret
            raw.push_back(RawGadget(string("\x01\x21\xc3", 3), 12)); // add [ecx], esp; ret
            raw.push_back(RawGadget(string("\x21\x49\xf7\xc3", 4), 13)); // and [ecx-9], ecx; ret
            raw.push_back(RawGadget(string("\x83\xC0\x03\xCD\x80", 5), 14)); // add eax, 3; int 0x80
            raw.push_back(RawGadget(string("\x83\xC5\x20\x0F\x34", 5), 15)); // add ebp, 32; sysenter

            db.analyse_raw_gadgets(raw, arch);

            // Test gadget classification
            nb += _assert_db(0, db.get_mov_cst(X86_EAX, 3));
            nb += _assert_db(1, db.get_mov_cst(X86_EBX, 1));
            nb += _assert_db(1, db.get_mov_reg(X86_ECX, X86_EDI));
            nb += _assert_db(2, db.get_mov_cst(X86_EAX, 3));
            nb += _assert_db(3, db.get_amov_cst(X86_EAX, X86_EAX, Op::ADD, 2));
            nb += _assert_db(3, db.get_amov_cst(X86_ESI, X86_EAX, Op::ADD, 2));
            nb += _assert_db(4, db.get_amov_cst(X86_EDX, X86_EDX, Op::ADD, -0x1234));
            nb += _assert_db(5, db.get_amov_reg(X86_EBP, X86_ESP, Op::ADD, X86_EBP));
            nb += _assert_db(6, db.get_load(X86_EAX, X86_ESP, 0));
            nb += _assert_db(6, db.get_load(X86_ESI, X86_ESP, 4));
            nb += _assert_db(7, db.get_load(X86_EBX, X86_ECX, -9));
            nb += _assert_db(7, db.get_load(X86_EAX, X86_ECX, -9));
            nb += _assert_db(8, db.get_aload(X86_EDI, Op::ADD, X86_ECX, 0));
            nb += _assert_db(9, db.get_aload(X86_EDI, Op::XOR, X86_ECX, -10));
            nb += _assert_db(10, db.get_jmp(X86_EAX));
            nb += _assert_db(10, db.get_mov_reg(X86_EIP, X86_EAX));
            nb += _assert_db(11, db.get_store(X86_EDI, 0, X86_ECX));
            nb += _assert_db(11, db.get_store(X86_ESI, -3, X86_EBX));
            nb += _assert_db(12, db.get_astore(X86_ECX, 0, Op::ADD, X86_ESP));
            nb += _assert_db(13, db.get_astore(X86_ECX, -9, Op::AND, X86_ECX));
            nb += _assert_db(14, db.get_int80());
            nb += _assert_db(15, db.get_syscall());

            delete arch;
            return nb;
        }
        
        unsigned int classification_x64(){
            unsigned int nb = 0;
            Arch* arch = new ArchX64();
            GadgetDB db;

            vector<RawGadget> raw;
            raw.push_back(RawGadget(string("\x83\xC5\x20\x0F\x05", 5), 1)); // add ebp, 32; syscall

            db.analyse_raw_gadgets(raw, arch);

            // Test gadget classification
            nb += _assert_db(1, db.get_syscall());

            delete arch;
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
    total += classification();
    total += classification_x64();
    // Return res
    cout << "\t" << total << "/" << total << green << "\t\tOK" << def << endl;
}
