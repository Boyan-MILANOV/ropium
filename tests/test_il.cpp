#include "il.hpp"
#include "arch.hpp"
#include "exception.hpp"
#include <cassert>
#include <iostream>
#include <string>
#include <sstream>
#include <iomanip>
#include "strategy.hpp"

using std::cout;
using std::endl; 
using std::string;

namespace test{
    namespace il{
        unsigned int _assert(bool val, const string& msg){
            if( !val){
                cout << "\nFail: " << msg << endl << std::flush; 
                throw test_exception();
            }
            return 1; 
        }

        unsigned int il_parser(){
            unsigned int nb = 0;
            ArchX86 arch;
            
            // mov reg
            string str = "   eax =     ebx";
            ILInstruction instr = ILInstruction(arch, str);
            nb += _assert(instr.type == ILInstructionType::MOV_REG, "Failed to parse IL Instruction");
            nb += _assert(instr.args[PARAM_MOVREG_DST_REG] == X86_EAX, "Failed to parse IL Instruction");
            nb += _assert(instr.args[PARAM_MOVREG_SRC_REG] == X86_EBX, "Failed to parse IL Instruction");
            
            str = "ecx=       esi       ";
            instr = ILInstruction(arch, str);
            nb += _assert(instr.type == ILInstructionType::MOV_REG, "Failed to parse IL Instruction");
            nb += _assert(instr.args[PARAM_MOVREG_DST_REG] == X86_ECX, "Failed to parse IL Instruction");
            nb += _assert(instr.args[PARAM_MOVREG_SRC_REG] == X86_ESI, "Failed to parse IL Instruction");
            
            // mov cst
            str = "eip=   1234       ";
            instr = ILInstruction(arch, str);
            nb += _assert(instr.type == ILInstructionType::MOV_CST, "Failed to parse IL Instruction");
            nb += _assert(instr.args[PARAM_MOVCST_DST_REG] == X86_EIP, "Failed to parse IL Instruction");
            nb += _assert(instr.args[PARAM_MOVCST_SRC_CST] == 1234, "Failed to parse IL Instruction");
            
            str = " edx  =12345";
            instr = ILInstruction(arch, str);
            nb += _assert(instr.type == ILInstructionType::MOV_CST, "Failed to parse IL Instruction");
            nb += _assert(instr.args[PARAM_MOVCST_DST_REG] == X86_EDX, "Failed to parse IL Instruction");
            nb += _assert(instr.args[PARAM_MOVCST_SRC_CST] == 12345, "Failed to parse IL Instruction");
            
            str = "eip = 0x1234       ";
            instr = ILInstruction(arch, str);
            nb += _assert(instr.type == ILInstructionType::MOV_CST, "Failed to parse IL Instruction");
            nb += _assert(instr.args[PARAM_MOVCST_DST_REG] == X86_EIP, "Failed to parse IL Instruction");
            nb += _assert(instr.args[PARAM_MOVCST_SRC_CST] == 0x1234, "Failed to parse IL Instruction");
            
            str = "eip =   -0x1234       ";
            instr = ILInstruction(arch, str);
            nb += _assert(instr.type == ILInstructionType::MOV_CST, "Failed to parse IL Instruction");
            nb += _assert(instr.args[PARAM_MOVCST_DST_REG] == X86_EIP, "Failed to parse IL Instruction");
            nb += _assert(instr.args[PARAM_MOVCST_SRC_CST] == -0x1234, "Failed to parse IL Instruction");
            
            str = "eip =   - 0x1234       ";
            instr = ILInstruction(arch, str);
            nb += _assert(instr.type == ILInstructionType::MOV_CST, "Failed to parse IL Instruction");
            nb += _assert(instr.args[PARAM_MOVCST_DST_REG] == X86_EIP, "Failed to parse IL Instruction");
            nb += _assert(instr.args[PARAM_MOVCST_SRC_CST] == -0x1234, "Failed to parse IL Instruction");

            // amov cst
            str = " esp = eax +      42     \n";
            instr = ILInstruction(arch, str);
            nb += _assert(instr.type == ILInstructionType::AMOV_CST, "Failed to parse IL Instruction");
            nb += _assert(instr.args[PARAM_AMOVCST_DST_REG] == X86_ESP, "Failed to parse IL Instruction");
            nb += _assert(instr.args[PARAM_AMOVCST_SRC_REG] == X86_EAX, "Failed to parse IL Instruction");
            nb += _assert(instr.args[PARAM_AMOVCST_SRC_OP] == (int)Op::ADD, "Failed to parse IL Instruction");
            nb += _assert(instr.args[PARAM_AMOVCST_SRC_CST] == 42, "Failed to parse IL Instruction");
            
            str = " esp = esi >>0x3     \n";
            instr = ILInstruction(arch, str);
            nb += _assert(instr.type == ILInstructionType::AMOV_CST, "Failed to parse IL Instruction");
            nb += _assert(instr.args[PARAM_AMOVCST_DST_REG] == X86_ESP, "Failed to parse IL Instruction");
            nb += _assert(instr.args[PARAM_AMOVCST_SRC_REG] == X86_ESI, "Failed to parse IL Instruction");
            nb += _assert(instr.args[PARAM_AMOVCST_SRC_OP] == (int)Op::SHR, "Failed to parse IL Instruction");
            nb += _assert(instr.args[PARAM_AMOVCST_SRC_CST] == 3, "Failed to parse IL Instruction");
            
            // amov reg
            str = " esp = eax *      ebp    \n\n";
            instr = ILInstruction(arch, str);
            nb += _assert(instr.type == ILInstructionType::AMOV_REG, "Failed to parse IL Instruction");
            nb += _assert(instr.args[PARAM_AMOVREG_DST_REG] == X86_ESP, "Failed to parse IL Instruction");
            nb += _assert(instr.args[PARAM_AMOVREG_SRC_REG1] == X86_EAX, "Failed to parse IL Instruction");
            nb += _assert(instr.args[PARAM_AMOVREG_SRC_OP] == (int)Op::MUL, "Failed to parse IL Instruction");
            nb += _assert(instr.args[PARAM_AMOVREG_SRC_REG2] == X86_EBP, "Failed to parse IL Instruction");
            
            str = " esp = esi <<      esi";
            instr = ILInstruction(arch, str);
            nb += _assert(instr.type == ILInstructionType::AMOV_REG, "Failed to parse IL Instruction");
            nb += _assert(instr.args[PARAM_AMOVREG_DST_REG] == X86_ESP, "Failed to parse IL Instruction");
            nb += _assert(instr.args[PARAM_AMOVREG_SRC_REG1] == X86_ESI, "Failed to parse IL Instruction");
            nb += _assert(instr.args[PARAM_AMOVREG_SRC_OP] == (int)Op::SHL, "Failed to parse IL Instruction");
            nb += _assert(instr.args[PARAM_AMOVREG_SRC_REG2] == X86_ESI, "Failed to parse IL Instruction");

            // load
            str = " eax = mem( esp + 32 )   \t\n";
            instr = ILInstruction(arch, str);
            nb += _assert(instr.type == ILInstructionType::LOAD, "Failed to parse IL Instruction");
            nb += _assert(instr.args[PARAM_LOAD_DST_REG] == X86_EAX, "Failed to parse IL Instruction");
            nb += _assert(instr.args[PARAM_LOAD_SRC_ADDR_REG] == X86_ESP, "Failed to parse IL Instruction");
            nb += _assert(instr.args[PARAM_LOAD_SRC_ADDR_OFFSET] == 32, "Failed to parse IL Instruction");
            
            str = " eax =mem(esi-0xabcd   )";
            instr = ILInstruction(arch, str);
            nb += _assert(instr.type == ILInstructionType::LOAD, "Failed to parse IL Instruction");
            nb += _assert(instr.args[PARAM_LOAD_DST_REG] == X86_EAX, "Failed to parse IL Instruction");
            nb += _assert(instr.args[PARAM_LOAD_SRC_ADDR_REG] == X86_ESI, "Failed to parse IL Instruction");
            nb += _assert(instr.args[PARAM_LOAD_SRC_ADDR_OFFSET] == -0xabcd, "Failed to parse IL Instruction");

            // load_cst
            str = " eax =mem(-1)";
            instr = ILInstruction(arch, str);
            nb += _assert(instr.type == ILInstructionType::LOAD_CST, "Failed to parse IL Instruction");
            nb += _assert(instr.args[PARAM_LOADCST_DST_REG] == X86_EAX, "Failed to parse IL Instruction");
            nb += _assert(instr.args[PARAM_LOADCST_SRC_ADDR_OFFSET] == -1, "Failed to parse IL Instruction");

            str = "eax=   mem(0xffffffff)";
            instr = ILInstruction(arch, str);
            nb += _assert(instr.type == ILInstructionType::LOAD_CST, "Failed to parse IL Instruction");
            nb += _assert(instr.args[PARAM_LOADCST_DST_REG] == X86_EAX, "Failed to parse IL Instruction");
            nb += _assert(instr.args[PARAM_LOADCST_SRC_ADDR_OFFSET] == 0xffffffff, "Failed to parse IL Instruction");
            
            // store
            str = " mem(eax - 2) = edx";
            instr = ILInstruction(arch, str);
            nb += _assert(instr.type == ILInstructionType::STORE, "Failed to parse IL Instruction");
            nb += _assert(instr.args[PARAM_STORE_DST_ADDR_REG] == X86_EAX, "Failed to parse IL Instruction");
            nb += _assert(instr.args[PARAM_STORE_DST_ADDR_OFFSET] == -2, "Failed to parse IL Instruction");
            nb += _assert(instr.args[PARAM_STORE_SRC_REG] == X86_EDX, "Failed to parse IL Instruction");
            
            str = " mem( eax) = edx";
            instr = ILInstruction(arch, str);
            nb += _assert(instr.type == ILInstructionType::STORE, "Failed to parse IL Instruction");
            nb += _assert(instr.args[PARAM_STORE_DST_ADDR_REG] == X86_EAX, "Failed to parse IL Instruction");
            nb += _assert(instr.args[PARAM_STORE_DST_ADDR_OFFSET] == 0, "Failed to parse IL Instruction");
            nb += _assert(instr.args[PARAM_STORE_SRC_REG] == X86_EDX, "Failed to parse IL Instruction");

            // cst_store
            str = " mem(6789) = edx";
            instr = ILInstruction(arch, str);
            nb += _assert(instr.type == ILInstructionType::CST_STORE, "Failed to parse IL Instruction");
            nb += _assert(instr.args[PARAM_CSTSTORE_DST_ADDR_OFFSET] == 6789, "Failed to parse IL Instruction");
            nb += _assert(instr.args[PARAM_CSTSTORE_SRC_REG] == X86_EDX, "Failed to parse IL Instruction");

            str = " mem(-2)=eip";
            instr = ILInstruction(arch, str);
            nb += _assert(instr.type == ILInstructionType::CST_STORE, "Failed to parse IL Instruction");
            nb += _assert(instr.args[PARAM_CSTSTORE_DST_ADDR_OFFSET] == -2, "Failed to parse IL Instruction");
            nb += _assert(instr.args[PARAM_CSTSTORE_SRC_REG] == X86_EIP, "Failed to parse IL Instruction");
            
            return nb;
        }

    }
}

using namespace test::il; 
// All unit tests 
void test_il(){
    unsigned int total = 0;
    string green = "\033[1;32m";
    string def = "\033[0m";
    string bold = "\033[1m";
    
    // Start testing 
    cout << bold << "[" << green << "+" << def << bold << "]" << def << std::left << std::setw(34) << " Testing il module... " << std::flush;  
    total += il_parser();
    // Return res
    cout << "\t" << total << "/" << total << green << "\t\tOK" << def << endl;
}
