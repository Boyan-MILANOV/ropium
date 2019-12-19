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
