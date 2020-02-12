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
            str = " eax = [ esp + 32 ]   \t\n";
            instr = ILInstruction(arch, str);
            nb += _assert(instr.type == ILInstructionType::LOAD, "Failed to parse IL Instruction");
            nb += _assert(instr.args[PARAM_LOAD_DST_REG] == X86_EAX, "Failed to parse IL Instruction");
            nb += _assert(instr.args[PARAM_LOAD_SRC_ADDR_REG] == X86_ESP, "Failed to parse IL Instruction");
            nb += _assert(instr.args[PARAM_LOAD_SRC_ADDR_OFFSET] == 32, "Failed to parse IL Instruction");
            
            str = " eax =[esi-0xabcd   ]";
            instr = ILInstruction(arch, str);
            nb += _assert(instr.type == ILInstructionType::LOAD, "Failed to parse IL Instruction");
            nb += _assert(instr.args[PARAM_LOAD_DST_REG] == X86_EAX, "Failed to parse IL Instruction");
            nb += _assert(instr.args[PARAM_LOAD_SRC_ADDR_REG] == X86_ESI, "Failed to parse IL Instruction");
            nb += _assert(instr.args[PARAM_LOAD_SRC_ADDR_OFFSET] == -0xabcd, "Failed to parse IL Instruction");
            
            // aload
            str = " eax *= [ esp + 32 ]   \t\n";
            instr = ILInstruction(arch, str);
            nb += _assert(instr.type == ILInstructionType::ALOAD, "Failed to parse IL Instruction");
            nb += _assert(instr.args[PARAM_ALOAD_DST_REG] == X86_EAX, "Failed to parse IL Instruction");
            nb += _assert(instr.args[PARAM_ALOAD_OP] == (int)Op::MUL, "Failed to parse IL Instruction");
            nb += _assert(instr.args[PARAM_ALOAD_SRC_ADDR_REG] == X86_ESP, "Failed to parse IL Instruction");
            nb += _assert(instr.args[PARAM_ALOAD_SRC_ADDR_OFFSET] == 32, "Failed to parse IL Instruction");
            
            str = " eax <<=[esi]";
            instr = ILInstruction(arch, str);
            nb += _assert(instr.type == ILInstructionType::ALOAD, "Failed to parse IL Instruction");
            nb += _assert(instr.args[PARAM_ALOAD_DST_REG] == X86_EAX, "Failed to parse IL Instruction");
            nb += _assert(instr.args[PARAM_ALOAD_OP] == (int)Op::SHL, "Failed to parse IL Instruction");
            nb += _assert(instr.args[PARAM_ALOAD_SRC_ADDR_REG] == X86_ESI, "Failed to parse IL Instruction");
            nb += _assert(instr.args[PARAM_ALOAD_SRC_ADDR_OFFSET] == 0, "Failed to parse IL Instruction");

            // load_cst
            str = " eax =[-1]";
            instr = ILInstruction(arch, str);
            nb += _assert(instr.type == ILInstructionType::LOAD_CST, "Failed to parse IL Instruction");
            nb += _assert(instr.args[PARAM_LOADCST_DST_REG] == X86_EAX, "Failed to parse IL Instruction");
            nb += _assert(instr.args[PARAM_LOADCST_SRC_ADDR_OFFSET] == -1, "Failed to parse IL Instruction");

            str = "eax=   [0xffffffff]";
            instr = ILInstruction(arch, str);
            nb += _assert(instr.type == ILInstructionType::LOAD_CST, "Failed to parse IL Instruction");
            nb += _assert(instr.args[PARAM_LOADCST_DST_REG] == X86_EAX, "Failed to parse IL Instruction");
            nb += _assert(instr.args[PARAM_LOADCST_SRC_ADDR_OFFSET] == 0xffffffff, "Failed to parse IL Instruction");
            
            // aload_cst
            str = " edi ^= [0]";
            instr = ILInstruction(arch, str);
            nb += _assert(instr.type == ILInstructionType::ALOAD_CST, "Failed to parse IL Instruction");
            nb += _assert(instr.args[PARAM_ALOADCST_DST_REG] == X86_EDI, "Failed to parse IL Instruction");
            nb += _assert(instr.args[PARAM_ALOADCST_OP] == (int)Op::XOR, "Failed to parse IL Instruction");
            nb += _assert(instr.args[PARAM_ALOADCST_SRC_ADDR_OFFSET] == 0, "Failed to parse IL Instruction");
            
            // store
            str = " [eax - 2] = edx";
            instr = ILInstruction(arch, str);
            nb += _assert(instr.type == ILInstructionType::STORE, "Failed to parse IL Instruction");
            nb += _assert(instr.args[PARAM_STORE_DST_ADDR_REG] == X86_EAX, "Failed to parse IL Instruction");
            nb += _assert(instr.args[PARAM_STORE_DST_ADDR_OFFSET] == -2, "Failed to parse IL Instruction");
            nb += _assert(instr.args[PARAM_STORE_SRC_REG] == X86_EDX, "Failed to parse IL Instruction");
            
            str = " [ eax] = edx";
            instr = ILInstruction(arch, str);
            nb += _assert(instr.type == ILInstructionType::STORE, "Failed to parse IL Instruction");
            nb += _assert(instr.args[PARAM_STORE_DST_ADDR_REG] == X86_EAX, "Failed to parse IL Instruction");
            nb += _assert(instr.args[PARAM_STORE_DST_ADDR_OFFSET] == 0, "Failed to parse IL Instruction");
            nb += _assert(instr.args[PARAM_STORE_SRC_REG] == X86_EDX, "Failed to parse IL Instruction");

            // cst_store
            str = " [6789] = edx";
            instr = ILInstruction(arch, str);
            nb += _assert(instr.type == ILInstructionType::CST_STORE, "Failed to parse IL Instruction");
            nb += _assert(instr.args[PARAM_CSTSTORE_DST_ADDR_OFFSET] == 6789, "Failed to parse IL Instruction");
            nb += _assert(instr.args[PARAM_CSTSTORE_SRC_REG] == X86_EDX, "Failed to parse IL Instruction");

            str = " [-2]=eip";
            instr = ILInstruction(arch, str);
            nb += _assert(instr.type == ILInstructionType::CST_STORE, "Failed to parse IL Instruction");
            nb += _assert(instr.args[PARAM_CSTSTORE_DST_ADDR_OFFSET] == -2, "Failed to parse IL Instruction");
            nb += _assert(instr.args[PARAM_CSTSTORE_SRC_REG] == X86_EIP, "Failed to parse IL Instruction");
            
            // astore
            str = " [esp] |= edx";
            instr = ILInstruction(arch, str);
            nb += _assert(instr.type == ILInstructionType::ASTORE, "Failed to parse IL Instruction");
            nb += _assert(instr.args[PARAM_ASTORE_DST_ADDR_REG] == X86_ESP, "Failed to parse IL Instruction");
            nb += _assert(instr.args[PARAM_ASTORE_DST_ADDR_OFFSET] == 0, "Failed to parse IL Instruction");
            nb += _assert(instr.args[PARAM_ASTORE_OP] == (int)Op::OR, "Failed to parse IL Instruction");
            nb += _assert(instr.args[PARAM_ASTORE_SRC_REG] == X86_EDX, "Failed to parse IL Instruction");

            // cst_astore
            str = " [0x1800] %= ebx";
            instr = ILInstruction(arch, str);
            nb += _assert(instr.type == ILInstructionType::CST_ASTORE, "Failed to parse IL Instruction");
            nb += _assert(instr.args[PARAM_CSTASTORE_DST_ADDR_OFFSET] == 0x1800, "Failed to parse IL Instruction");
            nb += _assert(instr.args[PARAM_CSTASTORE_SRC_REG] == X86_EBX, "Failed to parse IL Instruction");
            nb += _assert(instr.args[PARAM_CSTASTORE_OP] == (int)Op::MOD, "Failed to parse IL Instruction");

            // store_cst
            str = " [eax - 2] = 42";
            instr = ILInstruction(arch, str);
            nb += _assert(instr.type == ILInstructionType::STORE_CST, "Failed to parse IL Instruction");
            nb += _assert(instr.args[PARAM_STORECST_DST_ADDR_REG] == X86_EAX, "Failed to parse IL Instruction");
            nb += _assert(instr.args[PARAM_STORECST_DST_ADDR_OFFSET] == -2, "Failed to parse IL Instruction");
            nb += _assert(instr.args[PARAM_STORECST_SRC_CST] == 42, "Failed to parse IL Instruction");

            str = " [ eax] = 1234";
            instr = ILInstruction(arch, str);
            nb += _assert(instr.type == ILInstructionType::STORE_CST, "Failed to parse IL Instruction");
            nb += _assert(instr.args[PARAM_STORECST_DST_ADDR_REG] == X86_EAX, "Failed to parse IL Instruction");
            nb += _assert(instr.args[PARAM_STORECST_DST_ADDR_OFFSET] == 0, "Failed to parse IL Instruction");
            nb += _assert(instr.args[PARAM_STORECST_SRC_CST] == 1234, "Failed to parse IL Instruction");

            // cst_store_cst
            str = " [6789] = 0x42";
            instr = ILInstruction(arch, str);
            nb += _assert(instr.type == ILInstructionType::CST_STORE_CST, "Failed to parse IL Instruction");
            nb += _assert(instr.args[PARAM_CSTSTORECST_DST_ADDR_OFFSET] == 6789, "Failed to parse IL Instruction");
            nb += _assert(instr.args[PARAM_CSTSTORECST_SRC_CST] == 0x42, "Failed to parse IL Instruction");

            str = " [-20]=12";
            instr = ILInstruction(arch, str);
            nb += _assert(instr.type == ILInstructionType::CST_STORE_CST, "Failed to parse IL Instruction");
            nb += _assert(instr.args[PARAM_CSTSTORECST_DST_ADDR_OFFSET] == -20, "Failed to parse IL Instruction");
            nb += _assert(instr.args[PARAM_CSTSTORECST_SRC_CST] == 12, "Failed to parse IL Instruction");

            // astore_cst
            str = " [esp] |= 34";
            instr = ILInstruction(arch, str);
            nb += _assert(instr.type == ILInstructionType::ASTORE_CST, "Failed to parse IL Instruction");
            nb += _assert(instr.args[PARAM_ASTORECST_DST_ADDR_REG] == X86_ESP, "Failed to parse IL Instruction");
            nb += _assert(instr.args[PARAM_ASTORECST_DST_ADDR_OFFSET] == 0, "Failed to parse IL Instruction");
            nb += _assert(instr.args[PARAM_ASTORECST_OP] == (int)Op::OR, "Failed to parse IL Instruction");
            nb += _assert(instr.args[PARAM_ASTORECST_SRC_CST] == 34, "Failed to parse IL Instruction");

            // cst_astore_cst
            str = " [0x1800] %= 00";
            instr = ILInstruction(arch, str);
            nb += _assert(instr.type == ILInstructionType::CST_ASTORE_CST, "Failed to parse IL Instruction");
            nb += _assert(instr.args[PARAM_CSTASTORECST_DST_ADDR_OFFSET] == 0x1800, "Failed to parse IL Instruction");
            nb += _assert(instr.args[PARAM_CSTASTORECST_SRC_CST] == 0, "Failed to parse IL Instruction");
            nb += _assert(instr.args[PARAM_CSTASTORECST_OP] == (int)Op::MOD, "Failed to parse IL Instruction");

            // function 
            str = " 0x1000()";
            instr = ILInstruction(arch, str);
            nb += _assert(instr.type == ILInstructionType::FUNCTION, "Failed to parse IL Instruction");
            nb += _assert(instr.args[PARAM_FUNCTION_ADDR] == 0x1000, "Failed to parse IL Instruction");
            
            str = " 1000( 22  )";
            instr = ILInstruction(arch, str);
            nb += _assert(instr.type == ILInstructionType::FUNCTION, "Failed to parse IL Instruction");
            nb += _assert(instr.args[PARAM_FUNCTION_ADDR] == 1000, "Failed to parse IL Instruction");
            nb += _assert(instr.args[PARAM_FUNCTION_ARGS+0] == 22, "Failed to parse IL Instruction");
            nb += _assert(instr.args_type[PARAM_FUNCTION_ARGS+0] == IL_FUNC_ARG_CST, "Failed to parse IL Instruction");
            
            str = " 1000( eax  )";
            instr = ILInstruction(arch, str);
            nb += _assert(instr.type == ILInstructionType::FUNCTION, "Failed to parse IL Instruction");
            nb += _assert(instr.args[PARAM_FUNCTION_ADDR] == 1000, "Failed to parse IL Instruction");
            nb += _assert(instr.args[PARAM_FUNCTION_ARGS+0] == X86_EAX, "Failed to parse IL Instruction");
            nb += _assert(instr.args_type[PARAM_FUNCTION_ARGS+0] == IL_FUNC_ARG_REG, "Failed to parse IL Instruction");
            
            str = " 1000( 22, ebx  )";
            instr = ILInstruction(arch, str);
            nb += _assert(instr.type == ILInstructionType::FUNCTION, "Failed to parse IL Instruction");
            nb += _assert(instr.args[PARAM_FUNCTION_ADDR] == 1000, "Failed to parse IL Instruction");
            nb += _assert(instr.args[PARAM_FUNCTION_ARGS+0] == 22, "Failed to parse IL Instruction");
            nb += _assert(instr.args_type[PARAM_FUNCTION_ARGS+0] == IL_FUNC_ARG_CST, "Failed to parse IL Instruction");
            nb += _assert(instr.args[PARAM_FUNCTION_ARGS+1] == X86_EBX, "Failed to parse IL Instruction");
            nb += _assert(instr.args_type[PARAM_FUNCTION_ARGS+1] == IL_FUNC_ARG_REG, "Failed to parse IL Instruction");
            
            str = " 1000( eax , 34, ebx )";
            instr = ILInstruction(arch, str);
            nb += _assert(instr.type == ILInstructionType::FUNCTION, "Failed to parse IL Instruction");
            nb += _assert(instr.args[PARAM_FUNCTION_ADDR] == 1000, "Failed to parse IL Instruction");
            nb += _assert(instr.args[PARAM_FUNCTION_ARGS+0] == X86_EAX, "Failed to parse IL Instruction");
            nb += _assert(instr.args_type[PARAM_FUNCTION_ARGS+0] == IL_FUNC_ARG_REG, "Failed to parse IL Instruction");
            nb += _assert(instr.args[PARAM_FUNCTION_ARGS+1] == 34, "Failed to parse IL Instruction");
            nb += _assert(instr.args_type[PARAM_FUNCTION_ARGS+1] == IL_FUNC_ARG_CST, "Failed to parse IL Instruction");
            nb += _assert(instr.args[PARAM_FUNCTION_ARGS+2] == X86_EBX, "Failed to parse IL Instruction");
            nb += _assert(instr.args_type[PARAM_FUNCTION_ARGS+2] == IL_FUNC_ARG_REG, "Failed to parse IL Instruction");
            
            // syscall
            str = " sys_read()";
            instr = ILInstruction(arch, str);
            nb += _assert(instr.type == ILInstructionType::SYSCALL, "Failed to parse IL Instruction");
            nb += _assert(instr.syscall_name == "read", "Failed to parse IL Instruction");

            str = " sys_truc(42)";
            instr = ILInstruction(arch, str);
            nb += _assert(instr.type == ILInstructionType::SYSCALL, "Failed to parse IL Instruction");
            nb += _assert(instr.syscall_name == "truc", "Failed to parse IL Instruction");
            nb += _assert(instr.args[PARAM_SYSCALL_ARGS+0] == 42, "Failed to parse IL Instruction");
            nb += _assert(instr.args_type[PARAM_SYSCALL_ARGS+0] == IL_FUNC_ARG_CST, "Failed to parse IL Instruction");

            str = " sys_truc(42, esp, 1)";
            instr = ILInstruction(arch, str);
            nb += _assert(instr.type == ILInstructionType::SYSCALL, "Failed to parse IL Instruction");
            nb += _assert(instr.syscall_name == "truc", "Failed to parse IL Instruction");
            nb += _assert(instr.args[PARAM_SYSCALL_ARGS+0] == 42, "Failed to parse IL Instruction");
            nb += _assert(instr.args_type[PARAM_SYSCALL_ARGS+0] == IL_FUNC_ARG_CST, "Failed to parse IL Instruction");
            nb += _assert(instr.args[PARAM_SYSCALL_ARGS+1] == X86_ESP, "Failed to parse IL Instruction");
            nb += _assert(instr.args_type[PARAM_SYSCALL_ARGS+1] == IL_FUNC_ARG_REG, "Failed to parse IL Instruction");
            nb += _assert(instr.args[PARAM_SYSCALL_ARGS+2] == 1, "Failed to parse IL Instruction");
            nb += _assert(instr.args_type[PARAM_SYSCALL_ARGS+2] == IL_FUNC_ARG_CST, "Failed to parse IL Instruction");

            str = " sys_11()";
            instr = ILInstruction(arch, str);
            nb += _assert(instr.type == ILInstructionType::SYSCALL, "Failed to parse IL Instruction");
            nb += _assert(instr.syscall_num == 11, "Failed to parse IL Instruction");

            str = " sys_0x42(eax)";
            instr = ILInstruction(arch, str);
            nb += _assert(instr.type == ILInstructionType::SYSCALL, "Failed to parse IL Instruction");
            nb += _assert(instr.syscall_num == 0x42, "Failed to parse IL Instruction");
            nb += _assert(instr.args[PARAM_SYSCALL_ARGS+0] == X86_EAX, "Failed to parse IL Instruction");
            nb += _assert(instr.args_type[PARAM_SYSCALL_ARGS+0] == IL_FUNC_ARG_REG, "Failed to parse IL Instruction");

            // cst_store_string
            str = " [6789] = 'lala'";
            instr = ILInstruction(arch, str);
            nb += _assert(instr.type == ILInstructionType::CST_STORE_STRING, "Failed to parse IL Instruction");
            nb += _assert(instr.args[PARAM_CSTSTORE_STRING_ADDR_OFFSET] == 6789, "Failed to parse IL Instruction");
            nb += _assert(instr.str == "lala", "Failed to parse IL Instruction");

            str = " [6789] = 'lal\\\\a'";
            instr = ILInstruction(arch, str);
            nb += _assert(instr.type == ILInstructionType::CST_STORE_STRING, "Failed to parse IL Instruction");
            nb += _assert(instr.args[PARAM_CSTSTORE_STRING_ADDR_OFFSET] == 6789, "Failed to parse IL Instruction");
            nb += _assert(instr.str == "lal\\a", "Failed to parse IL Instruction");
            
            str = " [6789] = 'lal\\'a'";
            instr = ILInstruction(arch, str);
            nb += _assert(instr.type == ILInstructionType::CST_STORE_STRING, "Failed to parse IL Instruction");
            nb += _assert(instr.args[PARAM_CSTSTORE_STRING_ADDR_OFFSET] == 6789, "Failed to parse IL Instruction");
            nb += _assert(instr.str == "lal'a", "Failed to parse IL Instruction");
                
            str = " [6789] = 'lal\\x41\\x42a'";
            instr = ILInstruction(arch, str);
            nb += _assert(instr.type == ILInstructionType::CST_STORE_STRING, "Failed to parse IL Instruction");
            nb += _assert(instr.args[PARAM_CSTSTORE_STRING_ADDR_OFFSET] == 6789, "Failed to parse IL Instruction");
            nb += _assert(instr.str == "lalABa", "Failed to parse IL Instruction");

            str = " [6789] = \"\"";
            instr = ILInstruction(arch, str);
            nb += _assert(instr.type == ILInstructionType::CST_STORE_STRING, "Failed to parse IL Instruction");
            nb += _assert(instr.args[PARAM_CSTSTORE_STRING_ADDR_OFFSET] == 6789, "Failed to parse IL Instruction");
            nb += _assert(instr.str == "", "Failed to parse IL Instruction");

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
