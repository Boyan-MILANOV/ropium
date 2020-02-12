#ifndef IL_HPP
#define IL_HPP

#include "arch.hpp"

/* IL - Intermediate Language
   ==========================
  
  The IL is used to write ROP programs that the ROPCompiler will
  then try to satisfy using the available gadgets.
  
  It is very close to the different kinds of gadgets supported (
  MOV_REG, MOV_CST, LOAD, STORE, etc) with a few extra types 
  available for convenience (like CST_STORE, LOAD_CST, etc).
  
*/
   
enum class ILInstructionType{
    // Register to register
    MOV_CST,    // reg <- cst
    MOV_REG,    // reg <- reg
    AMOV_CST,   // reg <- reg OP cst
    AMOV_REG,   // reg <- reg OP reg
    // Read from memory
    LOAD,       // reg <- mem(reg + offset)
    ALOAD,      // reg OP<- mem(reg + offset)
    LOAD_CST,   // reg <- mem(offset)
    ALOAD_CST,  // reg OP<- mem(offset)
    // Store to memory
    STORE,      // mem(reg + offset) <- reg
    ASTORE,     // mem(reg + offset) OP<- reg
    CST_STORE,  // mem(offset) <- reg
    CST_ASTORE,  // mem(offset) OP<- reg
    STORE_CST,      // mem(reg + offset) <- cst
    ASTORE_CST,     // mem(reg + offset) OP<- cst
    CST_STORE_CST,  // mem(offset) <- cst
    CST_ASTORE_CST,  // mem(offset) OP<- cst
    CST_STORE_STRING, // mem(offset) <- string 
    // jump
    JMP,         // PC <- reg
    // Call functions
    FUNCTION,
    SYSCALL
};

/* IL - Instruction
   ================
  
  IL instructions are represented by a simple class which holds the
  instruction type and the list of arguments of the instruction. The 
  argument are ordered as defined in the strategy.hpp file (it holds 
  #define enums for gadget arguments and IL arguments since those are
  very similar in most cases).
  
  For example to access the destination register of a MOV_CST instruction
  we do:   instr.args[PARAM_MOVCST_DST_REG].

  Instructions are build directly from a string, examples are:
    "eax += ebx"
    "ecx = 678"
    "esi = ebx ^ 0xdead"
    "[edx+8] *= 2"
    "edx = [ecx]"
*/

#define IL_FUNC_ARG_REG 0
#define IL_FUNC_ARG_CST 1

class ILInstruction{
public:
    ILInstructionType type;
    string syscall_name; // Used for SYSCALL
    int syscall_num; // Use for SYSCALL
    string str; // Use for STORE_STRING
    vector<cst_t> args;
    vector<int> args_type; // Used for FUNCTION
    ILInstruction(ILInstructionType type, vector<cst_t>* args, vector<int>* args_type = nullptr, string syscall_name="",
            int syscall_num = -1, string str="");
    ILInstruction(Arch& arch, string instr_str); // raises il_exception if instr_str is invalid
};

#endif
