#ifndef IL_HPP
#define IL_HPP

#include "arch.hpp"

// High level language
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
    // jump
    JMP         // PC <- reg
};

class ILInstruction{
public:
    ILInstructionType type;
    vector<cst_t> args;
    ILInstruction(Arch& arch, string instr_str);
};

#endif
