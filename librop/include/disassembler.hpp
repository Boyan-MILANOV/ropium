#ifndef DISASSEMBLER_H
#define DISASSEMBLER_H

#include "arch.hpp"
#include "ir.hpp"
#include <cstdint>

/* Types aliasing */
typedef uint8_t* code_t;

/* Forward declaration */
enum class CPUMode;
class IRBlock;

/* Disassembler
   ============

A disassembler is aimed at translating bytecode into IR. 

It is basically a wrapper around capstone disassembly framework.
Every disassembler initializes a capstone context with a handle and an cs_insn 
pointer in order to disassembly code iteratively instruction by instruction. 

*/

class Disassembler{
public:
    CPUMode _mode;
    /* Capstone objects */
    csh _handle;
    cs_insn * _insn;
    virtual ~Disassembler();
    /* Disassemble instructions until next branch instruction and return an IRBlock* */
    virtual IRBlock* disasm_block(addr_t addr, code_t code, size_t code_size=0xffffffff)=0;
};

class DisassemblerX86: public Disassembler{
public:
    DisassemblerX86(CPUMode mode);
    IRBlock* disasm_block(addr_t addr, code_t code, size_t code_size=0xffffffff);
};

#endif
