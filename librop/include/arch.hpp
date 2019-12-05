#ifndef ARCH_H
#define ARCH_H

#include <cstdint>
#include <string>
#include <capstone/capstone.h>

using std::string;
using std::to_string;

/* Forward declarations */
class Disassembler;

/* Type aliasing */
typedef uint16_t reg_t; 

/* CPU modes */
enum class CPUMode{
    X86,
    X64,
    ARM32,
    ARM_THUMB,
    ARM64,
    NONE
};

/* Different architectures supported */
enum class ArchType{
    X86,
    X64,
    ARM32,
    ARM64,
    NONE
};

#include "disassembler.hpp"

/* Arch
   ====

The Arch object represents an architecture. It holds information such as
the size of the registers, the number of registers, and the mode for 
architectures that can have several modes (X86, ARM, ...). It also holds
a pointer to its corresponding Disassembler.

Registers are represented as integers under the type reg_t. 

The Arch class is a Base class. Each architecture must the have its own
child class, such as ArchX86, ArchX64, etc.

*/

class Arch{
public:
    ArchType type;
    Disassembler* disasm;
    int bits;
    int octets;
    int nb_regs;
    CPUMode mode;

    Arch(ArchType type, int bits, int octets, int nb_regs, CPUMode mode, Disassembler * disasm);
    virtual ~Arch();
    virtual string reg_name(reg_t num) = 0;
    virtual reg_t reg_num(string name) = 0;
    virtual reg_t sp() = 0; // Stack pointer
    virtual reg_t pc() = 0; // Program counter
    virtual reg_t tsc() = 0; // Timestamp counter
};

class ArchNone: public Arch{
public:
    ArchNone(): Arch(ArchType::NONE, 32, 4, 20, CPUMode::NONE, (Disassembler*)nullptr){};
    string reg_name(reg_t num){return "reg" + to_string(num);};
    reg_t reg_num(string name){return 0;};
    reg_t sp(){return 19;};
    reg_t pc(){return 18;};
    reg_t tsc(){return 17;};
};


/* ==================================================
 *                      Arch X86
 * ================================================= */
 
/* Registers */
#define X86_EAX 0
#define X86_EBX 1
#define X86_ECX 2
#define X86_EDX 3
#define X86_EDI 4
#define X86_ESI 5
#define X86_EBP 6
#define X86_ESP 7
#define X86_EIP 8
/* Segment Registers */
#define X86_CS 9
#define X86_DS 10
#define X86_ES 11
#define X86_FS 12
#define X86_GS 13
#define X86_SS 14
/* Flag Registers */
#define X86_CF 15 // Carry flag
#define X86_PF 16 // Parity flag
#define X86_AF 17 // Auxiliary carry flag
#define X86_ZF 18 // Zero flag
#define X86_SF 19 // Sign flag
#define X86_TF 20 // Trap flag
#define X86_IF 21 // Interrupt enable flag
#define X86_DF 22 // Direction flag
#define X86_OF 23 // Overflow flag
#define X86_IOPL 24 // I/O Priviledge level
#define X86_NT 25 // Nested task flag
#define X86_RF 26 // Resume flag
#define X86_VM 27 // Virtual 8086 mode flag
#define X86_AC 28 // Alignment check flag (486+)
#define X86_VIF 29 // Virutal interrupt flag
#define X86_VIP 30 // Virtual interrupt pending flag
#define X86_ID 31 // ID Flag
#define X86_TSC 32 // TImeSTamp counter
#define X86_NB_REGS 33

class ArchX86: public Arch{
public:
    ArchX86();
    string reg_name(reg_t num);
    reg_t reg_num(string name);
    reg_t sp();
    reg_t pc();
    reg_t tsc();
};


/* ==================================================
 *                      Arch X64
 * ================================================= */

/* Registers */
#define X64_RAX 0
#define X64_RBX 1
#define X64_RCX 2
#define X64_RDX 3
#define X64_RDI 4
#define X64_RSI 5
#define X64_RBP 6
#define X64_RSP 7
#define X64_RIP 8
#define X64_R8 9
#define X64_R9 10
#define X64_R10 11
#define X64_R11 12
#define X64_R12 13
#define X64_R13 14
#define X64_R14 15
#define X64_R15 16
/* Segment Registers */
#define X64_CS 17
#define X64_DS 18
#define X64_ES 19
#define X64_FS 20
#define X64_GS 21
#define X64_SS 22
/* Flag Registers */
#define X64_CF 23 // Carry flag
#define X64_PF 24 // Parity flag
#define X64_AF 25 // Auxiliary carry flag
#define X64_ZF 26 // Zero flag
#define X64_SF 27 // Sign flag
#define X64_TF 28 // Trap flag
#define X64_IF 29 // Interrupt enable flag
#define X64_DF 30 // Direction flag
#define X64_OF 31 // Overflow flag
#define X64_IOPL 32 // I/O Priviledge level
#define X64_NT 33 // Nested task flag
#define X64_RF 34 // Resume flag
#define X64_VM 35 // Virtual 8086 mode flag
#define X64_AC 36 // Alignment check flag (486+)
#define X64_VIF 37 // Virutal interrupt flag
#define X64_VIP 38 // Virtual interrupt pending flag
#define X64_ID 39 // ID Flag
#define X64_TSC 40 // Timestamp counter
#define X64_NB_REGS 41


class ArchX64: public Arch{
public:
    ArchX64();
    string reg_name(reg_t num);
    reg_t reg_num(string name);
    reg_t sp();
    reg_t pc();
    reg_t tsc();
};

#endif
