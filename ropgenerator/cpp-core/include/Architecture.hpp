#ifndef ARCHITECTURE_H
#define ARCHITECTURE_H

#include <string>
#include <vector>
#include <memory>

using std::shared_ptr; 
using std::string; 
using std::vector;

// Architecture class

enum EndiannessType{ ENDIAN_LITTLE, ENDIAN_BIG}; 

// When adding a register, remember to update the python API and the register
// strings in the .cpp file ! 

// Also, the 10 first registers should be the most important ones when chaining and 
// will be the ones kept in the search record (see ChainingEngine.hpp)
enum RegX86 : int { X86_EAX=0, X86_EBX, X86_ECX, X86_EDX, X86_ESI, X86_EDI, X86_ESP,
               X86_EIP, X86_EBP, X86_ZF, X86_CF, X86_SF, X86_PF, X86_AF, X86_OF, 
               X86_NB_REGS };
                            
enum RegX64 : int {X64_RAX=0, X64_RBX, X64_RCX, X64_RDX, X64_RSI, X64_RDI, 
                    X64_RSP, X64_RBP, X64_RIP, X64_R8, X64_R9, X64_R10,
                    X64_R11, X64_R12, X64_R13, X64_R14, X64_R15, X64_SF, 
                    X64_ZF, X64_AF, X64_CF, X64_DF, X64_ES, X64_FS, X64_OF, 
                    X64_PF, X64_NB_REGS};

enum RegARM32 : int {ARM32_R0, ARM32_R1, ARM32_R2, ARM32_R3, ARM32_R4, ARM32_R5, ARM32_R6, ARM32_R7, 
                    ARM32_R8, ARM32_R9, ARM32_R10, ARM32_R11, ARM32_R12, ARM32_R13, ARM32_R14, ARM32_R15, 
                    ARM32_NB_REGS};

enum ArchType {ARCH_X86, ARCH_X64, ARCH_ARM32};

class Architecture{
    ArchType _type; 
    string _name; 
    int _ip, _sp;
    int _octets, _bits; 
    int _min_page_size; 
    EndiannessType _endianness; 
    int _nb_regs; 
    vector<int> _ignored_regs;
    vector<string> _reg_names;
    
    public:
        Architecture(ArchType at, string n, int i, int s, int o, int b, int m, EndiannessType t, 
            int nb, vector<int> ig, vector<string> reg_names); 
        ArchType type(); 
        string name(); 
        int ip(); 
        int sp(); 
        int octets();
        int bits();
        int min_page_size();
        EndiannessType endianness();
        int nb_regs(); 
        bool is_valid_reg( int num);
        bool is_ignored_reg( int num );
        string reg_name(int num);
        int reg_num(string reg_name);
};

// Module wide functions to set global variables 
bool set_arch(ArchType a);
Architecture* curr_arch();

// Types of binaries 

enum BinType {BIN_ELF32, BIN_ELF64, BIN_PE32, BIN_PE64, BIN_UNKNOWN};
void set_bin_type(BinType t);
BinType curr_bin_type(); 

#endif
