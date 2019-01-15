#ifndef ARCHITECTURE_H
#include <string>
#include <vector>

#define ARCHITECTURE_H


using std::string; 
using std::vector;

// Architecture class

enum EndiannessType{ ENDIAN_LITTLE, ENDIAN_BIG}; 


enum RegX86 : int { X86_EAX=0, X86_EBX, X86_ECX, X86_EDX, X86_ESI, X86_EDI, X86_ESP,
               X86_EIP, X86_EBP, X86_ZF, X86_CF, X86_SF, X86_PF, X86_AF, X86_OF, 
               X86_NB_REGS };
                             
enum RegX64 : int {X64_RAX=0, X64_RBX, X64_RCX, X64_RDX, X64_RSI, X64_RDI, 
                    X64_RSP, X64_RBP, X64_RIP, X64_R8, X64_R9, X64_R10,
                    X64_R11, X64_R12, X64_R13, X64_R14, X64_R15, X64_SF, 
                    X64_ZF, X64_AF, X64_CF, X64_DF, X64_ES, X64_FS, X64_NB_REGS};


enum ArchType {ARCH_X86, ARCH_X64};

class Architecture{
    ArchType _type; 
    string _name; 
    int _ip, _sp;
    int _octets, _bits; 
    int _min_page_size; 
    EndiannessType _endianness; 
    int _nb_regs; 
    vector<int> _ignored_regs;
    
    public:
        Architecture(ArchType at, string n, int i, int s, int o, int b, int m, EndiannessType t, 
            int nb, vector<int> ig); 
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
};

// Module wide functions to set global variables 
bool set_arch(ArchType a);
Architecture* curr_arch();

// Types of binaries 

enum BinType {BIN_X86_ELF, BIN_X64_ELF, BIN_X86_PE, BIN_X64_PE, BIN_UNKNOWN};
bool set_bin_type(BinType t);
BinType curr_bin_type(); 

#endif
