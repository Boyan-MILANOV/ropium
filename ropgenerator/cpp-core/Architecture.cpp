#include "Architecture.hpp"
#include <algorithm>

// Architecture class 
Architecture::Architecture(ArchType at, string n, int i, int s, int o, 
            int b, int m, EndiannessType t, int nb, vector<int> ig): 
            _type(at), _name(n), _ip(i), _sp(s), _octets(o), _bits(b),
            _min_page_size(m), _endianness(t), _nb_regs(nb), _ignored_regs(ig)
            {} 
            
string Architecture::name(){return _name;}
int Architecture::ip(){return _ip;}
int Architecture::sp(){return _sp;}
int Architecture::min_page_size(){return _min_page_size;}
EndiannessType Architecture::endianness(){return _endianness;}
int Architecture::nb_regs(){return _nb_regs;}
bool Architecture::is_valid_reg( int num){return num > 0 && num < _nb_regs;}
bool Architecture::is_ignored_reg( int num ){
    return ( std::find(_ignored_regs.begin(), _ignored_regs.end(), num) != 
            _ignored_regs.end());
}

// X86
Architecture arch_X86 = Architecture(
    ARCH_X86, 
    "X86",
    X86_EIP, X86_ESP, 
    4, 32, 
    0x1000, 
    ENDIAN_LITTLE, 
    X86_NB_REGS, 
    {X86_AF, X86_CF, X86_ZF, X86_SF, X86_PF}
);

// X64 
Architecture arch_X64 = Architecture(
    ARCH_X64, 
    "X64",
    (int)X64_RIP, (int)X64_RSP, 
    8, 64, 
    0x1000, 
    ENDIAN_LITTLE, 
    X64_NB_REGS, 
    {X64_SF, X64_ZF, X64_AF, X64_CF, X64_DF, X64_ES, X64_FS}
);

// global variable for selected architecture 
Architecture* current_arch; 

// Module wide functions to set global variables 
bool set_arch(ArchType a){
    if( a == ARCH_X86 )
        current_arch = &arch_X86; 
    else if( a == ARCH_X64 )
        current_arch = &arch_X64; 
    else
        return false; 
    return true; 
}

Architecture* curr_arch(){ return current_arch;}
