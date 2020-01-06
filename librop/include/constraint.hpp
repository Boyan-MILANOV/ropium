#ifndef CONSTRAINT_H
#define CONSTRAINT_H

#include "ropchain.hpp"
#include "arch.hpp"
#include <algorithm>

class BadBytes{
    vector<unsigned char> _bad_bytes;
public:
    void add_bad_byte(unsigned char byte);
    void clear();
    bool is_valid_byte(unsigned char byte);
    unsigned char get_valid_byte();
    bool is_valid_address(addr_t addr, int arch_bytes);
    addr_t get_valid_padding(int arch_bytes);
    addr_t get_valid_address(Gadget* gadget, int nb_bytes);
    bool check(Gadget* gadget, int arch_bytes);
};

class KeepRegs{
    vector<int> _keep;
public:
    void add_keep_reg(int reg_num);
    void clear();
    bool check(Gadget* gadget);
};

class MemSafety{
    bool _force_safe;
    bool _safe_reg_pointers[NB_REGS_MAX]; // Registers that should be considered valid pointers
public:
    MemSafety();
    void force_safe();
    void enable_unsafe();
    void add_safe_reg(int reg_num);
    void clear();
    bool check(Gadget* gadget, int arch_nb_regs);
};

class Constraint{
public:
    BadBytes bad_bytes;
    KeepRegs keep_regs;
    MemSafety mem_safety;

    void clear();
    bool check(Gadget* gadget, Arch* arch);
};

#endif
