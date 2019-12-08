#ifndef ROPCHAIN_H
#define ROPCHAIN_H

#include "symbolic.hpp"
#include "arch.hpp"
#include "utils.hpp"
#include <string>

using std::string;


/* ======== Gadgets ========== */

enum class BranchType{
    RET,
    JMP,
    NONE
};

class Gadget{
public:
    int id; // To be set by the db when gadget is added
    int bin_num; // Identifies the binary/library it comes from
    string asm_str, _hex_str;
    Semantics* semantics;
    vector<addr_t> addresses; 
    /* Number of instructions in the gadget */
    int nb_instr, nb_instr_ir; 
    // Info about gadget semantics
    cst_t sp_inc;
    cst_t max_sp_inc;
    BranchType branch_type;
    reg_t jmp_reg;
    

    // Constructor
    Gadget();
    ~Gadget();
    // Other
    void add_address(addr_t addr);
    void print(ostream& os);
    bool lthan(shared_ptr<Gadget> other);
};

vector<Gadget*> gadgets_from_raw(vector<RawGadget>* raw, Arch* arch);

#endif
