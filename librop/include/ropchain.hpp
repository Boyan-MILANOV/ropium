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
    bool modified_regs[NB_REGS_MAX];

    // Constructor
    Gadget();
    ~Gadget();
    // Other
    void add_address(addr_t addr);
    void print(ostream& os);
    bool lthan(Gadget& other);
};
ostream& operator<<(ostream& os, Gadget& g);


/* ======== ROPChain ========== */

enum class ROPItemType{
    GADGET,
    CST,
    PADDING
};

class ROPItem{
public:
    ROPItemType type;
    Gadget* gadget; // If gadget
    addr_t addr;
    cst_t value; // If cst or padding
    string msg;
    
    ROPItem(addr_t a, Gadget* g, string m=""):type(ROPItemType::GADGET), addr(a), gadget(g), msg(m){};
    ROPItem(ROPItemType t, cst_t v, string m=""):type(t), value(v), msg(m){};
};

class ROPChain{
private:
    Arch *arch; // Not owned
    vector<ROPItem> items;
public:
    ROPChain(Arch* arch);
    void add_gadget(addr_t addr, Gadget* gadget);
    void add_padding(cst_t val);
    void add_cst(cst_t val);
    int len();
    void print_pretty(ostream& os, string tab="");
    void print_python(ostream& os, string tab="");
};

ostream& operator<<(ostream& os, ROPChain& ropchain);

#endif
