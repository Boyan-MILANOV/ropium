#ifndef ROPCHAIN_H
#define ROPCHAIN_H

#include "symbolic.hpp"
#include <string>

using std::string;


/* ======== Analysed gadget ========== */
class Gadget{
public:
    int id; // To be set by the db when gadget is added
    int bin_num; // Identifies the binary/library it comes from
    string asm_str, _hex_str;
    Semantics* semantics;
    vector<addr_t> addresses; 
    /* Number of instructions in the gadget */
    int nb_instr, nb_instr_ir; 
    
    // Constructor
    Gadget();
    ~Gadget();
    // Other
    void print(ostream& os);
    bool lthan(shared_ptr<Gadget> other);
};

#endif
