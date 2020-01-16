#ifndef SYMBOLIC_H
#define SYMBOLIC_H

#include "ir.hpp"
#include "expression.hpp"
#include "simplification.hpp"
#include "arch.hpp"

using std::tuple;
using std::string;

/* Semantics
   =========  */
class Semantics{
public:
    IRContext* regs; // Takes ownership
    MemContext* mem; // Takes ownership
    Semantics(IRContext* regs, MemContext* mem);
    void simplify();
    ~Semantics();
};

ostream& operator<<(ostream&, Semantics& s);

/* SymbolicEngine
   ============== */

class SymbolicEngine{
public:
    Arch* arch;

    SymbolicEngine(ArchType arch);
    ~SymbolicEngine();
    Semantics* execute_block(IRBlock* block);
};

#endif
