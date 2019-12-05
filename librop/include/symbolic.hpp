#ifndef SYMBOLIC_H
#define SYMBOLIC_H

#include "ir.hpp"
#include "expression.hpp"
#include "simplification.hpp"
#include "arch.hpp"

using std::tuple;
using std::string;

/* SymbolicEngine
   ============== */

class SymbolicEngine{
public:
    Arch* arch;

    SymbolicEngine(ArchType arch);
    ~SymbolicEngine();
    // TODO return semantics
    void execute_block(IRBlock* block);
};

#endif
