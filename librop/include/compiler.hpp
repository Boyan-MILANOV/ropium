#ifndef ROP_COMPILER_H
#define ROP_COMPILER_H

#include "strategy.hpp"
#include "il.hpp"
#include "database.hpp"
#include <queue>

using std::queue;


class CompilerTask{
    queue<StrategyGraph*> pending_strategies;
public:
    void add_strategy(StrategyGraph* graph);
    ROPChain* compile(Arch* arch, GadgetDB* db, int nb_tries=100);
    ~CompilerTask();
};

class ROPCompiler{
public:
    ROPCompiler(Arch* arch);
    ROPChain* compile(string program, Arch * arch, GadgetDB* db);
    ROPChain* process(vector<ILInstruction>& instructions, Arch * arch, GadgetDB* db);
    vector<ILInstruction> parse(string program, Arch* arch);
    void add_il_instruction_to_strategy(StrategyGraph& graph, ILInstruction& instr);
};

#endif
