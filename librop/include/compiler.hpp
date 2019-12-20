#ifndef ROP_COMPILER_H
#define ROP_COMPILER_H

#include "strategy.hpp"
#include "il.hpp"
#include "database.hpp"
#include <queue>

using std::queue;


class CompilerTask{
public:
    queue<StrategyGraph*> pending_strategies;
    void add_strategy(StrategyGraph* graph);
    ROPChain* compile(Arch* arch, GadgetDB* db, int nb_tries=100);
    ~CompilerTask();
};

class ROPCompiler{
    Arch* arch;
    GadgetDB* db;
public:
    ROPCompiler( Arch* arch, GadgetDB* db);
    ROPChain* compile(string program);
    ROPChain* process(vector<ILInstruction>& instructions);
    vector<ILInstruction> parse(string program);
    void il_to_strategy(queue<StrategyGraph*>& graphs, ILInstruction& instr);
};

#endif
