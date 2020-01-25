#ifndef ROP_COMPILER_H
#define ROP_COMPILER_H

#include "strategy.hpp"
#include "il.hpp"
#include "database.hpp"

using std::vector;

/* CompilerTask
   ============

   A compiler task is basically a set of StrategyGraph. For each graph,
   it tries to find a valid gadget selection. 

   - If it succeeds, the corresponding ROPChain is returned.
   - If it fails, it applies strategy rules to the graph to create new graphs,
     adds the new graphs to the queue of pending graphs, and then tries the 
     next one

*/

class CompilerTask{
    void apply_rules_to_graph(StrategyGraph* graph);
    Arch * arch;
public:
    CompilerTask(Arch* arch);
    vector<StrategyGraph*> pending_strategies;
    void add_strategy(StrategyGraph* graph);
    ROPChain* compile(Arch* arch, GadgetDB* db, Constraint* constraint=nullptr, int nb_tries=1000);
    ~CompilerTask();
};

/* ROPCompiler
   ============

   A ROP compiler is an abstraction over IL and StrategyGraph functionnalities.
   Basically it takes an IL program, parses it, translates it into strategy 
   graphs, and then start a compiler task to try to satisfy the program and
   find a matching ROPChain.

*/

class ROPCompiler{
    Arch* arch;
    GadgetDB* db;
public:
    ROPChain* process(vector<ILInstruction>& instructions, Constraint* constraint=nullptr);
    vector<ILInstruction> parse(string program);
    void il_to_strategy(vector<StrategyGraph*>& graphs, ILInstruction& instr);

    ROPCompiler( Arch* arch, GadgetDB* db);
    ROPChain* compile(string program, Constraint* constraint=nullptr);
};

#endif
