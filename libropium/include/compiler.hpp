#ifndef ROP_COMPILER_H
#define ROP_COMPILER_H

#include "strategy.hpp"
#include "il.hpp"
#include "database.hpp"
#include "systems.hpp"
#include <list>

using std::list;


enum class ABI{
    /* X86 */
    X86_CDECL,
    X86_STDCALL,
    X86_FASTCALL,
    X86_THISCALL_GCC,
    X86_THISCALL_MS,
    X86_LINUX_SYSENTER,
    X86_LINUX_INT80,
    /* X64 */
    X64_MS,
    X64_SYSTEM_V,
    /* No specific ABI */
    NONE
};

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
    void apply_rules_to_graph(StrategyGraph* graph, int max_tries);
    Arch * arch;
public:
    CompilerTask(Arch* arch);
    vector<StrategyGraph*> pending_strategies;
    void add_strategy(StrategyGraph* graph, int max_tries);
    ROPChain* compile(Arch* arch, GadgetDB* db, Constraint* constraint=nullptr, int nb_tries=3000); // DEBUG 
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
public:
    Arch* arch;
    GadgetDB* db;
    // Translate function calls into strategy graphs
    bool _x86_cdecl_to_strategy(StrategyGraph& graph, ILInstruction& instr);
    bool _x86_stdcall_to_strategy(StrategyGraph& graph, ILInstruction& instr);
    bool _x64_system_v_to_strategy(StrategyGraph& graph, ILInstruction& instr);
    bool _x64_ms_to_strategy(StrategyGraph& graph, ILInstruction& instr);
    bool _x86_linux_syscall_to_strategy(StrategyGraph& graph, ILInstruction& instr);
    bool _x64_linux_syscall_to_strategy(StrategyGraph& graph, ILInstruction& instr);

    // Main API
    ROPChain* process(vector<ILInstruction>& instructions, Constraint* constraint=nullptr, ABI abi = ABI::NONE, System sys=System::NONE);
    vector<ILInstruction> parse(string program);
    void il_to_strategy(vector<StrategyGraph*>& graphs, ILInstruction& instr, ABI abi = ABI::NONE, System sys=System::NONE);

    ROPCompiler( Arch* arch, GadgetDB* db);
    ROPChain* compile(string program, Constraint* constraint=nullptr, ABI abi=ABI::NONE, System sys=System::NONE);
};

#endif
