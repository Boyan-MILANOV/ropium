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
    ROPChain* compile(Arch* arch, GadgetDB* db, Constraint* constraint=nullptr, int nb_tries=3000);
    void clear();
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

    ROPCompiler( Arch* arch, GadgetDB* db);

    // Main API
    // Take a list of instructions and compile all of them sequentially into a ropchain
    ROPChain* process(vector<ILInstruction>& instructions, Constraint* constraint=nullptr, ABI abi = ABI::NONE, System sys=System::NONE);
    // Transform complex instructions into simpler instructions that can be handled by "process()"
    bool preprocess(vector<ILInstruction>& dst, vector<ILInstruction>& src, Constraint* constraint=nullptr);
    // Parse a program into a vector of instructions
    vector<ILInstruction> parse(string& program);
    // Translate an IL instruction into one or several strategy graphs
    void il_to_strategy(vector<StrategyGraph*>& graphs, ILInstruction& instr, Constraint* constraint = nullptr, ABI abi = ABI::NONE, System sys=System::NONE);
    // Parse and process a program
    ROPChain* compile(string program, Constraint* constraint=nullptr, ABI abi=ABI::NONE, System sys=System::NONE);
};

#endif
