#include "compiler.hpp"
#include "exception.hpp"
#include "il.hpp"
#include <algorithm>


/* ============= Compiler Task ============ */
CompilerTask::CompilerTask(Arch* a):arch(a){}

void CompilerTask::add_strategy(StrategyGraph* graph, int max_tries){
    vector<StrategyGraph*>::iterator g;
    if( pending_strategies.size() >= max_tries && pending_strategies.front()->size <= graph->size ){
        // If strategy list is already full with smaller strategies, ignore this one
        delete graph;
        return;
    }
    for( g = pending_strategies.begin();
         g != pending_strategies.end() && (*g)->size >= graph->size;
         g++ ){}
    pending_strategies.insert(g, graph);
    
}

ROPChain* CompilerTask::compile(Arch* arch, GadgetDB* db, Constraint* constraint, int nb_tries){
    StrategyGraph* graph;
    ROPChain* res = nullptr;
    nb_tries = 3000;

    // Set sigint handler to catch Ctrl+C
    set_sigint_handler();

    while( nb_tries-- > 0 && !pending_strategies.empty() && !res){
        // Check if user entered Ctrl+C
        if( is_pending_sigint() ){
            notify_sigint_handled();
            unset_signint_handler();
            return nullptr;
        }

        graph = pending_strategies.back();
        pending_strategies.pop_back();
        if( graph->select_gadgets(*db, constraint, arch) ){
            res = graph->get_ropchain(arch, constraint);
        }else{
            // Apply strategy rules to the graph to get new candidate strategies
            apply_rules_to_graph(graph, nb_tries);
        }
        delete graph; graph = nullptr;
    }
    
    // Restore original sigint handler
    unset_signint_handler();

    return res;
}


void CompilerTask::apply_rules_to_graph(StrategyGraph* graph, int max_tries){
    StrategyGraph* new_graph;
    vector<StrategyGraph*> new_list;

    // Iterate through all nodes of the graph
    for( Node& node : graph->nodes ){
        if( node.is_disabled || node.is_indirect )
            continue; // Skip invalid/removed nodes
        // Apply strategy rules
        // Generic transitivity
        new_graph = graph->copy();
        if( new_graph->rule_generic_transitivity(node.id)){
            add_strategy(new_graph, max_tries);
            new_graph = graph->copy();
        }
        // MovCst pop
        if( new_graph->rule_mov_cst_pop(node.id, arch)){
            add_strategy(new_graph, max_tries);
            new_graph = graph->copy();
        }
        // Generic adjust_jmp
        if( new_graph->rule_generic_adjust_jmp(node.id, arch)){
            add_strategy(new_graph, max_tries);
            new_graph = graph->copy();
        }
        // Adjust load
        if( new_graph->rule_adjust_load(node.id, arch)){
            add_strategy(new_graph, max_tries);
            new_graph = graph->copy();
        }
        // Generic src reg transitivity
        if( new_graph->rule_generic_src_transitivity(node.id)){
            add_strategy(new_graph, max_tries);
            new_graph = graph->copy();
        }
        // Adjust store
        if( new_graph->rule_adjust_store(node.id, arch)){
            add_strategy(new_graph, max_tries);
            new_graph = graph->copy();
        }
        
        if( new_graph->rule_mba_set_cst(node.id, arch)){
            add_strategy(new_graph, max_tries);
            // Put new_graph = graph->copy() when adding more strategies
        }else{
            delete new_graph; new_graph = nullptr;
        }
    }
}

void CompilerTask::clear(){
    for( StrategyGraph* g : pending_strategies ){
        delete g; g = nullptr;
    }
    pending_strategies.clear();
}

CompilerTask::~CompilerTask(){
    clear();
}



/* ============= ROPCompiler ============= */
ROPCompiler::ROPCompiler(Arch* a, GadgetDB *d):arch(a), db(d){}

bool ROPCompiler::is_complex_instr(ILInstruction& instr, ABI abi){
    if( instr.type == ILInstructionType::SYSCALL )
        return true;
    if( instr.type == ILInstructionType::FUNCTION ){
        if( abi == ABI::X64_MS || abi == ABI::X64_SYSTEM_V ){
            return true;
        }
    }
    return false;
}

ROPChain* ROPCompiler::compile(string program, Constraint* constraint, ABI abi, System system){
    Constraint* tmp_constraint;
    ROPChain* res;
    vector<ILInstruction> final_instr;
    vector<ILInstruction> instr = parse(program); // This raises il_exception if malformed program

    // Add some general assertions
    if( !constraint ){
        tmp_constraint = new Constraint();
        tmp_constraint->mem_safety.enable_unsafe();
    }else{
        tmp_constraint = constraint;
    }
    // Add generic constraints
    tmp_constraint->mem_safety.add_safe_reg(arch->sp()); // Stack pointer is always safe for RW
    

    if( is_complex_instr(instr[0], abi)){
        res = process_complex(instr, tmp_constraint, abi, system);
    }else{
        res = process_simple(instr, tmp_constraint, abi, system);
    }
    
    if( !constraint ){
        delete tmp_constraint;
    }

    return res;
}

ROPChain* ROPCompiler::process_simple(vector<ILInstruction>& ins, Constraint* constraint, ABI abi, System system){
    CompilerTask task = CompilerTask(arch);
    ROPChain * res = nullptr, *tmp = nullptr;
    vector<ILInstruction> instructions;
    
    // Preprocess instructions
    preprocess(instructions, ins, constraint);

    // Compile
    for( ILInstruction& instr : instructions ){
        task.clear();
        il_to_strategy(task.pending_strategies, instr, constraint, abi, system);
        if( (tmp = task.compile(arch, db, constraint)) != nullptr){
            if( !res )
                res = tmp;
            else{
                res->add_chain(*tmp);
                delete tmp; tmp = nullptr;
            }
        }else{
            delete res;
            return nullptr;
        }
    }
    return res;
}

ROPChain* ROPCompiler::process_complex(vector<ILInstruction>& ins, Constraint* constraint, ABI abi, System system){
    CompilerTask task = CompilerTask(arch);
    ILInstruction instr =  ins[0];

    if( instr.type == ILInstructionType::SYSCALL ){
    // Syscalls
        if( system == System::NONE ){
            throw compiler_exception("Target OS must be specified to compile syscalls");
        }
        if( arch->type == ArchType::X86 ){
            switch( system ){
                case System::LINUX: return _compile_x86_linux_syscall(instr, constraint);
                default: throw compiler_exception("Syscalls are not supported for this system on X86");
            }
        }else if( arch->type == ArchType::X64 ){
            switch( system ){
                case System::LINUX: return _compile_x64_linux_syscall(instr, constraint);
                default: throw compiler_exception("Syscalls are not supported for this system on X64");
            }
        }else{
            throw runtime_exception("Syscalls are not supported for this architecture");
        }
    }else if( instr.type == ILInstructionType::FUNCTION ){
    // Functions
        if( abi == ABI::NONE ){
            throw compiler_exception("ABI must be specified to call functions");
        }
        if( arch->type == ArchType::X86 ){
            switch( abi ){
                default: throw compiler_exception("This ABI is not supported for X86");
            }
        }else if( arch->type == ArchType::X64 ){
            switch( abi ){
                case ABI::X64_SYSTEM_V: return _compile_x64_system_v_call(instr, constraint);
                case ABI::X64_MS: return _compile_x64_ms_call(instr, constraint);
                default: throw compiler_exception("This ABI is not supported for X64");
            }
        }else{
            throw runtime_exception("Function calls are not supported for this architecture");
        }
    }
    return nullptr;
}

bool _is_empty_line(string& s){
    for( char& c : s ){
        if( !isspace(c))
            return false;
    }
    return true;
}

vector<ILInstruction> ROPCompiler::parse(string& program){
    size_t pos;
    string instr;
    vector<ILInstruction> res;
    pos = 0;
    while( !program.empty() && pos != string::npos){
        pos = program.find('\n');
        instr = program.substr(0, pos);
        if( !_is_empty_line(instr)){
            try{
                ILInstruction ins = ILInstruction(*arch, instr);
                res.push_back(ins);
                instr.clear();
            }catch(il_exception const& e) {
                std::cout << string(e.what()) << std::endl;
                throw il_exception(QuickFmt() << "Invalid query: " << instr >> QuickFmt::to_str);
            }
        }
        program.erase(0, pos + 1);
    }
    return res;
}


bool _permutation_contains(vector<int>& perm1, vector<int>& perm2){

    if( perm1.back() != perm2.back() )
        return false; // Last = failed one, so if not the same we don't remove the recorded fail
    
    // Check perm2 is a prefix of perm1
    for( auto i = perm2.begin(); i != perm2.end()-1; i++ ){
        if( std::find(perm1.begin(), perm1.end()-1, *i) == (perm1.end()-1)){
            return false;
        }
    }

    return true;
}

void _record_failed_permutation(list<vector<int>>& failed_perms, vector<int>& perm){
    failed_perms.remove_if(
        [&perm](vector<int>& failed_perm){
            return _permutation_contains(failed_perm, perm);
        });
    failed_perms.push_back(perm);
}

bool _is_failed_permutation(list<vector<int>>& failed_perms, vector<int>& perm){
    for( auto failed_perm : failed_perms ){
        if( _permutation_contains(perm, failed_perm)){
            return true;
        }
    }
    return false;
}


ROPChain* ROPCompiler::_set_registers_permutation( vector<ILInstruction>& instr, vector<int>& permutation, Constraint* constraint, list<vector<int>>& failed_perms, bool& failed_on_first){
    CompilerTask task(arch);
    Constraint constr, tmp_constr;
    ROPChain *res = nullptr, *chain=nullptr;
    vector<int> tmp_perm;
    vector<int> tmp_keep_regs;
        
    constr = *constraint; // Copy base constraint

    for( int i = 0; i < permutation.size(); i++ ){
        int idx = permutation[i];
        tmp_perm.push_back(idx);
        task.clear();
        il_to_strategy(task.pending_strategies, instr[idx], &constr);
        // Add the register args to the constr (don't modify them)
        tmp_constr = constr;
        tmp_keep_regs.clear();
        for( int j = i+1; j < permutation.size(); j++ ){
            if( instr[j].type == ILInstructionType::MOV_REG ){
                tmp_constr.keep_regs.add_keep_reg(instr[j].args[PARAM_MOVREG_SRC_REG]);
                tmp_keep_regs.push_back(instr[j].args[PARAM_MOVREG_SRC_REG]);
            }
        }
        chain = task.compile(arch, db, &tmp_constr);
        if( chain == nullptr ){
            if( i == 0 && tmp_keep_regs.empty()){
                // No chain to set he first register
                failed_on_first = true;
                return nullptr;
            }
            
            // Add the additional future keep reg to tmp_perm when recording the fail
            for( int keep : tmp_keep_regs ){
                if( std::find(tmp_perm.begin(), tmp_perm.end(), keep) == tmp_perm.end())
                    tmp_perm.push_back(keep);
            }
            // Record fail and return
            _record_failed_permutation(failed_perms, tmp_perm);
            delete res;
            return nullptr;
        }else{
            // Add it to res
            if( res == nullptr )
                res = chain;
            else
                res->add_chain(*chain);
            // Do not modify this dest reg later on
            constr.keep_regs.add_keep_reg(instr[idx].args[0]); // Add the dst reg to keepregs
        }
    }
    return res;
}
 

 
ROPChain* ROPCompiler::_set_multiple_registers(vector<ILInstruction>& instr, Constraint* constraint){
    ROPChain* res = nullptr;
    vector<int> order;
    list<vector<int>> failed_permutations;
    bool failed_on_first = false;
    for( int i = 0; i < instr.size(); i++)
        order.push_back(i);

    do{
        if( !_is_failed_permutation(failed_permutations, order)){
            res = _set_registers_permutation(instr, order, constraint, failed_permutations, failed_on_first);
            if( res ){
                break; // Found chain, stop searching
            }else if( failed_on_first ){
                return nullptr;
            }
        }
    }while( std::next_permutation(order.begin(), order.end()));

    return res;
}




bool ROPCompiler::_x86_cdecl_to_strategy(StrategyGraph& graph, ILInstruction& instr){
    // Arguments pushed on the stack right to left
    // Caller-cleanup = we have to set a proper gadget as return address to go to 
    // the next gadget in the ropchain
    node_t n_ret = graph.new_node(GadgetType::LOAD);
    node_t n = graph.new_node(GadgetType::MOV_CST);
    Node& node_ret = graph.nodes[n_ret];
    Node& node = graph.nodes[n];
    // Add the 'ret' gadget that will 
    node_ret.is_indirect = true; // Indirect
    node_ret.params[PARAM_LOAD_DST_REG].make_reg(X86_EIP);
    node_ret.params[PARAM_LOAD_SRC_ADDR_REG].make_reg(X86_ESP);
    // For return gadget, skip all the arguments and return 
    // (nb args is args.size() -1 because 1rst arg is the function address)
    node_ret.params[PARAM_LOAD_SRC_ADDR_OFFSET].make_cst(arch->octets*(instr.args.size()-1), graph.new_name("stack_offset"));    

    // Main node
    /* Arguments are on the stack, pushed right to left */
    
    
    node.params[PARAM_MOVCST_DST_REG].make_reg(X86_EIP);
    node.params[PARAM_MOVCST_SRC_CST].make_cst(instr.args[PARAM_FUNCTION_ADDR], graph.new_name("function_address"));
    // Add parameters at the final sp_inc of the gadget
    for( int i = 1; i < instr.args.size(); i++){
        node.special_paddings.push_back(ROPPadding());
        // The offset is sp_inc + arch_size_bytes*(param_num+1) (+1 because return address comes before args)
        node.special_paddings.back().offset.make_cst(
            node.id, PARAM_MOVCST_GADGET_SP_INC,
            exprvar(arch->bits, node.params[PARAM_MOVCST_GADGET_SP_INC].name) + (arch->octets * ((i-1)+1)),
            graph.new_name("func_arg_offset")
        );
        if( instr.args_type[i] == IL_FUNC_ARG_CST ){
            node.special_paddings.back().value.make_cst(instr.args[i], graph.new_name("func_arg"));
        }else{
            // Putting the registers on the stack then call a function isn't supported
            return false;
        }
    }
    // Add constraint to check that the sp-delta of the gadget is 0
    node.assigned_gadget_constraints.push_back(
        // The gadget should have a sp_delta == 0 (otherwise the arguments won't be in the right place when
        // jumping to the function
        [](Node* n, StrategyGraph* g, Arch* arch)->bool{
            return n->affected_gadget->max_sp_inc == n->affected_gadget->sp_inc;
        }
    );

    // Add the 'ret' gadget address as first padding of the first gadget :)
    node.special_paddings.push_back(ROPPadding());
    node.special_paddings.back().offset.make_cst(
            node.id, PARAM_MOVCST_GADGET_SP_INC,
            exprvar(arch->bits, node.params[PARAM_MOVCST_GADGET_SP_INC].name),
            graph.new_name("func_ret_addr_offset")
        );
    node.special_paddings.back().value.make_cst(node_ret.id, PARAM_LOAD_GADGET_ADDR,
        exprvar(arch->bits, node_ret.params[PARAM_LOAD_GADGET_ADDR].name), graph.new_name("func_ret_addr"));

    // Add mandatory following node
    node.mandatory_following_node = node_ret.id;

    return true;
}

bool ROPCompiler::_x86_stdcall_to_strategy(StrategyGraph& graph, ILInstruction& instr){
    // Similar to cdecl but easier since it's a callee-cleaup convention so we just need
    // a 'ret' as return gadget and don't need to adapt it to the number of arguments
    node_t n_ret = graph.new_node(GadgetType::LOAD);
    node_t n = graph.new_node(GadgetType::MOV_CST);
    Node& node_ret = graph.nodes[n_ret];
    Node& node = graph.nodes[n];
    // Add the 'ret' gadget
    node_ret.is_indirect = true; // Indirect
    node_ret.params[PARAM_LOAD_DST_REG].make_reg(X86_EIP);
    node_ret.params[PARAM_LOAD_SRC_ADDR_REG].make_reg(X86_ESP);
    node_ret.params[PARAM_LOAD_SRC_ADDR_OFFSET].make_cst(0, graph.new_name("stack_offset"));    

    // Main node
    /* Arguments are on the stack, pushed right to left */
    node.params[PARAM_MOVCST_DST_REG].make_reg(X86_EIP);
    node.params[PARAM_MOVCST_SRC_CST].make_cst(instr.args[PARAM_FUNCTION_ADDR], graph.new_name("func_address"));
    // Add parameters at the final sp_inc of the gadget
    for( int i = 1; i < instr.args.size(); i++){
        node.special_paddings.push_back(ROPPadding());
        // The offset is sp_inc + arch_size_bytes*(param_num+1) (+1 because return address comes before args)
        node.special_paddings.back().offset.make_cst(
            node.id, PARAM_MOVCST_GADGET_SP_INC,
            exprvar(arch->bits, node.params[PARAM_MOVCST_GADGET_SP_INC].name) + (arch->octets * ((i-1)+1)),
            graph.new_name("func_arg_offset")
        );
        if( instr.args_type[i] == IL_FUNC_ARG_CST ){
            node.special_paddings.back().value.make_cst(instr.args[i], graph.new_name("func_arg"));
        }else{
            // Putting the registers on the stack then call a function isn't supported
            return false;
        }
    }
    // Add constraint to check that the sp-delta of the gadget is 0
    node.assigned_gadget_constraints.push_back(
        // The gadget should have a sp_delta == 0 (otherwise the arguments won't be in the right place when
        // jumping to the function
        [](Node* n, StrategyGraph* g, Arch* arch)->bool{
            return n->affected_gadget->max_sp_inc == n->affected_gadget->sp_inc;
        }
    );

    // Add the 'ret' gadget address as first padding of the first gadget :)
    node.special_paddings.push_back(ROPPadding());
    node.special_paddings.back().offset.make_cst(
            node.id, PARAM_MOVCST_GADGET_SP_INC,
            exprvar(arch->bits, node.params[PARAM_MOVCST_GADGET_SP_INC].name),
            graph.new_name("func_ret_addr_offset")
        );
    node.special_paddings.back().value.make_cst(node_ret.id, PARAM_LOAD_GADGET_ADDR,
        exprvar(arch->bits, node_ret.params[PARAM_LOAD_GADGET_ADDR].name), graph.new_name("func_ret_addr"));

    // Add mandatory following node
    node.mandatory_following_node = node_ret.id;

    return true;
}

ROPChain* ROPCompiler::_compile_x64_system_v_call(ILInstruction& instr, Constraint* constraint){
    // First 6 args in RDI,RSI,RDX,RCX,R8,R9 then on the stack pushed right to left
    node_t call_node, ret_node;
    int arg_regs[6] = {X64_RDI, X64_RSI, X64_RDX, X64_RCX, X64_R8, X64_R9};
    int nb_args_on_stack;
    CompilerTask task(arch);
    ROPChain *res=nullptr, *tmp=nullptr;
    StrategyGraph *graph = new StrategyGraph();
    vector<ILInstruction> set_regs_instr;
    Constraint call_constr;
    
    // Get base constraint
    call_constr = *constraint; // Constraint for the call node with the keepregs set

    // Create node for strategy graph to call the function (with padding etc)
    if( instr.args.size()-1 > 6 )
        nb_args_on_stack = instr.args.size()-1 - 6;
    else
        nb_args_on_stack = 0;

    // Add the 'ret' gadget
    ret_node = graph->new_node(GadgetType::LOAD);
    graph->nodes[ret_node].is_indirect = true; // Indirect
    graph->nodes[ret_node].params[PARAM_LOAD_DST_REG].make_reg(X64_RIP);
    graph->nodes[ret_node].params[PARAM_LOAD_SRC_ADDR_REG].make_reg(X64_RSP);
    graph->nodes[ret_node].params[PARAM_LOAD_SRC_ADDR_OFFSET].make_cst(nb_args_on_stack*arch->octets, graph->new_name("stack_offset"));

    // Add the call node
    call_node = graph->new_node(GadgetType::MOV_CST);
    graph->nodes[call_node].params[PARAM_MOVCST_DST_REG].make_reg(X64_RIP);
    graph->nodes[call_node].params[PARAM_MOVCST_SRC_CST].make_cst(instr.args[PARAM_FUNCTION_ADDR], graph->new_name("func_address"));
    // Add constraint to check that the sp-delta of the gadget is 0
    graph->nodes[call_node].assigned_gadget_constraints.push_back(
        // The gadget should have a sp_delta == 0 (otherwise the arguments won't be in the right place when
        // jumping to the function
        [](Node* n, StrategyGraph* g, Arch* arch)->bool{
            return n->affected_gadget->max_sp_inc == n->affected_gadget->sp_inc;
        }
    );

    // If needed add special paddings for extra args (after the 6th argument)
    for( int i = 0; i < nb_args_on_stack; i++){
        graph->nodes[call_node].special_paddings.push_back(ROPPadding());
        // The offset is sp_inc + arch_size_bytes*(param_num+1) (+1 because return address comes before args)
        graph->nodes[call_node].special_paddings.back().offset.make_cst(
            call_node, PARAM_MOVCST_GADGET_SP_INC,
            exprvar(arch->bits, graph->nodes[call_node].params[PARAM_MOVCST_GADGET_SP_INC].name) + (arch->octets * (i+1)),
            graph->new_name("func_arg_offset")
        );
        if( instr.args_type[PARAM_FUNCTION_ARGS+6+i] == IL_FUNC_ARG_CST ){
            graph->nodes[call_node].special_paddings.back().value.make_cst(instr.args[PARAM_FUNCTION_ARGS+6+i], graph->new_name("func_arg"));
        }else{
            // Putting the registers on the stack then call a function isn't supported
            delete graph;
            return nullptr;
        }
    }
    // Add the 'ret' gadget address as first padding of the first gadget :)
    graph->nodes[call_node].special_paddings.push_back(ROPPadding());
    graph->nodes[call_node].special_paddings.back().offset.make_cst(
            call_node, PARAM_MOVCST_GADGET_SP_INC,
            exprvar(arch->bits, graph->nodes[call_node].params[PARAM_MOVCST_GADGET_SP_INC].name),
            graph->new_name("func_ret_addr_offset")
        );
    graph->nodes[call_node].special_paddings.back().value.make_cst(ret_node, PARAM_LOAD_GADGET_ADDR,
        exprvar(arch->bits, graph->nodes[ret_node].params[PARAM_LOAD_GADGET_ADDR].name), graph->new_name("func_ret_addr"));

    // Add 'ret' node as mandatory following node
    graph->nodes[call_node].mandatory_following_node = ret_node;

    // Create a vector of instructions to set the register arguments
    for( int i = 0; i < 6 && (i < instr.args.size()-PARAM_FUNCTION_ARGS); i++){
        // Set register that must hold the argument
        if( instr.args_type[PARAM_FUNCTION_ARGS+i] == IL_FUNC_ARG_CST ){
            set_regs_instr.push_back(ILInstruction(ILInstructionType::MOV_CST));
            set_regs_instr.back().args = {arg_regs[i], instr.args[PARAM_FUNCTION_ARGS+i]};
        }else{
            set_regs_instr.push_back(ILInstruction(ILInstructionType::MOV_REG));
            set_regs_instr.back().args = {arg_regs[i], instr.args[PARAM_FUNCTION_ARGS+i]};
        }
        call_constr.keep_regs.add_keep_reg(arg_regs[i]);
    }

    
    // Get the chain that sets the registers
    res = _set_multiple_registers(set_regs_instr, constraint);
    if( !res ){
        delete graph;
        return nullptr;
    }
    
    // Get the chain that calls the function
    task.clear();
    task.pending_strategies.push_back(graph);
    tmp = task.compile(arch, db, &call_constr);

    if( !tmp ){
        delete res;
        res = nullptr;
        return nullptr;
    }
    // Sucess, return chain!
    res->add_chain(*tmp);

    return res;
}


ROPChain* ROPCompiler::_compile_x64_ms_call(ILInstruction& instr, Constraint* constraint){
    //  Similar to system_v but only 4 args passed in RDX,RCX,R8,R9 then on the stack pushed right to left
    // (Code is almost identical to _x64_system_v_to_strategy, only number of stack regs changes, 
    //  it could be factorized in the future if needed)
    node_t call_node, ret_node;
    int arg_regs[4] = {X64_RDX, X64_RCX, X64_R8, X64_R9};
    int nb_args_on_stack;
    CompilerTask task(arch);
    ROPChain *res=nullptr, *tmp=nullptr;
    StrategyGraph *graph = new StrategyGraph();
    vector<ILInstruction> set_regs_instr;
    Constraint call_constr;
    
    // Get base constraint
    call_constr = *constraint; // Constraint for the call node with the keepregs set

    if( instr.args.size()-1 > 4 )
        nb_args_on_stack = instr.args.size()-1 - 4;
    else
        nb_args_on_stack = 0;

    // Add the 'ret' gadget
    ret_node = graph->new_node(GadgetType::LOAD);
    graph->nodes[ret_node].is_indirect = true; // Indirect
    graph->nodes[ret_node].params[PARAM_LOAD_DST_REG].make_reg(X64_RIP);
    graph->nodes[ret_node].params[PARAM_LOAD_SRC_ADDR_REG].make_reg(X64_RSP);
    graph->nodes[ret_node].params[PARAM_LOAD_SRC_ADDR_OFFSET].make_cst(nb_args_on_stack*arch->octets, graph->new_name("stack_offset"));

    // Add the call node
    call_node = graph->new_node(GadgetType::MOV_CST);
    graph->nodes[call_node].params[PARAM_MOVCST_DST_REG].make_reg(X64_RIP);
    graph->nodes[call_node].params[PARAM_MOVCST_SRC_CST].make_cst(instr.args[PARAM_FUNCTION_ADDR], graph->new_name("func_address"));
    // Add constraint to check that the sp-delta of the gadget is 0
    graph->nodes[call_node].assigned_gadget_constraints.push_back(
        // The gadget should have a sp_delta == 0 (otherwise the arguments won't be in the right place when
        // jumping to the function
        [](Node* n, StrategyGraph* g, Arch* arch)->bool{
            return n->affected_gadget->max_sp_inc == n->affected_gadget->sp_inc;
        }
    );

    // If needed add special paddings for extra args (after the 4th argument)
    for( int i = 0; i < nb_args_on_stack; i++){
        graph->nodes[call_node].special_paddings.push_back(ROPPadding());
        // The offset is sp_inc + arch_size_bytes*(param_num+1) (+1 because return address comes before args)
        graph->nodes[call_node].special_paddings.back().offset.make_cst(
            call_node, PARAM_MOVCST_GADGET_SP_INC,
            exprvar(arch->bits, graph->nodes[call_node].params[PARAM_MOVCST_GADGET_SP_INC].name) + (arch->octets * (i+1)),
            graph->new_name("func_arg_offset")
        );
        if( instr.args_type[PARAM_FUNCTION_ARGS+4+i] == IL_FUNC_ARG_CST ){
            graph->nodes[call_node].special_paddings.back().value.make_cst(instr.args[PARAM_FUNCTION_ARGS+4+i], graph->new_name("func_arg"));
        }else{
            // Putting the registers on the stack then call a function isn't supported
            delete graph;
            return nullptr;
        }
    }
    // Add the 'ret' gadget address as first padding of the first gadget :)
    graph->nodes[call_node].special_paddings.push_back(ROPPadding());
    graph->nodes[call_node].special_paddings.back().offset.make_cst(
            call_node, PARAM_MOVCST_GADGET_SP_INC,
            exprvar(arch->bits, graph->nodes[call_node].params[PARAM_MOVCST_GADGET_SP_INC].name),
            graph->new_name("func_ret_addr_offset")
        );
    graph->nodes[call_node].special_paddings.back().value.make_cst(ret_node, PARAM_LOAD_GADGET_ADDR,
        exprvar(arch->bits, graph->nodes[ret_node].params[PARAM_LOAD_GADGET_ADDR].name), graph->new_name("func_ret_addr"));

    // Add 'ret' node as mandatory following node
    graph->nodes[call_node].mandatory_following_node = ret_node;

    // Create a vector of instructions to set the register arguments
    for( int i = 0; i < 4 && (i < instr.args.size()-PARAM_FUNCTION_ARGS); i++){
        // Set register that must hold the argument
        if( instr.args_type[PARAM_FUNCTION_ARGS+i] == IL_FUNC_ARG_CST ){
            set_regs_instr.push_back(ILInstruction(ILInstructionType::MOV_CST));
            set_regs_instr.back().args = {arg_regs[i], instr.args[PARAM_FUNCTION_ARGS+i]};
        }else{
            set_regs_instr.push_back(ILInstruction(ILInstructionType::MOV_REG));
            set_regs_instr.back().args = {arg_regs[i], instr.args[PARAM_FUNCTION_ARGS+i]};
        }
        call_constr.keep_regs.add_keep_reg(arg_regs[i]);
    }

    
    // Get the chain that sets the registers
    res = _set_multiple_registers(set_regs_instr, constraint);
    if( !res ){
        delete graph;
        return nullptr;
    }
    
    // Get the chain that calls the function
    task.clear();
    task.pending_strategies.push_back(graph);
    tmp = task.compile(arch, db, &call_constr);

    if( !tmp ){
        delete res;
        res = nullptr;
        return nullptr;
    }
    // Sucess, return chain!
    res->add_chain(*tmp);

    return res;
}

ROPChain* ROPCompiler::_compile_x86_linux_syscall(ILInstruction& instr, Constraint* constraint){
    // Get syscall def for this syscall
    SyscallDef* def;
    bool def_by_name;
    int syscall_num;
    CompilerTask task(arch);
    vector<ILInstruction> set_regs_instr;
    ROPChain *res, *syscall_chain;
    Constraint syscall_constraint = *constraint;

    def_by_name = !instr.syscall_name.empty();
    
    if( def_by_name ){
        def = get_syscall_def(ArchType::X64, System::LINUX, instr.syscall_name);
        if( def == nullptr ){
            throw compiler_exception(QuickFmt() << "Syscall '" << instr.syscall_name << "' is not supported");
        }
        syscall_num = def->num;
    }else{
        syscall_num = instr.syscall_num;
    }

    int arg_regs[6] = {X86_EBX, X86_ECX, X86_EDX, X86_ESI, X86_EDI, X86_EBP};

    if( instr.args.size() > 6 )
        throw compiler_exception("X86 syscalls can not take more than 6 arguments");
    else if( def_by_name && instr.args.size() != def->nb_args ){
        throw compiler_exception(QuickFmt() << "Syscall " << def->name << "() expects " << std::dec << 
                def->nb_args << " arguments (got " << instr.args.size() << ")" >> QuickFmt::to_str );
    }
    
    
    // Create vector of instructions to put the first 6 args in registers
    for( int i = 0; i < 6 && (i < instr.args.size()-PARAM_SYSCALL_ARGS); i++){
        // Set register that must hold the argument
        if( instr.args_type[PARAM_SYSCALL_ARGS+i] == IL_FUNC_ARG_CST ){
            set_regs_instr.push_back(ILInstruction(ILInstructionType::MOV_CST));
            set_regs_instr.back().args = {arg_regs[i], instr.args[PARAM_SYSCALL_ARGS+i]}; // MOV_CST args
        }else{
            set_regs_instr.push_back(ILInstruction(ILInstructionType::MOV_REG));
            set_regs_instr.back().args = {arg_regs[i], instr.args[PARAM_SYSCALL_ARGS+i]}; // MOV_CST args
        }
        syscall_constraint.keep_regs.add_keep_reg(arg_regs[i]);
    }
    
    // Add instruction to put syscall number in eax
    set_regs_instr.push_back(ILInstruction(ILInstructionType::MOV_CST));
    set_regs_instr.back().args = {X86_EAX, syscall_num}; // Syscall num in EAX

    // Get the chain to set all the registers
    res = _set_multiple_registers(set_regs_instr, constraint);
    if( !res ){
        return nullptr;
    }

    // Get the chain to make the syscall
    syscall_chain = compile("syscall", &syscall_constraint);
    if( ! syscall_chain ){
        delete res;
        return nullptr;
    }else{
        res->add_chain(*syscall_chain);
    }

    return res;
}

ROPChain* ROPCompiler::_compile_x64_linux_syscall(ILInstruction& instr, Constraint* constraint){
    // Get syscall def for this syscall
    SyscallDef* def;
    bool def_by_name;
    int syscall_num;
    CompilerTask task(arch);
    vector<ILInstruction> set_regs_instr;
    ROPChain *res, *syscall_chain;
    Constraint syscall_constraint = *constraint;

    def_by_name = !instr.syscall_name.empty();
    
    if( def_by_name ){
        def = get_syscall_def(ArchType::X64, System::LINUX, instr.syscall_name);
        if( def == nullptr ){
            throw compiler_exception(QuickFmt() << "Syscall '" << instr.syscall_name << "' is not supported");
        }
        syscall_num = def->num;
    }else{
        syscall_num = instr.syscall_num;
    }

    int arg_regs[6] = {X64_RDI, X64_RSI, X64_RDX, X64_R10, X64_R8, X64_R9};

    if( instr.args.size() > 6 )
        throw compiler_exception("X64 syscalls can not take more than 6 arguments");
    else if( def_by_name && instr.args.size() != def->nb_args ){
        throw compiler_exception(QuickFmt() << "Syscall " << def->name << "() expects " << std::dec << 
                def->nb_args << " arguments (got " << instr.args.size() << ")" >> QuickFmt::to_str );
    }
    
    
    // Create vector of instructions to put the first 6 args in registers
    for( int i = 0; i < 6 && (i < instr.args.size()-PARAM_SYSCALL_ARGS); i++){
        // Set register that must hold the argument
        if( instr.args_type[PARAM_SYSCALL_ARGS+i] == IL_FUNC_ARG_CST ){
            set_regs_instr.push_back(ILInstruction(ILInstructionType::MOV_CST));
            set_regs_instr.back().args = {arg_regs[i], instr.args[PARAM_SYSCALL_ARGS+i]}; // MOV_CST args
        }else{
            set_regs_instr.push_back(ILInstruction(ILInstructionType::MOV_REG));
            set_regs_instr.back().args = {arg_regs[i], instr.args[PARAM_SYSCALL_ARGS+i]}; // MOV_CST args
        }
        syscall_constraint.keep_regs.add_keep_reg(arg_regs[i]);
    }
    
    // Add instruction to put syscall number in eax
    set_regs_instr.push_back(ILInstruction(ILInstructionType::MOV_CST));
    set_regs_instr.back().args = {X64_RAX, syscall_num}; // Syscall num in RAX

    // Get the chain to set all the registers
    res = _set_multiple_registers(set_regs_instr, constraint);
    if( !res ){
        return nullptr;
    }

    // Get the chain to make the syscall
    syscall_chain = compile("syscall", &syscall_constraint);
    if( ! syscall_chain ){
        delete res;
        return nullptr;
    }else{
        res->add_chain(*syscall_chain);
    }

    return res;
}


bool _string_to_integers(vector<cst_t>& integers, string& str, int arch_octets, Constraint* constraint){
    // Assuming little endian
    int i = 0, j; 
    cst_t val;
    unsigned char padding_byte = 0xff; // Default
    
    if( constraint != nullptr ){
        try{
            padding_byte = constraint->bad_bytes.get_valid_byte();
        }catch(runtime_exception& e){
            return false;
        }
    }

    while( i < str.size() ){
        val = 0;
        for( j = 0; j < arch_octets && i < str.size(); j++){
            val += ((cst_t)str[i++]) << (j*8);
        }
        // Check if full value
        if( j != arch_octets ){
            // Adjust value
            for( ; j < arch_octets; j++){
                val += ((cst_t)padding_byte) << (j*8);
            }
        }
        integers.push_back(val);
    }
    return true;
}

bool _cst_store_cst_to_strategy(StrategyGraph& graph, ILInstruction& instr, Arch* arch){
    node_t n1 = graph.new_node(GadgetType::STORE);
    node_t n2 = graph.new_node(GadgetType::MOV_CST);
    node_t n3 = graph.new_node(GadgetType::MOV_CST);
    Node& node1 = graph.nodes[n1];
    Node& node2 = graph.nodes[n2];
    Node& node3 = graph.nodes[n3];
    node1.branch_type = BranchType::RET;
    node2.branch_type = BranchType::RET;
    node3.branch_type = BranchType::RET;
    // First node is mem(X + C) <- reg
    // Second is X <- src_cst - C 
    node1.params[PARAM_STORE_SRC_REG].make_reg(-1, false); // Free reg
    node1.params[PARAM_STORE_DST_ADDR_REG].make_reg(-1, false); // Free
    node1.params[PARAM_STORE_DST_ADDR_OFFSET].make_cst(-1, graph.new_name("offset"), false);
    node1.strategy_constraints.push_back(
        // Can not adjust the addr_reg if it is the same as the reg that must be written
        // (i.e mov [ecx+8], ecx can't become mov [0x12345678], ecx
        [](Node* n, StrategyGraph* g, Arch* arch)->bool{
            return n->params[PARAM_STORE_DST_ADDR_REG].value != n->params[PARAM_STORE_SRC_REG].value;
        }
    );
    node1.node_assertion.valid_pointers.add_valid_pointer(PARAM_STORE_DST_ADDR_REG);
    
    node2.params[PARAM_MOVCST_DST_REG].make_reg(n1, PARAM_STORE_DST_ADDR_REG); // node2 X is same as addr reg in node1
    node2.params[PARAM_MOVCST_DST_REG].is_data_link = true;
    node2.params[PARAM_MOVCST_SRC_CST].make_cst(n1, PARAM_STORE_DST_ADDR_OFFSET, 
        instr.args[PARAM_CSTSTORECST_DST_ADDR_OFFSET] - exprvar(arch->bits, node1.params[PARAM_STORE_DST_ADDR_OFFSET].name)
        , graph.new_name("cst")); // node2 cst is the target const C minus the offset in the node1 load
    
    node3.params[PARAM_MOVCST_DST_REG].make_reg(n1, PARAM_STORE_SRC_REG);
    node3.params[PARAM_MOVCST_DST_REG].is_data_link = true;
    node3.params[PARAM_MOVCST_SRC_CST].make_cst(instr.args[PARAM_CSTSTORECST_SRC_CST], graph.new_name("cst"));

    graph.add_param_edge(n2, n1);
    graph.add_strategy_edge(n2, n1);
    graph.add_param_edge(n3, n1);
    graph.add_strategy_edge(n3, n1);
    
    return true;
}


bool _preprocess_cst_store_string(vector<ILInstruction>& dst, ILInstruction& instr, Arch* arch, Constraint* constraint){
    vector<cst_t> integers;

    if( !_string_to_integers(integers, instr.str, arch->octets, constraint)){
        return false;
    }
    // For each integer, add node to store it to the correct address :)
    for( int i = 0; i < integers.size(); i++ ){
        cst_t addr_offset = instr.args[PARAM_CSTSTORE_STRING_ADDR_OFFSET] + (i*arch->octets);
        cst_t src_cst = integers[i];
        vector<cst_t> store_cst_args = {addr_offset, src_cst};
        ILInstruction il_instr = ILInstruction(ILInstructionType::CST_STORE_CST, &store_cst_args);
        dst.push_back(il_instr);
    }
    return true;
}

bool ROPCompiler::preprocess(vector<ILInstruction>& dst, vector<ILInstruction>& src, Constraint* constraint){
    for( ILInstruction& instr : src ){
        if( instr.type == ILInstructionType::CST_STORE_STRING ){
            // Splite a store string into several smaller ones
            if( ! _preprocess_cst_store_string(dst, instr, arch, constraint))
                return false;
        }else{
            // Just copy it
            dst.push_back(instr);
        }
    }
    return true;
}


void ROPCompiler::il_to_strategy(vector<StrategyGraph*>& graphs, ILInstruction& instr, Constraint* constraint, ABI abi, System system){
    StrategyGraph* graph;
    if( instr.type == ILInstructionType::MOV_CST ){
        // MOV_CST
        graph = new StrategyGraph();
        node_t n = graph->new_node(GadgetType::MOV_CST);
        Node& node = graph->nodes[n];
        node.branch_type = BranchType::RET;
        node.params[PARAM_MOVCST_DST_REG].make_reg(instr.args[PARAM_MOVCST_DST_REG]);
        node.params[PARAM_MOVCST_DST_REG].is_data_link = true;
        node.params[PARAM_MOVCST_SRC_CST].make_cst(instr.args[PARAM_MOVCST_SRC_CST], graph->new_name("cst"));
        graph->update_size();
        graphs.push_back(graph);
    }else if( instr.type == ILInstructionType::MOV_REG ){
        // MOV_REG
        graph = new StrategyGraph();
        node_t n = graph->new_node(GadgetType::MOV_REG);
        Node& node = graph->nodes[n];
        node.branch_type = BranchType::RET;
        node.params[PARAM_MOVREG_DST_REG].make_reg(instr.args[PARAM_MOVREG_DST_REG]);
        node.params[PARAM_MOVREG_DST_REG].is_data_link = true;
        node.params[PARAM_MOVREG_SRC_REG].make_reg(instr.args[PARAM_MOVREG_SRC_REG]);
        node.params[PARAM_MOVREG_SRC_REG].is_data_link = true;
        graph->update_size();
        graphs.push_back(graph);
    }else if( instr.type == ILInstructionType::AMOV_CST){
        // AMOV_CST
        graph = new StrategyGraph();
        node_t n = graph->new_node(GadgetType::AMOV_CST);
        Node& node = graph->nodes[n];
        node.branch_type = BranchType::RET;
        node.params[PARAM_AMOVCST_DST_REG].make_reg(instr.args[PARAM_AMOVCST_DST_REG]);
        node.params[PARAM_AMOVCST_DST_REG].is_data_link = true;
        node.params[PARAM_AMOVCST_SRC_REG].make_reg(instr.args[PARAM_AMOVCST_SRC_REG]);
        node.params[PARAM_AMOVCST_SRC_OP].make_op((Op)instr.args[PARAM_AMOVCST_SRC_OP]);
        node.params[PARAM_AMOVCST_SRC_CST].make_cst(instr.args[PARAM_AMOVCST_SRC_CST], graph->new_name("cst"));
        graph->update_size();
        graphs.push_back(graph);
    }else if( instr.type == ILInstructionType::AMOV_REG){
        // AMOV_REG
        graph = new StrategyGraph();
        node_t n = graph->new_node(GadgetType::AMOV_REG);
        Node& node = graph->nodes[n];
        node.branch_type = BranchType::RET;
        node.params[PARAM_AMOVREG_DST_REG].make_reg(instr.args[PARAM_AMOVREG_DST_REG]);
        node.params[PARAM_AMOVREG_DST_REG].is_data_link = true;
        node.params[PARAM_AMOVREG_SRC_REG1].make_reg(instr.args[PARAM_AMOVREG_SRC_REG1]);
        node.params[PARAM_AMOVREG_SRC_REG1].is_data_link = true;
        node.params[PARAM_AMOVREG_SRC_OP].make_op((Op)instr.args[PARAM_AMOVREG_SRC_OP]);
        node.params[PARAM_AMOVREG_SRC_REG2].make_reg(instr.args[PARAM_AMOVREG_SRC_REG2]);
        node.params[PARAM_AMOVREG_SRC_REG2].is_data_link = true;
        graph->update_size();
        graphs.push_back(graph);
    }else if( instr.type == ILInstructionType::LOAD ){
        // LOAD
        graph = new StrategyGraph();
        node_t n = graph->new_node(GadgetType::LOAD);
        Node& node = graph->nodes[n];
        node.branch_type = BranchType::RET;
        node.params[PARAM_LOAD_DST_REG].make_reg(instr.args[PARAM_LOAD_DST_REG]);
        node.params[PARAM_LOAD_DST_REG].is_data_link = true;
        node.params[PARAM_LOAD_SRC_ADDR_REG].make_reg(instr.args[PARAM_LOAD_SRC_ADDR_REG]);
        node.params[PARAM_LOAD_SRC_ADDR_REG].is_data_link = true;
        node.params[PARAM_LOAD_SRC_ADDR_OFFSET].make_cst(instr.args[PARAM_LOAD_SRC_ADDR_OFFSET], graph->new_name("offset"));
        node.node_assertion.valid_pointers.add_valid_pointer(PARAM_LOAD_SRC_ADDR_REG);
        graph->update_size();
        graphs.push_back(graph);
    }else if( instr.type == ILInstructionType::ALOAD ){
        // ALOAD
        graph = new StrategyGraph();
        node_t n = graph->new_node(GadgetType::ALOAD);
        Node& node = graph->nodes[n];
        node.branch_type = BranchType::RET;
        node.params[PARAM_ALOAD_DST_REG].make_reg(instr.args[PARAM_LOAD_DST_REG]);
        node.params[PARAM_ALOAD_DST_REG].is_data_link = true;
        node.params[PARAM_ALOAD_OP].make_op((Op)instr.args[PARAM_ALOAD_OP]);
        node.params[PARAM_ALOAD_SRC_ADDR_REG].make_reg(instr.args[PARAM_ALOAD_SRC_ADDR_REG]);
        node.params[PARAM_ALOAD_SRC_ADDR_REG].is_data_link = true;
        node.params[PARAM_ALOAD_SRC_ADDR_OFFSET].make_cst(instr.args[PARAM_ALOAD_SRC_ADDR_OFFSET], graph->new_name("offset"));
        node.node_assertion.valid_pointers.add_valid_pointer(PARAM_ALOAD_SRC_ADDR_REG);
        graph->update_size();
        graphs.push_back(graph);
    }else if( instr.type == ILInstructionType::LOAD_CST ){
        // LOAD_CST
        graph = new StrategyGraph();
        node_t n1 = graph->new_node(GadgetType::LOAD);
        node_t n2 = graph->new_node(GadgetType::MOV_CST);
        Node& node1 = graph->nodes[n1];
        Node& node2 = graph->nodes[n2];
        node1.branch_type = BranchType::RET;
        node2.branch_type = BranchType::RET;
        // First node is reg <- mem(X + C)
        // Second is X <- src_cst - C 
        node1.params[PARAM_LOAD_DST_REG].make_reg(instr.args[PARAM_LOADCST_DST_REG]);
        node1.params[PARAM_LOAD_DST_REG].is_data_link = true;
        node1.params[PARAM_LOAD_SRC_ADDR_REG].make_reg(-1, false); // Free
        node1.params[PARAM_LOAD_SRC_ADDR_OFFSET].make_cst(-1, graph->new_name("offset"), false);
        node1.node_assertion.valid_pointers.add_valid_pointer(PARAM_LOAD_SRC_ADDR_REG);
        
        node2.params[PARAM_MOVCST_DST_REG].make_reg(n1, PARAM_LOAD_SRC_ADDR_REG); // node2 X is same as addr reg in node1
        node2.params[PARAM_MOVCST_SRC_CST].make_cst(n1, PARAM_LOAD_SRC_ADDR_OFFSET, 
            instr.args[PARAM_LOADCST_SRC_ADDR_OFFSET] - exprvar(arch->bits, node1.params[PARAM_LOAD_SRC_ADDR_OFFSET].name)
            , graph->new_name("cst")); // node2 cst is the target const C minus the offset in the node1 load
        
        graph->add_param_edge(n2, n1);
        graph->add_strategy_edge(n2, n1);
        
        graph->update_size();
        graphs.push_back(graph);
    }else if( instr.type == ILInstructionType::ALOAD_CST ){
        // ALOAD_CST
        graph = new StrategyGraph();
        node_t n1 = graph->new_node(GadgetType::ALOAD);
        node_t n2 = graph->new_node(GadgetType::MOV_CST);
        Node& node1 = graph->nodes[n1];
        Node& node2 = graph->nodes[n2];
        node1.branch_type = BranchType::RET;
        node2.branch_type = BranchType::RET;
        // First node is reg Op<- mem(X + C)
        // Second is X <- src_cst - C 
        node1.params[PARAM_ALOAD_DST_REG].make_reg(instr.args[PARAM_ALOADCST_DST_REG]);
        node1.params[PARAM_ALOAD_DST_REG].is_data_link = true;
        node1.params[PARAM_ALOAD_OP].make_op((Op)instr.args[PARAM_ALOADCST_OP]);
        node1.params[PARAM_ALOAD_SRC_ADDR_REG].make_reg(-1, false); // Free
        node1.params[PARAM_ALOAD_SRC_ADDR_OFFSET].make_cst(-1, graph->new_name("offset"), false);
        node1.node_assertion.valid_pointers.add_valid_pointer(PARAM_ALOAD_SRC_ADDR_REG);

        node2.params[PARAM_MOVCST_DST_REG].make_reg(n1, PARAM_ALOAD_SRC_ADDR_REG); // node2 X is same as addr reg in node1
        node2.params[PARAM_MOVCST_SRC_CST].make_cst(n1, PARAM_ALOAD_SRC_ADDR_OFFSET, 
            instr.args[PARAM_ALOADCST_SRC_ADDR_OFFSET] - exprvar(arch->bits, node1.params[PARAM_ALOAD_SRC_ADDR_OFFSET].name)
            , graph->new_name("cst")); // node2 cst is the target const C minus the offset in the node1 load
        
        graph->add_param_edge(n2, n1);
        graph->add_strategy_edge(n2, n1);
        
        graph->update_size();
        graphs.push_back(graph);
    }else if( instr.type == ILInstructionType::STORE ){
        // STORE
        graph = new StrategyGraph();
        node_t n = graph->new_node(GadgetType::STORE);
        Node& node = graph->nodes[n];
        node.branch_type = BranchType::RET;
        node.params[PARAM_STORE_DST_ADDR_REG].make_reg(instr.args[PARAM_STORE_DST_ADDR_REG]);
        node.params[PARAM_STORE_DST_ADDR_REG].is_data_link = true;
        node.params[PARAM_STORE_DST_ADDR_OFFSET].make_cst(instr.args[PARAM_STORE_DST_ADDR_OFFSET], graph->new_name("offset"));
        node.params[PARAM_STORE_SRC_REG].make_reg(instr.args[PARAM_STORE_SRC_REG]);
        node.params[PARAM_STORE_SRC_REG].is_data_link = true;
        node.node_assertion.valid_pointers.add_valid_pointer(PARAM_STORE_DST_ADDR_REG);
        
        graph->update_size();
        graphs.push_back(graph);
    }else if( instr.type == ILInstructionType::CST_STORE ){
        // CST_STORE
        graph = new StrategyGraph();
        node_t n1 = graph->new_node(GadgetType::STORE);
        node_t n2 = graph->new_node(GadgetType::MOV_CST);
        Node& node1 = graph->nodes[n1];
        Node& node2 = graph->nodes[n2];
        node1.branch_type = BranchType::RET;
        node2.branch_type = BranchType::RET;
        // First node is mem(X + C) <- reg
        // Second is X <- src_cst - C 
        node1.params[PARAM_STORE_SRC_REG].make_reg(instr.args[PARAM_CSTSTORE_SRC_REG]);
        node1.params[PARAM_STORE_SRC_REG].is_data_link = true;
        node1.params[PARAM_STORE_DST_ADDR_REG].make_reg(-1, false); // Free
        node1.params[PARAM_STORE_DST_ADDR_OFFSET].make_cst(-1, graph->new_name("offset"), false);
        node1.strategy_constraints.push_back(
            // Can not adjust the addr_reg if it is the same as the reg that must be written
            // (i.e mov [ecx+8], ecx can't become mov [0x12345678], ecx
            [](Node* n, StrategyGraph* g, Arch* arch)->bool{
                return n->params[PARAM_STORE_DST_ADDR_REG].value != n->params[PARAM_STORE_SRC_REG].value;
            }
        );
        node1.node_assertion.valid_pointers.add_valid_pointer(PARAM_STORE_DST_ADDR_REG);
        
        node2.params[PARAM_MOVCST_DST_REG].make_reg(n1, PARAM_STORE_DST_ADDR_REG); // node2 X is same as addr reg in node1
        node2.params[PARAM_MOVCST_SRC_CST].make_cst(n1, PARAM_STORE_DST_ADDR_OFFSET, 
            instr.args[PARAM_CSTSTORE_DST_ADDR_OFFSET] - exprvar(arch->bits, node1.params[PARAM_STORE_DST_ADDR_OFFSET].name)
            , graph->new_name("cst")); // node2 cst is the target const C minus the offset in the node1 load
        
        graph->add_param_edge(n2, n1);
        graph->add_strategy_edge(n2, n1);
        
        graph->update_size();
        graphs.push_back(graph);
    }else if( instr.type == ILInstructionType::ASTORE ){
        // ASTORE
        graph = new StrategyGraph();
        node_t n = graph->new_node(GadgetType::ASTORE);
        Node& node = graph->nodes[n];
        node.branch_type = BranchType::RET;
        node.params[PARAM_ASTORE_DST_ADDR_REG].make_reg(instr.args[PARAM_ASTORE_DST_ADDR_REG]);
        node.params[PARAM_ASTORE_DST_ADDR_REG].is_data_link = true;
        node.params[PARAM_ASTORE_DST_ADDR_OFFSET].make_cst(instr.args[PARAM_ASTORE_DST_ADDR_OFFSET], graph->new_name("offset"));
        node.params[PARAM_ASTORE_OP].make_op((Op)instr.args[PARAM_ASTORE_OP]);
        node.params[PARAM_ASTORE_SRC_REG].make_reg(instr.args[PARAM_ASTORE_SRC_REG]);
        node.params[PARAM_ASTORE_SRC_REG].is_data_link = true;
        node.node_assertion.valid_pointers.add_valid_pointer(PARAM_ASTORE_DST_ADDR_REG);
        
        graph->update_size();
        graphs.push_back(graph);
        
    }else if( instr.type == ILInstructionType::CST_ASTORE ){
        // CST_ASTORE
        graph = new StrategyGraph();
        node_t n1 = graph->new_node(GadgetType::ASTORE);
        node_t n2 = graph->new_node(GadgetType::MOV_CST);
        Node& node1 = graph->nodes[n1];
        Node& node2 = graph->nodes[n2];
        node1.branch_type = BranchType::RET;
        node2.branch_type = BranchType::RET;
        // First node is mem(X + C) op<- reg
        // Second is X <- src_cst - C
        node1.params[PARAM_ASTORE_SRC_REG].make_reg(instr.args[PARAM_CSTASTORE_SRC_REG]);
        node1.params[PARAM_ASTORE_SRC_REG].is_data_link = true;
        node1.params[PARAM_ASTORE_OP].make_op((Op)instr.args[PARAM_CSTASTORE_OP]);
        node1.params[PARAM_ASTORE_DST_ADDR_REG].make_reg(-1, false); // Free
        node1.params[PARAM_ASTORE_DST_ADDR_OFFSET].make_cst(-1, graph->new_name("offset"), false);
        node1.strategy_constraints.push_back(
            // Can not adjust the addr_reg if it is the same as the reg that must be written
            // (i.e mov [ecx+8], ecx can't become mov [0x12345678], ecx
            [](Node* n, StrategyGraph* g, Arch * arch)->bool{
                return n->params[PARAM_ASTORE_DST_ADDR_REG].value != n->params[PARAM_ASTORE_SRC_REG].value;
            }
        );
        node1.node_assertion.valid_pointers.add_valid_pointer(PARAM_ASTORE_DST_ADDR_REG);

        node2.params[PARAM_MOVCST_DST_REG].make_reg(n1, PARAM_ASTORE_DST_ADDR_REG); // node2 X is same as addr reg in node1
        node2.params[PARAM_MOVCST_SRC_CST].make_cst(n1, PARAM_ASTORE_DST_ADDR_OFFSET, 
            instr.args[PARAM_CSTASTORE_DST_ADDR_OFFSET] - exprvar(arch->bits, node1.params[PARAM_ASTORE_DST_ADDR_OFFSET].name)
            , graph->new_name("cst")); // node2 cst is the target const C minus the offset in the node1 load

        graph->add_param_edge(n2, n1);
        graph->add_strategy_edge(n2, n1);

        graph->update_size();
        graphs.push_back(graph);
    }else if( instr.type == ILInstructionType::STORE_CST ){
        // STORE_CST
        graph = new StrategyGraph();
        node_t n = graph->new_node(GadgetType::STORE);
        node_t n1 = graph->new_node(GadgetType::MOV_CST);
        Node& node = graph->nodes[n];
        Node& node1 = graph->nodes[n1];
        node.branch_type = BranchType::RET;
        node.params[PARAM_STORE_DST_ADDR_REG].make_reg(instr.args[PARAM_STORE_DST_ADDR_REG]);
        node.params[PARAM_STORE_DST_ADDR_OFFSET].make_cst(instr.args[PARAM_STORE_DST_ADDR_OFFSET], graph->new_name("offset"));
        node.params[PARAM_STORE_SRC_REG].make_reg(-1, false); // Free reg
        node.node_assertion.valid_pointers.add_valid_pointer(PARAM_STORE_DST_ADDR_REG);
        
        node1.branch_type = BranchType::RET;
        node1.params[PARAM_MOVCST_DST_REG].make_reg(node.id, PARAM_STORE_SRC_REG);
        node1.params[PARAM_MOVCST_DST_REG].is_data_link = true;
        node1.params[PARAM_MOVCST_SRC_CST].make_cst(instr.args[PARAM_STORECST_SRC_CST], graph->new_name("cst"));
        
        graph->add_strategy_edge(node1.id, node.id);
        graph->add_param_edge(node1.id, node.id);
        
        graph->update_size();
        graphs.push_back(graph);
    }else if( instr.type == ILInstructionType::CST_STORE_CST ){
        // CST_STORE_CST
        graph = new StrategyGraph();
        if( _cst_store_cst_to_strategy(*graph, instr, arch)){
            graph->update_size();
            graphs.push_back(graph);
        }
    }else if( instr.type == ILInstructionType::ASTORE_CST ){
        // ASTORE_CST
        graph = new StrategyGraph();
        node_t n = graph->new_node(GadgetType::ASTORE);
        node_t n1 = graph->new_node(GadgetType::MOV_CST);
        Node& node = graph->nodes[n];
        Node& node1 = graph->nodes[n1];
        node.branch_type = BranchType::RET;
        node.params[PARAM_ASTORE_DST_ADDR_REG].make_reg(instr.args[PARAM_ASTORE_DST_ADDR_REG]);
        node.params[PARAM_ASTORE_DST_ADDR_REG].is_data_link = true;
        node.params[PARAM_ASTORE_DST_ADDR_OFFSET].make_cst(instr.args[PARAM_ASTORE_DST_ADDR_OFFSET], graph->new_name("offset"));
        node.params[PARAM_ASTORE_SRC_REG].make_reg(-1, false); // Free reg
        node.params[PARAM_ASTORE_OP].make_op((Op)instr.args[PARAM_ASTORECST_OP]);
        node.node_assertion.valid_pointers.add_valid_pointer(PARAM_ASTORE_DST_ADDR_REG);
        
        node1.branch_type = BranchType::RET;
        node1.params[PARAM_MOVCST_DST_REG].make_reg(node.id, PARAM_ASTORE_SRC_REG);
        node1.params[PARAM_MOVCST_DST_REG].is_data_link = true;
        node1.params[PARAM_MOVCST_SRC_CST].make_cst(instr.args[PARAM_ASTORECST_SRC_CST], graph->new_name("cst"));
        
        graph->add_strategy_edge(node1.id, node.id);
        graph->add_param_edge(node1.id, node.id);
        
        graph->update_size();
        graphs.push_back(graph);
    }else if( instr.type == ILInstructionType::CST_ASTORE_CST ){
        // CST_ASTORE_CST
        graph = new StrategyGraph();
        node_t n1 = graph->new_node(GadgetType::ASTORE);
        node_t n2 = graph->new_node(GadgetType::MOV_CST);
        node_t n3 = graph->new_node(GadgetType::MOV_CST);
        Node& node1 = graph->nodes[n1];
        Node& node2 = graph->nodes[n2];
        Node& node3 = graph->nodes[n3];
        node1.branch_type = BranchType::RET;
        node2.branch_type = BranchType::RET;
        node3.branch_type = BranchType::RET;
        // First node is mem(X + C) <- reg
        // Second is X <- src_cst - C 
        node1.params[PARAM_ASTORE_OP].make_op((Op)instr.args[PARAM_CSTASTORECST_OP]);
        node1.params[PARAM_ASTORE_SRC_REG].make_reg(-1, false); // Free reg
        node1.params[PARAM_ASTORE_DST_ADDR_REG].make_reg(-1, false); // Free reg
        node1.params[PARAM_ASTORE_DST_ADDR_OFFSET].make_cst(-1, graph->new_name("offset"), false); // Free offset also
        node1.strategy_constraints.push_back(
            // Can not adjust the addr_reg if it is the same as the reg that must be written
            // (i.e mov [ecx+8], ecx can't become mov [0x12345678], ecx
            [](Node* n, StrategyGraph* g, Arch* arch)->bool{
                return n->params[PARAM_ASTORE_DST_ADDR_REG].value != n->params[PARAM_ASTORE_SRC_REG].value;
            }
        );
        node1.node_assertion.valid_pointers.add_valid_pointer(PARAM_ASTORE_DST_ADDR_REG);
        
        node2.params[PARAM_MOVCST_DST_REG].make_reg(n1, PARAM_ASTORE_DST_ADDR_REG); // node2 X is same as addr reg in node1
        node2.params[PARAM_MOVCST_DST_REG].is_data_link = true;
        node2.params[PARAM_MOVCST_SRC_CST].make_cst(n1, PARAM_ASTORE_DST_ADDR_OFFSET, 
            instr.args[PARAM_CSTASTORECST_DST_ADDR_OFFSET] - exprvar(arch->bits, node1.params[PARAM_ASTORE_DST_ADDR_OFFSET].name)
            , graph->new_name("cst")); // node2 cst is the target const C minus the offset in the node1 load
        
        node3.params[PARAM_MOVCST_DST_REG].make_reg(n1, PARAM_ASTORE_SRC_REG);
        node3.params[PARAM_MOVCST_DST_REG].is_data_link = true;
        node3.params[PARAM_MOVCST_SRC_CST].make_cst(instr.args[PARAM_CSTASTORECST_SRC_CST], graph->new_name("cst"));

        graph->add_param_edge(n2, n1);
        graph->add_strategy_edge(n2, n1);
        graph->add_param_edge(n3, n1);
        graph->add_strategy_edge(n3, n1);

        graph->update_size();
        graphs.push_back(graph);
    }else if( instr.type == ILInstructionType::FUNCTION ){
        graph = new StrategyGraph();
        bool success = false;
        switch( abi ){
            case ABI::X86_CDECL: success = _x86_cdecl_to_strategy(*graph, instr); break;
            case ABI::X86_STDCALL: success = _x86_stdcall_to_strategy(*graph, instr); break;
            case ABI::NONE: throw compiler_exception("You have to specify which ABI to use to call functions");
            default:
                throw compiler_exception("il_instruction_to_strategy(): Unsupported ABI for function call");
        }
        if( !success ){
            throw compiler_exception("Couldn't translate function call into a chaining strategy");
        }

        graph->update_size();
        graphs.push_back(graph);
    }else if( instr.type == ILInstructionType::SINGLE_SYSCALL ){
        graph = new StrategyGraph();
        node_t n = graph->new_node(GadgetType::SYSCALL);
        graph->nodes[n].branch_type = BranchType::ANY;
        graph->update_size();
        graphs.push_back(graph);
    }else{
        throw runtime_exception("il_instruction_to_strategy(): unsupported ILInstructionType");
    }
}
