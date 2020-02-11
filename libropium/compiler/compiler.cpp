#include "compiler.hpp"
#include "exception.hpp"
#include "il.hpp"


/* ============= Compiler Task ============ */
CompilerTask::CompilerTask(Arch* a):arch(a){}

void CompilerTask::add_strategy(StrategyGraph* graph){
    vector<StrategyGraph*>::iterator g;
    for( g = pending_strategies.begin();
         g != pending_strategies.end() && (*g)->size >= graph->size;
         g++ ){}
    pending_strategies.insert(g, graph);
}

ROPChain* CompilerTask::compile(Arch* arch, GadgetDB* db, Constraint* constraint, int nb_tries){
    int n = 0;
    StrategyGraph* graph;
    ROPChain* res = nullptr;
    while( n++ < nb_tries && !pending_strategies.empty() && !res){
        graph = pending_strategies.back();
        pending_strategies.pop_back();
        if( graph->select_gadgets(*db, constraint, arch) ){
            res = graph->get_ropchain(arch, constraint);
        }else{
            // Apply strategy rules to the graph to get new candidate strategies
            apply_rules_to_graph(graph);
        }
        delete graph; graph = nullptr;
    }
    return res;
}


void CompilerTask::apply_rules_to_graph(StrategyGraph* graph){
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
            add_strategy(new_graph);
            new_graph = graph->copy();
        }
        // MovCst pop
        if( new_graph->rule_mov_cst_pop(node.id, arch)){
            add_strategy(new_graph);
            new_graph = graph->copy();
        }
        // Generic adjust_jmp
        if( new_graph->rule_generic_adjust_jmp(node.id, arch)){
            add_strategy(new_graph);
            new_graph = graph->copy();
        }
        // Adjust load
        if( new_graph->rule_adjust_load(node.id, arch)){
            add_strategy(new_graph);
            new_graph = graph->copy();
        }
        // Generic src reg transitivity
        if( new_graph->rule_generic_src_transitivity(node.id)){
            add_strategy(new_graph);
            new_graph = graph->copy();
        }
        // Adjust store
        if( new_graph->rule_adjust_store(node.id, arch)){
            add_strategy(new_graph);
            // Put new_graph = graph->copy() when adding more strategies
        }else{
            delete new_graph; new_graph = nullptr;
        }
    }
}

CompilerTask::~CompilerTask(){
    for( StrategyGraph* g : pending_strategies ){
        delete g; g = nullptr;
    }
    pending_strategies.clear();
}



/* ============= ROPCompiler ============= */
ROPCompiler::ROPCompiler(Arch* a, GadgetDB *d):arch(a), db(d){}

ROPChain* ROPCompiler::compile(string program, Constraint* constraint, ABI abi, System system){
    
    vector<ILInstruction> instr = parse(program); // This raises il_exception if malformed program

    // Add some general assertions
    if( constraint ){
        constraint->mem_safety.add_safe_reg(arch->sp()); // Stack pointer is always safe for RW
    }
    
    return process(instr, constraint, abi, system);
}

ROPChain* ROPCompiler::process(vector<ILInstruction>& instructions, Constraint* constraint, ABI abi, System system){
    CompilerTask task = CompilerTask(arch);
    for( ILInstruction& instr : instructions ){
        il_to_strategy(task.pending_strategies, instr, abi, system);
    }
    return task.compile(arch, db, constraint);
}

bool _is_empty_line(string& s){
    for( char& c : s ){
        if( !isspace(c))
            return false;
    }
    return true;
}

vector<ILInstruction> ROPCompiler::parse(string program){
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
            }catch(il_exception const& e) {
                throw il_exception(QuickFmt() << "Invalid query: " << instr >> QuickFmt::to_str);
            }
        }
        program.erase(0, pos + 1);
    }
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

bool ROPCompiler::_x64_system_v_to_strategy(StrategyGraph& graph, ILInstruction& instr){
    // First 6 args in RDI,RSI,RDX,RCX,R8,R9 then on the stack pushed right to left
    node_t n, call_node, ret_node;
    int arg_regs[6] = {X64_RDI, X64_RSI, X64_RDX, X64_RCX, X64_R8, X64_R9};
    int nb_args_on_stack;
    
    if( instr.args.size()-1 > 6 )
        nb_args_on_stack = instr.args.size()-1 - 6;
    else
        nb_args_on_stack = 0;
    
    // Add the 'ret' gadget
    ret_node = graph.new_node(GadgetType::LOAD);
    graph.nodes[ret_node].is_indirect = true; // Indirect
    graph.nodes[ret_node].params[PARAM_LOAD_DST_REG].make_reg(X64_RIP);
    graph.nodes[ret_node].params[PARAM_LOAD_SRC_ADDR_REG].make_reg(X64_RSP);
    graph.nodes[ret_node].params[PARAM_LOAD_SRC_ADDR_OFFSET].make_cst(nb_args_on_stack*arch->octets, graph.new_name("stack_offset"));
    
    // Add the call node
    call_node = graph.new_node(GadgetType::MOV_CST);
    graph.nodes[call_node].params[PARAM_MOVCST_DST_REG].make_reg(X64_RIP);
    graph.nodes[call_node].params[PARAM_MOVCST_SRC_CST].make_cst(instr.args[PARAM_FUNCTION_ADDR], graph.new_name("func_address"));
    // Add constraint to check that the sp-delta of the gadget is 0
    graph.nodes[call_node].assigned_gadget_constraints.push_back(
        // The gadget should have a sp_delta == 0 (otherwise the arguments won't be in the right place when
        // jumping to the function
        [](Node* n, StrategyGraph* g, Arch* arch)->bool{
            return n->affected_gadget->max_sp_inc == n->affected_gadget->sp_inc;
        }
    );
    // If needed add special paddings for extra args (after the 6th argument)
    for( int i = 0; i < nb_args_on_stack; i++){
        graph.nodes[call_node].special_paddings.push_back(ROPPadding());
        // The offset is sp_inc + arch_size_bytes*(param_num+1) (+1 because return address comes before args)
        graph.nodes[call_node].special_paddings.back().offset.make_cst(
            call_node, PARAM_MOVCST_GADGET_SP_INC,
            exprvar(arch->bits, graph.nodes[call_node].params[PARAM_MOVCST_GADGET_SP_INC].name) + (arch->octets * (i+1)),
            graph.new_name("func_arg_offset")
        );
        if( instr.args_type[PARAM_FUNCTION_ARGS+6+i] == IL_FUNC_ARG_CST ){
            graph.nodes[call_node].special_paddings.back().value.make_cst(instr.args[PARAM_FUNCTION_ARGS+6+i], graph.new_name("func_arg"));
        }else{
            // Putting the registers on the stack then call a function isn't supported
            return false;
        }
    }
    // Add the 'ret' gadget address as first padding of the first gadget :)
    graph.nodes[call_node].special_paddings.push_back(ROPPadding());
    graph.nodes[call_node].special_paddings.back().offset.make_cst(
            call_node, PARAM_MOVCST_GADGET_SP_INC,
            exprvar(arch->bits, graph.nodes[call_node].params[PARAM_MOVCST_GADGET_SP_INC].name),
            graph.new_name("func_ret_addr_offset")
        );
    graph.nodes[call_node].special_paddings.back().value.make_cst(ret_node, PARAM_LOAD_GADGET_ADDR,
        exprvar(arch->bits, graph.nodes[ret_node].params[PARAM_LOAD_GADGET_ADDR].name), graph.new_name("func_ret_addr"));

    // Add 'ret' node as mandatory following node
    graph.nodes[call_node].mandatory_following_node = ret_node;

    // Eventually add nodes to put the first 6 args in registers
    for( int i = 0; i < 6 && (i < instr.args.size()-PARAM_FUNCTION_ARGS); i++){
        // Set register that must hold the argument
        if( instr.args_type[PARAM_FUNCTION_ARGS+i] == IL_FUNC_ARG_CST ){
            n = graph.new_node(GadgetType::MOV_CST);
            graph.nodes[n].params[PARAM_MOVCST_DST_REG].make_reg(arg_regs[i]);
            graph.nodes[n].params[PARAM_MOVCST_DST_REG].is_data_link = true; // Must not be clobbred until call
            graph.nodes[n].params[PARAM_MOVCST_DST_REG].add_dep(call_node, PARAM_MOVCST_DATA_LINK); // Must not be clobbred until call
            graph.nodes[n].params[PARAM_MOVCST_SRC_CST].make_cst(instr.args[PARAM_FUNCTION_ARGS+i], graph.new_name("func_arg"));
        }else{
            n = graph.new_node(GadgetType::MOV_REG);
            graph.nodes[n].params[PARAM_MOVREG_DST_REG].make_reg(arg_regs[i]);
            graph.nodes[n].params[PARAM_MOVREG_DST_REG].is_data_link = true; // Must not be clobbred until call
            graph.nodes[n].params[PARAM_MOVREG_DST_REG].add_dep(call_node, PARAM_MOVCST_DATA_LINK); // Must not be clobbred until call
            graph.nodes[n].params[PARAM_MOVREG_SRC_REG].make_reg(instr.args[PARAM_FUNCTION_ARGS+i]);
            graph.nodes[n].params[PARAM_MOVREG_SRC_REG].is_data_link = true; // src_reg not be clobbered before being passed as argument
        }
        graph.nodes[n].branch_type = BranchType::RET;
        graph.add_strategy_edge(n, call_node);
    }

    return true;
}
bool ROPCompiler::_x64_ms_to_strategy(StrategyGraph& graph, ILInstruction& instr){
    //  Similar to system_v but only 4 args passed in RDX,RCX,R8,R9 then on the stack pushed right to left
    // (Code is almost identical to _x64_system_v_to_strategy, only number of stack regs changes, 
    //  it could be factorized in the future if needed)
    node_t n, call_node, ret_node;
    int arg_regs[4] = {X64_RDX, X64_RCX, X64_R8, X64_R9};
    int nb_args_on_stack;
    
    if( instr.args.size()-1 > 4 )
        nb_args_on_stack = instr.args.size()-1 - 4;
    else
        nb_args_on_stack = 0;
    
    // Add the 'ret' gadget
    ret_node = graph.new_node(GadgetType::LOAD);
    graph.nodes[ret_node].is_indirect = true; // Indirect
    graph.nodes[ret_node].params[PARAM_LOAD_DST_REG].make_reg(X64_RIP);
    graph.nodes[ret_node].params[PARAM_LOAD_SRC_ADDR_REG].make_reg(X64_RSP);
    graph.nodes[ret_node].params[PARAM_LOAD_SRC_ADDR_OFFSET].make_cst(nb_args_on_stack*arch->octets, graph.new_name("stack_offset"));
    
    // Add the call node
    call_node = graph.new_node(GadgetType::MOV_CST);
    graph.nodes[call_node].params[PARAM_MOVCST_DST_REG].make_reg(X64_RIP);
    graph.nodes[call_node].params[PARAM_MOVCST_SRC_CST].make_cst(instr.args[PARAM_FUNCTION_ADDR], graph.new_name("func_address"));
    // Add constraint to check that the sp-delta of the gadget is 0
    graph.nodes[call_node].assigned_gadget_constraints.push_back(
        // The gadget should have a sp_delta == 0 (otherwise the arguments won't be in the right place when
        // jumping to the function
        [](Node* n, StrategyGraph* g, Arch* arch)->bool{
            return n->affected_gadget->max_sp_inc == n->affected_gadget->sp_inc;
        }
    );
    // If needed add special paddings for extra args (after the 6th argument)
    for( int i = 0; i < nb_args_on_stack; i++){
        graph.nodes[call_node].special_paddings.push_back(ROPPadding());
        // The offset is sp_inc + arch_size_bytes*(param_num+1) (+1 because return address comes before args)
        graph.nodes[call_node].special_paddings.back().offset.make_cst(
            call_node, PARAM_MOVCST_GADGET_SP_INC,
            exprvar(arch->bits, graph.nodes[call_node].params[PARAM_MOVCST_GADGET_SP_INC].name) + (arch->octets * (i+1)),
            graph.new_name("func_arg_offset")
        );
        if( instr.args_type[PARAM_FUNCTION_ARGS+4+i] == IL_FUNC_ARG_CST ){
            graph.nodes[call_node].special_paddings.back().value.make_cst(instr.args[PARAM_FUNCTION_ARGS+4+i], graph.new_name("func_arg"));
        }else{
            // Putting the registers on the stack then call a function isn't supported
            return false;
        }
    }
    // Add the 'ret' gadget address as first padding of the first gadget :)
    graph.nodes[call_node].special_paddings.push_back(ROPPadding());
    graph.nodes[call_node].special_paddings.back().offset.make_cst(
            call_node, PARAM_MOVCST_GADGET_SP_INC,
            exprvar(arch->bits, graph.nodes[call_node].params[PARAM_MOVCST_GADGET_SP_INC].name),
            graph.new_name("func_ret_addr_offset")
        );
    graph.nodes[call_node].special_paddings.back().value.make_cst(ret_node, PARAM_LOAD_GADGET_ADDR,
        exprvar(arch->bits, graph.nodes[ret_node].params[PARAM_LOAD_GADGET_ADDR].name), graph.new_name("func_ret_addr"));

    // Add 'ret' node as mandatory following node
    graph.nodes[call_node].mandatory_following_node = ret_node;

    // Eventually add nodes to put the first 6 args in registers
    for( int i = 0; i < 4 && (i < instr.args.size()-PARAM_FUNCTION_ARGS); i++){
        // Set register that must hold the argument
        if( instr.args_type[PARAM_FUNCTION_ARGS+i] == IL_FUNC_ARG_CST ){
            n = graph.new_node(GadgetType::MOV_CST);
            graph.nodes[n].params[PARAM_MOVCST_DST_REG].make_reg(arg_regs[i]);
            graph.nodes[n].params[PARAM_MOVCST_DST_REG].is_data_link = true; // Must not be clobbred until call
            graph.nodes[n].params[PARAM_MOVCST_DST_REG].add_dep(call_node, PARAM_MOVCST_DATA_LINK); // Must not be clobbred until call
            graph.nodes[n].params[PARAM_MOVCST_SRC_CST].make_cst(instr.args[PARAM_FUNCTION_ARGS+i], graph.new_name("func_arg"));
        }else{
            n = graph.new_node(GadgetType::MOV_REG);
            graph.nodes[n].params[PARAM_MOVREG_DST_REG].make_reg(arg_regs[i]);
            graph.nodes[n].params[PARAM_MOVREG_DST_REG].is_data_link = true; // Must not be clobbred until call
            graph.nodes[n].params[PARAM_MOVREG_DST_REG].add_dep(call_node, PARAM_MOVCST_DATA_LINK); // Must not be clobbred until call
            graph.nodes[n].params[PARAM_MOVREG_SRC_REG].make_reg(instr.args[PARAM_FUNCTION_ARGS+i]);
            graph.nodes[n].params[PARAM_MOVREG_SRC_REG].is_data_link = true; // src_reg not be clobbered before being passed as argument
        }
        graph.nodes[n].branch_type = BranchType::RET;
        graph.add_strategy_edge(n, call_node);
    }

    return true;
}

bool ROPCompiler::_x86_linux_syscall_to_strategy(StrategyGraph& graph, ILInstruction& instr){
    // Get syscall def for this syscall
    SyscallDef* def = get_syscall_def(ArchType::X86, System::LINUX, instr.syscall_name);
    if( def == nullptr ){
        throw compiler_exception(QuickFmt() << "Syscall '" << instr.syscall_name << "' is not supported");
    }

    node_t n, syscall_node;
    int arg_regs[6] = {X86_EBX, X86_ECX, X86_EDX, X86_ESI, X86_EDI, X86_EBP};

    if( instr.args.size() > 6 )
        throw compiler_exception("X86 syscalls can not take more than 6 arguments");
    else if( instr.args.size() != def->nb_args ){
        throw compiler_exception(QuickFmt() << "Syscall " << def->name << "() expects " << std::dec << 
                def->nb_args << " arguments (got " << instr.args.size() << ")" >> QuickFmt::to_str );
    }

    // Add the syscall node (we put syscall since "sysenter" are added as "syscall" gadgets in 32 bits)
    syscall_node = graph.new_node(GadgetType::SYSCALL);

    // Add nodes to put the first 6 args in registers
    for( int i = 0; i < 6 && (i < instr.args.size()-PARAM_SYSCALL_ARGS); i++){
        // Set register that must hold the argument
        if( instr.args_type[PARAM_SYSCALL_ARGS+i] == IL_FUNC_ARG_CST ){
            n = graph.new_node(GadgetType::MOV_CST);
            graph.nodes[n].params[PARAM_MOVCST_DST_REG].make_reg(arg_regs[i]);
            graph.nodes[n].params[PARAM_MOVCST_DST_REG].is_data_link = true; // Must not be clobbred until call
            graph.nodes[n].params[PARAM_MOVCST_DST_REG].add_dep(syscall_node, PARAM_MOVCST_DATA_LINK); // Must not be clobbred until call
            graph.nodes[n].params[PARAM_MOVCST_SRC_CST].make_cst(instr.args[PARAM_SYSCALL_ARGS+i], graph.new_name("syscall_arg"));
        }else{
            n = graph.new_node(GadgetType::MOV_REG);
            graph.nodes[n].params[PARAM_MOVREG_DST_REG].make_reg(arg_regs[i]);
            graph.nodes[n].params[PARAM_MOVREG_DST_REG].is_data_link = true; // Must not be clobbred until call
            graph.nodes[n].params[PARAM_MOVREG_DST_REG].add_dep(syscall_node, PARAM_MOVCST_DATA_LINK); // Must not be clobbred until call
            graph.nodes[n].params[PARAM_MOVREG_SRC_REG].make_reg(instr.args[PARAM_SYSCALL_ARGS+i]);
            graph.nodes[n].params[PARAM_MOVREG_SRC_REG].is_data_link = true; // src_reg not be clobbered before being passed as argument
        }
        graph.nodes[n].branch_type = BranchType::RET;
        graph.add_strategy_edge(n, syscall_node);
    }

    // Add node to put syscall number in eax
    n = graph.new_node(GadgetType::MOV_CST);
    graph.nodes[n].branch_type = BranchType::RET;
    graph.add_strategy_edge(n, syscall_node);
    graph.nodes[n].params[PARAM_MOVCST_DST_REG].make_reg(X86_EAX);
    graph.nodes[n].params[PARAM_MOVCST_DST_REG].is_data_link = true; // Must not be clobbred until call
    graph.nodes[n].params[PARAM_MOVCST_DST_REG].add_dep(syscall_node, PARAM_MOVCST_DATA_LINK); // Must not be clobbred until call
    graph.nodes[n].params[PARAM_MOVCST_SRC_CST].make_cst(def->num, graph.new_name("syscall_num"));

    return true;
}

bool ROPCompiler::_x64_linux_syscall_to_strategy(StrategyGraph& graph, ILInstruction& instr){
    // Get syscall def for this syscall
    SyscallDef* def = get_syscall_def(ArchType::X64, System::LINUX, instr.syscall_name);
    if( def == nullptr ){
        throw compiler_exception(QuickFmt() << "Syscall '" << instr.syscall_name << "' is not supported");
    }

    node_t n, syscall_node;
    int arg_regs[6] = {X64_RDI, X64_RSI, X64_RDX, X64_R10, X64_R8, X64_R9};

    if( instr.args.size() > 6 )
        throw compiler_exception("X64 syscalls can not take more than 6 arguments");
    else if( instr.args.size() != def->nb_args ){
        throw compiler_exception(QuickFmt() << "Syscall " << def->name << "() expects " << std::dec << 
                def->nb_args << " arguments (got " << instr.args.size() << ")" >> QuickFmt::to_str );
    }

    // Add the syscall node (we put syscall since "sysenter" are added as "syscall" gadgets in 32 bits)
    syscall_node = graph.new_node(GadgetType::SYSCALL);

    // Add nodes to put the first 6 args in registers
    for( int i = 0; i < 6 && (i < instr.args.size()-PARAM_SYSCALL_ARGS); i++){
        // Set register that must hold the argument
        if( instr.args_type[PARAM_SYSCALL_ARGS+i] == IL_FUNC_ARG_CST ){
            n = graph.new_node(GadgetType::MOV_CST);
            graph.nodes[n].params[PARAM_MOVCST_DST_REG].make_reg(arg_regs[i]);
            graph.nodes[n].params[PARAM_MOVCST_DST_REG].is_data_link = true; // Must not be clobbred until call
            graph.nodes[n].params[PARAM_MOVCST_DST_REG].add_dep(syscall_node, PARAM_MOVCST_DATA_LINK); // Must not be clobbred until call
            graph.nodes[n].params[PARAM_MOVCST_SRC_CST].make_cst(instr.args[PARAM_SYSCALL_ARGS+i], graph.new_name("syscall_arg"));
        }else{
            n = graph.new_node(GadgetType::MOV_REG);
            graph.nodes[n].params[PARAM_MOVREG_DST_REG].make_reg(arg_regs[i]);
            graph.nodes[n].params[PARAM_MOVREG_DST_REG].is_data_link = true; // Must not be clobbred until call
            graph.nodes[n].params[PARAM_MOVREG_DST_REG].add_dep(syscall_node, PARAM_MOVCST_DATA_LINK); // Must not be clobbred until call
            graph.nodes[n].params[PARAM_MOVREG_SRC_REG].make_reg(instr.args[PARAM_SYSCALL_ARGS+i]);
            graph.nodes[n].params[PARAM_MOVREG_SRC_REG].is_data_link = true; // src_reg not be clobbered before being passed as argument
        }
        graph.nodes[n].branch_type = BranchType::RET;
        graph.add_strategy_edge(n, syscall_node);
    }

    // Add node to put syscall number in eax
    n = graph.new_node(GadgetType::MOV_CST);
    graph.nodes[n].branch_type = BranchType::RET;
    graph.add_strategy_edge(n, syscall_node);
    graph.nodes[n].params[PARAM_MOVCST_DST_REG].make_reg(X64_RAX);
    graph.nodes[n].params[PARAM_MOVCST_DST_REG].is_data_link = true; // Must not be clobbred until call
    graph.nodes[n].params[PARAM_MOVCST_DST_REG].add_dep(syscall_node, PARAM_MOVCST_DATA_LINK); // Must not be clobbred until call
    graph.nodes[n].params[PARAM_MOVCST_SRC_CST].make_cst(def->num, graph.new_name("syscall_num"));

    return true;
}


void ROPCompiler::il_to_strategy(vector<StrategyGraph*>& graphs, ILInstruction& instr, ABI abi, System system){
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
        
        graphs.push_back(graph);
    }else if( instr.type == ILInstructionType::CST_STORE_CST ){
        // CST_STORE_CST
        graph = new StrategyGraph();
        node_t n1 = graph->new_node(GadgetType::STORE);
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
        node1.params[PARAM_STORE_SRC_REG].make_reg(-1, false); // Free reg
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
        node2.params[PARAM_MOVCST_DST_REG].is_data_link = true;
        node2.params[PARAM_MOVCST_SRC_CST].make_cst(n1, PARAM_STORE_DST_ADDR_OFFSET, 
            instr.args[PARAM_CSTSTORECST_DST_ADDR_OFFSET] - exprvar(arch->bits, node1.params[PARAM_STORE_DST_ADDR_OFFSET].name)
            , graph->new_name("cst")); // node2 cst is the target const C minus the offset in the node1 load
        
        node3.params[PARAM_MOVCST_DST_REG].make_reg(n1, PARAM_STORE_SRC_REG);
        node3.params[PARAM_MOVCST_DST_REG].is_data_link = true;
        node3.params[PARAM_MOVCST_SRC_CST].make_cst(instr.args[PARAM_CSTSTORECST_SRC_CST], graph->new_name("cst"));

        graph->add_param_edge(n2, n1);
        graph->add_strategy_edge(n2, n1);
        graph->add_param_edge(n3, n1);
        graph->add_strategy_edge(n3, n1);

        graphs.push_back(graph);
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

        graphs.push_back(graph);
    }else if( instr.type == ILInstructionType::FUNCTION ){
        graph = new StrategyGraph();
        bool success = false;
        switch( abi ){
            case ABI::X86_CDECL: success = _x86_cdecl_to_strategy(*graph, instr); break;
            case ABI::X86_STDCALL: success = _x86_stdcall_to_strategy(*graph, instr); break;
            case ABI::X64_SYSTEM_V: success = _x64_system_v_to_strategy(*graph, instr); break;
            case ABI::X64_MS: success = _x64_ms_to_strategy(*graph, instr); break;
            case ABI::NONE: throw compiler_exception("You have to specify which ABI to use to call functions");
            default:
                throw compiler_exception("Unsupported ABI when calling function");
        }
        if( !success ){
            throw compiler_exception("Couldn't translate function call into a chaining strategy");
        }
        graphs.push_back(graph);
    }else if( instr.type == ILInstructionType::SYSCALL ){
        graph = new StrategyGraph();
        bool success = false;
        if( system == System::NONE ){
            throw compiler_exception("Target OS must be specified to compile syscalls");
        }
        if( arch->type == ArchType::X86 ){
            switch( system ){
                case System::LINUX: success = _x86_linux_syscall_to_strategy(*graph, instr); break;
                default: throw compiler_exception("Syscalls are not supported for this system on X86");
            }
        }else if( arch->type == ArchType::X64 ){
            switch( system ){
                case System::LINUX: success = _x64_linux_syscall_to_strategy(*graph, instr); break;
                default: throw compiler_exception("Syscalls are not supported for this system on X64");
            }
        }else{
            throw runtime_exception("Syscalls are not supported for this architecture");
        }
        if( !success ){
            throw compiler_exception("Couldn't translate function call into a chaining strategy");
        }
        graphs.push_back(graph);
    }else{
        throw runtime_exception("il_instruction_to_strategy(): unsupported ILInstructionType");
    }
}
