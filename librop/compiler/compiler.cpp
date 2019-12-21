#include "compiler.hpp"
#include "exception.hpp"
#include "il.hpp"


/* ============= Compiler Task ============ */
void CompilerTask::add_strategy(StrategyGraph* graph){
    pending_strategies.push(graph);
}

ROPChain* CompilerTask::compile(Arch* arch, GadgetDB* db, int nb_tries){
    int n = 0;
    StrategyGraph* graph;
    ROPChain * ropchain;
    while( n++ < nb_tries && !pending_strategies.empty()){
        graph = pending_strategies.front();
        pending_strategies.pop();
        if( graph->select_gadgets(*db) )
            return graph->get_ropchain(arch);
        // TODO: apply munch rules and create new strategy trees
    }
    return nullptr;
}

CompilerTask::~CompilerTask(){
    while( !pending_strategies.empty()){
        delete pending_strategies.front();
        pending_strategies.pop();
    }
}



/* ============= ROPCompiler ============= */
ROPCompiler::ROPCompiler(Arch* a, GadgetDB *d):arch(a), db(d){}

ROPChain* ROPCompiler::compile(string program){
    vector<ILInstruction> instr = parse(program); // This raises il_exception if malformed program
    return process(instr);
}

ROPChain* ROPCompiler::process(vector<ILInstruction>& instructions){
    CompilerTask task;
    for( ILInstruction& instr : instructions ){
        il_to_strategy(task.pending_strategies, instr);
    }
    return task.compile(arch, db);
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

void ROPCompiler::il_to_strategy(queue<StrategyGraph*>& graphs, ILInstruction& instr){
    StrategyGraph* graph;
    if( instr.type == ILInstructionType::MOV_CST ){
        // MOV_CST
        graph = new StrategyGraph();
        node_t n = graph->new_node(GadgetType::MOV_CST);
        Node& node = graph->nodes[n];
        node.params[PARAM_MOVCST_DST_REG].make_reg(instr.args[PARAM_MOVCST_DST_REG]);
        node.params[PARAM_MOVCST_SRC_CST].make_cst(instr.args[PARAM_MOVCST_SRC_CST], graph->new_name("cst"));
        graphs.push(graph);
    }else if( instr.type == ILInstructionType::MOV_REG ){
        // MOV_REG
        graph = new StrategyGraph();
        node_t n = graph->new_node(GadgetType::MOV_REG);
        Node& node = graph->nodes[n];
        node.params[PARAM_MOVREG_DST_REG].make_reg(instr.args[PARAM_MOVREG_DST_REG]);
        node.params[PARAM_MOVREG_SRC_REG].make_reg(instr.args[PARAM_MOVREG_SRC_REG]);
        graphs.push(graph);
    }else if( instr.type == ILInstructionType::AMOV_CST){
        // AMOV_CST
        graph = new StrategyGraph();
        node_t n = graph->new_node(GadgetType::AMOV_CST);
        Node& node = graph->nodes[n];
        node.params[PARAM_AMOVCST_DST_REG].make_reg(instr.args[PARAM_AMOVCST_DST_REG]);
        node.params[PARAM_AMOVCST_SRC_REG].make_reg(instr.args[PARAM_AMOVCST_SRC_REG]);
        node.params[PARAM_AMOVCST_SRC_OP].make_op((Op)instr.args[PARAM_AMOVCST_SRC_OP]);
        node.params[PARAM_AMOVCST_SRC_CST].make_cst(instr.args[PARAM_AMOVCST_SRC_CST], graph->new_name("cst"));
        graphs.push(graph);
    }else if( instr.type == ILInstructionType::AMOV_REG){
        // AMOV_REG
        graph = new StrategyGraph();
        node_t n = graph->new_node(GadgetType::AMOV_REG);
        Node& node = graph->nodes[n];
        node.params[PARAM_AMOVREG_DST_REG].make_reg(instr.args[PARAM_AMOVREG_DST_REG]);
        node.params[PARAM_AMOVREG_SRC_REG1].make_reg(instr.args[PARAM_AMOVREG_SRC_REG1]);
        node.params[PARAM_AMOVREG_SRC_OP].make_op((Op)instr.args[PARAM_AMOVREG_SRC_OP]);
        node.params[PARAM_AMOVREG_SRC_REG2].make_reg(instr.args[PARAM_AMOVREG_SRC_REG2]);
        graphs.push(graph);
    }else if( instr.type == ILInstructionType::LOAD ){
        // LOAD
        graph = new StrategyGraph();
        node_t n = graph->new_node(GadgetType::LOAD);
        Node& node = graph->nodes[n];
        node.params[PARAM_LOAD_DST_REG].make_reg(instr.args[PARAM_LOAD_DST_REG]);
        node.params[PARAM_LOAD_SRC_ADDR_REG].make_reg(instr.args[PARAM_LOAD_SRC_ADDR_REG]);
        node.params[PARAM_LOAD_SRC_ADDR_OFFSET].make_cst(instr.args[PARAM_LOAD_SRC_ADDR_OFFSET], graph->new_name("offset"));
        graphs.push(graph);
    }else if( instr.type == ILInstructionType::ALOAD ){
        // ALOAD
        graph = new StrategyGraph();
        node_t n = graph->new_node(GadgetType::ALOAD);
        Node& node = graph->nodes[n];
        node.params[PARAM_ALOAD_DST_REG].make_reg(instr.args[PARAM_LOAD_DST_REG]);
        node.params[PARAM_ALOAD_OP].make_op((Op)instr.args[PARAM_ALOAD_OP]);
        node.params[PARAM_ALOAD_SRC_ADDR_REG].make_reg(instr.args[PARAM_ALOAD_SRC_ADDR_REG]);
        node.params[PARAM_ALOAD_SRC_ADDR_OFFSET].make_cst(instr.args[PARAM_ALOAD_SRC_ADDR_OFFSET], graph->new_name("offset"));
        graphs.push(graph);
    }else if( instr.type == ILInstructionType::LOAD_CST ){
        // LOAD_CST
        graph = new StrategyGraph();
        node_t n1 = graph->new_node(GadgetType::LOAD);
        node_t n2 = graph->new_node(GadgetType::MOV_CST);
        Node& node1 = graph->nodes[n1];
        Node& node2 = graph->nodes[n2];
        // First node is reg <- mem(X + C)
        // Second is X <- src_cst - C 
        node1.params[PARAM_LOAD_DST_REG].make_reg(instr.args[PARAM_LOADCST_DST_REG]);
        node1.params[PARAM_LOAD_SRC_ADDR_REG].make_reg(-1, false); // Free
        node1.params[PARAM_LOAD_SRC_ADDR_OFFSET].make_cst(-1, graph->new_name("offset"), false);
        
        node2.params[PARAM_MOVCST_DST_REG].make_reg(n1, PARAM_LOAD_SRC_ADDR_REG); // node2 X is same as addr reg in node1
        node2.params[PARAM_MOVCST_SRC_CST].make_cst(n1, PARAM_LOAD_SRC_ADDR_OFFSET, 
            instr.args[PARAM_LOADCST_SRC_ADDR_OFFSET] - exprvar(arch->bits, node1.params[PARAM_LOAD_SRC_ADDR_OFFSET].name)
            , graph->new_name("cst")); // node2 cst is the target const C minus the offset in the node1 load
        
        graph->add_param_edge(n2, n1);
        graph->add_strategy_edge(n2, n1);
        
        graphs.push(graph);
    }else if( instr.type == ILInstructionType::ALOAD_CST ){
        // ALOAD_CST
        graph = new StrategyGraph();
        node_t n1 = graph->new_node(GadgetType::ALOAD);
        node_t n2 = graph->new_node(GadgetType::MOV_CST);
        Node& node1 = graph->nodes[n1];
        Node& node2 = graph->nodes[n2];
        // First node is reg Op<- mem(X + C)
        // Second is X <- src_cst - C 
        node1.params[PARAM_ALOAD_DST_REG].make_reg(instr.args[PARAM_ALOADCST_DST_REG]);
        node1.params[PARAM_ALOAD_OP].make_op((Op)instr.args[PARAM_ALOADCST_OP]);
        node1.params[PARAM_ALOAD_SRC_ADDR_REG].make_reg(-1, false); // Free
        node1.params[PARAM_ALOAD_SRC_ADDR_OFFSET].make_cst(-1, graph->new_name("offset"), false);
        
        node2.params[PARAM_MOVCST_DST_REG].make_reg(n1, PARAM_ALOAD_SRC_ADDR_REG); // node2 X is same as addr reg in node1
        node2.params[PARAM_MOVCST_SRC_CST].make_cst(n1, PARAM_ALOAD_SRC_ADDR_OFFSET, 
            instr.args[PARAM_ALOADCST_SRC_ADDR_OFFSET] - exprvar(arch->bits, node1.params[PARAM_ALOAD_SRC_ADDR_OFFSET].name)
            , graph->new_name("cst")); // node2 cst is the target const C minus the offset in the node1 load
        
        graph->add_param_edge(n2, n1);
        graph->add_strategy_edge(n2, n1);
        
        graphs.push(graph);
    }else if( instr.type == ILInstructionType::STORE ){
        // STORE
        graph = new StrategyGraph();
        node_t n = graph->new_node(GadgetType::STORE);
        Node& node = graph->nodes[n];
        node.params[PARAM_STORE_DST_ADDR_REG].make_reg(instr.args[PARAM_STORE_DST_ADDR_REG]);
        node.params[PARAM_STORE_DST_ADDR_OFFSET].make_cst(instr.args[PARAM_STORE_DST_ADDR_OFFSET], graph->new_name("offset"));
        node.params[PARAM_STORE_SRC_REG].make_reg(instr.args[PARAM_STORE_SRC_REG]);
        graphs.push(graph);
    }else if( instr.type == ILInstructionType::CST_STORE ){
        // CST_STORE
        graph = new StrategyGraph();
        node_t n1 = graph->new_node(GadgetType::STORE);
        node_t n2 = graph->new_node(GadgetType::MOV_CST);
        Node& node1 = graph->nodes[n1];
        Node& node2 = graph->nodes[n2];
        // First node is mem(X + C) <- reg
        // Second is X <- src_cst - C 
        node1.params[PARAM_STORE_SRC_REG].make_reg(instr.args[PARAM_CSTSTORE_SRC_REG]);
        node1.params[PARAM_STORE_DST_ADDR_REG].make_reg(-1, false); // Free
        node1.params[PARAM_STORE_DST_ADDR_OFFSET].make_cst(-1, graph->new_name("offset"), false);
        node1.constraints.push_back(
            // Can not adjust the addr_reg if it is the same as the reg that must be written
            // (i.e mov [ecx+8], ecx can't become mov [0x12345678], ecx
            [](Node* n, StrategyGraph* g)->bool{
                return n->params[PARAM_STORE_DST_ADDR_REG].value != n->params[PARAM_STORE_SRC_REG].value;
            }
        );
        
        node2.params[PARAM_MOVCST_DST_REG].make_reg(n1, PARAM_STORE_DST_ADDR_REG); // node2 X is same as addr reg in node1
        node2.params[PARAM_MOVCST_SRC_CST].make_cst(n1, PARAM_STORE_DST_ADDR_OFFSET, 
            instr.args[PARAM_CSTSTORE_DST_ADDR_OFFSET] - exprvar(arch->bits, node1.params[PARAM_STORE_DST_ADDR_OFFSET].name)
            , graph->new_name("cst")); // node2 cst is the target const C minus the offset in the node1 load
        
        graph->add_param_edge(n2, n1);
        graph->add_strategy_edge(n2, n1);
        
        graphs.push(graph);
    }else if( instr.type == ILInstructionType::ASTORE ){
        // ASTORE
        graph = new StrategyGraph();
        node_t n = graph->new_node(GadgetType::ASTORE);
        Node& node = graph->nodes[n];
        node.params[PARAM_ASTORE_DST_ADDR_REG].make_reg(instr.args[PARAM_ASTORE_DST_ADDR_REG]);
        node.params[PARAM_ASTORE_DST_ADDR_OFFSET].make_cst(instr.args[PARAM_ASTORE_DST_ADDR_OFFSET], graph->new_name("offset"));
        node.params[PARAM_ASTORE_OP].make_op((Op)instr.args[PARAM_ASTORE_OP]);
        node.params[PARAM_ASTORE_SRC_REG].make_reg(instr.args[PARAM_ASTORE_SRC_REG]);
        graphs.push(graph);
    }else if( instr.type == ILInstructionType::CST_ASTORE ){
        // CST_ASTORE
        graph = new StrategyGraph();
        node_t n1 = graph->new_node(GadgetType::ASTORE);
        node_t n2 = graph->new_node(GadgetType::MOV_CST);
        Node& node1 = graph->nodes[n1];
        Node& node2 = graph->nodes[n2];
        // First node is mem(X + C) op<- reg
        // Second is X <- src_cst - C 
        node1.params[PARAM_ASTORE_SRC_REG].make_reg(instr.args[PARAM_CSTASTORE_SRC_REG]);
        node1.params[PARAM_ASTORE_OP].make_op((Op)instr.args[PARAM_CSTASTORE_OP]);
        node1.params[PARAM_ASTORE_DST_ADDR_REG].make_reg(-1, false); // Free
        node1.params[PARAM_ASTORE_DST_ADDR_OFFSET].make_cst(-1, graph->new_name("offset"), false);
                node1.constraints.push_back(
            // Can not adjust the addr_reg if it is the same as the reg that must be written
            // (i.e mov [ecx+8], ecx can't become mov [0x12345678], ecx
            [](Node* n, StrategyGraph* g)->bool{
                return n->params[PARAM_ASTORE_DST_ADDR_REG].value != n->params[PARAM_ASTORE_SRC_REG].value;
            }
        );

        
        node2.params[PARAM_MOVCST_DST_REG].make_reg(n1, PARAM_ASTORE_DST_ADDR_REG); // node2 X is same as addr reg in node1
        node2.params[PARAM_MOVCST_SRC_CST].make_cst(n1, PARAM_ASTORE_DST_ADDR_OFFSET, 
            instr.args[PARAM_CSTASTORE_DST_ADDR_OFFSET] - exprvar(arch->bits, node1.params[PARAM_ASTORE_DST_ADDR_OFFSET].name)
            , graph->new_name("cst")); // node2 cst is the target const C minus the offset in the node1 load
        
        graph->add_param_edge(n2, n1);
        graph->add_strategy_edge(n2, n1);
        
        graphs.push(graph);
    }else{
        throw runtime_exception("add_il_instruction_to_strategy(): unsupported ILInstructionType");
    }
}
