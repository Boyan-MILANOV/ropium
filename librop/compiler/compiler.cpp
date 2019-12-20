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

ROPChain* ROPCompiler::compile(string program, Arch* arch, GadgetDB* db){
    try{
        vector<ILInstruction> instr = parse(program, arch);
        return process(instr, arch, db);
    }catch(il_exception const& e){
        return nullptr;
    }
}

ROPChain* ROPCompiler::process(vector<ILInstruction>& instructions, Arch* arch, GadgetDB* db){
    StrategyGraph* init_strategy = new StrategyGraph();
    CompilerTask task;
    for( ILInstruction& instr : instructions ){
        add_il_instruction_to_strategy(*init_strategy, instr);
    }
    task.add_strategy(init_strategy);
    return task.compile(arch, db);
}

bool _is_empty_line(string& s){
    for( char& c : s ){
        if( !isspace(c))
            return false;
    }
    return true;
}

vector<ILInstruction> ROPCompiler::parse(string program, Arch* arch){
    size_t pos;
    string instr;
    vector<ILInstruction> res;
    while( (pos = program.find("\n")) != string::npos){
        instr = program.substr(0, pos); 
        if( !_is_empty_line(instr)){
            try{
                ILInstruction ins = ILInstruction(*arch, instr);
                res.push_back(ins);
            }catch(il_exception const& e) {
                throw il_exception("Couldn't parse IL program");
            }
        }
        program.erase(0, pos + 1);
    }
    return res;
}

void ROPCompiler::add_il_instruction_to_strategy(StrategyGraph& graph, ILInstruction& instr){
    if( instr.type == ILInstructionType::MOV_CST ){
        // MOV_CST
        node_t n = graph.new_node(GadgetType::MOV_CST);
        Node& node = graph.nodes[n];
        node.params[PARAM_MOVCST_DST_REG].make_reg(instr.args[PARAM_MOVCST_DST_REG]);
        node.params[PARAM_MOVCST_SRC_CST].make_cst(instr.args[PARAM_MOVCST_SRC_CST], graph.new_name("cst"));
    }else if( instr.type == ILInstructionType::MOV_REG ){
        // MOV_REG
        node_t n = graph.new_node(GadgetType::MOV_REG);
        Node& node = graph.nodes[n];
        node.params[PARAM_MOVREG_DST_REG].make_reg(instr.args[PARAM_MOVREG_DST_REG]);
        node.params[PARAM_MOVCST_DST_REG].make_reg(instr.args[PARAM_MOVREG_SRC_REG]);
    }else{
        throw runtime_exception("add_il_instruction_to_strategy(): unsupported ILInstructionType");
    }
}
