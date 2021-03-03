#include "strategy.hpp"
#include "expression.hpp"
#include "exception.hpp"
#include <algorithm>

/* =============== Strategy Rules ============== */

/* MovXXX dst_reg, src_xxx
 * =======================
 * (n1) MovReg R1, src_xxx
 * (n2) MovReg dst_reg, R1 
 * ======================= */
bool StrategyGraph::rule_generic_transitivity(node_t n){
    
    int i = 0;

    if( nodes[n].type != GadgetType::MOV_CST &&
        nodes[n].type != GadgetType::MOV_REG && 
        nodes[n].type != GadgetType::AMOV_CST && 
        nodes[n].type != GadgetType::AMOV_REG &&
        nodes[n].type != GadgetType::LOAD &&
        nodes[n].type != GadgetType::ALOAD ){
        return false;
    }
    
    // Get/Create nodes
    node_t n1 = new_node(nodes[n].type);
    node_t n2 = new_node(GadgetType::MOV_REG);
    Node& node = nodes[n];
    Node& node1 = nodes[n1];
    Node& node2 = nodes[n2];
    
    
    node1 = node; // Copy node to node1
    node1.id = n1; // But keep id
    // Modify dst_reg
    node1.params[node1.get_param_num_dst_reg()].make_reg(node2.id, PARAM_MOVREG_SRC_REG);
    
    // Set node2 with the reg transitivity gadget
    node2.params[PARAM_MOVREG_SRC_REG].make_reg(-1, false); // free reg
    node2.params[PARAM_MOVREG_DST_REG] = node.params[node.get_param_num_dst_reg()]; // Same dst reg as initial query in node
    
    // Add data link between node 1 and 2 for the transitive reg
    node1.params[node1.get_param_num_dst_reg()].is_data_link = true;

    // Node1 must end with a ret
    node1.branch_type = BranchType::RET;
    // Node2 same as node
    node2.branch_type = node.branch_type;

    // Redirect dst reg (to node2) (and datalink of course)
    redirect_param_edges(node.id, node.get_param_num_dst_reg(), node2.id, node2.get_param_num_dst_reg());
    redirect_param_edges(node.id, node.get_param_num_data_link(), node2.id, node2.get_param_num_data_link());
    redirect_param_edges(node.id, node.get_param_num_gadget_jmp_reg(), node2.id, node2.get_param_num_gadget_jmp_reg()); // If JMP
    redirect_param_edges(node.id, node.get_param_num_gadget_sp_inc(), node2.id, node2.get_param_num_gadget_sp_inc()); // If JMP
    redirect_param_edges(node.id, node.get_param_num_gadget_sp_delta(), node2.id, node2.get_param_num_gadget_sp_delta()); // If JMP

    // Redirect other input params arcs from node to node1
    for( i = 0; i < MAX_PARAMS; i++){
        redirect_param_edges(node.id, i, node1.id, i);
    }

    // Update param edges
    update_param_edges();

    // Redirect/add strategy edges
    add_strategy_edge(node1.id, node2.id);
    redirect_incoming_strategy_edges(node.id, node1.id);
    redirect_outgoing_strategy_edges(node.id, node2.id);
    
    // Disable previous node
    disable_node(node.id);
    
    // Update size in the end
    update_size();
    
    // Update graph history
    stringstream ss;
    ss << _history << "generic_transitivity(" << std::dec << n << ")" << std::endl;
    _history = ss.str();

    return true;
}

/* MovCst dst_reg, src_cst
+ * =======================
+ * Load dst_reg, mem(SP + off)
+ * padding(off, src_cst) 
+ * ======================= */
bool StrategyGraph::rule_mov_cst_pop(node_t n, Arch* arch){
    
    if( nodes[n].type != GadgetType::MOV_CST ){
        return false;
    }

    if( nodes[n].branch_type == BranchType::JMP ){
        return false;
    }

    // Get/Create nodes
    node_t n1 = new_node(GadgetType::LOAD);
    Node& node = nodes[n];
    Node& node1 = nodes[n1];

    // Node1 must have same return type than node
    node1.branch_type = node.branch_type;

    // Node1 must have same special paddings than node
    node1.special_paddings = node.special_paddings;

    // Modify parameters
    node1.params[PARAM_LOAD_DST_REG] = node.params[PARAM_MOVCST_DST_REG];
    node1.params[PARAM_LOAD_SRC_ADDR_REG].make_reg(arch->sp());
    node1.params[PARAM_LOAD_SRC_ADDR_OFFSET].make_cst(-1, new_name("stack_offset"), false); // Free offset

    // Set special padding at SP  offset to put the constant
    node1.special_paddings.push_back(ROPPadding());
    // Offset is the offset at which we pop the constant
    node1.special_paddings.back().offset.make_cst(n1, PARAM_LOAD_SRC_ADDR_OFFSET, exprvar(arch->bits, node1.params[PARAM_LOAD_SRC_ADDR_OFFSET].name), new_name("padding_offset"));
    // Padding value is just the constant
    node1.special_paddings.back().value = node.params[PARAM_MOVCST_SRC_CST];
    node1.special_paddings.back().value.name = new_name("padding_value"); // Get a new name for the value parameter

    // Add a constraint: the offset of the pop must not be too big (max 240)
    node1.strategy_constraints.push_back(
        [](Node* node, StrategyGraph* graph, Arch* arch){
            return node->params[PARAM_LOAD_SRC_ADDR_OFFSET].value < 240 &&
                   node->params[PARAM_LOAD_SRC_ADDR_OFFSET].value >= 0;
        }
    );

    // Add a constraint: the offset of the pop must not be bigger than the sp inc
    // and if the gadget is RET then the pop must not correspond to the return address ! 
    node1.assigned_gadget_constraints.push_back(
        [](Node* node, StrategyGraph* graph, Arch* arch){
            int adjust=0;
            // Padding can't overlap return address unless the register we want
            // to set is PC ;)
            if( node->affected_gadget->branch_type == BranchType::RET && 
                node->params[PARAM_LOAD_DST_REG].value != arch->pc()){
                adjust = arch->octets; //
            }
            return node->params[PARAM_LOAD_SRC_ADDR_OFFSET].value < node->affected_gadget->sp_inc - adjust;
        }
    );

    // Redirect the different params and edges
    // Generic params
    redirect_generic_param_edges(node.id, node1.id);
    redirect_param_edges(node.id, node.get_param_num_data_link(), node1.id, node1.get_param_num_data_link());

    // Redirect strategy edges
    redirect_incoming_strategy_edges(node.id, node1.id);
    redirect_outgoing_strategy_edges(node.id, node1.id);

    // Update param edges
    update_param_edges();

    // Disable node
    disable_node(node.id);
    
    // Update size in the end
    update_size();
    
    // Update graph history
    stringstream ss;
    ss << _history << "mov_cst_pop(" << std::dec << n << ")" << std::endl;
    _history = ss.str();
    
    return true;
}

/* <Any type>; ret
 * ====================
 * R1 <- @(next gadget)
 * <Any type>; jmp R1; 
 */
bool StrategyGraph::rule_generic_adjust_jmp(node_t n, Arch* arch){
    // Only apply on "RET" nodes (and "ANY" by extension)
    if( nodes[n].branch_type != BranchType::RET &&
        nodes[n].branch_type != BranchType::ANY ){
        return false;
    }
    
    // Get/Create nodes
    node_t n1 = new_node(GadgetType::MOV_CST); // Node to adjust the jmp reg
    node_t n_ret = new_node(GadgetType::LOAD); // Node of the 'adjust gadget' (ret N basically)
    Node& node = nodes[n];
    Node& node1 = nodes[n1];
    Node& node_ret = nodes[n_ret];
        
    // Change return type to JMP in node
    node.branch_type = BranchType::JMP;
    // Node MUST be followed by the indirect gadget ;)
    node.mandatory_following_node = node_ret.id;
    // Node1 (set the jmp reg) MUST be a RET one
    node1.branch_type = BranchType::RET;

    // Set the 'adjust gadget' node. It must adjust the PC that the next value on the
    // stack after the 'jmp' gadget is executed
    node_ret.params[PARAM_LOAD_DST_REG].make_reg(arch->pc()); // Dest reg is PC
    node_ret.params[PARAM_LOAD_SRC_ADDR_REG].make_reg(arch->sp()); // addr reg is SP (pop from the stack)
    node_ret.params[PARAM_LOAD_SRC_ADDR_OFFSET].make_cst( n, node.get_param_num_gadget_sp_delta(), nullptr, new_name("adjust_jmp_offset"));
    node_ret.is_indirect = true; // This node is 'indirect' (gadget not added explicitely on the stack)

    // Set the 'pre-jmp' gadget. It sets the jmp reg to the address of the 'adjust gadget'.
    // Dest reg of node1 is the jmp reg of node
    node1.params[PARAM_MOVCST_DST_REG].make_reg(n, node.get_param_num_gadget_jmp_reg());
    // Src cst of node1 is the address of the adjust gadget
    node1.params[PARAM_MOVCST_SRC_CST].make_cst(node_ret.id, node_ret.get_param_num_gadget_addr(), nullptr, new_name("adjust_jmp_addr"));
    // Add data link between node1 and node (the jmp reg must NOT be clobbered after it was set to 
    // point to the adjust gadget
    node1.params[PARAM_MOVCST_DST_REG].is_data_link = true;

    // Redirect strategy edges
    redirect_incoming_strategy_edges(node.id, node1.id);
    add_strategy_edge(node1.id, node.id); // Add after so it's not redirected ;)
    
    // Add callback that checks that the jmp reg is not implied in the operation
    // for example if the gadget is mov eax,ebx; jmp ebx; and we adjust ebx then
    // the semantics are corrupted because ebx's value will be overwritten with 
    // the address of the 'adjust-gadget'
    node.assigned_gadget_constraints.push_back(
        [](Node* node, StrategyGraph* graph, Arch* arch){
            switch( node->type ){
                case GadgetType::MOV_CST:
                    return node->params[node->get_param_num_gadget_jmp_reg()].value != node->params[PARAM_MOVCST_DST_REG].value;
                case GadgetType::MOV_REG:
                    return  node->params[node->get_param_num_gadget_jmp_reg()].value != node->params[PARAM_MOVREG_DST_REG].value && 
                            node->params[node->get_param_num_gadget_jmp_reg()].value != node->params[PARAM_MOVREG_SRC_REG].value;
                case GadgetType::AMOV_CST:
                    return  node->params[node->get_param_num_gadget_jmp_reg()].value != node->params[PARAM_AMOVCST_DST_REG].value && 
                            node->params[node->get_param_num_gadget_jmp_reg()].value != node->params[PARAM_AMOVCST_SRC_REG].value;
                case GadgetType::AMOV_REG:
                    return  node->params[node->get_param_num_gadget_jmp_reg()].value != node->params[PARAM_AMOVREG_DST_REG].value && 
                            node->params[node->get_param_num_gadget_jmp_reg()].value != node->params[PARAM_AMOVREG_SRC_REG1].value &&
                            node->params[node->get_param_num_gadget_jmp_reg()].value != node->params[PARAM_AMOVREG_SRC_REG2].value;
                case GadgetType::LOAD:
                    return  node->params[node->get_param_num_gadget_jmp_reg()].value != node->params[PARAM_LOAD_DST_REG].value && 
                            node->params[node->get_param_num_gadget_jmp_reg()].value != node->params[PARAM_LOAD_SRC_ADDR_REG].value;
                case GadgetType::ALOAD:
                    return  node->params[node->get_param_num_gadget_jmp_reg()].value != node->params[PARAM_ALOAD_DST_REG].value && 
                            node->params[node->get_param_num_gadget_jmp_reg()].value != node->params[PARAM_ALOAD_SRC_ADDR_REG].value;
                case GadgetType::STORE:
                    return  node->params[node->get_param_num_gadget_jmp_reg()].value != node->params[PARAM_STORE_SRC_REG].value && 
                            node->params[node->get_param_num_gadget_jmp_reg()].value != node->params[PARAM_STORE_DST_ADDR_REG].value;
                case GadgetType::ASTORE:
                    return  node->params[node->get_param_num_gadget_jmp_reg()].value != node->params[PARAM_ASTORE_SRC_REG].value && 
                            node->params[node->get_param_num_gadget_jmp_reg()].value != node->params[PARAM_ASTORE_DST_ADDR_REG].value;
                default:
                    throw runtime_exception("rule_generic_adjust_jmp(): constraint callback got unsupported GadgetType! ");
            }
        }
    );

    // Update param edges
    update_param_edges();

    // Update size in the end
    update_size();

    // Update graph history
    stringstream ss;
    ss << _history << "generic_adjust_jmp(" << std::dec << n << ")" << std::endl;
    _history = ss.str();

    return true;
}

/* dst_reg <-- mem(src_addr_reg +  src_addr_offset)
 * =======================
 * (n1) MovReg R1, src_addr_reg + (src_addr_offset - C1)
 * (n2) dst_reg <-- mem(R1 + C1)
 * ======================= */
bool StrategyGraph::rule_adjust_load(node_t n, Arch* arch){

    if( nodes[n].type != GadgetType::LOAD &&
        nodes[n].type != GadgetType::ALOAD ){
        return false;
    }
    
    if( nodes[n].params[nodes[n].get_param_num_src_addr_reg()].value == arch->sp()){
        // If we want to read from the stack pointer (typically to pop a value), don't
        // apply this strategy
        return false;
    }

    // Get/Create nodes
    node_t n1 = new_node(GadgetType::AMOV_CST);
    node_t n2 = new_node(nodes[n].type);
    Node& node = nodes[n];
    Node& node1 = nodes[n1];
    Node& node2 = nodes[n2];
    
    
    node2 = node; // Copy node to node2
    node2.id = n2; // But keep id
    // SET NODE 2
    // Modify src_addr_reg to be any register
    node2.params[node2.get_param_num_src_addr_reg()].make_reg(-1, false); // free reg
    // Make the offset also free
    node2.params[node2.get_param_num_src_addr_offset()].make_cst(0, new_name("addr_offset"), false); // free cst

    // SET NODE 1
    node1.params[PARAM_AMOVCST_SRC_OP].make_op(Op::ADD);
    // Set node1 with the right reg and cst
    node1.params[PARAM_AMOVCST_DST_REG].make_reg(node2.id,node2.get_param_num_src_addr_reg()); // depends on the load src addr reg
    node1.params[PARAM_AMOVCST_SRC_REG] = node.params[node.get_param_num_src_addr_reg()]; // Reg should be set with the same reg of the initial LOAD
    // Cst must be the original offset (of node) minus the new one (of node2)
    Param& node_offset = node.params[node.get_param_num_src_addr_offset()];
    Param& node2_offset = node2.params[node2.get_param_num_src_addr_offset()];
    Expr src_cst_expr = exprvar(arch->bits, node_offset.name) 
                        - exprvar(arch->bits, node2_offset.name);
    node1.params[PARAM_AMOVCST_SRC_CST].make_cst(node2.id, node2.get_param_num_src_addr_offset(), 
            src_cst_expr, new_name("addr_offset"));
    node1.params[PARAM_AMOVCST_SRC_CST].add_dep(node.id, node.get_param_num_src_addr_offset());

    // Add data link between node 1 and 2 for the address reg
    node1.params[PARAM_AMOVCST_DST_REG].is_data_link = true;

    // Node1 must end with a ret
    node1.branch_type = BranchType::RET;
    // Node2 same as node
    node2.branch_type = node.branch_type;

    // Redirect input params arcs from node to node1
    redirect_param_edges(node.id, node.get_param_num_dst_reg(), 
                                  node2.id, node2.get_param_num_dst_reg());

    // Redirect data_link to node2
    redirect_param_edges(node.id, node.get_param_num_data_link(), node2.id, node2.get_param_num_data_link());

    // Redirect/add strategy edges
    add_strategy_edge(node1.id, node2.id);
    redirect_incoming_strategy_edges(node.id, node1.id);
    redirect_outgoing_strategy_edges(node.id, node2.id);

    // Update param edges
    update_param_edges();

    // Disable previous node
    disable_node(node.id);

    // Update size in the end
    update_size();

    // Update graph history
    stringstream ss;
    ss << _history << "adjust_load(" << std::dec << n << ")" << std::endl;
    _history = ss.str();

    return true;
}

/* <AnyType> dst, src_reg
 * =======================
 * (n2) MovReg R1, src_reg
 * (n1) <AnyType> dst, R1
 * ======================= */
bool StrategyGraph::rule_generic_src_transitivity(node_t n){

    if( nodes[n].type != GadgetType::STORE &&
        nodes[n].type != GadgetType::ASTORE ){
        return false;
    }
    
    // Don't apply this strategy if the src reg is already free no sense to add a 
    // transitivy step
    if( nodes[n].params[nodes[n].get_param_num_src_reg()].is_free()){
        return false;
    }

    // Get/Create nodes
    node_t n2 = new_node(GadgetType::MOV_REG);
    Node& node = nodes[n];
    Node& node2 = nodes[n2];

    // Redirect parameter to src_reg
    redirect_param_edges(node.id, node.get_param_num_src_reg(), node2.id, node2.get_param_num_src_reg());

    // Set node2 with the reg transitivity gadget
    node2.params[PARAM_MOVREG_DST_REG].make_reg(node.id, node.get_param_num_src_reg()); // Depends on node src reg
    node2.params[PARAM_MOVREG_SRC_REG] = node.params[node.get_param_num_src_reg()]; // Same src reg as initial query in node
    // Add data link between node 1 and 2 for the transitive reg
    node2.params[PARAM_MOVREG_DST_REG].is_data_link = true;
    // Node2 must end in ret
    node2.branch_type = BranchType::RET;

    // Modify src_reg to make it free
    node.params[node.get_param_num_src_reg()].make_reg(-1, false); // Free

    // Update param edges
    update_param_edges();

    // Redirect/add strategy edges
    add_strategy_edge(node2.id, node.id);

    // Update size in the end
    update_size();
    
    // Update graph history
    stringstream ss;
    ss << _history << "generic_src_transitivity(" << std::dec << n << ")" << std::endl;
    _history = ss.str();
    
    return true;
}

/* mem(dst_addr_reg, dst_addr_offset) <-- src_reg
 * =======================
 * (n1) MovReg R1, dst_addr_reg + (dst_addr_offset - C1)
 * (n2) mem(R1 + C1) <-- src_reg
 * ======================= */
bool StrategyGraph::rule_adjust_store(node_t n, Arch* arch){

    if( nodes[n].type != GadgetType::STORE &&
        nodes[n].type != GadgetType::ASTORE ){
        return false;
    }
    
    // If we want to store at the stack pointer, don't apply this strategy
    if( nodes[n].params[nodes[n].get_param_num_dst_addr_reg()].value == arch->sp()){
        return false;
    }
    
    // If the parameters are free then it doesn't make sense to adjust it
    if( nodes[n].params[nodes[n].get_param_num_dst_addr_reg()].is_free() && 
        nodes[n].params[nodes[n].get_param_num_dst_addr_offset()].is_free()){
        return false;
    }

    // Get/Create nodes
    node_t n1 = new_node(GadgetType::AMOV_CST);
    node_t n2 = new_node(nodes[n].type);
    Node& node = nodes[n];
    Node& node1 = nodes[n1];
    Node& node2 = nodes[n2];

    // SET NODE 2
    node2 = node; // Copy node to node2
    node2.id = n2; // But keep id
    // Modify dst_addr_reg to be any register
    node2.params[node2.get_param_num_dst_addr_reg()].make_reg(-1, false); // free reg
    // Make the offset also free
    node2.params[node2.get_param_num_dst_addr_offset()].make_cst(0, new_name("addr_offset"), false); // free cst

    // SET NODE 1
    node1.params[PARAM_AMOVCST_SRC_OP].make_op(Op::ADD);
    // Set node1 with the right reg and cst
    node1.params[PARAM_AMOVCST_DST_REG].make_reg(node2.id,node2.get_param_num_dst_addr_reg()); // depends on the store dst addr reg
    node1.params[PARAM_AMOVCST_SRC_REG] = node.params[node.get_param_num_dst_addr_reg()]; // Reg should be set with the same reg of the initial STORE
    // Cst must be the original offset (of node) minus the new one (of node2)
    Param& node_offset = node.params[node.get_param_num_dst_addr_offset()];
    Param& node2_offset = node2.params[node2.get_param_num_dst_addr_offset()];
    Expr src_cst_expr = exprvar(arch->bits, node_offset.name) 
                        - exprvar(arch->bits, node2_offset.name);
    node1.params[PARAM_AMOVCST_SRC_CST].make_cst(node2.id, node2.get_param_num_dst_addr_offset(), 
            src_cst_expr, new_name("addr_offset"));
    node1.params[PARAM_AMOVCST_SRC_CST].add_dep(node.id, node.get_param_num_dst_addr_offset());

    // Add data link between node 1 and 2 for the address reg
    node1.params[PARAM_AMOVCST_DST_REG].is_data_link = true;

    // Node1 must end with a ret
    node1.branch_type = BranchType::RET;
    // Node2 same as node
    node2.branch_type = node.branch_type;

    // Redirect input params arcs from node to node1
    redirect_param_edges(node.id, node.get_param_num_dst_addr_reg(), 
                                  node2.id, node2.get_param_num_dst_addr_reg());
    redirect_param_edges(node.id, node.get_param_num_src_reg(), 
                                  node2.id, node2.get_param_num_src_reg());

    // Redirect data_link
    redirect_param_edges(node.id, node.get_param_num_data_link(), node2.id, node2.get_param_num_data_link());

    // Redirect/add strategy edges
    add_strategy_edge(node1.id, node2.id);
    redirect_incoming_strategy_edges(node.id, node1.id);
    redirect_outgoing_strategy_edges(node.id, node2.id);

    // Update param edges
    update_param_edges();

    // Disable previous node
    disable_node(node.id);

    // Update size in the end
    update_size();

    // Update graph history
    stringstream ss;
    ss << _history << "adjust_store(" << std::dec << n << ")" << std::endl;
    _history = ss.str();

    return true;
}



/* dst_reg <-- src_cst
 * ===================
 * (n1) MovReg R1, C1
 * (n2) dst_reg <-- R1 OP (C1 OP{-1} src_cst)
 * ======================= */
bool StrategyGraph::rule_mba_set_cst(node_t n, Arch* arch){

    if( nodes[n].type != GadgetType::MOV_CST){
        return false;
    }

    // Get/Create nodes
    node_t n1 = new_node(GadgetType::MOV_CST);
    node_t n2 = new_node(GadgetType::AMOV_CST);
    Node& node = nodes[n];
    Node& node1 = nodes[n1];
    Node& node2 = nodes[n2];

    // Make cst and operation free in node 2
    node2.params[PARAM_AMOVCST_SRC_CST].make_cst(-1, new_name("cst"), false);
    node2.params[PARAM_AMOVCST_SRC_OP].make_op(Op::NONE);
    node2.params[PARAM_AMOVCST_SRC_REG].make_reg(-1, false);
    // Dst reg in node2 is same as in node
    node2.params[PARAM_AMOVCST_DST_REG] = node.params[PARAM_MOVCST_DST_REG];

    // Set node1 with the reg <- cst gadget
    node1.params[PARAM_MOVCST_DST_REG].make_reg(-1, false); // free reg
    node1.params[PARAM_MOVCST_DST_REG].add_dep(n2, PARAM_AMOVCST_SRC_REG);
    // Make the cst a MBA dependency
    node1.params[PARAM_MOVCST_SRC_CST].make_cst(n, PARAM_MOVCST_SRC_CST, n2, PARAM_AMOVCST_SRC_OP, n2, PARAM_AMOVCST_SRC_CST, new_name("cst"));

    // Add data link between node 1 and 2 for the transitive reg
    node1.params[node1.get_param_num_dst_reg()].is_data_link = true;

    // Node1 must end with a ret
    node1.branch_type = BranchType::RET;
    // Node2 same as node
    node2.branch_type = node.branch_type;

    // Redirect dst reg (to node2) (and datalink of course)
    redirect_param_edges(node.id, node.get_param_num_dst_reg(), node2.id, node2.get_param_num_dst_reg());
    redirect_param_edges(node.id, node.get_param_num_data_link(), node2.id, node2.get_param_num_data_link());

    // Redirect/add strategy edges
    add_strategy_edge(node1.id, node2.id);
    redirect_incoming_strategy_edges(node.id, node1.id);
    redirect_outgoing_strategy_edges(node.id, node2.id);

    // Update param edges
    update_param_edges();
    
    // Disable previous node
    disable_node(node.id);
    
    // Update size in the end
    update_size();
    
    // Update graph history
    stringstream ss;
    ss << _history << "mba_set_cst(" << std::dec << n << ")" << std::endl;
    _history = ss.str();

    return true;
}
