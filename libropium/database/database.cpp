#include "database.hpp"
#include "exception.hpp"
#include <iostream>

int find_insert_index(vector<Gadget*>& gadget_list, Gadget* gadget){
    int count= gadget_list.size(); 
    int first = 0; 
    int curr;
    while(count > 0){
        curr = first;
        curr += count/2;
        if( gadget_list.at(curr)->lthan(*gadget)){
            first = curr+1;
            count -= count/2 + 1;
        }else{
            count = count/2;
        }
    }
    return first; 
}


int find_insert_index_possible_gadgets(PossibleGadgets* possible, Gadget* gadget){
    int count= possible->gadgets.size(); 
    int first = 0; 
    int curr;
    while(count > 0){
        curr = first;
        curr += count/2;
        if( possible->gadgets.at(curr).second->at(0)->lthan(*gadget)){
            first = curr+1;
            count -= count/2 + 1;
        }else{
            count = count/2;
        }
    }
    return first; 
}

gadget_t GadgetDB::add(Gadget* gadget, Arch* arch){
    Expr e, addr;
    
    // Add to global list
    gadget->id = all.size();
    all.push_back(gadget);

    // Check semantics and classify gadget
    // 0. First check is special branch gadget such as syscall/int80
    if( gadget->branch_type == BranchType::SYSCALL ){
        syscall.add(0, gadget);
    }else if( gadget->branch_type == BranchType::INT80 ){
        int80.add(0, gadget);
    }

    // 1. Register semantics
    for( int reg = 0; reg < gadget->semantics->regs->nb_vars(); reg++){
        e = gadget->semantics->regs->get(reg);

        // JMP
        if( reg == arch->pc() && e->is_var()){
            jmp.add(e->reg(), gadget);
        }
        // MOV_CST
        if( e->is_cst() ){
            mov_cst.add(make_tuple(reg, e->cst()), gadget);
        }
        // MOV_REG
        else if( e->is_var() && !e->is_reg(reg) ){
            mov_reg.add(make_tuple(reg, e->reg()), gadget);
        }
        // AMOV_CST
        else if( e->is_binop() && e->args[0]->is_cst() && e->args[1]->is_var() && 
                 op_is_symetric(e->op())){
            amov_cst.add(make_tuple(reg, e->args[1]->reg(), (op_t)e->op(), e->args[0]->cst()), gadget);
        }else if( e->is_binop() && e->args[1]->is_cst() && e->args[0]->is_var()){
            amov_cst.add(make_tuple(reg, e->args[0]->reg(), (op_t)e->op(), e->args[1]->cst()), gadget);
        } 
        // AMOV_REG
        else if( e->is_binop() && e->args[0]->is_var() && e->args[1]->is_var()){
            amov_reg.add(make_tuple(reg, e->args[0]->reg(), (op_t)e->op(), e->args[1]->reg()), gadget);
            if( op_is_symetric(e->op())){
                amov_reg.add(make_tuple(reg, e->args[1]->reg(), (op_t)e->op(), e->args[0]->reg()), gadget);
            }
        }
        // LOAD
        else if( e->is_mem() && e->args[0]->is_var()){
            load.add(make_tuple(reg, e->args[0]->reg(), 0), gadget);
        }else if( e->is_mem() && e->args[0]->is_binop(Op::ADD) && e->args[0]->args[0]->is_cst()
                  && e->args[0]->args[1]->is_var()){
            load.add(make_tuple(reg, e->args[0]->args[1]->reg(), e->args[0]->args[0]->cst()), gadget);
        }
        // ALOAD
        else if( e->is_binop() && e->args[1]->is_reg(reg) && e->args[0]->is_mem() && 
                 e->args[0]->args[0]->is_var()){
            aload.add(make_tuple(reg, (op_t)e->op(), e->args[0]->args[0]->reg(), 0), gadget);
        }else if( e->is_binop() && e->args[1]->is_reg(reg) &&
                  e->args[0]->is_mem() && e->args[0]->args[0]->is_binop(Op::ADD) && 
                  e->args[0]->args[0]->args[0]->is_cst() && e->args[0]->args[0]->args[1]->is_var()){
            aload.add(make_tuple(reg, (op_t)e->op(), e->args[0]->args[0]->args[1]->reg(), 
                                              e->args[0]->args[0]->args[0]->cst()), gadget);
        }
    }

    // 2. Memory semantics
    for( auto write : gadget->semantics->mem->writes ){
        addr = write.first;
        e = write.second;
        // STORE
        if( addr->is_var() && e->is_var()){
            store.add(make_tuple(addr->reg(), 0, e->reg()), gadget);
        }else if( addr->is_binop(Op::ADD) && addr->args[0]->is_cst() && addr->args[1]->is_var()
                  && e->is_var()){
            store.add(make_tuple(addr->args[1]->reg(), addr->args[0]->cst(), e->reg()), gadget);
        
        }
        // ASTORE 
        else if( e->is_binop() && e->args[0]->is_mem() && e->args[1]->is_var()
                 && (addr->eq(e->args[0]->args[0]))){
            if( addr->is_var() ){
                astore.add(make_tuple(addr->reg(), 0, (op_t)e->op(), e->args[1]->reg()), gadget);
            }else if( addr->is_binop(Op::ADD) && addr->args[0]->is_cst() && addr->args[1]->is_var() ){
                astore.add(make_tuple(addr->args[1]->reg(), addr->args[0]->cst(), (op_t)e->op(), e->args[1]->reg()), gadget);
            }
        }
    }
    return gadget->id;
}

int GadgetDB::analyse_raw_gadgets(vector<RawGadget>& raw_gadgets, Arch* arch){
    unordered_map<string, Gadget*>::iterator git;
    Gadget* gadget;
    Semantics* semantics;
    IRBlock* irblock;
    SymbolicEngine sym = SymbolicEngine(arch->type);
    Expr e;
    int nb_success = 0;
    
    for( auto raw: raw_gadgets ){
        if( (git = seen.find(raw.raw)) != seen.end()){
            // Already seen, just add a new address
            git->second->add_address(raw.addr);
            nb_success++;
        }else{
            // New gadget
            gadget = new Gadget();
            // Lift instructions
            try{
                if( (irblock = arch->disasm->disasm_block(raw.addr, (code_t)raw.raw.c_str(), raw.raw.size())) == nullptr){
                    throw runtime_exception("disassembler returned null block");
                }
            }catch(std::exception& e){
                // std::cout << "DEBUG COULDN'T LIFT GADGET: " << e.what() << std::endl;
                    delete gadget; continue;
            }
            
            // Get semantics
            try{
                if( (semantics = sym.execute_block(irblock)) == nullptr ){
                    throw symbolic_exception("symbolic engine returned null semantics");
                }
            }catch(symbolic_exception& e){
                //std::cout << "DEBUG ERROR WHILE EXECUTING GADGET: " << irblock->name << " --> " << e.what() << std::endl;
                    delete gadget; continue;
                    delete irblock; irblock = nullptr;
            }

            semantics->simplify();
            gadget->semantics = semantics;

            // Set nb instructions
            gadget->nb_instr = irblock->_nb_instr;
            gadget->nb_instr_ir = irblock->_nb_instr_ir;

            // Set dereferenced regs
            for( int i = 0; i < NB_REGS_MAX; i++){
                gadget->dereferenced_regs[i] = irblock->dereferenced_regs[i];
            }

            // Get sp increment
            if( !irblock->known_max_sp_inc ){
                // std::cout << "DEBUG ERROR UNKNOWN MAX SP INC " << irblock->name << std::endl; // Might clobber our ropchain
                delete gadget; continue;
            }else{
                gadget->max_sp_inc = irblock->max_sp_inc;
            }

            e = semantics->regs->get(arch->sp());
            if( e->is_binop(Op::ADD) && e->args[0]->is_cst() && e->args[1]->is_reg(arch->sp())){
                if( e->args[0]->cst() % arch->octets != 0 ){
                    // std::cout << "DEBUG ERROR got SP INC Not multiple of arch size: " << irblock->name << std::endl;
                    delete gadget; continue;
                }
                gadget->sp_inc = e->args[0]->cst();
            }else if( e->is_binop(Op::ADD) && e->args[0]->is_unop(Op::NEG) &&
                      e->args[0]->args[0]->is_cst() && e->args[0]->args[0]->cst() % arch->octets == 0 &&
                      e->args[1]->is_reg(arch->sp())){
                // sp = sp0 - cst
                gadget->sp_inc = -1*e->args[0]->args[0]->cst();
            }else if( e->is_reg(arch->sp()) ){
                gadget->sp_inc = 0;
            }

            // Get branch type
            if( irblock->ends_with_syscall ){
                gadget->branch_type = BranchType::SYSCALL;
            }else if( irblock->ends_with_int80 ){
                gadget->branch_type = BranchType::INT80;
            }else{
                // Check last PC value
                e = semantics->regs->get(arch->pc());
                if( e->is_var() ){
                    // Jmp
                    gadget->branch_type = BranchType::JMP;
                    gadget->jmp_reg = arch->reg_num(e->name());
                }else if( e->is_mem()){
                    // Ret (sp)
                    if( e->args[0]->is_var() && arch->reg_num(e->args[0]->name()) == arch->sp() && gadget->sp_inc == arch->octets ){
                        gadget->branch_type = BranchType::RET;
                    }else if( e->args[0]->is_binop(Op::ADD) && e->args[0]->args[0]->is_cst() &&
                              e->args[0]->args[1]->is_var() && (e->args[0]->args[0]->cst() + arch->octets == gadget->sp_inc) && 
                              arch->reg_num(e->args[0]->args[1]->name()) == arch->sp()){
                        gadget->branch_type = BranchType::RET;
                    }else{
                        // std::cout << "DEBUG ERROR, NO VALID BRANCH TYPE: " << irblock->name << std::endl;
                        delete gadget; continue;
                    }
                }else{
                    // std::cout << "DEBUG ERROR, NO VALID BRANCH TYPE: " << irblock->name << std::endl;
                    delete gadget; continue;
                }
            }

            // Set name
            gadget->asm_str = irblock->name;
            // Set address
            gadget->addresses.push_back(raw.addr);
            // Set modified registers
            for( int r = 0; r < arch->nb_regs; r++){
                if( !semantics->regs->get(r)->is_var() ||
                        semantics->regs->get(r)->name() != arch->reg_name(r)){
                    gadget->modified_regs[r] = true;
                }
            }

            // Delete irblock (we don't need it anymore, only semantics)
            delete irblock; irblock = nullptr;

            // Classify gadget in db
            seen[raw.raw] = gadget;
            add(gadget, arch);
            nb_success++;
        }
    }
    return nb_success;
}

Gadget* GadgetDB::get(gadget_t gadget_num){
    if( gadget_num >= all.size())
        throw runtime_exception("GadgetDB::get() got invalid gadget number");
    return all[gadget_num];
}

const vector<Gadget*>& GadgetDB::get_mov_cst(reg_t reg, cst_t cst){
    return mov_cst.get(make_tuple(reg, cst));
}

const vector<Gadget*>& GadgetDB::get_mov_reg(reg_t dst_reg, reg_t src_reg){
    return mov_reg.get(make_tuple(dst_reg, src_reg));
}

const vector<Gadget*>& GadgetDB::get_amov_cst(reg_t dst_reg, reg_t src_reg, Op op, cst_t src_cst){
    return amov_cst.get(make_tuple(dst_reg, src_reg, (op_t)op, src_cst));
}

const vector<Gadget*>& GadgetDB::get_amov_reg(reg_t dst_reg, reg_t src_reg1, Op op, reg_t src_reg2){
    return amov_reg.get(make_tuple(dst_reg, src_reg1, (op_t)op, src_reg2));
}

const vector<Gadget*>& GadgetDB::get_load(reg_t dst_reg, reg_t addr_reg, cst_t offset){
    return load.get(make_tuple(dst_reg, addr_reg, offset));
}

const vector<Gadget*>& GadgetDB::get_aload(reg_t dst_reg, Op op, reg_t addr_reg, cst_t offset){
    return aload.get(make_tuple(dst_reg, (op_t)op, addr_reg, offset));
}

const vector<Gadget*>& GadgetDB::get_jmp(reg_t jmp_reg){
    return jmp.get(jmp_reg);
}

const vector<Gadget*>& GadgetDB::get_store(reg_t addr_reg, cst_t offset, reg_t src_reg){
    return store.get(make_tuple(addr_reg, offset, src_reg));
}

const vector<Gadget*>& GadgetDB::get_astore(reg_t addr_reg, cst_t offset, Op op, reg_t src_reg){
    return astore.get(make_tuple(addr_reg, offset, (op_t)op, src_reg));
}

const vector<Gadget*>& GadgetDB::get_int80(){
    return int80.get(0); // Use dummy key 0
}

const vector<Gadget*>& GadgetDB::get_syscall(){
    return syscall.get(0); // Use dummy key 0
}

/* ============== Get possible gadgets ===================== */

PossibleGadgets* GadgetDB::get_possible_mov_reg(reg_t dst_reg, reg_t src_reg, bool* param_is_free){
    return mov_reg.get_possible(make_tuple(dst_reg, src_reg), param_is_free, 2);
}

PossibleGadgets* GadgetDB::get_possible_amov_reg(reg_t dst_reg, reg_t src_reg1, Op src_op, reg_t src_reg2, bool* param_is_free){
    return amov_reg.get_possible(make_tuple(dst_reg, src_reg1, (op_t)src_op, src_reg2), param_is_free, 4);
}

PossibleGadgets* GadgetDB::get_possible_mov_cst(reg_t dst_reg, cst_t src_cst, bool* param_is_free){
    return mov_cst.get_possible(make_tuple(dst_reg, src_cst), param_is_free, 2);
}

PossibleGadgets* GadgetDB::get_possible_amov_cst(reg_t dst_reg, reg_t src_reg, Op src_op, cst_t src_cst, bool* param_is_free){
    return amov_cst.get_possible(make_tuple(dst_reg, src_reg, (op_t)src_op, src_cst), param_is_free, 4);
}

PossibleGadgets* GadgetDB::get_possible_load(reg_t dst_reg, reg_t src_addr_reg, cst_t src_addr_offset, bool* param_is_free){
    return load.get_possible(make_tuple(dst_reg, src_addr_reg, src_addr_offset), param_is_free, 3);
}

PossibleGadgets* GadgetDB::get_possible_aload(reg_t dst_reg, Op op, reg_t src_addr_reg, cst_t src_addr_offset, bool* param_is_free){
    return aload.get_possible(make_tuple(dst_reg, (op_t)op, src_addr_reg, src_addr_offset), param_is_free, 4);
}

PossibleGadgets* GadgetDB::get_possible_store(reg_t dst_addr_reg, cst_t dst_addr_cst, reg_t src_reg, bool* param_is_free){
    return store.get_possible(make_tuple(dst_addr_reg, dst_addr_cst, src_reg), param_is_free, 3);
}

PossibleGadgets* GadgetDB::get_possible_astore(reg_t dst_addr_reg, cst_t dst_addr_cst, Op op, reg_t src_reg, bool* param_is_free){
    return astore.get_possible(make_tuple(dst_addr_reg, dst_addr_cst, (op_t)op, src_reg), param_is_free, 3);
}

void GadgetDB::clear(){
    mov_cst.clear();
    amov_cst.clear();
    mov_reg.clear();
    amov_reg.clear();
    load.clear();
    aload.clear();
    store.clear();
    astore.clear();
    for( auto g : all ){
        delete g;
    }
    all.clear();
    seen.clear();
}

GadgetDB::~GadgetDB(){
    // Delete all gadgets
    clear();
}
