#include "ropchain.hpp"
#include <unordered_map>
#include <iostream>
#include <cstring>

using std::unordered_map;

Gadget::Gadget():semantics(nullptr), bin_num(-1), branch_type(BranchType::NONE){
    memset(modified_regs, 0, sizeof(modified_regs));
}

Gadget::~Gadget(){
    delete semantics;
    semantics = nullptr;
}

void Gadget::add_address(addr_t addr){
    addresses.push_back(addr);
}

void Gadget::print(ostream& os){
    os << "Gadget: " << asm_str << std::endl;
    for( int i = 0; i < semantics->regs->nb_vars(); i++){
        if( modified_regs[i] )
            os << "Reg_" << i << " : " << semantics->regs->get(i) << std::endl;
    }
    os << *(semantics->mem) << std::endl;
}

ostream& operator<<(ostream& os, Gadget& g){
    g.print(os);
    return os;
}

bool Gadget::lthan(Gadget& other){
    if( nb_instr != other.nb_instr ){
        return nb_instr < other.nb_instr;
    }else{
        return nb_instr_ir < other.nb_instr_ir; 
    }
}

// Build gadget objects from raw gadgets
vector<Gadget*> gadgets_from_raw(vector<RawGadget>& raw_gadgets, Arch* arch){
    vector<Gadget*> res;
    unordered_map<string, Gadget*> seen;
    unordered_map<string, Gadget*>::iterator git;
    Gadget* gadget;
    Semantics* semantics;
    IRBlock* irblock;
    SymbolicEngine sym = SymbolicEngine(arch->type);
    Expr e;
    
    for( auto raw: raw_gadgets ){
        if( (git = seen.find(raw.raw)) != seen.end()){
            // Already seen, just add a new address
            git->second->add_address(raw.addr);
        }else{
            // New gadget
            gadget = new Gadget();
            // Lift instructions
            try{
                if( (irblock = arch->disasm->disasm_block(raw.addr, (code_t)raw.raw.c_str(), raw.raw.size())) == nullptr){
                    throw runtime_exception("disassembler returned null block");
                }
            }catch(std::exception& e){
                std::cout << "DEBUG COULDN'T LIFT GADGET: " << e.what() << std::endl;
                    delete gadget; continue;
            }
            
            // Get semantics
            try{
                if( (semantics = sym.execute_block(irblock)) == nullptr ){
                    throw symbolic_exception("symbolic engine returned null semantics");
                }
            }catch(symbolic_exception& e){
                std::cout << "DEBUG ERROR WHILE EXECUTING GADGET: " << 
                             irblock->name << " --> " << e.what() << std::endl;
                    delete gadget; continue;
            }
            semantics->simplify();
            gadget->semantics = semantics;

            // Set nb instructions
            gadget->nb_instr = irblock->_nb_instr;
            gadget->nb_instr_ir = irblock->_nb_instr_ir;

            // Get sp increment
            if( !irblock->known_max_sp_inc ){
                std::cout << "DEBUG ERROR UNKNOWN MAX SP INC " << std::endl;
                delete gadget; continue;
            }else{
                gadget->max_sp_inc = irblock->max_sp_inc;
            }
            e = semantics->regs->get(arch->sp());
            if( e->is_binop(Op::ADD) && e->args[0]->is_cst() ){
                if( e->args[0]->cst() % arch->octets != 0 ){
                    std::cout << "DEBUG ERROR got SP INC Not multiple of arch size: " << irblock->name << std::endl;
                    delete gadget; continue;
                }
                gadget->sp_inc = e->args[0]->cst();
            }
            
            // Get branch type
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
                    std::cout << "DEBUG ERROR, NO VALID BRANCH TYPE: " << irblock->name << std::endl;
                    delete gadget; continue;
                }
            }else{
                std::cout << "DEBUG ERROR, NO VALID BRANCH TYPE: " << irblock->name << std::endl;
                delete gadget; continue;
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

            // Add gadget to result
            res.push_back(gadget);
            seen[raw.raw] = gadget;
        }
    }
    return res;
}
