#include "ropchain.hpp"
#include <unordered_map>
#include <iostream>

using std::unordered_map;

Gadget::Gadget():semantics(nullptr), bin_num(-1), branch_type(BranchType::NONE){}
Gadget::~Gadget(){
    delete semantics;
    semantics = nullptr;
}

void Gadget::add_address(addr_t addr){
    addresses.push_back(addr);
}

void Gadget::print(ostream& os){
    os << asm_str;
}

bool Gadget::lthan(shared_ptr<Gadget> other){
    if( nb_instr != other->nb_instr ){
        return nb_instr < other->nb_instr;
    }else{
        return nb_instr_ir < other->nb_instr_ir; 
    }
}

// Build gadget objects from raw gadgets
vector<Gadget*> gadgets_from_raw(vector<RawGadget>* raw_gadgets, Arch* arch){
    vector<Gadget*> res;
    unordered_map<string, Gadget*> seen;
    unordered_map<string, Gadget*>::iterator git;
    Gadget* gadget;
    Semantics* semantics;
    IRBlock* irblock;
    SymbolicEngine sym = SymbolicEngine(arch->type);
    Expr e;
    
    for( auto raw: *raw_gadgets ){
        if( (git = seen.find(raw.raw)) != seen.end()){
            // Already seen, just add a new address
            git->second->add_address(raw.addr);
        }else{
            // New gadget
            gadget = new Gadget();
            // Get semantics
            if( (irblock = arch->disasm->disasm_block(raw.addr, (code_t)raw.raw.c_str(), raw.raw.size())) == nullptr){
                std::cout << "DEBUG COULDN'T LIFT GADGET " << std::endl;
                delete gadget; continue;
            }
            
            if( (semantics = sym.execute_block(irblock)) == nullptr ){
                std::cout << "DEBUG ERROR WHILE EXECUTING GADGET " << std::endl;
                delete gadget; continue;
            }
            gadget->semantics = semantics;
            // Set nb instructions
            gadget->nb_instr = irblock->_nb_instr;
            gadget->nb_instr_ir = irblock->_nb_instr_ir;
            // Get sp increment
            // DEBUG TODO set the max sp_inc during symbolic execution
            e = semantics->regs->get(arch->sp());
            if( e->is_binop(Op::ADD) && e->args[0]->is_cst() ){
                if( e->args[0]->cst() % arch->octets != 0 ){
                    throw runtime_exception("DEBUG ERROR got SP INC Not multiple of arch size ");
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
                    std::cout << "DEBUG ERROR, NO VALID BRANCH TYPE " << std::endl;
                    delete gadget; continue;
                }
            }else{
                std::cout << "DEBUG ERROR, NO VALID BRANCH TYPE " << std::endl;
                delete gadget; continue;
            }
            
            // Add gadget to result
            res.push_back(gadget);
            seen[raw.raw] = gadget;
        }
    }
    return res;
}
