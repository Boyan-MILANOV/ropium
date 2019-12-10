#include "symbolic.hpp"
#include "exception.hpp"
#include "simplification.hpp"
#include <cassert>
#include <vector>
#include <iostream>
#include <algorithm>
#include <sstream>

using std::get;
using std::vector;
using std::stringstream;
using std::make_shared;

Semantics::Semantics(IRContext* r, MemContext* m): regs(r), mem(m){}
void Semantics::simplify(){
    ExprSimplifier* simp = NewDefaultExprSimplifier();
    for( int reg = 0; reg < regs->nb_vars(); reg++ ){
        regs->set(reg, simp->simplify(regs->get(reg)));
    }
    for( unordered_map<Expr, Expr>::iterator write = mem->writes.begin(); write != mem->writes.end(); write++ ){
        mem->writes[write->first] = simp->simplify(write->second);
    }
    delete simp;
}

Semantics::~Semantics(){
    delete regs; regs = nullptr;
    delete mem; mem = nullptr;
}

ostream& operator<<(ostream& os, Semantics& s){
    os << *(s.regs) << std::endl << *(s.mem);
    return os;
}

/* ======================================= */

SymbolicEngine::SymbolicEngine(ArchType a){
    if(a == ArchType::X86){
        arch = new ArchX86();
    }else if( a == ArchType::X64 ){
        arch = new ArchX64();
    }else if (a == ArchType::NONE){
        arch = new ArchNone();
    }else{
        throw symbolic_exception("SymbolicEngine::SymbolicEngine() unsupported ArchType");
    }
}

SymbolicEngine::~SymbolicEngine(){
    delete arch; arch = nullptr;
}

/* Some util functions to manipulate values during symbolic execution */
Expr _reduce_rvalue(Expr e, exprsize_t high, exprsize_t low ){
    if( high-low+1 == e->size )
        return e;
    else
        return extract(e, high, low);
}

Expr _expand_lvalue(Expr current, Expr e, exprsize_t high, exprsize_t low){
    if( high-low+1 >= current->size )
        return e;
    else if(low == 0){
        return concat(extract(current, current->size-1, high+1), e);
    }else if(high == current->size-1){
        return concat(e, extract(current, low-1, 0));
    }else{
        return concat(extract(current, current->size-1, high+1),
                      concat(e, extract(current, low-1, 0))); 
    }
}

inline void _set_tmp_var(int num, Expr e, int high, int low, vector<Expr>& tmp_vars){
    unsigned int tmp_vars_size = tmp_vars.size();
    if( tmp_vars_size <= num ){
        /* Fill missing tmp variables if needed *//*
        for( int i = 0; i < (num - tmp_vars_size); i++){
            tmp_vars.push_back(nullptr);
        }*/
        std::fill_n(std::back_inserter(tmp_vars), (num - tmp_vars_size+1), nullptr);
    }
    
    if( tmp_vars[num] == nullptr ){
        if( low == 0 ){
            tmp_vars[num] = e;
        }else{
            /* If new tmp and low is != 0, then we pad the lower bits
             * with zero. That's a ugly hack but used to avoid some bugs 
             * for some instructions when their IR gets optimized */
            tmp_vars[num] = _expand_lvalue(exprcst(high+1, 0), e, high, low);
        }
    }else{
        tmp_vars[num] = _expand_lvalue(tmp_vars[num], e, high, low);
    }
}

Expr _get_operand(IROperand& arg, IRContext* irctx, vector<Expr>& tmp_vars){
    if( arg.is_cst() ){
        if( arg.high-arg.low+1 == sizeof(cst_t)*8 )
            return exprcst(arg.high-arg.low+1, arg.cst());
        else
            return exprcst(arg.high-arg.low+1, 
                ((ucst_t)arg.cst() & (((ucst_t)1 << (arg.high+1))-1)) >> (ucst_t)arg.low);
    }else if( arg.is_var() ){
        return _reduce_rvalue(irctx->get(arg.var()), arg.high, arg.low);
    }else if( arg.is_tmp() ){
        return _reduce_rvalue(tmp_vars[arg.tmp()], arg.high, arg.low);
    }else{
        return nullptr;
    }
}


Semantics* SymbolicEngine::execute_block(IRBlock* block){
    Expr rvalue, dst, src1, src2;
    IRBasicBlock::iterator instr;
    bool stop = false;
    IRContext* regs = new IRContext(arch->nb_regs); // TODO: free it if not returned
    MemContext* mem = new MemContext();
    vector<Expr> tmp_vars;
    ExprSimplifier *simp = NewDefaultExprSimplifier(); 
    IRBasicBlockId bblkid = 0;

    /* Init context */
    for( reg_t reg = 0; reg < arch->nb_regs; reg++){
        regs->set(reg, exprvar(arch->bits, arch->reg_name(reg), reg));
    }
    block->known_max_sp_inc = true;
    block->max_sp_inc = 0;

    while( !stop ){
        /* ====================== Execute an IR basic block ======================== */ 
        /* Execute the basic block as long as there is no reason to stop */
        for( instr = block->get_bblock(bblkid).begin(); instr != block->get_bblock(bblkid).end(); instr++){
            // FOR DEBUG
            // std::cout << "DEBUG, executing " << *instr << std::endl;

            /* Get operands expressions */
            src1 = _get_operand(instr->src1, regs, tmp_vars);
            src2 = _get_operand(instr->src2, regs, tmp_vars);
            
            /* Arithmetic and logic operations */
            if( iroperation_is_assignment(instr->op)){
                /* Build rvalue */
                switch( instr->op ){
                    case IROperation::ADD: 
                        rvalue = src1 + src2;
                        break;
                    case IROperation::SUB:
                        rvalue = src1 - src2; 
                        break;
                    case IROperation::MUL: 
                        rvalue = src1 * src2;
                        break;
                    case IROperation::MULH: 
                        rvalue = mulh(src1, src2);
                        break;
                    case IROperation::SMULL: 
                        rvalue = smull(src1,src2);
                        break;
                    case IROperation::SMULH: 
                        rvalue = smulh(src1,src2);
                        break;
                    case IROperation::DIV:
                        rvalue = src1 / src2;
                        break;
                    case IROperation::SDIV: 
                        rvalue = sdiv(src1, src2);
                        break;
                    case IROperation::SHL: 
                        rvalue = shl(src1, src2);
                        break;
                    case IROperation::SHR: 
                        rvalue = shr(src1, src2);
                        break;
                    case IROperation::AND:
                        rvalue = src1 & src2;
                        break;
                    case IROperation::OR:
                        rvalue = src1 | src2;
                        break;
                    case IROperation::XOR:
                        rvalue = src1 ^ src2;
                        break;
                    case IROperation::MOD:
                        rvalue = src1 % src2;
                        break;
                    case IROperation::SMOD:
                        rvalue = smod(src1,src2);
                        break;
                    case IROperation::NEG:
                        rvalue = -src1;
                        break;
                    case IROperation::NOT:
                        rvalue = ~src1;
                        break;
                    case IROperation::MOV:
                        rvalue = src1;
                        break;
                    case IROperation::CONCAT:
                        rvalue = concat(src1, src2);
                        break;
                    default: throw runtime_exception("Unsupported assignment IROperation in SymbolicEngine::execute_block()");
                }

                /* Affect lvalue */
                if( instr->dst.is_tmp()){
                    _set_tmp_var(instr->dst.tmp(), rvalue, instr->dst.high, instr->dst.low, tmp_vars);
                }else if( instr->dst.is_var()){
                    regs->set(instr->dst.var(), _expand_lvalue(regs->get(instr->dst.var()), rvalue,
                                                                    instr->dst.high, instr->dst.low));
                }else{
                    throw runtime_exception("SymbolicEngine::execute_block() got invalid dst operand type");
                }
            }else if(instr->op == IROperation::STM){
                /* Store memory */
                dst = _get_operand(instr->dst, regs, tmp_vars);
                /* THEN execute the store */
                mem->write(dst, src1);
            }else if( instr->op == IROperation::LDM){
                /* Load memory */  
                // Affect lvalue
                rvalue = mem->read(src1, (instr->dst.high-instr->dst.low+1)/8);
                if( instr->dst.is_tmp()){
                    _set_tmp_var(instr->dst.tmp(), rvalue, instr->dst.high, instr->dst.low, tmp_vars);
                }else if( instr->dst.is_var()){
                    regs->set(instr->dst.var(), _expand_lvalue(regs->get(instr->dst.var()), rvalue,
                                                                    instr->dst.high, instr->dst.low));
                }else{
                    throw runtime_exception("SymbolicEngine::execute_block() got invalid dst operand type");
                }
            }else if( instr->op == IROperation::BCC){
                dst = _get_operand(instr->dst, regs, tmp_vars);
                /* Check condition and update basic block to execute */
                if( !dst->is_cst() || !src1->is_cst() || (src2 != nullptr && !src2->is_cst())){
                    throw symbolic_exception("BCC with non constant operand(s) not supported");
                }
                if( cst_sign_trunc(dst->size, dst->cst()) != 0){
                    bblkid = src1->cst();
                }else{
                    bblkid = src2->cst();
                }
                break;
            }else if( instr->op == IROperation::JCC ){
                dst = _get_operand(instr->dst, regs, tmp_vars);
                /* Set new PC */
                if( dst->is_cst() && cst_sign_trunc(dst->size, dst->cst()) != 0){
                    regs->set(arch->pc(), _expand_lvalue(regs->get(arch->pc()), src1,
                                                                instr->dst.high, instr->dst.low));
                }else{
                    throw symbolic_exception("JCC with non constant or null condition not supported");
                }
                /* Quit this block */
                stop = true; // Go out of this block
                break; // Stop executing instructions in the basic block
            }else if(instr->op == IROperation::BISZ){
                if( !src2->is_cst() ){
                    throw symbolic_exception("BISZ with not constant mode not supported");
                }
                rvalue = bisz((instr->dst.high-instr->dst.low)+1 , src1, cst_sign_trunc(src2->size, src2->cst()));
                /* Affect lvalue */
                if( instr->dst.is_tmp()){
                    _set_tmp_var(instr->dst.tmp(), rvalue, instr->dst.high, instr->dst.low, tmp_vars);
                }else if( instr->dst.is_var()){
                    regs->set(instr->dst.var(), _expand_lvalue(regs->get(instr->dst.var()), rvalue,
                                                                    instr->dst.high, instr->dst.low));
                }else{
                    throw runtime_exception("SymbolicEngine::execute_block() got invalid dst operand type");
                }
            
            }else if(instr->op == IROperation::INT){
                throw symbolic_exception("INT operation not supported in gadgets");
                break; // Stop executing instructions in the basic block
            }else if(instr->op == IROperation::SYSCALL){
                throw symbolic_exception("SYSCALL operation not supported in gadgets");
                break; // Stop executing instructions in the basic block
            }else{
                throw runtime_exception("SymbolicEngine::execute_block(): unknown IR instruction type");
            }
            
            /* Check for sp increment */
            Expr sp = regs->get(arch->sp());
            sp = simp->simplify(sp);
            cst_t sp_inc = 0xffffffff;
            if( sp->is_binop(Op::ADD) && sp->args[0]->is_cst() &&
                sp->args[0]->cst()%8 == 0 ){
                // sp = sp0 + cst
                sp_inc = sp->args[0]->cst();
            }else if( sp->is_binop(Op::ADD) && sp->args[0]->is_unop(Op::NEG) &&
                      sp->args[0]->args[0]->is_cst() && sp->args[0]->args[0]->cst()%8 == 0){
                // sp = sp0 - cst
                sp_inc = -1*sp->args[0]->args[0]->cst();
            }else if( sp->is_var() && arch->reg_num(sp->name()) == arch->sp()){
                // sp = sp0
                sp_inc = 0;
            }
            // Assign max sp inc
            if( sp_inc != 0xffffffff && block->known_max_sp_inc){
                block->max_sp_inc = block->max_sp_inc > sp_inc ? block->max_sp_inc : sp_inc;
            }
        }
    }

    delete simp;
    return new Semantics(regs, mem);
}
