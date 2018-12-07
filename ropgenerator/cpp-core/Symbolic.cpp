#include "Symbolic.hpp"

using namespace std; 

// Arguments for REIL-type of operations 
SymArg::SymArg(ArgType t, int i, int s): _type(t), _id(i), _size(s){}
SymArg::SymArg(ArgType t, int i, int s, int l, int h): _type(t), _id(i), _size(s), _low(l), _high(h){}
ArgType SymArg::type(){return _type;}
int SymArg::id(){return _id;}
int SymArg::size(){return _size;}
int SymArg::low(){return _low;}
int SymArg::high(){return _high;}


ArgEmpty::ArgEmpty(): SymArg(ARG_EMPTY, -1, -1){}

ArgCst::ArgCst(cst_t v, int s): SymArg(ARG_CST, -1, s), _value(v){}
cst_t ArgCst::value(){return _value;} 


ArgReg::ArgReg(int n, int s): SymArg(ARG_REG, n, s){}
ArgReg::ArgReg(int n, int s, int l, int h): SymArg(ARG_REG, n, s, l, h){}

ArgTmp::ArgTmp( int n, int s): SymArg(ARG_TMP, n, s){}
ArgTmp::ArgTmp( int n, int s, int l, int h): SymArg(ARG_TMP, n, s, l, h){}

// IR Instruction
IRInstruction::IRInstruction(IROperation o, SymArg a1, SymArg a2, SymArg d): _op(o), _src1(a1), _src2(a2), _dst(d){}
IROperation IRInstruction::op(){return _op;}
SymArg* IRInstruction::src1(){return &_src1;}
SymArg* IRInstruction::src2(){return &_src2;}
SymArg* IRInstruction::dst(){return &_dst;}

// Some useful functions 
bool is_calculation_instr(IRInstruction& instr){
    return  instr.op() == IR_ADD || 
            instr.op() == IR_AND ||
            instr.op() == IR_BSH || 
            instr.op() == IR_DIV || 
            instr.op() == IR_MOD || 
            instr.op() == IR_MUL || 
            instr.op() == IR_OR ||
            instr.op() == IR_SUB ||
            instr.op() == IR_XOR ;    
}

// IR Block of instructions 
IRBlock::IRBlock(){
    int i;
    for( i = 0; i < NB_REGS_MAX; i++ )
        _reg_modified[i] = false;
}

bool IRBlock::add_instr(IRInstruction ins){
    if( _instr.size() == NB_INSTR_MAX )
        return false;
    else
        _instr.push_back(ins);
        return true;
}

ExprObjectPtr IRBlock::arg_to_expr(SymArg& arg ){
    ExprObjectPtr res; 
    if( arg.type() == ARG_CST ){
        res = make_shared<ExprObject>(make_shared<ExprCst>(arg.value(), arg.size()));
    }else if( arg.type() == ARG_TMP){
        res = _tmp_table[arg.id()]; 
    }else if( arg.type() == ARG_REG){
        if( _reg_modified[arg.id()])
            res = _reg_table[arg.id()];
        else{
            // We create a new value for it 
            res = make_shared<ExprObject>(make_shared<ExprReg>(arg.id(), arg.size())); 
            _reg_table[arg.id()] = res; 
        }
    }else
        throw "SymArg type not supported in arg_to_expr()";
    // Translate if low and high specified 
    if( arg.low() != 0 || arg.high() != arg.size())
        return Extract(res, arg.high(), arg.low());
    else
        return res; 
}

ExprObjectPtr IRBlock::full_reg_assignment(ExprObjectPtr expr, SymArg& reg){
    ExprObjectPtr prev; 
    if( reg.low() == 0 && reg.high() == reg.size()-1)
        return expr; 
    else if( reg.low() == 0 ){
        prev = arg_to_expr(reg);
        return Concat(Extract(prev, reg.size()-1, reg.high()+1), expr);
    }else if( reg.high() == reg.size()-1){
        prev = arg_to_expr(reg);
        return Concat(expr, Extract(prev, reg.low()-1, 0));
    }else{
        prev = arg_to_expr(reg);
        return Concat( Extract(prev, reg.size()-1, reg.high()+1), Concat(expr, Extract(prev, reg.low()-1, 0)));
    }    
}

Semantics* IRBlock::compute_semantics(){
    list<class IRInstruction>::iterator it; 
    Semantics* res = new Semantics();
    ExprObjectPtr src1, src2, comb; 
    // TODO 
    for( it = _instr.begin(); it != _instr.end(); ++it){
        if( is_calculation_instr((*it))){
            // Get src1 and src2
            src1 = this->arg_to_expr(*(it->src1())); 
            src2 = this->arg_to_expr(*(it->src2()));
            // Compute their combinaison 
            switch(it->op()){
                case IR_ADD:
                    comb = src1+src2; 
                    break;
                case IR_AND:
                    comb = src1 & src2; 
                    break;
                case IR_BSH:
                    throw "Not supported: need to add it to my IR :( ";
                    break;
                case IR_DIV:
                    comb = src1 / src2; 
                    break;
                case IR_MOD:
                    throw "Not supported, need to add it"; 
                    break;
                case IR_MUL:
                    comb = src1 * src2; 
                    break;
                case IR_OR:
                    comb = src1 | src2; 
                    break;
                case IR_SUB:
                    comb = src1 - src2; 
                    break;
                case IR_XOR:
                    comb = src1 ^ src2; 
                    break;
                default:
                    throw "Unknown type of calculation in IR";
            }
            if( it->dst()->type() == ARG_REG )
                _reg_table[it->dst()->id()] = this->full_reg_assignment(comb, *(it->dst()));
            else if( it->dst()->type() == ARG_TMP )
                _tmp_table[it->dst()->id()] = comb; 
            else
                throw "Invalid arg type for dst in IR calculation instruction"; 
        }else if( it->op() == IR_STR ){
            src1 = this->arg_to_expr(*(it->src1())); 
            if( it->dst()->type() == ARG_REG )
                _reg_table[it->dst()->id()] = this->full_reg_assignment(src1, *(it->dst()));
            else if( it->dst()->type() == ARG_TMP )
                _tmp_table[it->dst()->id()] = comb; 
            else
                throw "Invalid arg type for dst in IR_STR instruction"; 
        }// TODO Rest of them 
        
        
    }
    
    return res; 
}
