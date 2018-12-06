#include "Symbolic.hpp"

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

Semantics* IRBlock::compute_semantics(){
    Semantics* res = new Semantics(); 
    // TODO 
    return res; 
}

