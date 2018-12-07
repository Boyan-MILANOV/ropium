#ifndef SYMBOLIC_H
#define SYMBOLIC_H

#include "Semantic.hpp"
#include "Expression.hpp"
#include "Condition.hpp"
#include "Simplification.hpp"
#include <list>

using namespace std; 

// Arguments for REIL-type of operations 
enum ArgType {ARG_EMPTY, ARG_CST, ARG_REG, ARG_TMP};

class SymArg{
    ArgType _type; 
    int _id; 
    int _size;
    int _low, _high; 
    public: 
        SymArg(ArgType t, int i, int s);
        SymArg(ArgType t, int i, int s, int l, int h);
        ArgType type(); 
        int id();
        int size();
        int low();
        int high();
        // From child classes 
        virtual cst_t value(); 
};

class ArgEmpty: public SymArg{
    public:
        ArgEmpty();
};

class ArgCst: public SymArg{
    cst_t _value; 
    public:
        ArgCst(cst_t v, int s);
        cst_t value(); 
};

class ArgReg: public SymArg{
    public:
        ArgReg(int n, int s);
        ArgReg(int n, int s, int l, int h);
};

class ArgTmp: public SymArg{
    public:
        ArgTmp( int n, int s);
        ArgTmp( int n, int s, int l, int h); 
};

// Operation types: 
enum IROperation{IR_ADD, IR_AND, IR_BSH, IR_DIV, IR_LDM, IR_MOD, IR_MUL, IR_NOP, IR_OR, IR_STM, IR_STR, IR_SUB, IR_XOR};

// IR Instruction
class IRInstruction{
    IROperation _op;
    SymArg _src1, _src2, _dst; 
    public: 
        IRInstruction(IROperation o, SymArg a1, SymArg a2, SymArg d);
        IROperation op(); 
        SymArg* src1();
        SymArg* src2();
        SymArg* dst();
};

// IR Block
#define NB_TMP_MAX 256
#define NB_MEM_MAX 32
#define NB_INSTR_MAX 2048

class IRBlock{
    list<class IRInstruction> _instr;
    ExprObjectPtr _reg_table[NB_REGS_MAX];
    bool _reg_modified[NB_REGS_MAX];
    ExprObjectPtr _tmp_table[NB_TMP_MAX];
    mem_tuple _mem_table[NB_MEM_MAX];
    public:
        IRBlock();
        bool add_instr(IRInstruction ins);
        Semantics* compute_semantics();
    private:
        ExprObjectPtr full_reg_assignment(ExprObjectPtr expr, SymArg& reg);
        list<SPair> get_mem_semantics(ExprObjectPtr addr, int size);
        ExprObjectPtr arg_to_expr(SymArg& arg);
};

#endif 

 
