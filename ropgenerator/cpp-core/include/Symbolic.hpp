#ifndef SYMBOLIC_H
#define SYMBOLIC_H

#include "Semantic.hpp"
#include "Expression.hpp"
#include "Condition.hpp"
#include "Simplification.hpp"
#include <vector>

using namespace std; 

// Arguments for REIL-type of operations 
enum ArgType {ARG_EMPTY, ARG_CST, ARG_REG, ARG_TMP};

class SymArg{
    ArgType _type; 
    int _id; 
    int _size;
    int _high, _low;
    protected:
        cst_t _value; 
    public: 
        SymArg(ArgType t, int i, int s);
        SymArg(ArgType t, int i, int s, int h, int l);
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

class ArgCst: public SymArg {
    public:
        ArgCst(cst_t v, int s);
};

class ArgReg: public SymArg{
    public:
        ArgReg(int n, int s);
        ArgReg(int n, int s, int h, int l);
};

class ArgTmp: public SymArg{
    public:
        ArgTmp( int n, int s);
        ArgTmp( int n, int s, int h, int l); 
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
    vector<class IRInstruction> _instr;
    vector<SPair>* _reg_table[NB_REGS_MAX];
    bool _reg_modified[NB_REGS_MAX];
    vector<SPair>* _tmp_table[NB_TMP_MAX];
    pair<ExprObjectPtr, vector<SPair>*> _mem_table[NB_MEM_MAX]; //<addr, list of spairs>
    int _mem_write_cnt; 
    vector<ExprObjectPtr> _mem_writes; 
    vector<ExprObjectPtr> _mem_reads; 
    public:
        IRBlock();
        bool add_instr(IRInstruction ins);
        vector<ExprObjectPtr> mem_writes();
        vector<ExprObjectPtr> mem_reads();
        bool reg_modified(int num);
        Semantics* compute_semantics();
        ~IRBlock();
    private:
        inline ExprObjectPtr full_reg_assignment(ExprObjectPtr expr, ExprObjectPtr prev, SymArg& reg);
        vector<SPair>* full_reg_assignment(vector<SPair>* spairs, SymArg& reg);
        vector<SPair>* arg_to_spairs(SymArg& arg);
        
        void execute_stm(vector<SPair>* src1, vector<SPair>* dst, int &memory_writes_cnt);
        vector<SPair>* execute_calculation(IROperation op,vector<SPair>* src1, vector<SPair>*src2);
        vector<SPair>* execute_ldm(SPair& pair, int size, int mem_write_cnt);
        
        inline void assign_reg_table(int num, vector<SPair>* val);
        inline void assign_tmp_table(int num, vector<SPair>* val);
        
};

#endif 

 
