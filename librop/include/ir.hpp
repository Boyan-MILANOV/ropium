#ifndef IR_H
#define IR_H

#include <vector>
#include <unordered_map>
#include "expression.hpp"

using std::unordered_map;

/* Type aliasing */ 
typedef unsigned int IRVar;
typedef unsigned int IRBasicBlockId;

/* IR Operations 
 ===============
IR supports basic arithmetic and logical operations, 
store/load operations, and register 'mov'  
It also has two branchment instructions:
 - BCC : conditionnal jump to an IRBasicBlock
 - JCC : conditionnal jump to an IRBlock
And two special instructions: 
 - INT
 - SYSCALL
*/

enum class IROperation{
    /* Arithmetic and logical operations */
    ADD,
    SUB,
    MUL,
    MULH,
    SMULL,
    SMULH,
    DIV,
    SDIV,
    NEG,
    AND,
    OR,
    XOR,
    NOT,
    SHL,
    SHR,
    MOD,
    SMOD,
    /* Memory read and write */
    LDM,
    STM,
    /* Set register with a value */
    MOV,
    /* Conditionnal jumps */
    BCC, // Internal, to same IRBlock. Used for conditionnal instructions
    JCC, // External, to other IRBlock Used for branch instructions 
    /* Boolean flag set if zero */
    BISZ,
    /* Concatenate two variables */
    CONCAT,
    /* System calls and interrupt */
    INT,
    SYSCALL
};
bool iroperation_is_assignment(IROperation& op);
bool iroperation_is_memory(IROperation& op);
ostream& operator<<(ostream& os, IROperation& op);

/* Values for syscalls */
#define SYSCALL_X86_INT80 1
#define SYSCALL_X86_SYSENTER 2


/* IR Operations 
 ===============
IR operands can be of 3 main types.
    - CST: a constant operand 
    - VAR: a operand representing a register of the disassembled arch
    - TMP: temporary registers used to model complex operations, they don't 
           correspond to actual processor registers
    - NONE: represents the fact that there is no argument used */ 
enum class IROperandType{
    CST,
    VAR,
    TMP,
    NONE
};

class IROperand{
    cst_t _val;
public:
    IROperandType type;
    exprsize_t high, low, size;
    
    IROperand();
    IROperand(IROperandType t, cst_t val, exprsize_t high, exprsize_t low);
    
    bool is_cst();
    bool is_var();
    bool is_tmp();
    bool is_none();
    
    cst_t cst();
    IRVar var();
    IRVar tmp();
};

ostream& operator<<(ostream& os, IROperand& op);
/* Helpers to create operands */
IROperand ir_cst(cst_t val, exprsize_t high, exprsize_t low);
IROperand ir_var(cst_t num, exprsize_t high, exprsize_t low);
IROperand ir_tmp(cst_t num, exprsize_t high, exprsize_t low);
IROperand ir_none();

/* IR Instructions
   ===============
IR Instructions are composed of an IROperation, and 3
IROperands: one destination, and two (optional) sources  */

class IRInstruction{
public:
    addr_t addr;
    IROperation op;
    IROperand dst;
    IROperand src1;
    IROperand src2;
    
    IRInstruction(IROperation op, IROperand dst, IROperand src1, addr_t addr = 0);
    IRInstruction(IROperation op, IROperand dst, IROperand src1, IROperand src2, addr_t addr = 0);
    bool reads_var(IRVar var);
    bool writes_var(IRVar var);
    bool uses_var(IRVar var);
    bool reads_tmp(IRVar tmp);
    bool writes_tmp(IRVar tmp);
    vector<IROperand> used_vars_read();
    vector<IROperand> used_vars_write();
    vector<IROperand> used_tmps_read();
    vector<IROperand> used_tmps_write();
};

ostream& operator<<(ostream& os, IRInstruction& ins);
/* Helpers to create instructions */
IRInstruction ir_add(IROperand dst, IROperand src1, IROperand src2, addr_t addr = 0);
IRInstruction ir_sub(IROperand dst, IROperand src1, IROperand src2, addr_t addr = 0);
IRInstruction ir_mul(IROperand dst, IROperand src1, IROperand src2, addr_t addr = 0);
IRInstruction ir_mulh(IROperand dst, IROperand src1, IROperand src2, addr_t addr = 0);
IRInstruction ir_smull(IROperand dst, IROperand src1, IROperand src2, addr_t addr = 0);
IRInstruction ir_smulh(IROperand dst, IROperand src1, IROperand src2, addr_t addr = 0);
IRInstruction ir_div(IROperand dst, IROperand src1, IROperand src2, addr_t addr = 0);
IRInstruction ir_sdiv(IROperand dst, IROperand src1, IROperand src2, addr_t addr = 0);
IRInstruction ir_and(IROperand dst, IROperand src1, IROperand src2, addr_t addr = 0);
IRInstruction ir_or(IROperand dst, IROperand src1, IROperand src2, addr_t addr = 0);
IRInstruction ir_xor(IROperand dst, IROperand src1, IROperand src2, addr_t addr = 0);
IRInstruction ir_shl(IROperand dst, IROperand src1, IROperand src2, addr_t addr = 0);
IRInstruction ir_shr(IROperand dst, IROperand src1, IROperand src2, addr_t addr = 0);
IRInstruction ir_mod(IROperand dst, IROperand src1, IROperand src2, addr_t addr = 0);
IRInstruction ir_smod(IROperand dst, IROperand src1, IROperand src2, addr_t addr = 0);
IRInstruction ir_neg(IROperand dst, IROperand src1, addr_t addr = 0);
IRInstruction ir_not(IROperand dst, IROperand src1, addr_t addr = 0);
IRInstruction ir_ldm(IROperand dst, IROperand src1, addr_t addr = 0);
IRInstruction ir_stm(IROperand dst, IROperand src1, addr_t addr = 0);
IRInstruction ir_mov(IROperand dst, IROperand src1, addr_t addr = 0);
IRInstruction ir_bcc(IROperand dst, IROperand src1, IROperand src2, addr_t addr = 0);
IRInstruction ir_jcc(IROperand dst, IROperand src1, IROperand src2, addr_t addr = 0);
IRInstruction ir_bisz(IROperand dst, IROperand src1, IROperand src2, addr_t addr = 0);
IRInstruction ir_concat(IROperand dst, IROperand src1, IROperand src2, addr_t addr = 0);
IRInstruction ir_int(IROperand num, IROperand ret, addr_t addr = 0);
IRInstruction ir_syscall(IROperand type, IROperand ret, addr_t addr = 0);

/* IRContext 
   =========
Holds current expressions for every register */

class IRContext{
friend class BreakpointManager;
    Expr* _var;
    int _nb_var;
public:
    IRContext();
    IRContext(IRVar nb_var);
    ~IRContext();
    int nb_vars();
    /* Get and set IR variables */
    void set(IRVar num, Expr e);
    Expr get(IRVar num);
};

ostream& operator<<(ostream& os, IRContext& ctx);

/* MemEngine 
   ========== */
class MemContext{
public:
    unordered_map<Expr, Expr> writes;

    void write(Expr addr, Expr expr);
    Expr read(Expr addr, int octets);
};


/* Type aliasing */
typedef vector<IRInstruction> IRBasicBlock;


/* IRBlock
   =======
   An IRBlock represents a basic block in assembly. By basic block we mean
   a sequence of contiguous instructions that are executed sequentially (so
   no branchement instruction in the middle of a basic block, only at the
   end).

    An IRBlock is **uniquely** identifier by its start address ! There is a 'name'
    field but it's just here for convenience.

    An IRBlock is made of several IRBasicBlocks (which are just lists of
    IRInstructions). It also holds several "meta" informations like the number
    of tmp ir vars it holds, it's size in IR, in raw assembly, the branchment
    type it finishes with, etc.
*/
class IRBlock{
public:
    vector<IRBasicBlock> _bblocks;
    int _nb_tmp_vars; // Number of tmp variables used in the block
    int _nb_instr, _nb_instr_ir;
    addr_t start_addr, end_addr;
    string name;
    unsigned int ir_size;
    unsigned int raw_size;
    addr_t branch_target[2]; // [0]: target when condition expression is 0
                             // [1]: target when condition expression is != 0
    IRBlock(string name, addr_t start=0, addr_t end=0);
    void add_instr(IRBasicBlockId bblock, IRInstruction instr);
    /* Manage IR Basic Blocks */
    IRBasicBlockId new_bblock();
    IRBasicBlock& get_bblock(IRBasicBlockId id);
    int nb_bblocks();
    vector<IRBasicBlock>& bblocks();
};

ostream& operator<<(ostream& os, IRBlock& blk);




#endif

