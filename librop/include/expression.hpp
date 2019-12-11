#ifndef EXPRESSION_H
#define EXPRESSION_H

#include <cstdint>
#include <string>
#include <vector>
#include <memory>
#include <ostream>
#include <map>
#include "exception.hpp"

using std::string;
using std::vector;
using std::shared_ptr;
using std::ostream;
using std::map;

/* Type aliasing */
typedef uint16_t exprsize_t ;
typedef uint32_t hash_t;
typedef int64_t cst_t;
typedef uint64_t ucst_t;
typedef ucst_t addr_t;

/* Types of expressions
   ====================

Different expression types are supported: 
 - CST: constant value
 - VAR: symbolic variable, identified by its name
 - MEM: a memory content, identified by an address and the number of bits
        that are read
 - UNOP/BINOP:  unary and binary operations on expressions
 - EXTRACT: extraction of a bit-interval of another expression, the interval
            is specified with the values of the higher and lower bits to
            extract
 - CONCAT: binary concatenation of two expressions
 - BISZ: zero testing. Depending on its mode, it can be equal to 1 IFF 
         the argument is zero, or to 0 IFF the argument is zero
 - UNKNOWN: represents a value which is unknown or can't be computed
*/
enum class ExprType {
    VAR, 
    MEM,
    EXTRACT, 
    CONCAT,
    UNOP, 
    BINOP,
    BISZ,
    CST,
    UNKNOWN
};
bool operator<(ExprType t1, ExprType t2);

/* Types of operations
   ===================

Different operations on expressions are supported. Their effects are 
pretty straightforward. 

Note that unary and binary operations are a member of the same enum.
Note that there is no binary SUB operation, only a unary SUB.
*/
enum class Op {
    ADD=0,
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
    SHL,
    SHR,
    MOD,
    SMOD,
    NOT,
    NONE // No operation
}; 
string op_to_str(Op op);
bool operator<(Op op1, Op op2);
bool op_is_symetric(Op op);
bool op_is_associative(Op op);
bool op_is_left_associative(Op op);
bool op_is_distributive_over(Op op1, Op op2);
bool op_is_multiplication(Op op);


/* Forward declarations */
class ExprObject;
class VarContext;
typedef shared_ptr<ExprObject> Expr;

/* Generic base class */ 
class ExprObject{
friend class ExprSimplifier;
protected:
    // Hash 
    bool _hashed;
    hash_t _hash;
    // Concrete
    cst_t _concrete;
    int _concrete_ctx_id;
    // Simplification
    Expr _simplified_expr;
    bool _is_simplified;
public:
    // General
    const ExprType type;
    exprsize_t size;
    vector<Expr> args;

    ExprObject(ExprType type, exprsize_t size, bool _is_simp=false);
    virtual void get_associative_args(Op op, vector<Expr>& vec){};
    virtual void get_left_associative_args(Op op, vector<Expr>& vec, Expr& leftmost){};
    
    /* Virtual accessors of specialized child classes members */
    virtual hash_t hash(){throw runtime_exception("Called virtual function in ExprObject base class!");};
    virtual cst_t cst(){throw runtime_exception("Called virtual function in ExprObject base class!");};
    virtual const string& name(){throw runtime_exception("Called virtual function in ExprObject base class!");};
    virtual Op op(){throw runtime_exception("Called virtual function in ExprObject base class!");};
    virtual cst_t mode(){throw runtime_exception("Called virtual function in ExprObject base class!");};
    virtual void print(ostream& out){out << "???";};
    virtual int reg(){throw runtime_exception("Called virtual function in ExprObject base class!");};
    
    /* Type */
    bool is_cst();
    bool is_var();
    virtual bool is_reg(int reg){return false;}
    bool is_mem();
    virtual bool is_unop(Op op=Op::NONE);
    virtual bool is_binop(Op op=Op::NONE);
    bool is_extract();
    bool is_concat();
    bool is_bisz();
    bool is_unknown();
    
    /* Concretize */
    virtual cst_t concretize(VarContext* ctx=nullptr);
    
    /* Equality between expressions */
    bool eq(Expr other);
    bool neq(Expr other);
    
    /* Priority between expressions */
    bool inf(Expr other);
};

/* Child specialized classes */
class ExprCst: public ExprObject{
    cst_t _cst;
public:
    ExprCst(exprsize_t size, cst_t cst);
    hash_t hash();
    cst_t cst();
    virtual cst_t concretize(VarContext* ctx=nullptr);
    void print(ostream& out);
};

class ExprVar: public ExprObject{
    const string _name;
    int _num;
public:
    ExprVar(exprsize_t size, string name, int num=0);
    hash_t hash();
    bool is_reg(int reg);
    int reg();
    virtual cst_t concretize(VarContext* ctx=nullptr);
    const string& name();
    void print(ostream& out);
};

class ExprMem: public ExprObject{
public:
    ExprMem(exprsize_t size, Expr addr);
    hash_t hash();
    virtual cst_t concretize(VarContext* ctx=nullptr);
    void print(ostream& out);
};

class ExprUnop: public ExprObject{
    Op _op;
public:
    ExprUnop(Op op, Expr arg);
    hash_t hash();
    Op op();
    virtual cst_t concretize(VarContext* ctx=nullptr);
    void print(ostream& out);
    bool is_unop(Op op);
};

class ExprBinop: public ExprObject{
    Op _op;
public:
    ExprBinop(Op op, Expr left, Expr right);
    hash_t hash();
    Op op();
    void get_associative_args(Op op, vector<Expr>& vec);
    void get_left_associative_args(Op op, vector<Expr>& vec, Expr& leftmost);

    virtual cst_t concretize(VarContext* ctx=nullptr);
    void print(ostream& out);
    bool is_binop(Op op);
};

class ExprExtract: public ExprObject{
public:
    ExprExtract(Expr arg, Expr higher, Expr lower);
    hash_t hash();
    virtual cst_t concretize(VarContext* ctx=nullptr);
    void print(ostream& out);
};

class ExprConcat: public ExprObject{
public:
    ExprConcat(Expr upper, Expr lower);
    hash_t hash();
    virtual cst_t concretize(VarContext* ctx=nullptr);
    void print(ostream& out);
};

class ExprBisz: public ExprObject{
    cst_t _mode;
public:
    ExprBisz(exprsize_t size, Expr cond, cst_t mode);
    hash_t hash();
    cst_t mode();
    virtual cst_t concretize(VarContext* ctx=nullptr);
    void print(ostream& out);
};

class ExprUnknown: public ExprObject{
public:
    ExprUnknown(exprsize_t size);
    hash_t hash();
    virtual cst_t concretize(VarContext* ctx=nullptr);
    void print(ostream& out);
};

/* Helper functions to create new expressions */
// Create from scratch  
Expr exprcst(exprsize_t size, cst_t cst);
Expr exprvar(exprsize_t size, string name, int num=-1);
Expr exprmem(exprsize_t size, Expr addr);
Expr exprbinop(Op op, Expr left, Expr right);
Expr extract(Expr arg, unsigned long higher, unsigned long lower);
Expr extract(Expr arg, Expr higher, Expr lower);
Expr concat(Expr upper, Expr lower);
Expr bisz(exprsize_t size, Expr arg, cst_t mode);
Expr exprunknown(exprsize_t size);

// Binary operations 
Expr operator+(Expr left, Expr right);
Expr operator+(Expr left, cst_t right);
Expr operator+(cst_t left, Expr right);

Expr operator-(Expr left, Expr right);
Expr operator-(Expr left, cst_t right);
Expr operator-(cst_t left, Expr right);

Expr operator*(Expr left, Expr right);
Expr operator*(Expr left, cst_t right);
Expr operator*(cst_t left, Expr right);

Expr operator/(Expr left, Expr right);
Expr operator/(Expr left, cst_t right);
Expr operator/(cst_t left, Expr right);

Expr operator&(Expr left, Expr right);
Expr operator&(Expr left, cst_t right);
Expr operator&(cst_t left, Expr right);

Expr operator|(Expr left, Expr right);
Expr operator|(Expr left, cst_t right);
Expr operator|(cst_t left, Expr right);

Expr operator^(Expr left, Expr right);
Expr operator^(Expr left, cst_t right);
Expr operator^(cst_t left, Expr right);

Expr operator%(Expr left, Expr right);
Expr operator%(Expr left, cst_t right);
Expr operator%(cst_t left, Expr right);

Expr operator<<(Expr left, Expr right);
Expr operator<<(Expr left, cst_t right);
Expr operator<<(cst_t left, Expr right);

Expr operator>>(Expr left, Expr right);
Expr operator>>(Expr left, cst_t right);
Expr operator>>(cst_t left, Expr right);

Expr shl(Expr arg, Expr shift);
Expr shl(Expr arg, cst_t shift);
Expr shl(cst_t arg, Expr shift);

Expr shr(Expr arg, Expr shift);
Expr shr(Expr arg, cst_t shift);
Expr shr(cst_t arg, Expr shift);

Expr sdiv(Expr left, Expr right);
Expr sdiv(Expr left, cst_t right);
Expr sdiv(cst_t left, Expr right);

Expr smod(Expr left, Expr right);
Expr smod(Expr left, cst_t right);
Expr smod(cst_t left, Expr right);

Expr mulh(Expr left, Expr right);
Expr mulh(Expr left, cst_t right);
Expr mulh(cst_t left, Expr right);

Expr smull(Expr left, Expr right);
Expr smull(Expr left, cst_t right);
Expr smull(cst_t left, Expr right);

Expr smulh(Expr left, Expr right);
Expr smulh(Expr left, cst_t right);
Expr smulh(cst_t left, Expr right);

// Unary operations
Expr operator~(Expr arg);
Expr operator-(Expr arg);

/* Printing expressions */
ostream& operator<< (ostream& os, Expr e);

/* Canonizing expressions */
Expr expr_canonize(Expr e);

cst_t cst_sign_trunc(exprsize_t size, cst_t val);
cst_t cst_mask(exprsize_t size);
cst_t cst_sign_extend(exprsize_t size, cst_t val);


// Macros to statically cast expressions to access fields if needed
#define _exprobject_(e) (*(static_cast<ExprObject*>(e.get())))
#define _cst_(e) (*(static_cast<ExprCst*>(e.get())))
#define _var_(e) (*(static_cast<ExprVar*>(e.get())))
#define _mem_(e) (*(static_cast<ExprMem*>(e.get())))
#define _unop_(e) (*(static_cast<ExprUnop*>(e.get())))
#define _binop_(e) (*(static_cast<ExprBinop*>(e.get())))
#define _extract_(e) (*(static_cast<ExprExtract*>(e.get())))
#define _concat_(e) (*(static_cast<ExprConcat*>(e.get())))
#define _bisz_(e) (*(static_cast<ExprBisz*>(e.get())))
#define _unknown_(e) (*(static_cast<ExprUnknown*>(e.get())))


/* VarContext
   ==========
A VarContext associates a list of concrete values to a list of variables.
It used with the variables names as keys for lookup. */
class VarContext{
    map<string, cst_t> varmap;
public:
    int id;
    VarContext(int id=0);
    void set(const string& name, cst_t value);
    cst_t get(const string& name);
    void remove(const string& name);
    void print(ostream& os);
};

ostream& operator<<(ostream& os, VarContext& c);

#endif
