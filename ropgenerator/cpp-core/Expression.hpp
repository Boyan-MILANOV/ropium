#ifndef EXPRESSION_H 
#define EXPRESSION_H

#include <iostream>
#include <memory>

#define NB_REGS_MAX 32

using namespace std; 

// Types of expressions 
enum ExprType {EXPR_CST, EXPR_REG, EXPR_MEM, EXPR_UNOP, EXPR_BINOP, EXPR_EXTRACT, EXPR_CONCAT, EXPR_UNKNOWN}; 

// Operators between Expressions 
enum Unop {OP_NEG};
enum Binop {OP_ADD, OP_SUB, OP_MUL, OP_DIV, OP_AND, OP_OR, OP_XOR, OP_MOD, OP_BSH }; 

// Type used to store the values for ExprCst
using cst_t= long long;  

class ExprObject;
using ExprObjectPtr = shared_ptr<ExprObject>; 
class ExprAsPolynom; 
// Abstract base class for Expressions 
class Expr{
    protected:
        const ExprType _type; // Type of the expression 
        int _size; // Size in bits
        ExprAsPolynom* _polynom;
        bool _computed_polynom;
    public:
        // Constructors
        Expr(ExprType t);
        Expr(ExprType t, int s);
        // Accessors and modifiers 
        int size();
        int set_size(int s);
        ExprType type(); 
        // Misc 
        virtual void print(ostream& os);
        virtual ExprAsPolynom* polynom();
        void set_polynom(ExprAsPolynom* p);
        virtual void compute_polynom();
        virtual bool equal(shared_ptr<Expr> other){throw "Wrong class to call this method";} 
        virtual bool lthan(shared_ptr<Expr> other){throw "Wrong class to call this method";} 
        virtual tuple<bool,int,cst_t> is_reg_increment();
        virtual tuple<bool, cst_t> is_reg_increment(int num);
        // Destructor
        ~Expr();
        
        // Virtual functions of all child classes to avoid heavy casting when manipulating expressions
        // From ExprCst
        virtual cst_t value(){throw "Wrong class to call this method";}
        // From ExprReg
        virtual int num(){throw "Wrong class to call this method";}
        // From ExprMem
        virtual shared_ptr<ExprObject> addr_object_ptr(){throw "Wrong class to call this method";}
        virtual shared_ptr<Expr> addr_expr_ptr(){throw "Wrong class to call this method";}
        // From ExprBinop
        virtual ExprObjectPtr left_object_ptr(){throw "Wrong class to call this method";}
        virtual ExprObjectPtr right_object_ptr(){throw "Wrong class to call this method";}
        virtual shared_ptr<Expr> left_expr_ptr(){throw "Wrong class to call this method";}
        virtual shared_ptr<Expr> right_expr_ptr(){throw "Wrong class to call this method";}
        virtual Binop binop(){throw "Wrong class to call this method";}; 
        virtual Unop unop(){throw "Wrong class to call this method";}
        virtual void exchange_args(){throw "Wrong class to call this method";} 
        // From ExprExtract
        virtual int low(){throw "Wrong class to call this method";}
        virtual int high(){throw "Wrong class to call this method";}
        virtual shared_ptr<Expr> arg_expr_ptr(){throw "Wrong class to call this method";}
        virtual shared_ptr<ExprObject> arg_object_ptr(){throw "Wrong class to call this method";}
        // From ExprConcat
        virtual shared_ptr<ExprObject> upper_object_ptr(){throw "Wrong class to call this method";}
        virtual shared_ptr<ExprObject> lower_object_ptr(){throw "Wrong class to call this method";}
        virtual shared_ptr<Expr> upper_expr_ptr(){throw "Wrong class to call this method";}
        virtual shared_ptr<Expr> lower_expr_ptr(){throw "Wrong class to call this method";}
};

// Shared pointer to expressions 
using ExprPtr = shared_ptr<Expr>;

////////////////////////////////////////////////////////////////////////
// ExprObject (wrapper around Expr)
class ExprObject{
    protected:
        ExprPtr _expr_ptr; 
        bool _simplified; // If the expression has been simplified 
    public:
        // Constructors 
        ExprObject(ExprPtr p);
        // Accessors, modifiers
        ExprPtr expr_ptr();
        Expr expr();
        // Misc
        void simplify(); // Should always compute polynom
        bool equal(ExprObjectPtr other);
         
};
// ExprObjectPtr level manipulation 
// IO
ostream& operator<< (ostream& os, ExprObjectPtr p);
// Operators 
ExprObjectPtr operator+ (ExprObjectPtr p1, ExprObjectPtr p2);
ExprObjectPtr operator- (ExprObjectPtr p1, ExprObjectPtr p2);
ExprObjectPtr operator* (ExprObjectPtr p1, ExprObjectPtr p2);
ExprObjectPtr operator/ (ExprObjectPtr p1, ExprObjectPtr p2);
ExprObjectPtr operator& (ExprObjectPtr p1, ExprObjectPtr p2);
ExprObjectPtr operator| (ExprObjectPtr p1, ExprObjectPtr p2);
ExprObjectPtr operator^ (ExprObjectPtr p1, ExprObjectPtr p2);
ExprObjectPtr operator% (ExprObjectPtr p1, ExprObjectPtr p2);
ExprObjectPtr Bsh(ExprObjectPtr p1,  ExprObjectPtr p2);
ExprObjectPtr Extract (ExprObjectPtr p1, int high, int low);
ExprObjectPtr Concat (ExprObjectPtr p1, ExprObjectPtr p2); 
ExprObjectPtr operator~ (ExprObjectPtr p1);

// Wrappers
ExprObjectPtr NewExprCst(cst_t value, int size);
ExprObjectPtr NewExprMem(ExprObjectPtr addr, int s);


////////////////////////////////////////////////////////////////////////
//// Different kinds of expressions 
// Constant Expression 
class ExprCst: public Expr{
    cst_t _value; // The value, signed 
    public:
        // Constructor 
        ExprCst(cst_t v, int s);
        // Accessors and modifiers 
        cst_t value();
        // Misc 
        void print(ostream& os);
        void compute_polynom();
        bool equal(shared_ptr<Expr> other);
        bool lthan(ExprPtr other);
        
}; 

// Register Expression 
class ExprReg: public Expr{
    int _num;
    public:
        // Constructor 
        ExprReg(int n, int s);
        // Accessor
        int num(); 
        // Misc 
        void compute_polynom();
        void print(ostream& os);
        bool equal(shared_ptr<Expr> other);
        bool lthan(ExprPtr other);
        virtual tuple<bool,int,cst_t> is_reg_increment();
        virtual tuple<bool, cst_t> is_reg_increment(int num);
}; 

// Memory Expression 
class ExprMem: public Expr{
    ExprObjectPtr _addr;
    public: 
        // Constructor 
        ExprMem( ExprObjectPtr a, int s);
        // Accessors
        ExprObjectPtr addr_object_ptr();
        ExprPtr addr_expr_ptr();
        // Misc 
        void print(ostream& os);
        bool equal(shared_ptr<Expr> other);
        bool lthan(ExprPtr other);
        
}; 

// Binary Operation Expression 
class ExprBinop: public Expr{
    Binop _op; 
    ExprObjectPtr _left, _right;
    public: 
        // Constructor 
        ExprBinop(Binop o, ExprObjectPtr l, ExprObjectPtr r);
        // Accessors and modifiers 
        ExprObjectPtr left_object_ptr();
        ExprObjectPtr right_object_ptr();
        ExprPtr left_expr_ptr();
        ExprPtr right_expr_ptr();
        Binop binop();
        // Misc 
        void print(ostream& os);
        void exchange_args();
        void compute_polynom();
        bool equal(shared_ptr<Expr> other);
        bool lthan(ExprPtr other);
        virtual tuple<bool,int,cst_t> is_reg_increment();
        virtual tuple<bool, cst_t> is_reg_increment(int num);
};

// Unary Operation Expression 
class ExprUnop: public Expr{
    Unop _op; 
    ExprObjectPtr _arg; 
    public: 
        // Constructor 
        ExprUnop(Unop o, ExprObjectPtr a);
        // Accessors 
        ExprObjectPtr arg_object_ptr();
        ExprPtr arg_expr_ptr();
        Unop unop();
        // Misc 
        void print(ostream& os);
        bool equal(shared_ptr<Expr> other);
        bool lthan(ExprPtr other);
        
}; 

// Extraction Expression 
class ExprExtract: public Expr{
    ExprObjectPtr _arg; 
    int _low, _high; 
    public: 
        // Constructor 
        ExprExtract( ExprObjectPtr a, int high, int low);
        // Accessors and modifiers
        int low();
        int high();
        ExprPtr arg_expr_ptr();
        ExprObjectPtr arg_object_ptr();
        // Misc 
        void print(ostream& os);
        bool equal(shared_ptr<Expr> other);
        bool lthan(ExprPtr other);
}; 

// Concatenate Expression
class ExprConcat: public Expr{
    ExprObjectPtr _upper, _lower; 
    public: 
        // Constructor
        ExprConcat( ExprObjectPtr u, ExprObjectPtr l );
        // Accessors and modifiers 
        ExprObjectPtr upper_object_ptr();
        ExprObjectPtr lower_object_ptr();
        ExprPtr upper_expr_ptr();
        ExprPtr lower_expr_ptr();
        // Misc 
        void print(ostream& os);
        bool equal(shared_ptr<Expr> other);
        bool lthan(ExprPtr other);
};

class ExprUnknown: public Expr{
    public:
        ExprUnknown();
}; 

#endif 
