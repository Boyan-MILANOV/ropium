#ifndef EXPRESSION_H 
#define EXPRESSION_H

#include <iostream>
#include <memory>

#define PTRCAST(t,p) static_pointer_cast<t>(p)
#define NB_REGS_MAX 64

using namespace std; 

// Types of expressions 
enum ExprType {EXPR_CST, EXPR_REG, EXPR_MEM, EXPR_UNOP, EXPR_BINOP, EXPR_CONCAT, EXPR_EXTRACT, EXPR_UNKNOWN}; 

// Operators between Expressions 
enum Unop {OP_NEG};
enum Binop {OP_ADD, OP_SUB, OP_MUL, OP_DIV, OP_AND, OP_OR, OP_XOR }; 

// Type used to store the values for ExprCst
using cst_t= unsigned long long;  

// Abstract class for Expressions 
class ExprObject;
using ExprObjectPtr = shared_ptr<ExprObject>; 
class ExprAsPolynom; 

class Expr{
    protected:
        const ExprType _type;
        int _size;
        bool _simplified;
        ExprAsPolynom* _polynom;
        bool _computed_polynom;
    public:
        // Constructors
        Expr(ExprType t);
        Expr(ExprType t, int s);
        Expr(ExprType t, int s, bool simp); 
        // Accessors and modifiers 
        int size();
        int set_size(int s);
        ExprType type(); 
        virtual ExprAsPolynom* polynom();
        virtual 
        void set_polynom(ExprAsPolynom* p);
        void set_simplified(bool v);
        // Misc 
        virtual void print(ostream& os);
        virtual shared_ptr<Expr> get_shared_ptr();
        virtual void compute_polynom();
        // Destructor
        ~Expr();
        
        // Virtual functions of all child classes to avoid heavy casting when manipulating expressions
        // From ExprCst
        virtual cst_t value(){throw "Wrong class to call this method";}; 
        // From ExprBinop
        virtual ExprObjectPtr left_object_ptr(){throw "Wrong class to call this method";}; 
        virtual ExprObjectPtr right_object_ptr(){throw "Wrong class to call this method";}; 
        virtual shared_ptr<Expr> left_expr_ptr(){throw "Wrong class to call this method";}; 
        virtual shared_ptr<Expr> right_expr_ptr(){throw "Wrong class to call this method";}; 
        virtual Binop binop(){throw "Wrong class to call this method";}; 
        virtual void exchange_args(){throw "Wrong class to call this method";}; 
};

// Shared pointer to expressions 
using ExprPtr = shared_ptr<Expr>;

////////////////////////////////////////////////////////////////////////
// ExprObject 
class ExprAsPolynom; 

class ExprObject{
    protected:
        ExprPtr _expr_ptr; 
    public:
        // Constructors 
        ExprObject(ExprPtr p);
        // Accessors, modifiers
        ExprPtr expr_ptr();
        Expr expr();
        void set_expr_ptr(ExprPtr p);
        // Misc
        void simplify(); // Should always compute polynom
         
};
// Shared pointer level manipulation 
// IO
ostream& operator<< (ostream& os, ExprObjectPtr p);
// Combine expressions 
ExprObjectPtr operator+ (ExprObjectPtr p1, ExprObjectPtr p2);
ExprObjectPtr operator- (ExprObjectPtr p1, ExprObjectPtr p2);
ExprObjectPtr operator* (ExprObjectPtr p1, ExprObjectPtr p2);
ExprObjectPtr operator/ (ExprObjectPtr p1, ExprObjectPtr p2);
ExprObjectPtr operator& (ExprObjectPtr p1, ExprObjectPtr p2);
ExprObjectPtr operator| (ExprObjectPtr p1, ExprObjectPtr p2);
ExprObjectPtr operator^ (ExprObjectPtr p1, ExprObjectPtr p2);
ExprObjectPtr Extract (ExprObjectPtr p1, int high, int low);
ExprObjectPtr operator~ (ExprObjectPtr p1);
////////////////////////////////////////////////////////////////////////


// Constant Expression 
class ExprCst: public Expr, public std::enable_shared_from_this<ExprCst>{
    cst_t _value; // The value, signed 
    public:
        // Constructor 
        ExprCst(cst_t v, int s);
        // Accessors and modifiers 
        cst_t value();
        void compute_polynom();
        // Misc 
        void print(ostream& os);
        ExprPtr get_shared_ptr();
        
}; 

// Register Expression 
class ExprReg: public Expr, public std::enable_shared_from_this<ExprReg>{
    int _num;
    public:
        // Constructor 
        ExprReg(int n, int s);
        // Misc 
        void compute_polynom();
        void print(ostream& os);
        ExprPtr get_shared_ptr();

}; 

// Memory Expression 
class ExprMem: public Expr, public std::enable_shared_from_this<ExprMem>{
    ExprObjectPtr addr;
    public: 
        // Constructor 
        ExprMem( ExprObjectPtr a, int s);
        // Misc 
        void print(ostream& os);
        ExprPtr get_shared_ptr();
}; 

// Binary Operation Expression 
class ExprBinop: public Expr , public std::enable_shared_from_this<ExprBinop>{
    Binop op; 
    ExprObjectPtr left, right;
    public: 
        // Constructor 
        ExprBinop(Binop o, ExprObjectPtr l, ExprObjectPtr r);
        // Misc 
        void print(ostream& os);
        ExprObjectPtr left_object_ptr();
        ExprObjectPtr right_object_ptr();
        ExprPtr left_expr_ptr();
        ExprPtr right_expr_ptr();
        Binop binop();
        void exchange_args();
        ExprPtr get_shared_ptr();
};

// Unary Operation Expression 
class ExprUnop: public Expr, public std::enable_shared_from_this<ExprUnop>{
    Unop op; 
    ExprObjectPtr arg; 
    public: 
        // Constructor 
        ExprUnop(Unop o, ExprObjectPtr a);
        // Misc 
        void print(ostream& os);
        ExprPtr get_shared_ptr();
}; 

// Extraction Expression 
class ExprExtract: public Expr, public std::enable_shared_from_this<ExprExtract>{
    ExprObjectPtr arg; 
    int low, high; 
    public: 
        // Constructor 
        ExprExtract( ExprObjectPtr a, int high, int low);
        // Misc 
        void print(ostream& os);
        ExprPtr get_shared_ptr();
}; 

////////////////////////////////////////////////////////////////////////
// Polynom representation for simplifications :) 
#define POLYNOM_MAXLEN 150
class ExprAsPolynom{
    int* _polynom; //polynom[i] = reg i , last element is the constant
    int _len; 
    public: 
        // Constructor 
        ExprAsPolynom(int l);
        // Accessors 
        int len();
        int * polynom();
        // Operations
        void set(int index, int value);
        ExprAsPolynom* merge_op(ExprAsPolynom *other, Binop op);
        ExprAsPolynom* mul_all(int factor);
        ExprPtr to_expr(int expr_size);
        // Destructor 
        ~ExprAsPolynom();
};

#endif 
