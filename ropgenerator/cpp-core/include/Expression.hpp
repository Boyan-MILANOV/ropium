/*                      ROPGenerator - Expressions
  
 * Different kinds of expressions are supported by ROPGenerator:
 *  - Constants
 *  - Registers (as R1, R2, ... ). The max number of supported registers
 *    is defined by NB_REGS_MAX
 *  - Memory read (as mem[<expression>]) 
 *  - Unary and binary operations (supported operations are listed in 
 *    Unop and Binop enums)
 *  - Extract (extract some bits from another expression)
 *  - Concatenate (concatenate two expressions)
 *  - Unknown (represents all expressions not supported by ROPGenerator)
  
 * Each kind of expression has their own class, which inherits from the 
 * parent class 'Expr'. However to facilitate memory managment, we prefer
 * to manipulate shared pointers to expressions, aliased as 'ExprPtr'. 
  
 * But for optimisation purposes, we will not use ExprPtr directly but we will
 * wrap them in 'ExprObject' instances. ExprObject is a class that basically
 * stores an ExprPtr and implements the simplification routines used to 
 * simplify the expression it stores. 
  
 * Again, for memory managment reasons, ExprObject will be manipulated as 
 * shared poitners, aliased as 'ExprObjectPtr'. ExprObjectPtr should be 
 * the only class used to create and manipulate expressions (not ExprObject, 
 * ExprPtr, or Expr). 

 * You can use NewExprCst(), NewExprMem(), ... functions in order to create 
 * new ExprObjectPtr instances in a convenient way. 
 * You can use standard operators (+,*,/,-,~,^, .... ) to combine expressions
 * together and create new expressions. 

 */ 

#ifndef EXPRESSION_H 
#define EXPRESSION_H

#include <iostream>
#include <memory>

/* Maximum number of registers */ 
#define NB_REGS_MAX 32

using namespace std; 

/* Types of expressions */  
enum ExprType {EXPR_CST=0, EXPR_REG, EXPR_MEM, EXPR_UNOP, EXPR_BINOP, EXPR_EXTRACT, EXPR_CONCAT, EXPR_UNKNOWN}; 

/* Unary and binary operators between expressions */  
enum Unop {OP_NEG, COUNT_NB_UNOP};
enum Binop {OP_ADD, OP_SUB, OP_MUL, OP_DIV, OP_AND, OP_OR, OP_XOR, OP_MOD, OP_BSH, COUNT_NB_BINOP }; 

/* Type used to store the values for ExprCst */ 
using cst_t= long long;  

/* Declaration of some classes for compilation */ 
class ExprObject;
using ExprObjectPtr = shared_ptr<ExprObject>; 
class ExprAsPolynom; 

/*                          - Expr -  
 
 * Expr is the parent class for all expression classes. It stores the type
 * of the expression (_type) and its size in bits (_size). Also there is a 
 * pointer available if the expression has an associated polyom (_polynom)
 * and the _computed_polynom variable indicateds if we already tried to 
 * calculate this associated polynom (it's a time consuming operation and we 
 * don't want to do it several times)  
  
 */ 
class Expr{
    protected:
        const ExprType _type; // Type of the expression 
        int _size; // Size in bits
        ExprAsPolynom* _polynom; // Representation of the expression as a polynom 
        bool _computed_polynom; 
    public:
        bool _is_polynom; // True iff the expression is a polynom
    public:
        // Constructors
        Expr(ExprType t, bool i);
        Expr(ExprType t, int s, bool i);
        // Accessors and modifiers 
        int size();
        int set_size(int s);
        ExprType type(); 
        // IO 
        virtual void print(ostream& os);
        // Polynom manipulation 
        virtual ExprAsPolynom* polynom();
        void set_polynom(ExprAsPolynom* p);
        virtual void compute_polynom();
        bool computed_polynom();
        bool is_polynom();
        // Structural equality (NOT semantic equality)
        virtual bool equal(shared_ptr<Expr> other){throw "Wrong class to call this method";} 
        // Expression comparison to sort/canonize them (NOT semantic comparison)
        virtual bool lthan(shared_ptr<Expr> other){throw "Wrong class to call this method";} 
        // Check if the expression is REG +- CST 
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

/*                          - ExprObject - 
 * 
 * Wrapper around ExprPtr. Basically it stores an ExprPtr as _expr_ptr,
 * and it has a simplify() method that will replace _expr_ptr by another
 * ExprPtr if the expression can be simplified. 
 * 
 */ 

class ExprObject{
    protected:
        ExprPtr _expr_ptr; 
        bool _simplified; // If the expression has been simplified
        bool _filtered;  
    public:
        // Constructors 
        ExprObject(ExprPtr p);
        // Accessors, modifiers
        ExprPtr expr_ptr();
        Expr expr();
        // Misc
        void simplify();
        bool filter();
        bool equal(ExprObjectPtr other);
         
};
/* ExprObjectPtr level manipulation */ 
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
// Create new instances 
ExprObjectPtr NewExprCst(cst_t value, int size);
ExprObjectPtr NewExprMem(ExprObjectPtr addr, int s);
ExprObjectPtr NewExprUnknown();
// Create new ExprPtr for ExprUnknown, ONLY INTERNAL USAGE
ExprPtr special_NewExprPtrUnknown(); 

/*                  - Expr* classes                     */ 
// Constant Expression 
class ExprCst: public Expr{
    cst_t _value;
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
    int _num; // Registers are identified by their number (R1, R2, ...)
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
    int _high, _low;
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

// Unknown/Unsupported Expression 
class ExprUnknown: public Expr{
    public:
        ExprUnknown();
        void print(ostream& os);
}; 



#endif 
