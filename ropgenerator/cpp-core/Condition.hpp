#ifndef CONDITION_H
#define CONDITION_H

#include "Expression.hpp"

using namespace std; 

// Types of conditions
enum CondType{COND_TRUE, COND_FALSE, COND_EQ, COND_NEQ, COND_LT, COND_LE, 
              COND_AND, COND_OR, COND_NOT, COND_VALID_READ, COND_VALID_WRITE};
              
CondType invert_cond_type(CondType c);
bool is_compare_cond(CondType c);
bool is_binlogic_cond(CondType c);
bool is_unlogic_cond(CondType c);
bool is_pointer_cond(CondType c);
bool is_const_cond(CondType c);

// Evaluation of the value of a condition 
enum CondEval{EVAL_TRUE, EVAL_FALSE, EVAL_UNKNOWN};

class CondObject;
using CondObjectPtr = shared_ptr<CondObject>;
// Condition base class 
class Cond{
    protected:
        CondType _type;  
    public:
        Cond(CondType t);
        CondType type();
        virtual CondEval eval();
        // Modifiers 
        virtual shared_ptr<Cond> invert(){throw "Method invert() should have been overwritten";};
        // Misc
        virtual void print(ostream& os);
        // From child classes to avoid casting in the code 
        // From CondCompare
        virtual ExprObjectPtr left_exprobject_ptr(){throw "Wrong class to call this method";}
        virtual ExprObjectPtr right_exprobject_ptr(){throw "Wrong class to call this method";}
        virtual ExprPtr left_expr_ptr(){throw "Wrong class to call this method";}
        virtual ExprPtr right_expr_ptr(){throw "Wrong class to call this method";}
        // From CondBinLogic
        virtual CondObjectPtr left_condobject_ptr(){throw "Wrong class to call this method";}
        virtual CondObjectPtr right_condobject_ptr(){throw "Wrong class to call this method";}
        virtual shared_ptr<Cond> left_cond_ptr(){throw "Wrong class to call this method";}
        virtual shared_ptr<Cond> right_cond_ptr(){throw "Wrong class to call this method";}
        // From CondPointer
        virtual ExprObjectPtr arg_exprobject_ptr(){throw "Wrong class to call this method";}
        virtual ExprPtr arg_expr_ptr(){throw "Wrong class to call this method";}
        // From CondUnop
        virtual CondObjectPtr arg_condobject_ptr(){throw "Wrong class to call this method";}
        virtual shared_ptr<Cond> arg_cond_ptr(){throw "Wrong class to call this method";}
};

using CondPtr = shared_ptr<Cond>;

////////////////////////////////////////////////////////////////////////
// CondObject (wrapper around Cond)
class CondObject{
    protected:
        CondPtr _cond_ptr; 
        bool _simplified; // If the condition has been simplified 
    public:
        // Constructors 
        CondObject(CondPtr p);
        // Accessors, modifiers
        CondPtr cond_ptr();
        Cond cond();
        // Misc
        void simplify();
        
         
};
using CondObjectPtr = shared_ptr<CondObject>;


/////////////////////////////////////////////////////////////////////////
// Types of condition 
class CondConst: public Cond{
    public:
        CondConst(CondType t);
        CondPtr invert();
        // Misc 
        void print(ostream& os);
};

class CondCompare: public Cond{
    ExprObjectPtr _left, _right;
    public:
        CondCompare(CondType t, ExprObjectPtr l, ExprObjectPtr r);
        ExprObjectPtr left_exprobject_ptr();
        ExprObjectPtr right_exprobject_ptr();
        ExprPtr left_expr_ptr();
        ExprPtr right_expr_ptr();
        CondPtr invert();
        // Misc 
        void print(ostream& os);
};

class CondBinLogic: public Cond{
    CondObjectPtr _left, _right;
    public:
        CondBinLogic(CondType t, CondObjectPtr l, CondObjectPtr r);
        CondObjectPtr left_condobject_ptr();
        CondObjectPtr right_condobject_ptr();
        CondPtr left_cond_ptr();
        CondPtr right_cond_ptr();
        CondPtr invert();
        // Misc 
        void print(ostream& os);
};

class CondUnLogic: public Cond{
    CondObjectPtr _arg;
    public:
        CondUnLogic(CondType t, CondObjectPtr a);
        CondObjectPtr arg_condobject_ptr();
        CondPtr arg_cond_ptr();
        CondPtr invert();
        // Misc 
        void print(ostream& os);
};

class CondPointer: public Cond{
    ExprObjectPtr _arg;
    public:
        CondPointer(CondType t, ExprObjectPtr a);
        ExprObjectPtr arg_exprobject_ptr();
        ExprPtr arg_expr_ptr();
        CondPtr invert();
        // Misc 
        void print(ostream& os);
};

////////////////////////////////////////////////////////////////////////
// ExprObjectPtr level manipulation 
// IO
ostream& operator<< (ostream& os, CondObjectPtr p);
// Operators 
CondObjectPtr operator== (ExprObjectPtr p1, ExprObjectPtr p2);
CondObjectPtr operator!= (ExprObjectPtr p1, ExprObjectPtr p2);
CondObjectPtr operator< (ExprObjectPtr p1, ExprObjectPtr p2);
CondObjectPtr operator<= (ExprObjectPtr p1, ExprObjectPtr p2);
CondObjectPtr Valid_read (ExprObjectPtr p1);
CondObjectPtr Valid_write (ExprObjectPtr p1);
CondObjectPtr operator&& (CondObjectPtr p1, CondObjectPtr p2);
CondObjectPtr operator|| (CondObjectPtr p1, CondObjectPtr p2);
CondObjectPtr operator! (CondObjectPtr p1);

CondObjectPtr NewCondTrue();
CondObjectPtr NewCondPointer(CondType t, ExprObjectPtr a);
#endif 
