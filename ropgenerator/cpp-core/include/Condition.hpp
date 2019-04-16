/*                      ROPGenerator - Conditions 
  
 * Different kinds of conditions are supported by ROPGenerator:
 *  - Logical constants (true, false)
 *  - Arithmetic comparisons ( <, <=, ==, !=)
 *  - Logical operations ( &&, ||, ~ )
 *  - Memory access (valid read/write operations)
  
 * Each kind of condition has their own class, which inherits from the 
 * parent class 'Cond'. However to facilitate memory managment, we prefer
 * to manipulate shared pointers to expressions, aliased as 'CondPtr'. 
  
 * But for optimisation purposes, we will not use CondPtr directly but we will
 * wrap them in 'CondObject' instances. CondObject is a class that basically
 * stores an CondPtr and implements the simplification routines used to 
 * simplify the condition it stores. 
  
 * Again, for memory managment reasons, CondObject will be manipulated as 
 * shared pointer, aliased as 'CondObjectPtr'. CondObjectPtr should be 
 * the only class used to create and manipulate conditions (not CondObject, 
 * CondPtr, or Cond). 

 * You can use NewCondTrue(), NewCondPointer(), ... functions in order to create 
 * new CondObjectPtr instances in a convenient way. 
  
 * You can use the standards ==, <=, ... operators on ExprObjectPtr instances to 
 * create new arithmetic conditions.
 
 * You can use the standards &&, ||, ... operators on CondObjectPtr instances to
 * create new logical conditions. 

 */ 


#ifndef CONDITION_H
#define CONDITION_H

#include <memory>
#include "Exception.hpp"

using namespace std; 

/* Class definition for compilation */ 
class CondObject;
using CondObjectPtr = shared_ptr<CondObject>;

// Types of conditions
enum CondType{COND_TRUE, COND_FALSE, COND_EQ, COND_NEQ, COND_LT, COND_LE, 
              COND_AND, COND_OR, COND_NOT, COND_VALID_READ, COND_VALID_WRITE, 
              COND_THUMB_MODE, COND_UNKNOWN};

// Useful functions
CondType invert_cond_type(CondType c);
bool is_compare_cond(CondType c);
bool is_binlogic_cond(CondType c);
bool is_unlogic_cond(CondType c);
bool is_pointer_cond(CondType c);
bool is_const_cond(CondType c);

/* Evaluation of the value of a condition
 * EVAL_TRUE means that the condition is ALWAYS true 
 * EVAL_FALSE means that it is ALWAYS false
 * EVAL_UNKNOWN means that well... we don't know
 */ 
enum CondEval{EVAL_TRUE, EVAL_FALSE, EVAL_UNKNOWN};


// Condition base class 
#include "Expression.hpp"
class Cond{
    protected:
        CondType _type;  
    public:
        Cond(CondType t);
        CondType type();
        virtual CondEval eval();
        bool is_true(); 
        // Modifiers 
        virtual shared_ptr<Cond> invert(){throw_exception("Method invert() should have been overwritten");};
        // Misc
        virtual void print(ostream& os);
        // From child classes to avoid casting in the code 
        // From CondCompare
        virtual ExprObjectPtr left_exprobject_ptr(){throw_exception("Wrong class to call this method");}
        virtual ExprObjectPtr right_exprobject_ptr(){throw_exception("Wrong class to call this method");}
        virtual ExprPtr left_expr_ptr(){throw_exception("Wrong class to call this method");}
        virtual ExprPtr right_expr_ptr(){throw_exception("Wrong class to call this method");}
        // From CondBinLogic
        virtual CondObjectPtr left_condobject_ptr(){throw_exception("Wrong class to call this method");}
        virtual CondObjectPtr right_condobject_ptr(){throw_exception("Wrong class to call this method");}
        virtual shared_ptr<Cond> left_cond_ptr(){throw_exception("Wrong class to call this method");}
        virtual shared_ptr<Cond> right_cond_ptr(){throw_exception("Wrong class to call this method");}
        // From CondPointer
        virtual ExprObjectPtr arg_exprobject_ptr(){throw_exception("Wrong class to call this method");}
        virtual ExprPtr arg_expr_ptr(){throw_exception("Wrong class to call this method");}
        // From CondUnLogic
        virtual CondObjectPtr arg_condobject_ptr(){throw_exception("Wrong class to call this method");}
        virtual shared_ptr<Cond> arg_cond_ptr(){throw_exception("Wrong class to call this method");}
};

using CondPtr = shared_ptr<Cond>;

////////////////////////////////////////////////////////////////////////
// CondObject (wrapper around Cond)
class CondObject{
    protected:
        CondPtr _cond_ptr; 
        bool _simplified; // If the condition has been simplified
        bool _filtered; 
    public:
        // Constructors
        CondObject(CondPtr p);
        // Accessors, modifiers
        CondPtr cond_ptr();
        Cond cond();
        // Misc
        void simplify();
        bool filter(); 
        pair<CondObjectPtr,CondObjectPtr> tweak();
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

class CondCPUMode: public Cond{
    public:
        CondCPUMode(CondType t);
        void print(ostream& os);
};

class CondUnknown: public Cond{
    public:
        CondUnknown();
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
CondObjectPtr NewCondFalse();
CondObjectPtr NewCondPointer(CondType t, ExprObjectPtr a);
CondObjectPtr NewCondCompare(CondType t, ExprObjectPtr l, ExprObjectPtr r);
CondObjectPtr NewCondBinLogic(CondType t, CondObjectPtr l, CondObjectPtr r);
CondObjectPtr NewCondUnLogic(CondType t, CondObjectPtr a);
CondObjectPtr NewCondCPUMode(CondType t);
CondObjectPtr NewCondUnknown();
// Create new ExprPtr for COND_UNKNOWN, ONLY INTERNAL USAGE
CondPtr special_NewCondPtrUnknown(); 
#endif 
