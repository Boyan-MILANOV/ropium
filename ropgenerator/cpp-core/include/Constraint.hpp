#ifndef CONSTRAINT_H
#define CONSTRAINT_H

#include "Expression.hpp"
#include "Condition.hpp"
#include "Gadget.hpp"
#include <vector>

using std::vector;
using std::pair; 

enum SubConstraintType: int {  CONSTR_RETURN=0, CONSTR_BAD_BYTES, CONSTR_KEEP_REGS, 
                            CONSTR_VALID_READ, CONSTR_VALID_WRITE, CONSTR_SP_INC, 
                            COUNT_NB_CONSTR};
                            
enum ConstrEval {EVAL_VALID, EVAL_INVALID, EVAL_MAYBE};

class SubConstraint{
    SubConstraintType _type; 
    public: 
        SubConstraint(SubConstraintType t);
        SubConstraintType type();
        // Functions of child classes
        virtual SubConstraint* copy(){throw "Should not be called here";}
        virtual void merge(SubConstraint* c, bool del){throw "SHould not be called here";}
        // From ConstrBadBytes
        vector<unsigned char>* bad_bytes(){throw "Should not be called here";}
        // From ValidPoitner
        vector<ExprObjectPtr>* addresses(){throw "Should not be called here";}
};

class ConstrReturn: public SubConstraint{
    bool _ret, _jmp, _call; 
    public: 
        ConstrReturn(bool r, bool j, bool c);
        bool ret(); 
        bool jmp();
        bool call();
        pair<ConstrEval,CondObjectPtr> verify(Gadget* g);
        virtual SubConstraint* copy();
        virtual void merge(SubConstraint* c, bool del);
};

class ConstrBadBytes: public SubConstraint{
    vector<unsigned char> _bad_bytes; 
    public:
        ConstrBadBytes();
        ConstrBadBytes(vector<unsigned char> bb);
        vector<unsigned char>* bad_bytes(); 
        bool verify_address(addr_t a);
        pair<ConstrEval,CondObjectPtr> verify(Gadget* g);
        virtual SubConstraint* copy();
        virtual void merge(SubConstraint* c, bool del);
};

class ConstrKeepRegs: public SubConstraint{
    bool _regs[NB_REGS_MAX];
    public:
        ConstrKeepRegs();
        bool get(int num);
        void add_reg(int num);
        void remove_reg(int num);
        pair<ConstrEval,CondObjectPtr> verify(Gadget* g);
        virtual SubConstraint* copy();
        virtual void merge(SubConstraint* c, bool del);
};

class ConstrValidRead: public SubConstraint{
    vector<ExprObjectPtr> _addresses;
    public:
        ConstrValidRead();
        vector<ExprObjectPtr>* addresses(); 
        void add_addr( ExprObjectPtr a);
        pair<ConstrEval,CondObjectPtr> verify(Gadget* g);
        virtual SubConstraint* copy();
        virtual void merge(SubConstraint* c, bool del);
};

class ConstrValidWrite: public SubConstraint{
    vector<ExprObjectPtr> _addresses;
    public:
        ConstrValidWrite();
        vector<ExprObjectPtr>* addresses(); 
        void add_addr( ExprObjectPtr a);
        pair<ConstrEval,CondObjectPtr> verify(Gadget* g);
        virtual SubConstraint* copy();
        virtual void merge(SubConstraint* c, bool del);
};

class ConstrSpInc: public SubConstraint{
    cst_t _inc;
    public:
        ConstrSpInc(cst_t i);
        pair<ConstrEval,CondObjectPtr> verify(Gadget* g);
        virtual SubConstraint* copy();
};

// Constraint class (collection of subconstraints)
class Constraint{
    SubConstraint* _constr[COUNT_NB_CONSTR];
    public:
        Constraint();
        // Accessors 
        SubConstraint* get(SubConstraintType t);
        // Modifiers
        void add(SubConstraint* c, bool del);
        void update(SubConstraint* c);
        void remove(SubConstraintType t);
        pair<ConstrEval,CondObjectPtr> verify(Gadget* g);
        Constraint* copy(); 
        ~Constraint();
};

/* 
 * ASSERTIONS
 */ 
 
enum SubAssertionType: int {    ASSERT_REGS_EQUAL=0, ASSERT_REGS_NO_OVERLAP, ASSERT_VALID_READ, 
                                ASSERT_VALID_WRITE, ASSERT_REG_SUP_TO, ASSERT_REG_INF_TO, 
                                COUNT_NB_ASSERT};

class SubAssertion{
    protected:
    SubAssertionType _type; 
    public: 
        SubAssertion(SubAssertionType t);
        SubAssertionType type();
        // Functions of child classes
        virtual bool validate(CondObjectPtr c){throw "Should not be called here";}
        virtual SubAssertion* copy(){throw "Should not be called here";}
        virtual void merge(SubAssertion* a, bool del){throw "SHould not be called here";}
        // From AssertRegsEqual
        virtual void add(int reg1, int reg2){throw "Should not be called here";}
        virtual bool** regs(){throw "Should not be called here";}
        // From AssertValidRead
        virtual void add(int reg){throw "Should not be called here";}
        virtual bool* reg(){throw "Should not be called here";}
        // From AssertRegSupTo
        virtual cst_t* limit(){throw "Should not be called here";}
};

class AssertRegsEqual: public SubAssertion{
    public: 
        bool _regs[NB_REGS_MAX][NB_REGS_MAX];
    public:
        AssertRegsEqual();
        AssertRegsEqual( bool array[NB_REGS_MAX][NB_REGS_MAX]);
        virtual bool** regs();  
        void add(int reg1, int reg2);
        bool validate( CondObjectPtr c);
        virtual SubAssertion* copy(); 
        virtual void merge(SubAssertion* a, bool del); 
};

class AssertRegsNoOverlap: SubAssertion{
    public: 
        bool _regs[NB_REGS_MAX][NB_REGS_MAX];
    public: 
        AssertRegsNoOverlap();
        AssertRegsNoOverlap( bool array[NB_REGS_MAX][NB_REGS_MAX]);
        virtual bool ** regs(); 
        void add(int reg1, int reg2);
        bool validate( CondObjectPtr c);
        virtual SubAssertion* copy();
        virtual void merge(SubAssertion* a, bool del); 
};

class AssertValidRead: SubAssertion{
    public: 
        bool _regs[NB_REGS_MAX];
    public: 
        AssertValidRead();
        AssertValidRead(bool* array);
        virtual bool* reg(); 
        void add(int reg); 
        bool validate( CondObjectPtr c);
        virtual SubAssertion* copy();
        virtual void merge(SubAssertion* a, bool del); 
};

class AssertValidWrite: SubAssertion{
    public:
        bool _regs[NB_REGS_MAX];
    public: 
        AssertValidWrite();
        AssertValidWrite(bool* array);
        virtual bool* reg();
        void add(int reg); 
        bool validate( CondObjectPtr c);
        virtual SubAssertion* copy();
        virtual void merge(SubAssertion* a, bool del); 
};

class AssertRegSupTo: SubAssertion{
    public: 
        bool _regs[NB_REGS_MAX];
        cst_t _limit[NB_REGS_MAX]; // Strict limit 
    public: 
        AssertRegSupTo(); 
        AssertRegSupTo(bool regs[NB_REGS_MAX], cst_t limit[NB_REGS_MAX]);
        virtual bool* reg();
        virtual cst_t* limit();
        void add(int reg, cst_t cst ); 
        bool validate( CondObjectPtr c);
        virtual SubAssertion* copy();
        virtual void merge(SubAssertion* a, bool del); 
};

class AssertRegInfTo: SubAssertion{
    public: 
        bool _regs[NB_REGS_MAX];
        cst_t _limit[NB_REGS_MAX]; // Strict limit 
    public: 
        AssertRegInfTo(); 
        AssertRegInfTo(bool regs[NB_REGS_MAX], cst_t limit[NB_REGS_MAX]);
        virtual bool* reg();
        virtual cst_t* limit();
        void add(int reg, cst_t cst ); 
        bool validate( CondObjectPtr c);
        virtual SubAssertion* copy();
        virtual void merge(SubAssertion* a, bool del); 
};

// Assertion class (collection of subassertions)
class Assertion{
    SubAssertion * _assert[COUNT_NB_ASSERT]; 
    public:
        Assertion();
        // Modifiers
        void add(SubAssertion* c, bool del);
        void update(SubAssertion* c);
        void remove(SubAssertionType t);
        bool validate(CondObjectPtr c);
        Assertion* copy(); 
        ~Assertion();
};

#endif
