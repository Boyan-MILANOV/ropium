#ifndef CONSTRAINT_H
#define CONSTRAINT_H

#include "Exception.hpp"
#include "Expression.hpp"
#include "Condition.hpp"
#include "Gadget.hpp"
#include <vector>

using std::vector;
using std::pair; 

class FailRecord;
class SearchEnvironment; 

/* ---------------------------------------------------------------------
 *                          Constraints 
 * --------------------------------------------------------------------*/

enum SubConstraintType: int {  CONSTR_RETURN=0, CONSTR_BAD_BYTES, CONSTR_KEEP_REGS, 
                            CONSTR_VALID_READ, CONSTR_VALID_WRITE, CONSTR_MAX_SP_INC, 
                            CONSTR_MIN_SP_INC, CONSTR_THUMB_MODE,
                            COUNT_NB_CONSTR};
                            
enum ConstrEval {EVAL_VALID, EVAL_INVALID, EVAL_MAYBE};

class SubConstraint{
    SubConstraintType _type; 
    public: 
        SubConstraint(SubConstraintType t);
        SubConstraintType type();
        // Functions of child classes
        virtual SubConstraint* copy(){throw_exception("Should not be called here");}
        virtual void merge(SubConstraint* c, bool del){throw_exception("SHould not be called here");}
        virtual pair<ConstrEval,CondObjectPtr> verify(shared_ptr<Gadget> g, FailRecord* fail_record){throw_exception("SHould not be called here");}
        // From return
        virtual bool ret(){throw_exception( "Should not be called here");}
        virtual bool jmp(){throw_exception( "Should not be called here");}
        virtual bool call(){throw_exception( "Should not be called here");}
        // From keepRegs
        virtual bool get(int num){throw_exception( "Should not be called here");}
        // From ConstrBadBytes
        virtual vector<unsigned char>* bad_bytes(){throw_exception( "Should not be called here");}
        virtual bool verify_address(addr_t a, FailRecord* fail_record){throw_exception( "Should not be called here");}
        // From ValidPoitner
        virtual vector<ExprObjectPtr>* addresses(){throw_exception("Should not be called here");}
};

class ConstrReturn: public SubConstraint{
    bool _ret, _jmp, _call; 
    public: 
        ConstrReturn();
        ConstrReturn(bool r, bool j, bool c);
        bool ret(); 
        bool jmp();
        bool call();
        pair<ConstrEval,CondObjectPtr> verify(shared_ptr<Gadget> g, FailRecord* fail_record);
        virtual SubConstraint* copy();
        virtual void merge(SubConstraint* c, bool del);
};

class ConstrBadBytes: public SubConstraint{
    vector<unsigned char> _bad_bytes; 
    public:
        ConstrBadBytes();
        ConstrBadBytes(vector<unsigned char> bb);
        vector<unsigned char>* bad_bytes(); 
        bool verify_address(addr_t a, FailRecord* fail_record);
        pair<ConstrEval,CondObjectPtr> verify(shared_ptr<Gadget> g, FailRecord* fail_record);
        virtual SubConstraint* copy();
        virtual void merge(SubConstraint* c, bool del);
};

class ConstrKeepRegs: public SubConstraint{
    bool _regs[NB_REGS_MAX];
    public:
        ConstrKeepRegs();
        ConstrKeepRegs(int num);
        ConstrKeepRegs(vector<int>& k);
        bool get(int num);
        void add_reg(int num);
        void remove_reg(int num);
        pair<ConstrEval,CondObjectPtr> verify(shared_ptr<Gadget> g, FailRecord* fail_record);
        virtual SubConstraint* copy();
        virtual void merge(SubConstraint* c, bool del);
};

class ConstrValidRead: public SubConstraint{
    vector<ExprObjectPtr> _addresses;
    public:
        ConstrValidRead();
        vector<ExprObjectPtr>* addresses(); 
        void add_addr( ExprObjectPtr a);
        pair<ConstrEval,CondObjectPtr> verify(shared_ptr<Gadget> g, FailRecord* fail_record);
        virtual SubConstraint* copy();
        virtual void merge(SubConstraint* c, bool del);
};

class ConstrValidWrite: public SubConstraint{
    vector<ExprObjectPtr> _addresses;
    public:
        ConstrValidWrite();
        vector<ExprObjectPtr>* addresses(); 
        void add_addr( ExprObjectPtr a);
        pair<ConstrEval,CondObjectPtr> verify(shared_ptr<Gadget> g, FailRecord* fail_record);
        virtual SubConstraint* copy();
        virtual void merge(SubConstraint* c, bool del);
};

class ConstrMaxSpInc: public SubConstraint{
    cst_t _inc;
    public:
        ConstrMaxSpInc(cst_t i);
        cst_t inc();
        pair<ConstrEval,CondObjectPtr> verify(shared_ptr<Gadget> g, FailRecord* fail_record);
        virtual SubConstraint* copy();
};

class ConstrMinSpInc: public SubConstraint{
    cst_t _inc;
    public:
        ConstrMinSpInc(cst_t i);
        cst_t inc();
        pair<ConstrEval,CondObjectPtr> verify(shared_ptr<Gadget> g, FailRecord* fail_record);
        virtual SubConstraint* copy();
};

class ConstrThumbMode: public SubConstraint{
    public:
        ConstrThumbMode();
        pair<ConstrEval,CondObjectPtr> verify(shared_ptr<Gadget> g, FailRecord* fail_record);
        virtual SubConstraint* copy();
};

// Constraint class (collection of subconstraints)
using cstr_sig_t = uint64_t;

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
        pair<ConstrEval,CondObjectPtr> verify(shared_ptr<Gadget> g, FailRecord* fail_record=nullptr);
        bool verify_address(addr_t a, FailRecord* fail_record=nullptr);
        bool keep_reg(int num, FailRecord* fail_record=nullptr);
        Constraint* copy();
        cstr_sig_t signature(SearchEnvironment* env);
        pair<bool, addr_t> valid_padding();
        ~Constraint();
};

/* -------------------------------------------------------------------
 *        Constraint Signature
 * 
 * The modified regs are stored as the lower bits 
 * 0 to NB_REGS_MAX-1. It always applicable and missing as default of 
 * 0 (no regs are set). 
 * 
 * The return type is stored on 3 bits after modified
 * regs. From left to right (CALL,JMP,RET). It is always applicable and
 * missing has default 0b000 (all types allowed). Forbidden type is
 * set to 1 
 *  
 * The depth is stored on 8 bits after the return type. We assume that 
 * the depth will never be bigger than 8. A depth of 1 gives the signature
 * 0b00000001n a depth of 5 gives 0b00011111. I.E set as many bits to 1 as
 * the depth value. This is to keep the requirement of inclusion between 
 * weaker and stronger constraints/signatures. 
 * 
 * Requirement: sig1 included in sig2 <=> constr1 is weaker than constr2
 * 
 * ------------------------------------------------------------------*/

#define MODIFIED_REGS_BIT 0
#define MODIFIED_REGS_SIG_SIZE NB_REGS_MAX
#define RET_TYPE_BIT MODIFIED_REGS_SIG_SIZE
#define RET_TYPE_SIG_SIZE 3
#define DEPTH_BIT 40 // DEBUG (MODIFIED_REGS_SIG_SIZE + RET_TYPE_SIG_SIZE)
#define DEPTH_SIG_SIZE 8 


/* 
 * ASSERTIONS
 */ 
 
enum SubAssertionType: int {    ASSERT_REGS_EQUAL=0, ASSERT_REGS_NO_OVERLAP, ASSERT_VALID_READ, 
                                ASSERT_VALID_WRITE, ASSERT_REG_SUP_TO, ASSERT_REG_INF_TO, ASSERT_THUMB_MODE,
                                COUNT_NB_ASSERT};

class SubAssertion{
    protected:
    SubAssertionType _type; 
    public: 
        SubAssertion(SubAssertionType t);
        SubAssertionType type();
        // Functions of child classes
        virtual bool validate(CondObjectPtr c){throw_exception("Should not be called here");}
        virtual SubAssertion* copy(){throw_exception("Should not be called here");}
        virtual void merge(SubAssertion* a, bool del){throw_exception("SHould not be called here");}
        // From AssertRegsNoOverlap and AssertRegsEqual
        virtual bool get(int reg1, int reg2){throw_exception("Should not be called here");}
        virtual void add(int reg1, int reg2){throw_exception("Should not be called here");}
        // From AssertValidRead
        virtual void add(int reg){throw_exception("Should not be called here");}
        virtual bool* reg(){throw_exception("Should not be called here");}
        // From AssertRegSupTo
        virtual cst_t* limit(){throw_exception("Should not be called here");}
};

class AssertRegsEqual: public SubAssertion{
    public: 
        bool _regs[NB_REGS_MAX][NB_REGS_MAX];
    public:
        AssertRegsEqual();
        AssertRegsEqual( bool array[NB_REGS_MAX][NB_REGS_MAX]);
        void add(int reg1, int reg2);
        virtual bool get(int reg1, int reg2);
        bool validate( CondObjectPtr c);
        virtual SubAssertion* copy(); 
        virtual void merge(SubAssertion* a, bool del); 
};

class AssertRegsNoOverlap: public SubAssertion{
    public: 
        bool _regs[NB_REGS_MAX][NB_REGS_MAX];
    public: 
        AssertRegsNoOverlap();
        AssertRegsNoOverlap(int reg1, int reg2);
        AssertRegsNoOverlap( bool array[NB_REGS_MAX][NB_REGS_MAX]);
        virtual bool get(int reg1, int reg2);
        void add(int reg1, int reg2);
        bool validate( CondObjectPtr c);
        virtual SubAssertion* copy();
        virtual void merge(SubAssertion* a, bool del); 
};

class AssertValidRead: public SubAssertion{
    public: 
        bool _regs[NB_REGS_MAX];
    public: 
        AssertValidRead();
        AssertValidRead(int num);
        AssertValidRead(bool* array);
        virtual bool* reg(); 
        void add(int reg); 
        bool validate( CondObjectPtr c);
        virtual SubAssertion* copy();
        virtual void merge(SubAssertion* a, bool del); 
};

class AssertValidWrite: public SubAssertion{
    public:
        bool _regs[NB_REGS_MAX];
    public: 
        AssertValidWrite();
        AssertValidWrite(int num);
        AssertValidWrite(bool* array);
        virtual bool* reg();
        void add(int reg); 
        bool validate( CondObjectPtr c);
        virtual SubAssertion* copy();
        virtual void merge(SubAssertion* a, bool del); 
};

class AssertRegSupTo: public SubAssertion{
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

class AssertRegInfTo: public SubAssertion{
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

class AssertThumbMode: public SubAssertion{
    public:
        AssertThumbMode();
        bool validate(CondObjectPtr c);
        virtual SubAssertion* copy();
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
