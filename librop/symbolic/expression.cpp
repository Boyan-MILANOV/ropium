#include "expression.hpp"
#include "exception.hpp"
#include <cassert>
#include <cstring>
#include "murmur3.h"
#include <algorithm>
#include <iostream>
#include <sstream>

using std::make_shared;
using std::stringstream;

/* Expression hashes 

In order to enabe quick equality checks between expressions, each
expression has a 32-bit hash that 'uniquely' identifies it (colisions
are estimated unlikely enough to be ignored).  

The hash is not computed at expression creation. Some benchmarks seemed
to indicate that it was increasing the creation time by about 80%. For
this reason, hashes are computed dynamically when needed. 

The current implementation uses the murmur3 hash function C implementation
available on https://github.com/PeterScott/murmur3.  

Hash computation:
Several util functions named "prepare_hash_with_<type>" enable to add data
to the input buffer, and the exprhash() function computes the hash of the
buffer contents.

*/ 

#define MAXLEN_HASH_IN 1024

/* Set of functions to add a value to be hashed in the hash input buffer
 * 'hash_in' and returns the number of bytes added */ 
inline int prepare_hash_with_i64(uint8_t* hash_in, int64_t val, int index=0){
     *(int64_t*)(hash_in+index) = val;
     return index + 8; 
}

inline int prepare_hash_with_str(uint8_t* hash_in, const string& str, int index=0){
    strncpy((char*)hash_in+index, str.data(), str.length());
    return index + str.length();
}

inline int prepare_hash_with_i32(uint8_t* hash_in, int32_t val, int index=0){
    *(int32_t*)(hash_in+index) = val;
     return (index + 4); 
}

inline int prepare_hash_with_op(uint8_t* hash_in, Op op, int index=0){
    *((uint8_t*)((char*)hash_in+index)) = static_cast<uint8_t>(op);
    return index + 1; 
}
/* Hash the currently prepared buffer */ 
hash_t exprhash(void* hash_in, int len, uint32_t seed){
    unsigned char hash_out[4];
    MurmurHash3_x86_32(hash_in, len, seed, hash_out);
    return *((hash_t*)hash_out);
}

/* Implementation of expression classes */ 
// ==================================
ExprObject::ExprObject(ExprType t, exprsize_t s, bool _is_simp): type(t), size(s), _hashed(false), _hash(0), 
    _simplified_expr(nullptr), _is_simplified(_is_simp){}
bool ExprObject::is_cst(){return type == ExprType::CST;}
bool ExprObject::is_var(){return type == ExprType::VAR;}
bool ExprObject::is_mem(){return type == ExprType::MEM;}
bool ExprObject::is_unop(Op op){return false;}
bool ExprObject::is_binop(Op op){return false;}
bool ExprObject::is_extract(){return type == ExprType::EXTRACT;}
bool ExprObject::is_concat(){return type == ExprType::CONCAT;}
bool ExprObject::is_bisz(){return type == ExprType::BISZ;}
bool ExprObject::is_unknown(){return type == ExprType::UNKNOWN;}
bool ExprObject::eq(Expr other){return hash() == other->hash();}
bool ExprObject::neq(Expr other){return hash() != other->hash();}
bool ExprObject::inf(Expr e2){
    if( type != e2->type ){
        return type < e2->type;
    }else{
        switch(type){
            case ExprType::CST: return cst() < e2->cst();
            case ExprType::VAR: return name().compare(e2->name()) > 0;
            case ExprType::MEM: return args[0] < e2->args[0];
            case ExprType::UNOP:
                return( op() < e2->op() || 
                        args[0]->inf(e2->args[0]));
            case ExprType::BINOP:
                if( op() == e2->op() ){
                    if( args[0]->eq(e2->args[0]) )
                        return args[1]->inf(e2->args[1]);
                    else
                        return args[0]->inf(e2->args[0]); 
                }else
                    return op() < e2->op(); 
            case ExprType::EXTRACT:
            case ExprType::CONCAT:
                for( int i = 0; i < (this->is_extract()?3:2); i++){
                    if( args[i]->eq(e2->args[i]) )
                        continue;
                    return args[i]->inf(e2->args[i]); 
                }
                return false;
            case ExprType::BISZ:
                return args[0]->inf(e2->args[0]);
            case ExprType::UNKNOWN:
                return false;
            default:
                throw runtime_exception("ExprObject::inf() got unsupported ExprType");
        }
    }
}

// ==================================
ExprCst::ExprCst(exprsize_t s, cst_t c): ExprObject(ExprType::CST, s, true){
    _cst = cst_sign_extend(s, c);
    if( s > 64 ){
        throw expression_exception(QuickFmt() << "Cannot create constant expression of size > 64 (got "
            << std::dec << s << ")" >> QuickFmt::to_str);
    }
}
hash_t ExprCst::hash(){
    unsigned char hash_in[MAXLEN_HASH_IN]; 
    if( !_hashed ){
        _hash = exprhash(hash_in, prepare_hash_with_i64(hash_in, _cst), size);
        _hashed = true;
    }
    return _hash;
}
cst_t ExprCst::cst(){ return _cst; }
void ExprCst::print(ostream& os){os << std::showbase << cst_sign_trunc(size, _cst) << std::noshowbase;}
// ==================================
ExprVar::ExprVar(exprsize_t s, string n, int num): ExprObject(ExprType::VAR, s, true), _name(n), _num(num){
    if( s > 64 ){
        throw expression_exception(QuickFmt() << "Cannot create symbolic variables of size > 64 (got "
            << std::dec << s << ")" >> QuickFmt::to_str);
    }
    assert( n.size() <= MAXLEN_HASH_IN );
}
hash_t ExprVar::hash(){
    unsigned char hash_in[MAXLEN_HASH_IN]; 
    if( !_hashed ){
        _hash = exprhash(hash_in, prepare_hash_with_str(hash_in, _name),size); 
        _hashed = true;
    }
    return _hash;
}

bool ExprVar::is_reg(int reg){
    return _num == reg;
}
int ExprVar::reg(){ return _num;}
const string& ExprVar::name(){ return _name; } 
void ExprVar::print(ostream& os){os << _name;}
// ==================================
ExprMem::ExprMem(exprsize_t s, Expr addr): ExprObject(ExprType::MEM, s, false) {
    args.push_back(addr);
}
hash_t ExprMem::hash(){
    unsigned char hash_in[MAXLEN_HASH_IN]; 
    if( !_hashed ){
        _hash = exprhash(hash_in, prepare_hash_with_i32(hash_in, args[0]->hash()), size);
        _hashed = true;
    }
    return _hash; 
}
void ExprMem::print(ostream& os){
    os << "@" << std::dec << size << "[" << std::hex << args.at(0) << "]";
}

// ==================================
ExprUnop::ExprUnop(Op o, Expr arg): ExprObject(ExprType::UNOP, arg->size), _op(o){
    args.push_back(arg);
}
hash_t ExprUnop::hash(){
    unsigned char hash_in[MAXLEN_HASH_IN]; 
    if( !_hashed ){
        _hash = exprhash(hash_in, prepare_hash_with_i32(hash_in, args[0]->hash(), prepare_hash_with_op(hash_in, _op)), size);
        _hashed = true;
    }
    return _hash;
}
Op ExprUnop::op(){ return _op;}
void ExprUnop::print(ostream& os){
    os << op_to_str(_op) << std::hex; 
    args.at(0)->print(os);
}

bool ExprUnop::is_unop(Op op){
    if( op == Op::NONE )
        return true;
    else
        return op == _op; 
}

// ==================================
ExprBinop::ExprBinop(Op o, Expr left, Expr right): ExprObject(ExprType::BINOP, left->size), _op(o){
    if( left->size != right->size ){
        throw expression_exception(QuickFmt() << "Cannot use binary operator on expressions of different sizes (got " << left->size << " and " << right->size << ")" >> QuickFmt::to_str);
    }
    args.push_back(left);
    args.push_back(right);
}
hash_t ExprBinop::hash(){
    unsigned char hash_in[MAXLEN_HASH_IN]; 
    if( !_hashed ){
        _hash = exprhash(hash_in, prepare_hash_with_i32(hash_in, args[1]->hash(), 
                    prepare_hash_with_op(hash_in, _op,
                    prepare_hash_with_i32(hash_in, args[0]->hash()))), size);
        _hashed = true;
    }
    return _hash; 
}
Op ExprBinop::op(){ return _op;}
void ExprBinop::get_associative_args(Op o, vector<Expr>& vec){
    if( _op == o ){
        if( args[0]->is_binop() && args[0]->op() == o )
            args[0]->get_associative_args(o, vec);
        else
            vec.push_back(args[0]);
        if( args[1]->is_binop(o) )
            args[1]->get_associative_args(o, vec);
        else
            vec.push_back(args[1]);
    }
    /* No else statement
     * This function should never be called recursively when the operand
     * is not equal to the argument 'o'. The reason is that leaf expressions
     * (i.e that are not from the requested operator) cannot return shared_ptr
     * to themselves without loosing the type information. So all checks are done
     * by the enclosing binary operations */ 
}
void ExprBinop::get_left_associative_args(Op o, vector<Expr>& vec, Expr& leftmost){
    if( _op == o ){
        vec.push_back(args[1]);
        if( args[0]->is_binop(o))
            args[0]->get_left_associative_args(o, vec, leftmost );
        else
            leftmost = args[0];
    }else{
        leftmost = make_shared<ExprObject>(*this);
    }
}


void ExprBinop::print(ostream& os){
    os << "(" << std::hex;
    args.at(0)->print(os);
    os << op_to_str(_op) << std::hex;
    args.at(1)->print(os); 
    os << ")";
}

bool ExprBinop::is_binop(Op op){
    if( op == Op::NONE )
        return true;
    else
        return op == _op; 
}

// ==================================
ExprExtract::ExprExtract(Expr arg, Expr higher, Expr lower): ExprObject(ExprType::EXTRACT, 0){
    assert(higher->is_cst() && lower->is_cst() && 
    "Cannot create extract with bit parameters that are not constant expressions");
    if( (ucst_t)higher->cst() < (ucst_t)lower->cst() ){
        throw expression_exception("Can not use Extract() with higher bit smaller than lower bit");
    }
    if( (ucst_t)higher->cst() >= arg->size ){
        throw expression_exception(QuickFmt() << "Can not extract bit " << higher->cst() << " from expression of size " << arg->size >> QuickFmt::to_str );
    }
    args.push_back(arg);
    args.push_back(higher);
    args.push_back(lower);
    size = (ucst_t)higher->cst() - (ucst_t)lower->cst() + 1;
}
hash_t ExprExtract::hash(){
    unsigned char hash_in[MAXLEN_HASH_IN];
    if( !_hashed ){
        _hash = exprhash(hash_in, prepare_hash_with_i32(hash_in, args[2]->hash(),
                    prepare_hash_with_i32(hash_in, args[1]->hash(),
                    prepare_hash_with_i32(hash_in, args[0]->hash()))), size);
        _hashed = true;
    }
    return _hash; 
}
void ExprExtract::print(ostream& os){
    os << std::hex;
    args.at(0)->print(os);
    os << "[" << std::dec;
    args.at(1)->print(os);
    os << ":" << std::dec;
    args.at(2)->print(os);
    os << "]";
}


// ==================================
ExprConcat::ExprConcat(Expr upper, Expr lower): ExprObject(ExprType::CONCAT, upper->size+lower->size){
    args.push_back(upper);
    args.push_back(lower);
}
hash_t ExprConcat::hash(){
    unsigned char hash_in[MAXLEN_HASH_IN]; 
    if( !_hashed ){
        _hash = exprhash(hash_in, prepare_hash_with_i32(hash_in, args[1]->hash(), 
                    prepare_hash_with_i32(hash_in, args[0]->hash())), size);
        _hashed = true;
    }
    return _hash; 
}

void ExprConcat::print(ostream& os){
    os << "{" << std::hex;
    args.at(0)->print(os); 
    os << "," << std::hex;
    args.at(1)->print(os); 
    os << "}";
}

/* ===================================== */
ExprBisz::ExprBisz(exprsize_t _size, Expr cond, cst_t mode): ExprObject(ExprType::BISZ, _size){
    if( mode != 0 && mode != 1){
        throw expression_exception(QuickFmt() << "Can only use Bisz() with mode 0 or 1 (got " << mode << ")" >> QuickFmt::to_str );
    }
    args.push_back(cond);
    _mode = mode;
}
hash_t ExprBisz::hash(){
    unsigned char hash_in[MAXLEN_HASH_IN]; 
    if( !_hashed ){
        _hash = exprhash(hash_in, prepare_hash_with_i32(hash_in, args[0]->hash(), 
            prepare_hash_with_str(hash_in, (_mode)?"BISZ1":"BISZ0")), size);
        _hashed = true;
    }
    return _hash;
}

cst_t ExprBisz::mode(){return _mode;}

void ExprBisz::print(ostream& out){
    if( _mode ){
        out << "bisz<1>(" << std::hex;
        args[0]->print(out);
        out << ")";
    }else{
        out << "bisz<0>(" << std::hex;
        args[0]->print(out);
        out << ")";
    }
}

// ==================================
ExprUnknown::ExprUnknown(exprsize_t s): ExprObject(ExprType::UNKNOWN, s){}
hash_t ExprUnknown::hash(){
    unsigned char hash_in[MAXLEN_HASH_IN]; 
    if( !_hashed ){
        _hash = exprhash(hash_in, prepare_hash_with_i32(hash_in, 0x77777777), size);
        _hashed = true;
    }
    return _hash; 
}
void ExprUnknown::print(ostream& os){
    os << "???";
}

// ==================================

/* Helper functions to create new expressions */
// Create from scratch  
Expr exprcst(exprsize_t size, cst_t cst){
    return make_shared<ExprCst>(size, cst);
}
Expr exprvar(exprsize_t size, string name, int num){
    return make_shared<ExprVar>(size, name, num);
}
Expr exprmem(exprsize_t size, Expr addr){
    return make_shared<ExprMem>(size, addr);
}
Expr exprbinop(Op op, Expr left, Expr right){
    return expr_canonize(make_shared<ExprBinop>(op, left, right));
} 
Expr extract(Expr arg, unsigned long higher, unsigned long lower){
    return make_shared<ExprExtract>(arg, exprcst(sizeof(cst_t)*8, higher), exprcst(sizeof(cst_t)*8, lower));
}
Expr extract(Expr arg, Expr higher, Expr lower){
    return make_shared<ExprExtract>(arg, higher, lower);
}
Expr concat(Expr upper, Expr lower){
    return expr_canonize(make_shared<ExprConcat>(upper, lower));
}
Expr exprunknown(exprsize_t size){
    return make_shared<ExprUnknown>(size);
}
// Binary operations 
Expr operator+(Expr left, Expr right){
    return exprbinop(Op::ADD, left, right);
}
Expr operator+(Expr left, cst_t right ){
    return exprbinop(Op::ADD, left, exprcst(left->size, right));
}
Expr operator+(cst_t left, Expr right){
    return exprbinop(Op::ADD, exprcst(right->size, left), right);
}

Expr operator-(Expr left, Expr right){
    return exprbinop(Op::ADD, left, 
            make_shared<ExprUnop>(Op::NEG,right));
}
Expr operator-(Expr left, cst_t right ){
    return left - exprcst(left->size, right);
}
Expr operator-(cst_t left, Expr right){
    return exprcst(right->size, left) - right;
}

Expr operator*(Expr left, Expr right){
    return exprbinop(Op::MUL, left, right);
}
Expr operator*(Expr left, cst_t right ){
    return exprbinop(Op::MUL, left, exprcst(left->size, right));
}
Expr operator*(cst_t left, Expr right){
    return exprbinop(Op::MUL, exprcst(right->size, left), right);
}

Expr operator/(Expr left, Expr right){
    return exprbinop(Op::DIV, left, right);
}
Expr operator/(Expr left, cst_t right ){
    return exprbinop(Op::DIV, left, exprcst(left->size, right));
}
Expr operator/(cst_t left, Expr right){
    return exprbinop(Op::DIV, exprcst(right->size, left), right);
}

Expr operator&(Expr left, Expr right){
    return exprbinop(Op::AND, left, right);
}
Expr operator&(Expr left, cst_t right ){
    return exprbinop(Op::AND, left, exprcst(left->size, right));
}
Expr operator&(cst_t left, Expr right){
    return exprbinop(Op::AND, exprcst(right->size, left), right);
}

Expr operator|(Expr left, Expr right){
    return exprbinop(Op::OR, left, right);
}
Expr operator|(Expr left, cst_t right ){
    return exprbinop(Op::OR, left, exprcst(left->size, right));
}
Expr operator|(cst_t left, Expr right){
    return exprbinop(Op::OR, exprcst(right->size, left), right);
}

Expr operator^(Expr left, Expr right){
    return exprbinop(Op::XOR, left, right);
}
Expr operator^(Expr left, cst_t right ){
    return exprbinop(Op::XOR, left, exprcst(left->size, right));
}
Expr operator^(cst_t left, Expr right){
    return exprbinop(Op::XOR, exprcst(right->size, left), right);
}

Expr operator%(Expr left, Expr right){
    return exprbinop(Op::MOD, left, right);
}
Expr operator%(Expr left, cst_t right ){
    return exprbinop(Op::MOD, left, exprcst(left->size, right));
}
Expr operator%(cst_t left, Expr right){
    return exprbinop(Op::MOD, exprcst(right->size, left), right);
}

Expr operator<<(Expr left, Expr right){
    return exprbinop(Op::SHL, left, right);
}
Expr operator<<(Expr left, cst_t right ){
    return exprbinop(Op::SHL, left, exprcst(left->size, right));
}
Expr operator<<(cst_t left, Expr right){
    return exprbinop(Op::SHL, exprcst(right->size, left), right);
}

Expr operator>>(Expr left, Expr right){
    return exprbinop(Op::SHR, left, right);
}
Expr operator>>(Expr left, cst_t right ){
    return exprbinop(Op::SHR, left, exprcst(left->size, right));
}
Expr operator>>(cst_t left, Expr right){
    return exprbinop(Op::SHR, exprcst(right->size, left), right);
}

Expr shl(Expr arg, Expr shift){
    return exprbinop(Op::SHL, arg, shift);
}
Expr shl(Expr arg, cst_t shift){
    return exprbinop(Op::SHL, arg, exprcst(arg->size,shift));
}
Expr shl(cst_t arg, Expr shift){
    return exprbinop(Op::SHL, exprcst(shift->size,arg), shift);
}

Expr shr(Expr arg, Expr shift){
    return exprbinop(Op::SHR, arg, shift);
}
Expr shr(Expr arg, cst_t shift){
    return exprbinop(Op::SHR, arg, exprcst(arg->size,shift));
}
Expr shr(cst_t arg, Expr shift){
    return exprbinop(Op::SHR, exprcst(shift->size,arg), shift);
}

Expr sdiv(Expr left, Expr right){
    return exprbinop(Op::SDIV, left, right);
}
Expr sdiv(Expr left, cst_t right){
    return exprbinop(Op::SDIV, left, exprcst(left->size, right));
}
Expr sdiv(cst_t left, Expr right){
    return exprbinop(Op::SDIV, exprcst(right->size, left), right);
}

Expr smod(Expr left, Expr right){
    return exprbinop(Op::SMOD, left, right);
}
Expr smod(Expr left, cst_t right){
    return exprbinop(Op::SMOD, left, exprcst(left->size, right));
}
Expr smod(cst_t left, Expr right){
    return exprbinop(Op::SMOD, exprcst(right->size, left), right);
}

Expr mulh(Expr left, Expr right){
    return exprbinop(Op::MULH, left, right);
}
Expr mulh(Expr left, cst_t right){
    return exprbinop(Op::MULH, left, exprcst(left->size, right));
}
Expr mulh(cst_t left, Expr right){
    return exprbinop(Op::MULH, exprcst(right->size, left), right);
}

Expr smull(Expr left, Expr right){
    return exprbinop(Op::SMULL, left, right);
}
Expr smull(Expr left, cst_t right){
    return exprbinop(Op::SMULL, left, exprcst(left->size, right));
}
Expr smull(cst_t left, Expr right){
    return exprbinop(Op::SMULL, exprcst(right->size, left), right);
}

Expr smulh(Expr left, Expr right){
    return exprbinop(Op::SMULH, left, right);
}
Expr smulh(Expr left, cst_t right){
    return exprbinop(Op::SMULH, left, exprcst(left->size, right));
}
Expr smulh(cst_t left, Expr right){
    return exprbinop(Op::SMULH, exprcst(right->size, left), right);
}

// Unary operations
Expr operator~(Expr arg){
    return make_shared<ExprUnop>(Op::NOT, arg);
}
Expr operator-(Expr arg){
    return make_shared<ExprUnop>(Op::NEG, arg);
}
Expr bisz(exprsize_t size, Expr cond, cst_t mode){
    return make_shared<ExprBisz>(size, cond, mode);
}

/* Printing operators */ 
ostream& operator<<(ostream& os, Expr e){
    os << std::hex; // Default, print constants in hex
    e->print(os);
    return os;
}
string op_to_str(Op op){
    switch(op){
        case Op::ADD: return "+";
        case Op::MUL: return "*";
        case Op::MULH: return "*h ";
        case Op::SMULL: return "*lS ";
        case Op::SMULH: return "*hS ";
        case Op::DIV: return "/";
        case Op::SDIV: return "/S ";
        case Op::NEG: return "-";
        case Op::AND: return "&"; 
        case Op::OR: return "|";
        case Op::XOR: return "^";  
        case Op::SHL: return "<<";
        case Op::SHR: return ">>";
        case Op::NOT: return "~";
        case Op::MOD: return "%";
        case Op::SMOD: return "%S ";
        default: throw expression_exception("op_to_str(): got unknown operation!");
    }
}

/* ======= Canonize an expression ========== */

/* This function can be used to build an associative binary operation from 
 * an expression and a list of arguments.
 *  
 * This function is used when canonizing associative binary expressions where
 * arguments should be reordered and grouped by higher priority first. 
 * 
 * The function takes several arguments:
 *  - e : an expression that must be combined with the expressions in 'new_args'
 *        to build the new associative expression. It will be handled differently
 *        if it is a binop corresponding to 'op' or if it's a normal expression
 *  - op : the associative operation we build
 *  - new_args : a list of args that must be combined to 'e' with operation 'op'.
 *               the arguments are expected to be sorted from higher priority to
 *               lower priority
 * 
 * The function combines the arguments in the canonic way ! 
 * */
Expr build_associative_from_args(Expr e, Op op, vector<Expr>& new_args){
    Expr new_arg = nullptr, next_arg = nullptr;
    Expr res = nullptr;
    if( new_args.empty() ){
        return e;
    }
    if( !e->is_binop(op)){
        // e is not a binop of type 'op', we stop here and combine all args by priority
        bool added_leaf = false;
        for( vector<Expr>::iterator it = new_args.begin(); it != new_args.end(); it++ ){
            if( !added_leaf && (*it)->inf(e)){
                // Time to add args[0]
                next_arg = e;
                added_leaf = true;
                it = it-1; // Dont forget to stay on the same new_arg then
            }else{
                // Get next arg
                next_arg = *it;
            }
            if( res == nullptr){
                res = next_arg;
            }else{
                res = make_shared<ExprBinop>(op, res, next_arg);
            }
        }
        if( !added_leaf){
            res = make_shared<ExprBinop>(op, res, e);
        }
        return res;
    }else if( new_args.back()->inf(e->args[1]) ){
        // e is a binop of type 'op' and the smaller new argument is smaller than
        // the right side of 'e'.  So we insert the rest of the new arguments and
        // add the smaller one in the end
        new_arg = new_args.back();
        new_args.pop_back();
        res = build_associative_from_args(e, op, new_args);
        return make_shared<ExprBinop>(op, res, new_arg);
    }else{
        // e is a binop of type 'op' and the smaller new argument is bigger than
        // the right side of 'e'. So we need to insert all new args to the left side
        // and finally add the right one in the end (because smallest priority)
        res = build_associative_from_args(e->args[0], op, new_args);
        return make_shared<ExprBinop>(op, res, e->args[1]);
    }
}

Expr build_left_associative_from_args(Expr e, Op op, vector<Expr>& new_args){
    Expr new_arg = nullptr, next_arg = nullptr;
    Expr res = nullptr;
    if( new_args.empty() ){
        return e;
    }
    if( !e->is_binop(op)){
        // e is not a binop of type 'op', we stop here and combine all args by priority
        res = e;
        for( vector<Expr>::iterator it = new_args.begin(); it != new_args.end(); it++ ){
            res = make_shared<ExprBinop>(op, res, *it);
        }
        return res;
    }else if( new_args.back()->inf(e->args[1]) ){
        // e is a binop of type 'op' and the smaller new argument is smaller than
        // the right side of 'e'.  So we insert the rest of the new arguments and
        // add the smaller one in the end
        new_arg = new_args.back();
        new_args.pop_back();
        res = build_left_associative_from_args(e, op, new_args);
        return make_shared<ExprBinop>(op, res, new_arg);
    }else{
        // e is a binop of type 'op' and the smaller new argument is bigger than
        // the right side of 'e'. So we need to insert all new args to the left side
        // and finally add the right one in the end (because smallest priority)
        res = build_left_associative_from_args(e->args[0], op, new_args);
        return make_shared<ExprBinop>(op, res, e->args[1]);
    }
}


Expr expr_canonize(Expr e){
    vector<Expr> new_args;
    Expr e1, e2, leftmost; 
    Expr res;
    /* Binop */
    if( e->is_binop() ){
        if( op_is_associative(e->op()) && op_is_symetric(e->op())){
            // Associative and symetric -> re-order arguments
            // First get arguments list as long as the operator is used for
            // right side argument 
            if( e->args[1]->is_binop(e->op()))
                e->args[1]->get_associative_args(e->op(), new_args);
            else
                new_args.push_back(e->args[1]);
            // Sort the arguments to call build_associative_from_args
            std::reverse(new_args.begin(), new_args.end()); // Invert vector to have the bigger ones first
            res = build_associative_from_args(e->args[0], e->op(), new_args);
            return res;
        }else if( op_is_left_associative(e->op()) && e->args[0]->is_binop(e->op())){
            // Left associative -> (a/b)/c -> (a/c)/b
            new_args.push_back(e->args[1]);
            res = build_left_associative_from_args(e->args[0], e->op(), new_args);
            return res;
        }
        // Canonize and return
        if( new_args.size() > 0 ){
            // Group higher args together first
            while( new_args.size() > 1 ){
                e1 = new_args.back();
                new_args.pop_back();
                e2 = new_args.back();
                new_args.pop_back();
                new_args.push_back(make_shared<ExprBinop>(e->op(), e1, e2));
            }
            return new_args.back();
        }else{
            // Nothing to do, return the same expression
            return e;
        }
    /* Concat */
    }else if( e->is_concat() ){
        if( e->args[0]->is_concat() )
            return concat(e->args[0]->args[0], concat(e->args[0]->args[1], e->args[1]));
        else
            return e;
    }else
        return e; 
}

/* ====================================== */
/* Misc operations and functions on enums */ 
bool operator<(Op op1, Op op2){
    return static_cast<int>(op1) < static_cast<int>(op2);
}
bool op_is_symetric(Op op){
    return (op == Op::ADD || op == Op::AND || op == Op::MUL || op == Op::MULH ||
            op == Op::OR || op == Op::XOR || op == Op::SMULL ||
            op == Op::SMULH );
}
bool op_is_associative(Op op){
    return (op == Op::ADD || op == Op::AND || op == Op::MUL || op == Op::MULH ||
            op == Op::OR || op == Op::XOR || op == Op::SMULL ||
            op == Op::SMULH );
}
bool op_is_left_associative(Op op){
    return (op == Op::DIV);
}

bool op_is_multiplication(Op op){
    return (op == Op::MUL || op == Op::SMULL || op == Op::SMULH || op == Op::MULH);
}

bool op_is_distributive_over(Op op1, Op op2){
    switch(op1){
        case Op::MUL:
        case Op::MULH: 
        case Op::SMULL:
        case Op::SMULH: 
            return (op2 == Op::ADD);
        case Op::AND: return (  op2 == Op::AND ||
                                op2 == Op::OR );
        case Op::OR: return (   op2 == Op::OR ||
                                op2 == Op::AND );
        default: return false;
    }
}

bool operator<(ExprType t1, ExprType t2){
    return static_cast<int>(t1) < static_cast<int>(t2);
}

/* Constant manipulation */
cst_t cst_sign_trunc(exprsize_t size, cst_t val){
    if( size == sizeof(cst_t)*8 )
        return val;
    else
        return val & (((ucst_t)1<<(ucst_t)size)-1);
}
cst_t cst_mask(exprsize_t size){
    if( size == sizeof(cst_t)*8 )
        return -1;
    else
        return ((ucst_t)1<<size)-1; 
}
cst_t cst_sign_extend(exprsize_t size, cst_t c){
    if( size == sizeof(cst_t)*8 ){
        return c;
    }else{
        /* Adjust the sign to whole variable  */
        if( ((ucst_t)1<<((ucst_t)size-1)) & (ucst_t)c ){
            // Negative, set higher bits to 1
            return ((ucst_t)0xffffffffffffffff<< size) | c; 
        }else{
            // Positive, set higher bits to 0
            return ((((ucst_t)1<<size)-1) & c);
        }
    }
}
