#include "simplification.hpp"
#include "expression.hpp"
#include "exception.hpp"
#include <iostream>
#include <algorithm>
#include <iterator>

using std::make_shared;

/* ExprSimplifier implementation */ 
ExprSimplifier::ExprSimplifier(){}

void ExprSimplifier::add(ExprSimplifierFunc func){
    simplifiers.push_back(func);
}
void ExprSimplifier::add(RecExprSimplifierFunc func){
    rec_simplifiers.push_back(func);
}
void ExprSimplifier::add_restruct(RecExprSimplifierFunc func){
    restruct_simplifiers.push_back(func);
}

Expr ExprSimplifier::run_simplifiers(Expr e){
    Expr tmp_expr = e; 
    vector<ExprSimplifierFunc>::iterator func;
    vector<RecExprSimplifierFunc>::iterator rec_func;
    /* Normal functions */ 
    for (func = simplifiers.begin(); func != simplifiers.end(); func++){
        tmp_expr = (**func)(tmp_expr);
    }
    /* Recursive functions */ 
    for (rec_func = rec_simplifiers.begin(); rec_func != rec_simplifiers.end(); rec_func++)
        tmp_expr = (**rec_func)(tmp_expr, *this);
    return tmp_expr; 
}

Expr ExprSimplifier::simplify(Expr e){
    Expr tmp_expr = e;
    Expr prev_expr;
    Expr prev_arg;
    // Check if already simplified or if simple constant
    if( e->_is_simplified || e->is_cst()){
        return e;
    }else if( e->_simplified_expr != nullptr ){
        return e->_simplified_expr;
    }
    // Simplify util fix point is found
    do{
        prev_expr = tmp_expr;
        tmp_expr = run_simplifiers(tmp_expr);
        /* If no high level change, simplify arguments and try again */
        /* !!! Don't enter the block if args.size() == 0 because it would
         * cause basic expressions (cst, var) to loose their taint ! */
        if( prev_expr->eq(tmp_expr) && tmp_expr->args.size() > 0){
            // Simplify args in place :)
            for( int i = 0; i < tmp_expr->args.size(); i++ ){
                tmp_expr->args[i] = simplify(tmp_expr->args[i]);
            }
            // ! If binop we recanonize it because arguments changed !
            tmp_expr = expr_canonize(tmp_expr);
            // ! We remove the hash and taint of tmp_expr because we modify its 
            // arguments directly in the AST  
            tmp_expr->_hashed = false;
            // Re-apply simplifications
            prev_expr = tmp_expr; 
            tmp_expr = run_simplifiers(tmp_expr);
        }
    }while( prev_expr->neq(tmp_expr) );
    if( tmp_expr->neq(e) ){
        // If the expression was simplified then save the pointer to the 
        // simplified expression. If not the don't save anything because
        // the object shouldn't hold a shared pointer to itself :/
        e->_simplified_expr = tmp_expr;
    }
    tmp_expr->_is_simplified = true;
    return tmp_expr;
}

ExprSimplifier* NewDefaultExprSimplifier(){
    ExprSimplifier* simp = new ExprSimplifier();
    simp->add(es_constant_folding);
    simp->add(es_neutral_elements);
    simp->add(es_absorbing_elements);
    simp->add(es_arithmetic_properties);
    simp->add(es_involution);
    simp->add(es_extract_patterns);
    simp->add(es_basic_transform);
    simp->add(es_logical_properties);
    simp->add(es_concat_patterns);
    simp->add(es_arithmetic_factorize);
    //simp->add(es_generic_distribute);
    simp->add(es_generic_factorize);
    //simp->add(es_deep_associative);
    return simp;
}

/* ==================================================
                 Light simplifications
   ================================================= */
/* Constant folding */
Expr es_constant_folding(Expr e){
    bool was_tainted;
    Expr res = nullptr;
    cst_t _concrete, high, low;
    ucst_t mask;

    if( e->is_binop() && e->args[0]->is_cst() &&
        e->args[1]->is_cst()){
        /* Binary operators */
        switch(e->op()){
            case Op::ADD: _concrete = (e->args[0]->cst() + e->args[1]->cst()); break;
            case Op::MUL: _concrete = ((ucst_t)e->args[0]->cst() * (ucst_t)e->args[1]->cst()); break;
            case Op::MULH: _concrete = (cst_t)(((__uint128_t)cst_sign_trunc(e->args[0]->size, e->args[0]->cst()) * 
                                                            cst_sign_trunc(e->args[1]->size, (__uint128_t)e->args[1]->cst())) >> e->size ); break;
            case Op::DIV: _concrete = ((ucst_t)cst_sign_trunc(e->args[0]->size, e->args[0]->cst()) / (ucst_t)cst_sign_trunc(e->args[1]->size, e->args[1]->cst())); break;
            case Op::SDIV: _concrete = (e->args[0]->cst() / e->args[1]->cst()); break;
            case Op::AND: _concrete = (e->args[0]->cst() & e->args[1]->cst()); break;
            case Op::OR: _concrete = (e->args[0]->cst() | e->args[1]->cst()); break;
            case Op::XOR: _concrete = (e->args[0]->cst() ^ e->args[1]->cst()); break;
            case Op::MOD: _concrete = ((ucst_t)e->args[0]->cst() % (ucst_t)e->args[1]->cst()); break;
            case Op::SMOD: _concrete = (e->args[0]->cst() % e->args[1]->cst()); break;
            case Op::SMULL: _concrete = (cst_t)((__int128_t)e->args[0]->cst() * e->args[1]->cst()); break;
            case Op::SMULH: _concrete = (cst_t)(((__int128_t)e->args[0]->cst() * e->args[1]->cst()) >> e->size); break;
            case Op::SHL: 
                if( e->args[1]->cst() >= e->args[0]->size ){
                    _concrete = 0;
                }else{ 
                    _concrete = ((ucst_t)cst_sign_trunc(e->args[0]->size, e->args[0]->cst())) << ((ucst_t)e->args[1]->cst());
                }
                break;
            case Op::SHR: 
                if( cst_sign_trunc(e->args[1]->size, e->args[1]->cst()) >= e->args[0]->size ){
                    _concrete = 0;
                }else{
                    _concrete = ((ucst_t)cst_sign_trunc(e->args[0]->size, e->args[0]->cst())) >> ((ucst_t)e->args[1]->cst());
                }
                break;
            default: throw runtime_exception("Missing case in constant folding simplification");
        }
        res = exprcst(e->size, cst_sign_extend(e->size, _concrete));
    }else if( e->is_unop() && e->args[0]->is_cst()){
        /* Unary operators */
        switch(e->op()){
            case Op::NEG: _concrete =cst_sign_extend(e->size, -(e->args[0]->cst())); break;
            case Op::NOT: _concrete =cst_sign_extend(e->size, ~(e->args[0]->cst())); break;
            default: throw runtime_exception("Missing case in constant folding simplification");
        }
        res = exprcst(e->size, cst_sign_extend(e->size, _concrete));
    }else if( e->is_bisz() && e->args[0]->is_cst()){
        /* BISZ */
        _concrete = (e->args[0]->cst() == 0)? e->mode() : e->mode()^1;
        res = exprcst(e->size, cst_sign_extend(e->size, _concrete));
    }else if(   e->is_extract() && e->args[0]->is_cst() &&
                e->args[1]->is_cst() && e->args[2]->is_cst()){
        /* Extract */ 
        high = e->args[1]->cst();
        low = e->args[2]->cst();
        if( high == 63 ){
            mask = 0xffffffffffffffff;
        }else{
            mask = (((cst_t)1 << (high+1))-1);
        }
        _concrete =  ((ucst_t)e->args[0]->cst() & mask) >> (ucst_t)low;
        res = exprcst(e->size, cst_sign_extend(e->size, _concrete));
    }else if( e->is_concat() && e->args[0]->is_cst() &&
                e->args[1]->is_cst() ){
        /* Concat */ 
        high = e->args[0]->cst();
        low = e->args[1]->cst();
        _concrete = cst_sign_extend(e->size, (((ucst_t)high)<<(ucst_t)e->args[1]->size)
                                             | (ucst_t)cst_sign_trunc(e->args[1]->size, low));
        res = exprcst(e->size, cst_sign_extend(e->size, _concrete));
    }
    /* Return result */
    if( res != nullptr ){
        return res;
    }else
        return e;
}

/* Neutral elements */
Expr es_neutral_elements(Expr e){
    if( e->is_binop() && e->args[0]->is_cst()){
        // 0 + X 
        if( e->op() == Op::ADD && e->args[0]->cst() == 0)
            return e->args[1];
        // 1 * X
        else if( (op_is_multiplication(e->op())) && e->args[0]->cst() == 1)
            return e->args[1];
        // 0xfffff.... & X
        else if( e->op() == Op::AND && cst_sign_trunc(e->size, e->args[0]->cst()) == cst_mask(e->size))
            return e->args[1];
        // 0 |^ X 
        else if( (e->op() == Op::OR || e->op() == Op::XOR)
                 && e->args[0]->cst() == 0)
            return e->args[1];
    }else if( e->is_binop() && e->args[1]->is_cst()){
        // X / 1
        if( (e->op()==Op::DIV || e->op() == Op::SDIV) && e->args[1]->cst() == 1 )
            return e->args[0];
        // X << 0 or X >> 0
        else if( (e->op() == Op::SHL || e->op() == Op::SHR) && e->args[1]->cst() == 0 )
            return e->args[0];
    }else if(e->is_extract() && e->args[1]->is_cst() && e->args[2]->is_cst()){
        // Extract(X, sizeof(X)-1, 0)
        if( e->args[1]->cst() == e->args[0]->size-1 && e->args[2]->cst() == 0 )
            return e->args[0];
    }
    return e;
}

/* Absorbing elements */
Expr es_absorbing_elements(Expr e){
    if( !e->is_binop() )
        return e; 
    
    if( e->args[0]->is_cst()){
        // 0 &*//S X
        if( (e->op() == Op::AND || op_is_multiplication(e->op()) || e->op() == Op::DIV || e->op() == Op::SDIV) 
             && e->args[0]->cst() == 0)
            return e->args[0];
        // 0xffff..... | X 
        else if( (e->op() == Op::OR)
                 && cst_sign_trunc(e->size, e->args[0]->cst()) == cst_mask(e->size))
            return e->args[0];
        // X << sizeof(X) or X >> sizeof(X)
    }else if( (e->op() == Op::SHL || e->op() == Op::SHR) && e->args[1]->is_cst() &&
            (e->args[1]->cst() >= (cst_t)e->size)){
            return exprcst(e->size, 0);
    }
    return e;
}

/* ADD specific simplifications */
Expr es_arithmetic_properties(Expr e){
    if( !e->is_binop(Op::ADD)){
        return e;
    }
    // X-X --> 0 
    if( e->args[1]->is_unop(Op::NEG) && e->args[0]->eq(e->args[1]->args[0])){
        return exprcst(e->size, 0);
    // X+(-1*X) --> 0 
    if( e->args[1]->is_binop() && op_is_multiplication(e->args[1]->op()) 
         && e->args[1]->args[0]->is_cst()
         && e->args[1]->args[0]->cst() == -1 && e->args[1]->args[1]->eq(e->args[0])){
        return exprcst(e->size, 0);
    // -X+X --> 0
    }else if( e->args[0]->is_unop(Op::NEG) && e->args[1]->eq(e->args[0]->args[0])){
        return exprcst(e->size, 0);
    // (-1*X)+X --> 0
    }else if(e->args[1]->is_binop() && op_is_multiplication(e->args[1]->op()) 
            && e->args[0]->args[0]->is_cst()
            && e->args[0]->args[0]->cst() == -1 && e->args[0]->args[1]->eq(e->args[1]))
        return exprcst(e->size, 0);
    }
    return e;
}

/* NEG and NOT involution simplifications */
Expr es_involution(Expr e){
    if( e->is_unop(Op::NEG) || e->is_unop(Op::NOT)){
        if( e->args[0]->is_unop(e->op()))
            return e->args[0]->args[0];
    }
    return e;
}

/* Extract specific simplifications */ 
Expr es_extract_patterns(Expr e){
    if( e->is_extract() ){
        if( e->args[0]->is_concat() && e->args[1]->is_cst() && e->args[2]->is_cst()){
            // extract(concat(X,Y), a, b) --> extract(X, a', b')
            if( e->args[2]->cst() >= e->args[0]->args[1]->size ){
                return extract( e->args[0]->args[0], 
                                e->args[1]->cst()-e->args[0]->args[1]->size,
                                e->args[2]->cst()-e->args[0]->args[1]->size);
            }
            // extract(concat(X,Y), a, b) --> extract(Y, a', b')
            else if( e->args[1]->cst() < e->args[0]->args[1]->size ){
                return extract( e->args[0]->args[1], 
                                e->args[1]->cst(),
                                e->args[2]->cst());
            }
        // extract(extract(X,a,b),c,d) --> extract(X, a',b')
        }else if( e->args[0]->is_extract() && 
                (e->args[0]->args[2]->size == e->args[1]->size) &&
                (e->args[0]->args[2]->size == e->args[2]->size)){
            return extract(e->args[0]->args[0],
                e->args[0]->args[2]->cst()+e->args[1]->cst(),
                e->args[0]->args[2]->cst()+e->args[2]->cst());
        }
    }
    return e;
}

/* Basic transformations to canonize expressions a bit more */
Expr es_basic_transform(Expr e){
    if( e->is_binop(Op::SHL) && e->args[1]->is_cst()){
        // X << Y --> X * (2**Y)
        return e->args[0]*exprcst(e->size, ((ucst_t)1<<(ucst_t)e->args[1]->cst()));
    }else if( e->is_binop(Op::SHR) && e->args[1]->is_cst() ){
        // X >> Y --> X / (2**Y)
        return e->args[0]/exprcst(e->size, ((ucst_t)1<<(ucst_t)(e->args[1]->cst())));
    // -X --> -1*X
    }else if(e->is_unop(Op::NEG)){
        return exprcst(e->size, -1)*e->args[0]; 
    // -Y*X --> -(Y*X)
    /*
    }else if( e->is_binop(Op::MUL) && e->args[0]->is_unop(Op::NEG)){
        return -(e->args[0]->args[0]*e->args[1]); */
    // X*-Y --> -(X*Y)
    /*
    }else if( e->is_binop(Op::MUL) && e->args[1]->is_unop(Op::NEG)){
        return -(e->args[1]->args[0]*e->args[0]); */
    // 1+~X --> -X
    }else if( e->is_binop(Op::ADD) && e->args[0]->is_cst() && e->args[0]->cst()==1
                && e->args[1]->is_unop(Op::NOT)){
        return -e->args[1]->args[0];
    // -1^X --> ~X
    }else if( e->is_binop(Op::XOR) && e->args[0]->is_cst() && e->args[0]->cst() == -1){
        return ~e->args[1];
    // CST*-Y --> -CST*Y
    }else if(  ((e->is_binop() && op_is_multiplication(e->op())) || e->is_binop(Op::SDIV)) &&
               (e->args[1]->is_unop(Op::NEG)) &&
               (e->args[0]->is_cst()) ) {
        return exprbinop(e->op(), -e->args[0], e->args[1]->args[0]);
    // (-Y)*CST --> Y*(-CST) 
    }else if(  ((e->is_binop() && op_is_multiplication(e->op())) || e->is_binop(Op::SDIV)) &&
               (e->args[0]->is_unop(Op::NEG)) &&
               (e->args[1]->is_cst()) ) {
        return exprbinop(e->op(), e->args[0]->args[0], -e->args[1]);
    }
    return e;
}

/* logical properties */ 
Expr es_logical_properties(Expr e){
    // X &| X --> X
    if( (e->is_binop(Op::AND) || e->is_binop(Op::OR)) && ( e->args[0]->eq(e->args[1]))){
        return e->args[0];
    // X & ~X --> 0
    }else if( e->is_binop(Op::AND) && e->args[1]->is_unop(Op::NOT) && 
            e->args[0]->eq(e->args[1]->args[0])){
        return exprcst(e->size, 0);
    // ~X & X --> 0
    }else if( e->is_binop(Op::AND) && e->args[0]->is_unop(Op::NOT) && 
            e->args[1]->eq(e->args[0]->args[0])){
        return exprcst(e->size, 0);
    // ~X |^ X --> 0xfffff....
    }else if( (e->is_binop(Op::OR) || e->is_binop(Op::XOR)) && e->args[0]->is_unop(Op::NOT) && 
            e->args[1]->eq(e->args[0]->args[0])){
        return exprcst(e->size, (cst_t)-1);
    // X |^ ~X --> 0xfffff....
    }else if( (e->is_binop(Op::OR) || e->is_binop(Op::XOR)) && e->args[1]->is_unop(Op::NOT) && 
            e->args[0]->eq(e->args[1]->args[0])){
        return exprcst(e->size, (cst_t)-1);
    // X ^ X --> 0
    }else if( e->is_binop(Op::XOR) && e->args[0]->eq(e->args[1])){
        return exprcst(e->size, 0);
    }
    return e;
}

/* Concat simplification patterns */
Expr es_concat_patterns(Expr e){
    // concat(X[a:b], X[b-1:c]))
    if( e->is_concat() && e->args[0]->is_extract() && e->args[1]->is_extract() &&
            e->args[0]->args[0]->eq(e->args[1]->args[0]) && 
            e->args[0]->args[2]->cst() == e->args[1]->args[1]->cst()+1){
        return extract(e->args[0]->args[0], e->args[0]->args[1], e->args[1]->args[2]);
    }
    if( e->is_binop(Op::AND) && e->args[0]->is_cst() && e->args[1]->is_concat()){

        if( cst_sign_trunc(e->args[0]->size, e->args[0]->cst()) == (((ucst_t)1<<e->args[1]->args[1]->size)-1)){
            if( e->args[1]->args[1]->is_cst() && e->args[1]->args[1]->is_cst() == 0 ){
                // concat(X,0) & 0x000...11111 = 0
                return exprcst(e->size, 0);
            }else{
                // concat(X,Y) & 0x000...11111 = concat(0, Y)
                return concat(exprcst(e->args[1]->args[0]->size, 0), e->args[1]->args[1]);
            }
        }
        
        if( e->args[0]->cst() == (((cst_t)-1)<<e->args[1]->args[1]->size)){
            if( e->args[1]->args[0]->is_cst() && e->args[1]->args[0]->is_cst() == 0 ){
                // concat(0,Y) & 0x111...000 = 0
                return exprcst(e->size, 0);
            }else{ 
                // concat(X,Y) & 0x111...000 = concat(X, 0)
                return concat(e->args[1]->args[0], exprcst(e->args[1]->args[1]->size, 0));
            }
        }
    }
    return e; 
}

/* Basic factorization patterns */
Expr es_arithmetic_factorize(Expr e){
    if( !e->is_binop(Op::ADD))
        return e;
    if( e->args[0]->is_binop() && op_is_multiplication(e->args[0]->op())){
        // (X*Y)+Y --> (X+1)*Y
        if (e->args[0]->args[1]->eq(e->args[1])){
            return (e->args[0]->args[0]+exprcst(e->size,1))*(e->args[1]);
        // (Y*X)+Y --> (X+1)*Y
        }else if(e->args[0]->args[0]->eq(e->args[1])){
            return (e->args[0]->args[1]+exprcst(e->size,1))*(e->args[1]);
        // (X*Y)-Y --> (X-1)*Y
        }else if(e->args[1]->is_unop(Op::NEG) && 
                e->args[0]->args[1]->eq(e->args[1]->args[0])){
            return (e->args[0]->args[0]-exprcst(e->size,1))*e->args[0]->args[1]; 
        
        }else if( e->args[1]->is_binop() && op_is_multiplication(e->args[1]->op())){
            // (Y*X)-Y --> (X-1)*Y
            if(e->args[1]->is_unop(Op::NEG) && 
                    e->args[0]->args[0]->eq(e->args[1]->args[0])){
                return (e->args[0]->args[1]-exprcst(e->size,1))*e->args[0]->args[0];
            // (A*Y)+(B*Y) --> (A+B)*Y
            }else if( e->args[0]->args[1]->eq(e->args[1]->args[1])){
                return (e->args[0]->args[0]+e->args[1]->args[0])*e->args[0]->args[1];
            // (A*Y)+(Y*B) --> (A+B)*Y
            }else if( e->args[0]->args[1]->eq(e->args[1]->args[0])){
                return (e->args[0]->args[0]+e->args[1]->args[1])*e->args[0]->args[1];
            // (Y*A)+(B*Y) --> (A+B)*Y
            }else if( e->args[0]->args[0]->eq(e->args[1]->args[1])){
                return (e->args[0]->args[1]+e->args[1]->args[0])*e->args[0]->args[0];
            // (Y*A)+(Y*B) --> (A+B)*Y
            }else if( e->args[0]->args[0]->eq(e->args[1]->args[0])){
                return (e->args[0]->args[1]+e->args[1]->args[1])*e->args[0]->args[0];
            }
        }
    }else if(e->args[1]->is_binop() && op_is_multiplication(e->args[1]->op())) {
        // Y+(X*Y) --> (X+1)*Y
        if(e->args[0]->eq(e->args[1]->args[1])){
            return (e->args[1]->args[0]+exprcst(e->size, 1))*(e->args[0]);
        // Y+(Y*X) --> (X+1)*Y
        }else if( e->args[0]->eq(e->args[1]->args[0]) ){
            return (e->args[1]->args[1]+exprcst(e->size,1))*(e->args[0]);
        // -Y+(Y*X) --> (X-1)*Y
        }else if( e->args[0]->is_unop(Op::NEG) &&
                e->args[0]->args[0]->eq(e->args[1]->args[0])){
            return (e->args[1]->args[1]-exprcst(e->size, 1))*e->args[0]->args[0];
        // -Y+(X*Y) --> (X-1)*Y
        }else if( e->args[0]->is_unop(Op::NEG) &&
                e->args[0]->args[0]->eq(e->args[1]->args[1])){
            return (e->args[1]->args[0]-exprcst(e->size, 1))*e->args[0]->args[0];
        }
    // X+X --> 2*X
    }else if( e->args[0]->eq(e->args[1])){
        return exprcst(e->size, 2)*e->args[0];
    }
    return e; 
}

/* Generic factorization on distributive operators */
Expr es_generic_factorize(Expr e){
    if( e->is_binop() && e->args[0]->is_binop() && 
          e->args[1]->is_binop() && e->args[0]->op() == e->args[1]->op() &&
          op_is_distributive_over(e->args[0]->op(), e->op()) && 
          op_is_symetric(e->args[0]->op())){
        // (AxB)o(AxC) --> Ax(BoC)
        if( e->args[0]->args[0]->eq(e->args[1]->args[0])){
            return exprbinop(e->args[0]->op(), e->args[0]->args[0], 
                        exprbinop(e->op(), e->args[0]->args[1], e->args[1]->args[1]));
        // (AxB)o(CxA)
        }else if( e->args[0]->args[0]->eq(e->args[1]->args[1])){
            return exprbinop(e->args[0]->op(), e->args[0]->args[0], 
                        exprbinop(e->op(), e->args[0]->args[1], e->args[1]->args[0]));
        // (BxA)o(CxA)
        }else if( e->args[0]->args[1]->eq(e->args[1]->args[1])){
            return exprbinop(e->args[0]->op(), e->args[0]->args[1], 
                        exprbinop(e->op(), e->args[0]->args[0], e->args[1]->args[0]));
        // (BxA)o(AxC)
        }else if( e->args[0]->args[1]->eq(e->args[1]->args[0])){
            return exprbinop(e->args[0]->op(), e->args[0]->args[1], 
                        exprbinop(e->op(), e->args[0]->args[0], e->args[1]->args[1]));
        }
    }
    return e; 
}

/* Propagate distributive operators */
Expr es_generic_distribute(Expr e){
    // (AxB)oC --> AoC x BoC
    if( e->is_binop() && e->args[0]->is_binop() &&
            op_is_distributive_over(e->op(), e->args[0]->op())){
        return exprbinop(e->args[0]->op(), 
                exprbinop(e->op(), e->args[0]->args[0], e->args[1]),
                exprbinop(e->op(), e->args[0]->args[1], e->args[1]));
    // Co(AxB) --> CoA x CoB
    }else if( e->is_binop() && e->args[1]->is_binop() &&
            op_is_distributive_over(e->op(), e->args[1]->op())){
        return exprbinop(e->args[1]->op(), 
                exprbinop(e->op(), e->args[0], e->args[1]->args[0]),
                exprbinop(e->op(), e->args[0], e->args[1]->args[1]));
    }
    return e;
}

/* =========================================
 *           Heavy Simplifications
 * ========================================= */

/* Associativity deep in the AST 
 * Try to unfold nested associative operators and see if 
 * pairs can be simplified for all possible associations */
Expr es_deep_associative(Expr e, ExprSimplifier& s){
    vector<Expr> vec;
    Expr expr, simp, tmp1, tmp2;
    bool restart;
    int i=0, j=0;
    if( e->is_binop() && op_is_associative(e->op()) &&
            op_is_symetric(e->op())){
        /* Get all args */
        e->get_associative_args(e->op(), vec);
        /* If only two args, no need to simplify in depth */ 
        if( vec.size() <= 2 ){
            return e; 
        }
        /* Else enter simplify loop */
        while( i < vec.size()-1 ){
            j = i+1;
            tmp1 = vec[i];
            restart = false;
            while( j < vec.size() ){
                tmp2 = vec[j];
                /* Normal op */ 
                expr = exprbinop(e->op(), tmp1, tmp2);
                /* Simplified one */ 
                simp = s.simplify(expr);
                /* If changed, push the new one and continue,
                 * else continue with other args */
                if( expr->neq(simp) ){
                    vec.erase(std::next(vec.begin(),j));
                    vec.erase(vec.begin()+i);
                    i = 0;
                    /* Insert in sorted ! */
                    vec.push_back(simp);
                    restart = true;
                    break;
                }else{
                    j++;
                }
            }
            if( !restart){
                i++;
            }
        }
        /* Recombine all expressions */ 
        std::sort(vec.begin(), vec.end());
        while( vec.size() > 1 ){
            tmp1 = vec.back(); 
            vec.pop_back();
            tmp2 = vec.back();
            vec.pop_back();
            vec.push_back(exprbinop(e->op(), tmp1, tmp2));
        }
        return vec.back();
    }
    return e; 
}

