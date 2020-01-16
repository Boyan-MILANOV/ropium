#ifndef SIMPLIFICATION_H
#define SIMPLIFICATION_H

#include "expression.hpp"
#include <vector>

using std::vector; 

/* Forward declaration */ 
class ExprSimplifier;

/* Type aliasing */
typedef Expr (*ExprSimplifierFunc)(Expr);
typedef Expr (*RecExprSimplifierFunc)(Expr, ExprSimplifier&);

/* Expression simplifier */
class ExprSimplifier{
protected:
    vector<ExprSimplifierFunc> simplifiers;
    vector<RecExprSimplifierFunc> rec_simplifiers;
    vector<RecExprSimplifierFunc> restruct_simplifiers;
    Expr run_simplifiers(Expr e);
public:
    ExprSimplifier();
    Expr simplify(Expr e);
    void add(ExprSimplifierFunc func);
    void add(RecExprSimplifierFunc func);
    void add_restruct(RecExprSimplifierFunc func);
};

ExprSimplifier* NewDefaultExprSimplifier();

/* Simplification functions */
Expr es_constant_folding(Expr e);
Expr es_neutral_elements(Expr e);
Expr es_absorbing_elements(Expr e);
Expr es_arithmetic_properties(Expr e);
Expr es_involution(Expr e);
Expr es_extract_patterns(Expr e);
Expr es_basic_transform(Expr e);
Expr es_logical_properties(Expr e);
Expr es_concat_patterns(Expr e);
Expr es_arithmetic_factorize(Expr e);
Expr es_generic_factorize(Expr e);
Expr es_generic_distribute(Expr e);
Expr es_deep_associative(Expr e, ExprSimplifier& simp);

#endif
