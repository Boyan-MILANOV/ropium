#include "Symbolic.hpp"
#include "Exception.hpp"
#include "Architecture.hpp"
#include <exception>
#include <cstring>
#include <cmath>

using namespace std; 

// Arguments for REIL-type of operations 
SymArg::SymArg(ArgType t, int i, int s): _type(t), _id(i), _size(s){
    _low = 0; 
    _high = _size-1;
}
SymArg::SymArg(ArgType t, int i, int s, int h, int l): _type(t), _id(i), _size(s),  _high(h), _low(l){}
ArgType SymArg::type(){return _type;}
int SymArg::id(){return _id;}
int SymArg::size(){return _size;}
int SymArg::low(){return _low;}
int SymArg::high(){return _high;}
cst_t SymArg::value(){
    if( _type != ARG_CST )
        throw_exception("Error, value() should not be called for this class");
    else
        return _value; 
}
void SymArg::print(ostream& os){
    switch(_type){
        case ARG_EMPTY:
            os << "EMPTY";
            return; 
        case ARG_CST:
            os << "CST(" << ((ArgCst*)this)->value() << ", " << _size << ")"; 
            return;
        case ARG_REG:
            os << "REG(" << _id << "," << _size << ")[" << _high << ":" << _low << "]";
            return;
        case ARG_TMP:
            os << "TMP(" << _id << "," << _size << ")[" << _high << ":" << _low << "]";
            return;
        case ARG_UNKNOWN:
            os << "UNKNOWN";
        default:
            return; 
    }
}


ArgEmpty::ArgEmpty(): SymArg(ARG_EMPTY, -1, -1){}

ArgCst::ArgCst(cst_t v, int s): SymArg(ARG_CST, -1, s){
    _value = v; 
}

ArgReg::ArgReg(int n, int s): SymArg(ARG_REG, n, s){}
ArgReg::ArgReg(int n, int s, int h, int l): SymArg(ARG_REG, n, s, h, l){}

ArgTmp::ArgTmp( int n, int s): SymArg(ARG_TMP, n, s){}
ArgTmp::ArgTmp( int n, int s, int h, int l): SymArg(ARG_TMP, n, s, h, l){}

ArgUnknown::ArgUnknown(int s): SymArg(ARG_UNKNOWN, -1, s){}

// IR Instruction
IRInstruction::IRInstruction(IROperation o, SymArg a1, SymArg a2, SymArg d): _op(o), _src1(a1), _src2(a2), _dst(d){}
IROperation IRInstruction::op(){return _op;}
SymArg* IRInstruction::src1(){return &_src1;}
SymArg* IRInstruction::src2(){return &_src2;}
SymArg* IRInstruction::dst(){return &_dst;}
void IRInstruction::print(ostream& os){
    switch(_op){
        case IR_ADD:
            os << "ADD";
            break;
        case IR_AND:
            os << "AND";
            break;
        case IR_BSH:
            os << "BSH";
            break;
        case IR_DIV:
            os << "DIV";
            break;
        case IR_LDM:
            os << "LDM";
            break;
        case IR_MOD:
            os << "MOD";
            break;
        case IR_MUL:
            os << "MUL";
            break;
        case IR_NOP:
            os << "NOP";
            break;
        case IR_OR:
            os << "OR";
            break;
        case IR_STM:
            os << "STM";
            break;
        case IR_STR:
            os << "STR";
            break;
        case IR_SUB:
            os << "SUB";
            break;
        case IR_XOR:
            os << "XOR";
            break;
        case IR_UNKNOWN:
            os << "UNKNOWN";
            break;
        default:
            break;
    }
    os << "   [";
    _src1.print(os); os << ",  ";
    _src2.print(os); os << ",  ";
    _dst.print(os); 
    os << " ]\n";
}


// Some useful functions 
bool is_calculation_instr(IRInstruction& instr){
    return  instr.op() == IR_ADD || 
            instr.op() == IR_AND ||
            instr.op() == IR_BSH || 
            instr.op() == IR_DIV || 
            instr.op() == IR_MOD || 
            instr.op() == IR_MUL || 
            instr.op() == IR_OR ||
            instr.op() == IR_SUB ||
            instr.op() == IR_XOR ;    
}

// IR Block of instructions 
IRBlock::IRBlock(): _mem_write_cnt(0){
    int i;
    for( i = 0; i < NB_REGS_MAX; i++ ){
        _reg_modified[i] = false;
        _reg_table[i] = nullptr; 
    }
    for( i = 0; i < NB_TMP_MAX; i++ ){
        _tmp_table[i] = nullptr; 
    }
}

int IRBlock::nb_instr(){
    return _instr.size();
}

bool IRBlock::add_instr(IRInstruction ins){
    if( _instr.size() == NB_INSTR_MAX )
        return false;
    else{
        _instr.push_back(ins);
        return true;
    }
}

vector<ExprObjectPtr> IRBlock::mem_writes(){return _mem_writes;}
vector<ExprObjectPtr> IRBlock::mem_reads(){return _mem_reads;}
bool IRBlock::reg_modified(int num){return _reg_modified[num];}

inline void IRBlock::assign_reg_table(int num, vector<SPair>* val){
    if( _reg_table[num] != nullptr )
        delete _reg_table[num]; 
    _reg_table[num] = val; 
    _reg_modified[num] = true;
}
inline void IRBlock::assign_tmp_table(int num, vector<SPair>* val){
    if( _tmp_table[num] != nullptr )
        delete _tmp_table[num]; 
    _tmp_table[num] = val; 
}

/* Translate an arg to a list of its possible values (SPairs)
 * If the low/high fields of arg don't match its size, the 
 * possible values are adjusted with Extract()
 */ 
 
vector<SPair>* IRBlock::arg_to_spairs(SymArg& arg ){
    vector<SPair>* res=nullptr, *res2=nullptr;
    ExprObjectPtr expr; 
    vector<SPair>::iterator tmp;
     
    if( arg.type() == ARG_CST ){
        expr = NewExprCst(arg.value(), arg.size());
        res = new vector<SPair>();
        res->push_back(SPair(expr, NewCondTrue()));
    }else if( arg.type() == ARG_TMP){
        res = new vector<SPair>(*_tmp_table[arg.id()]);
    }else if( arg.type() == ARG_REG){
        if( _reg_modified[arg.id()] || (_reg_table[arg.id()] != nullptr))
            res = new vector<SPair>(*_reg_table[arg.id()]);
        else{
            // We create a new value for it
            expr = make_shared<ExprObject>(make_shared<ExprReg>(arg.id(), arg.size()));
            _reg_table[arg.id()] = new vector<SPair>();
            _reg_table[arg.id()]->push_back(SPair(expr, NewCondTrue()));
            res = new vector<SPair>(*_reg_table[arg.id()]); 
        }
    }else if( arg.type() == ARG_UNKNOWN ){
        res = new vector<SPair>();
        res->push_back(SPair(NewExprUnknown(arg.size()), NewCondTrue()));
    }else{
        throw_exception("SymArg type not supported in arg_to_expr()");
    }
    // Translate if low and high specified 
    if( arg.low() != 0 || arg.high() != arg.size()-1){
        res2 = new vector<SPair>(); 
        for( tmp = res->begin(); tmp != res->end(); tmp++){
            res2->push_back(SPair(Extract((*tmp).expr(), arg.high(), arg.low()),  (*tmp).cond()));
        }
        delete res; 
        res = nullptr; 
        return res2; 
    }else
        return res; 
}

#define MAX_VALUES_PER_ARG 30
struct too_many_values: public std::exception{
	const char * what () const throw (){
    	return "Too many values for one symbolic argument";
    }
};

/* We assign 'expr' to argument 'reg' that has the previous value 'prev'
 * If expr is smaller than prev, then we use the low/high fields of reg to 
 * know where to insert it in the previous value using a Concat() expression
 */ 
inline ExprObjectPtr IRBlock::full_reg_assignment(ExprObjectPtr expr, ExprObjectPtr prev, SymArg& reg){
    // Check if we need to convert the expr assigned 
    if( expr->expr_ptr()->size() != reg.high()-reg.low()+1 ){
        expr = expr->convert(reg.high()-reg.low()+1);
    }
    
    if( reg.low() == 0 && reg.high() == reg.size()-1)
        return expr; 
    else if( reg.low() == 0 ){
        return Concat(Extract(prev, reg.size()-1, reg.high()+1), expr);
    }else if( reg.high() == reg.size()-1){
        return Concat(expr, Extract(prev, reg.low()-1, 0));
    }else{
        return Concat( Extract(prev, reg.size()-1, reg.high()+1), Concat(expr, Extract(prev, reg.low()-1, 0)));
    }    
}

/* Same than previous function but does it for all possible values in spairs
 * Pre-condition: all expressions in spairs have the same size and correspond to the 
 * low-high of reg
 */  
vector<SPair>* IRBlock::full_reg_assignment(vector<SPair>* spairs, SymArg& reg){
    vector<SPair>::iterator p, p2; 
    vector<SPair>* res, *prev;
    SymArg full_reg = ArgReg(reg.id(), reg.size()); 
    if( spairs->empty() || 
        (( reg.low() == 0 && reg.high() == reg.size()-1) && 
        (spairs->at(0).expr()->expr_ptr()->size() == reg.size())
        )
    )
        return new vector<SPair>(*spairs); 
        
    res = new vector<SPair>();
    prev = arg_to_spairs(full_reg); // We discard high/low because we want the full value ! 
    for(p = spairs->begin(); p != spairs->end(); p++ ){
        for(p2 = prev->begin(); p2 != prev->end(); p2++ ){
            if( res->size() >= MAX_VALUES_PER_ARG ){
                delete prev; 
                delete res; 
                throw too_many_values();
            }
            res->push_back(SPair(full_reg_assignment((*p).expr(), (*p2).expr(), reg), (*p).cond()));
        }
    }
    delete prev; 
    return res; 
}

/* Same than full_reg but for tmp values */ 
inline ExprObjectPtr IRBlock::full_tmp_assignment(ExprObjectPtr expr, SymArg& tmp){
    if( tmp.size() == expr->expr_ptr()->size() )
        return expr; 
    else{
        return expr->expr_ptr()->convert(tmp.size());
    }
}

vector<SPair>* IRBlock::full_tmp_assignment(vector<SPair>* spairs, SymArg& tmp){
    vector<SPair>::iterator p; 
    vector<SPair>* res;
    if( spairs->empty() || (spairs->at(0).expr()->expr_ptr()->size() == tmp.size()))
        return new vector<SPair>(*spairs); 
    res = new vector<SPair>();
    for(p = spairs->begin(); p != spairs->end(); p++ ){
        if( res->size() >= MAX_VALUES_PER_ARG ){
            delete res;
            throw too_many_values();
        }
        res->push_back(SPair(full_tmp_assignment((*p).expr(), tmp), (*p).cond()));
    }
    return res;
}

/* Returns the possible values for a calculation expression */ 
vector<SPair>* IRBlock::execute_calculation(IROperation op, vector<SPair>* src1, vector<SPair>*src2){
    vector<SPair>* res = new vector<SPair>(); 
    vector<SPair>::iterator arg1, arg2;
    for( arg1 = src1->begin(); arg1 != src1->end(); arg1++){
        for( arg2 = src2->begin(); arg2 != src2->end(); arg2++){
            if( res->size() > MAX_VALUES_PER_ARG )
                throw too_many_values();
            // Compute their combinaison 
            switch(op){
                case IR_ADD:
                    res->push_back( SPair((*arg1).expr()+(*arg2).expr(), (*arg1).cond() && (*arg2).cond())) ; 
                    break;
                case IR_AND:
                    res->push_back( SPair((*arg1).expr()&(*arg2).expr(), (*arg1).cond() && (*arg2).cond())) ;
                    break;
                case IR_BSH:
                    // Special processing of BSH, if the right arg is a constant, transform it into MUL or DIV 
                    if( arg2->expr()->expr_ptr()->type() == EXPR_CST ){
                        if( arg2->expr()->expr_ptr()->value() >= 0 )
                            res->push_back( SPair((*arg1).expr()*NewExprCst(std::pow(2,arg2->expr()->expr_ptr()->value()), arg1->expr()->expr_ptr()->size()), 
                                                  (*arg1).cond() && (*arg2).cond()));
                        else
                            res->push_back( SPair((*arg1).expr()/NewExprCst(std::pow(2,-1*arg2->expr()->expr_ptr()->value()), arg1->expr()->expr_ptr()->size()), 
                                                  (*arg1).cond() && (*arg2).cond()));
                    }else
                        res->push_back( SPair(Bsh((*arg1).expr(),(*arg2).expr()), (*arg1).cond() && (*arg2).cond())) ;
                    break;
                case IR_DIV:
                    res->push_back( SPair((*arg1).expr()/(*arg2).expr(), (*arg1).cond() && (*arg2).cond())) ;
                    break;
                case IR_MOD:
                    res->push_back( SPair((*arg1).expr()%(*arg2).expr(), (*arg1).cond() && (*arg2).cond())) ;
                    break;
                case IR_MUL:
                    res->push_back( SPair((*arg1).expr()*(*arg2).expr(), (*arg1).cond() && (*arg2).cond())) ;
                    break;
                case IR_OR:
                    res->push_back( SPair((*arg1).expr()|(*arg2).expr(), (*arg1).cond() && (*arg2).cond())) ;
                    break;
                case IR_SUB:
                    res->push_back( SPair((*arg1).expr()-(*arg2).expr(), (*arg1).cond() && (*arg2).cond())) ;
                    break;
                case IR_XOR:
                    res->push_back( SPair((*arg1).expr()^(*arg2).expr(), (*arg1).cond() && (*arg2).cond())) ;
                    break;
                default:
                    delete res; 
                    res = nullptr; 
                    throw_exception("Unknown type of calculation in IR in combine_args()");
            }
        }
    }
    return res; 
}

/* Executes a IR_STM instruction
 * src1 are the possible stored values
 * dst are the possible store addresses
 * mem_write_cnt = the number of stores done so far
 *
 * All the previous stored values are updated depending on the new one 
 * (overwritting) 
 */ 
void IRBlock::execute_stm(vector<SPair>* src1, vector<SPair>* dst, int& mem_write_cnt){
    int i;
    vector<SPair>::iterator value, addr, it;
    vector<SPair> *tmp, *prev;
    ExprObjectPtr prev_addr; 
    CondObjectPtr no_overwrite_cond; 
    int size; 
    // Get the possible values for the write address 
    for( addr = dst->begin(); addr != dst->end(); addr++){
        if( mem_write_cnt >= NB_MEM_MAX )
            throw_exception("Too many memory writes!");
        _mem_writes.push_back((*addr).expr()); // Update list of mem writes  
        tmp = new vector<SPair>();        
        // Get values for this write 
        size = src1->front().expr()->expr_ptr()->size(); // We assume all values have the same size 
        for( value = src1->begin();  value != src1->end(); value++)
            tmp->push_back(SPair((*value).expr(), (*value).cond() && (*addr).cond()));
        _mem_table[mem_write_cnt++] = make_pair((*addr).expr(), tmp);
        // Update all the previous ones to add the non-overwritten condition 
        for( i = mem_write_cnt-2; i >= 0; i--){
            // Get the i-th access SPairs
            std::tie(prev_addr, prev) = _mem_table[i];
            // Divide sizes by 8 to get sizes in bytes not bits (assume their are 8 multiples ! ) 
            no_overwrite_cond = (((*addr).expr()+NewExprCst((cst_t)(size/8-1), (*addr).expr()->expr_ptr()->size())) < prev_addr)
                            || 
                        ((prev_addr+NewExprCst((cst_t)(prev_addr->expr_ptr()->size()/8-1), prev_addr->expr_ptr()->size())) < (*addr).expr());
            // For each previous possible value, and the non-overwritten condition 
            for( value = prev->begin(); value != prev->end(); value++){
                (*value).set_cond( (*value).cond() && no_overwrite_cond );
            }
            // Add those possible values if overwritten
            for( it = tmp->begin(); it != tmp->end(); it++){
                prev->push_back( SPair( (*it).expr(), (*it).cond() && ((*addr).expr() == prev_addr)));
            }
        }
    }
}

/* Returns the possible values from a IR_LDM instruction
 * spair: is the address we are reading at 
 * size: the number of bits we read from 
 * mem_write_cnt = the number of memory writes so far 
 */  
vector<SPair>* IRBlock::execute_ldm(SPair& spair, int size, int mem_write_cnt){
    int i, write_size;
    ExprObjectPtr write_addr; 
    vector<SPair>* pairs, *res; 
    ExprObjectPtr addr = spair.expr();
    CondObjectPtr no_overwrite_cond = NewCondTrue();
    CondObjectPtr equal_cond, nequal_cond;
    vector<SPair>::iterator it; 
    
    _mem_reads.push_back(addr); // Update list of mem reads 
    res = new vector<SPair>(); 
    // For each memory access
    for( i = mem_write_cnt-1; i >= 0; i--){
        tie(write_addr, pairs) = _mem_table[i]; 
        // Get the condition for equal addresses
        equal_cond = (write_addr == addr);
        // Add the possible value(s)
        for(it = pairs->begin(); it != pairs->end(); it++){
            // TODO FIXEME ? Here we approximate if we read more than what we wrote
            if( size > (*it).expr()->expr_ptr()->size())
                res->push_back(SPair(
                    Concat( NewExprMem( addr+NewExprCst(
                                                (*it).expr()->expr_ptr()->size()/8,
                                                addr->expr_ptr()->size()), 
                                        size - (*it).expr()->expr_ptr()->size()
                                      ),
                            (*it).expr()),  
                    (*it).cond() && equal_cond  && spair.cond() )
                    );
            else if( size == (*it).expr()->expr_ptr()->size())
                res->push_back(SPair((*it).expr(),  (*it).cond() && equal_cond  && spair.cond() ));
            else
                res->push_back(SPair(Extract((*it).expr(), size-1, 0 ),  (*it).cond() && equal_cond  && spair.cond()));
        }
        write_size = (*pairs)[0].expr()->expr_ptr()->size(); 
        // Update the condition if different addresses
        nequal_cond =   ((write_addr+NewExprCst((cst_t)(write_size/8-1), write_addr->expr_ptr()->size())) < addr)
                        || 
                        ((addr+NewExprCst((cst_t)(size/8-1), addr->expr_ptr()->size())) < write_addr);
        no_overwrite_cond = no_overwrite_cond && nequal_cond; 
    } 
    // If all writes don't match the read, the value is the initial memory 
    res->push_back(SPair(NewExprMem( addr, size), no_overwrite_cond));
    return res; 
}

vector<SPair>* arg_to_unknown(SymArg& arg){
    vector<SPair> *res = new vector<SPair>();
    res->push_back(SPair(NewExprUnknown(arg.size()), NewCondTrue()));
    return res;
}

/* Symbolically executes the list of IRInstructions and returns a poitner tp
 * a Semantics instance containing this IRBlock semantics
 * 
 * !!! This function should be called only once per IRBlock or the program will
 * likely crash 
 */ 
Semantics* IRBlock::compute_semantics(bool discard_ignored_regs){
    vector<class IRInstruction>::iterator it; 
    Semantics* res;
    vector<SPair>* src1=nullptr, *src2=nullptr, *comb=nullptr, *dst=nullptr, *mem=nullptr, *tmp=nullptr;
    vector<SPair>::iterator pit;
    ExprObjectPtr addr; 
    int mem_write_cnt = 0, i, instr_count; 
    bool *instr_table;
    
    // If no instruction, return 
    if( _instr.empty() )
        return new Semantics();
    
    // Check if we ignore some instructions or not 
    instr_table = new bool[_instr.size()];
    if( discard_ignored_regs )
        this->filter_instructions(instr_table, _instr.size());
    else
        memset(instr_table, true, _instr.size());
    
    // Do symbolic execution 
    instr_count = 0;
    for( it = _instr.begin(); it != _instr.end(); ++it){    
        // If ignored, continue
        if( ! instr_table[instr_count++] ){
            continue;
        }
        // DEBUG
        //it->print(cout);
        // Else, execute
        try{
            // Skip instructions setting ignored registers 
            if( it->dst()->type() == ARG_REG && 
                curr_arch()->is_ignored_reg(it->dst()->id())){
                continue;
            }
            // Execute instruction
            if( is_calculation_instr((*it))){
                // Get src1 and src2
                src1 = this->arg_to_spairs(*(it->src1())); 
                src2 = this->arg_to_spairs(*(it->src2()));
                // Compute their combinaison 
                comb = this->execute_calculation(it->op(), src1, src2);
                delete src1; src1 = nullptr;
                delete src2; src2 = nullptr;
                if( it->dst()->type() == ARG_REG ){
                    assign_reg_table(it->dst()->id(), this->full_reg_assignment(comb, *(it->dst())));
                    delete comb; comb = nullptr;
                }else if( it->dst()->type() == ARG_TMP ){
                    assign_tmp_table(it->dst()->id(), this->full_tmp_assignment(comb, *(it->dst()))); 
                    delete comb; comb = nullptr;
                }else{
                    delete instr_table;
                    throw_exception("Invalid arg type for dst in IR calculation instruction"); 
                }
            }else if( it->op() == IR_STR ){
                src1 = this->arg_to_spairs(*(it->src1())); 
                if( it->dst()->type() == ARG_REG ){
                    assign_reg_table(it->dst()->id(), this->full_reg_assignment(src1, *(it->dst())));
                    delete src1; src1 = nullptr;
                }else if( it->dst()->type() == ARG_TMP ){
                    assign_tmp_table(it->dst()->id(), this->full_tmp_assignment(src1, *(it->dst())));
                    delete src1; src1 = nullptr;
                }else{
                    delete instr_table;
                    throw_exception("Invalid arg type for dst in IR_STR instruction"); 
                }
            }else if( it->op() == IR_STM ){
                src1 = this->arg_to_spairs(*(it->src1()));
                dst = this->arg_to_spairs(*(it->dst()));
                execute_stm(src1, dst, mem_write_cnt);
                delete src1; src1 = nullptr;
                delete dst; dst = nullptr;
            }else if( it->op() == IR_LDM){
                src1 = this->arg_to_spairs(*(it->src1()));
                mem = new vector<SPair>();
                // For all possible read address values, get the semantics  
                for(pit = src1->begin(); pit != src1->end(); pit++){
                    tmp = execute_ldm(*pit, it->dst()->size(), mem_write_cnt);
                    mem->insert(mem->end(), std::make_move_iterator(tmp->begin()), std::make_move_iterator(tmp->end()));
                    delete tmp;
                    tmp = nullptr;  
                }
                delete src1; src1=nullptr;
                if( it->dst()->type() == ARG_REG ){
                    assign_reg_table(it->dst()->id(), this->full_reg_assignment(mem, *(it->dst())));
                    delete mem; mem = nullptr;
                }else if( it->dst()->type() == ARG_TMP ){
                    assign_tmp_table(it->dst()->id(), this->full_tmp_assignment(mem, *(it->dst()))); 
                    delete mem; mem = nullptr;
                }else{
                    delete instr_table;
                    throw_exception("Invalid arg type for dst in IR_LDM instruction"); 
                }
            }else if( it->op() == IR_UNKNOWN ){
                if( it->dst()->type() == ARG_REG ){
                    assign_reg_table(it->dst()->id(), arg_to_unknown(*(it->dst())));
                }else if( it->dst()->type() == ARG_TMP ){
                    assign_tmp_table(it->dst()->id(), arg_to_unknown(*(it->dst())));
                }else{
                    delete instr_table;
                    throw_exception("Invalid arg type for dst in IR_UNKNOWN instruction"); 
                }
            }
        }catch(too_many_values& e){
            delete src1;
            delete src2; 
            delete mem;
            delete comb; 
            delete tmp;
            delete dst;
            return new Semantics(); // TODO faire remonter l'erreur et annuler le gadget pour test/opti ;) 
        }
    }
    
    // Fill the semantic object and return it
    res = new Semantics();
    // Register semantics 
    for( i = 0; i < NB_REGS_MAX; i++ ){
        if( _reg_modified[i] )
            res->add_reg( i, new vector<SPair>(*_reg_table[i]));
    }
    // Memory semantics 
    for( i = 0; i < mem_write_cnt; i++){
        std::tie(addr, tmp) = _mem_table[i];
        res->add_mem(addr, new vector<SPair>(*tmp));
    }
    
    _mem_write_cnt = mem_write_cnt; 
    return res; 
}

/* Detect tmp arguments that only go to ignored regs and ignore them
 * as well 
 * 
 * After execution, instr_table[i] = false means that we can ignore
 * this instrution when doing symbolic execution
 * */ 
void IRBlock::filter_instructions(bool *instr_table, int len){
    vector<class IRInstruction>::reverse_iterator it; 
    bool keep;
    bool tmp_table[NB_TMP_MAX];
    int i;
    
    memset(tmp_table, false, sizeof(tmp_table));
    memset(instr_table, false, len);
    i = len-1;
    for( it = _instr.rbegin(); it != _instr.rend(); ++it){
        keep = false;
        if( it->dst()->type() == ARG_REG ){
            keep = ! curr_arch()->is_ignored_reg(it->dst()->id());
        }else if( it->dst()->type() == ARG_TMP ){
            // If already marked as keep, does nothing
            // If store operation, then the tmp is the address so we don't ignore it! 
            if( it->op() == IR_STM )
                tmp_table[it->dst()->id()] = true;
            keep = tmp_table[it->dst()->id()]; 
        }
        if( it->src1()->type() == ARG_TMP )
            tmp_table[it->src1()->id()] |= keep;
        if( it->src2()->type() == ARG_TMP )
            tmp_table[it->src2()->id()] |= keep;
        instr_table[i--] |= keep;
    }
}


void IRBlock::print(ostream& os){
    vector<class IRInstruction>::iterator it; 
    for( it = _instr.begin(); it != _instr.end(); ++it){
        it->print(os);
    }
}


IRBlock::~IRBlock(){
    int i;
    for( i = 0; i < NB_REGS_MAX; i++ ){
        if( _reg_table[i] != nullptr ){
            delete _reg_table[i];
            _reg_table[i] = nullptr; 
        }
    }
    for( i = 0; i < NB_TMP_MAX; i++ ){
        if( _tmp_table[i] != nullptr ){
            delete _tmp_table[i];
            _tmp_table[i] = nullptr; 
        }
    }
    for( i = 0; i < _mem_write_cnt; i++ ){
        if( _mem_table[i].second != nullptr){
            delete _mem_table[i].second; 
            _mem_table[i].second = nullptr; 
        }
    }
}
