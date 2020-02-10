#ifndef DATABASE_H
#define DATABASE_H

#include <iostream>
#include <tuple>
#include <unordered_map>
#include "utils.hpp"
#include "expression.hpp"
#include "ropchain.hpp"
#include "arch.hpp"

using std::pair;
using std::tuple;
using std::make_tuple;
using std::unordered_map;

typedef int gadget_t; 

#define NO_GADGET -1

#define DB_MAX_REGS 64

// Types of gadgets supported in database
enum class GadgetType{
    NOP,
    // Register to register
    MOV_CST,    // reg <- cst
    MOV_REG,    // reg <- reg
    AMOV_CST,   // reg <- reg OP cst
    AMOV_REG,   // reg <- reg OP reg
    // Read from memory
    LOAD,       // reg <- mem(reg + offset)
    ALOAD,      // reg OP<- mem(reg + offset)
    // Store to memory
    STORE,      // mem(reg + offset) <- reg
    ASTORE,     // mem(reg + offset) OP<- reg
    // jump
    JMP,     // PC <- reg
    // Syscalls
    SYSCALL,
    INT80
};

/* PossibleGadgets
   ===============
    This class holds query results to the database where some parameters
    are 'free' (ie eax = ebx + X where X is not fixed)
*/

class PossibleGadgets{
public:
    vector<pair<vector<cst_t>, vector<Gadget*>*>> gadgets; // Pointers to vector<Gadget*> are not owned! 
    int size(){return gadgets.size();};
    vector<Gadget*>& get_gadgets(int i){return *(gadgets[i].second);};
    cst_t get_param(int i, int p){return gadgets[i].first[p];};
    PossibleGadgets(){};
    PossibleGadgets(const PossibleGadgets& other){
        gadgets = std::move(other.gadgets);
    };
};


// Generic database for different kinds of gadgets
int find_insert_index(vector<Gadget*>& gadget_list, Gadget* gadget);
int find_insert_index_possible_gadgets(PossibleGadgets* possible, Gadget* gadget);

template<class K> 
class BaseDB{
public:
    unordered_map<K, vector<Gadget*>> db;

    // Template methods
    void add(K key, Gadget* gadget){
        vector<Gadget*>::iterator it;
        int index;
        if( db.count(key) > 0 ){
            index = find_insert_index(db[key], gadget);
            db[key].insert(db[key].begin()+index, gadget);
        }else{
            db[key] = vector<Gadget*>{gadget};
        }
    }

    const vector<Gadget*>& get(K key){
        typename unordered_map<K, vector<Gadget*>>::iterator it;
        if( (it = db.find(key)) == db.end()){
            db[key] = vector<Gadget*>{};
            return db[key];
        }else{
            return it->second;
        }
    }
    
    bool _check_key_match(const K& key1, const K& key2, bool* param_is_free, int nb_params){
        auto a1 = tuple_to_array(key1);
        auto a2 = tuple_to_array(key2);
        for( int p = 0; p < a1.size(); p++){
            if( !param_is_free[p] && !(a1[p] == a2[p]))
                return false;
        }
        return true;
    }

    PossibleGadgets* get_possible(K key, bool* param_is_free, int nb_params){
        PossibleGadgets* res = new PossibleGadgets();
        int index;
        for( auto& it : db ){
            // Check if key matches
            if( !it.second.empty() && _check_key_match(key, it.first, param_is_free, nb_params)){
                vector<cst_t> vec = tuple_to_vector(it.first);
                index = find_insert_index_possible_gadgets(res, it.second[0]);
                res->gadgets.insert(res->gadgets.begin()+index, std::make_pair(vec, &(it.second)));
            }
        }
        return res;
    }
    
    void clear(){
        db.clear();
    }
};

// Big gadget database

typedef int op_t;
class GadgetDB{
    // Map of raw gadget strings that have already be analysed 
    unordered_map<string, Gadget*> seen;
public:
    // Global gadgets lisst (gadgets are owned)
    vector<Gadget*> all;
    // Databases for all different gadgets types
    BaseDB<tuple<reg_t, cst_t>> mov_cst;
    BaseDB<tuple<reg_t, reg_t>> mov_reg;
    BaseDB<tuple<reg_t, reg_t, op_t, cst_t>> amov_cst;
    BaseDB<tuple<reg_t, reg_t, op_t, reg_t>> amov_reg;
    BaseDB<tuple<reg_t, reg_t, addr_t>> load;
    BaseDB<tuple<reg_t, op_t, reg_t, addr_t>> aload;
    BaseDB<tuple<reg_t, addr_t, reg_t>> store;
    BaseDB<tuple<reg_t, addr_t, op_t, reg_t>> astore;
    BaseDB<reg_t> jmp;
    BaseDB<int> syscall; // <int> key is always 0
    BaseDB<int> int80; // <int> key is always 0

    // Add and classify a gadget in the database
    gadget_t add(Gadget* gadget, Arch* arch);
    // Analyse raw gadgets and fill the database accordingly
    // return the number of successfuly analysed gadgets
    int analyse_raw_gadgets(vector<RawGadget>& raw_gadgets, Arch* arch);
    // Get a gadget by id
    Gadget* get(gadget_t gadget_num);
    
    // Get gadgets semantically
    const vector<Gadget*>& get_mov_cst(reg_t reg, cst_t cst);
    const vector<Gadget*>& get_mov_reg(reg_t dst_reg, reg_t src_reg);
    const vector<Gadget*>& get_amov_cst(reg_t dst_reg, reg_t src_reg, Op op, cst_t src_cst);
    const vector<Gadget*>& get_amov_reg(reg_t dst_reg, reg_t src_reg1, Op op, reg_t src_reg2);
    const vector<Gadget*>& get_load(reg_t dst_reg, reg_t addr_reg, cst_t offset);
    const vector<Gadget*>& get_aload(reg_t dst_reg, Op op, reg_t addr_reg, cst_t offset);
    const vector<Gadget*>& get_jmp(reg_t jmp_reg);
    const vector<Gadget*>& get_store(reg_t addr_reg, cst_t offset, reg_t src_reg);
    const vector<Gadget*>& get_astore(reg_t addr_reg, cst_t offset, Op op, reg_t src_reg);
    const vector<Gadget*>& get_syscall();
    const vector<Gadget*>& get_int80();

    // Get gadgets with optional parameters
    PossibleGadgets* get_possible_mov_cst(reg_t reg, cst_t cst, bool* param_is_free);
    PossibleGadgets* get_possible_mov_reg(reg_t dst_reg, reg_t src_reg, bool* param_is_free);
    PossibleGadgets* get_possible_amov_cst(reg_t dst_reg, reg_t src_reg, Op op, cst_t src_cst, bool* param_is_free);
    PossibleGadgets* get_possible_amov_reg(reg_t dst_reg, reg_t src_reg1, Op op, reg_t src_reg2, bool* param_is_free);
    PossibleGadgets* get_possible_load(reg_t dst_reg, reg_t addr_reg, cst_t offset, bool* param_is_free);
    PossibleGadgets* get_possible_aload(reg_t dst_reg, Op op, reg_t addr_reg, cst_t offset, bool* param_is_free);
    PossibleGadgets* get_possible_jmp(reg_t jmp_reg, bool* param_is_free);
    PossibleGadgets* get_possible_store(reg_t addr_reg, cst_t offset, reg_t src_reg, bool* param_is_free);
    PossibleGadgets* get_possible_astore(reg_t addr_reg, cst_t offset, Op op, reg_t src_reg, bool* param_is_free);

    // Clear
    void clear();

    // Destructor
    ~GadgetDB();
};

#endif
