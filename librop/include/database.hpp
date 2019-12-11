#ifndef DATABASE_H
#define DATABASE_H

#include <iostream>
#include <tuple>
#include <unordered_map>
#include "utils.hpp"
#include "expression.hpp"
#include "ropchain.hpp"
#include "arch.hpp"

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
};

// Generic database for different kinds of gadgets
int find_insert_index(vector<Gadget*>& gadget_list, Gadget* gadget);

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

    vector<Gadget*>& get(K key){
        typename unordered_map<K, vector<Gadget*>>::iterator it;
        if( (it = db.find(key)) == db.end()){
            db[key] = vector<Gadget*>{};
            return db[key];
        }else{
            return it->second;
        }
    }
};

// Big gadget database
class GadgetDB{
public:
    // Global gadgets lisst (gadgets are owned)
    vector<Gadget*> all;
    // Databases for all different gadgets types
    BaseDB<tuple<reg_t, cst_t>> mov_cst;
    BaseDB<tuple<reg_t, reg_t>> mov_reg;
    BaseDB<tuple<reg_t, reg_t, Op, cst_t>> amov_cst;
    BaseDB<tuple<reg_t, reg_t, Op, reg_t>> amov_reg;
    BaseDB<tuple<reg_t, reg_t, addr_t>> load;
    BaseDB<tuple<reg_t, Op, reg_t, addr_t>> aload;
    BaseDB<tuple<reg_t, addr_t, reg_t>> store;
    BaseDB<tuple<reg_t, addr_t, Op, reg_t>> astore;
    BaseDB<reg_t> jmp;

    // Add and classify a gadget in the database
    gadget_t add(Gadget* gadget, Arch* arch);
    // Analyse raw gadgets and fill the database accordingly
    // return the number of successfuly analysed gadgets
    int fill_from_raw_gadgets(vector<RawGadget>& raw_gadgets, Arch* arch);
    // Get a gadget by id
    Gadget* get(gadget_t gadget_num);
    
    // Get gadgets semantically
    vector<Gadget*>& get_mov_cst(reg_t reg, cst_t cst);
    vector<Gadget*>& get_mov_reg(reg_t dst_reg, reg_t src_reg);
    vector<Gadget*>& get_amov_cst(reg_t dst_reg, reg_t src_reg, Op op, cst_t src_cst);
    vector<Gadget*>& get_amov_reg(reg_t dst_reg, reg_t src_reg1, Op op, reg_t src_reg2);
    vector<Gadget*>& get_load(reg_t dst_reg, reg_t addr_reg, cst_t offset);
    vector<Gadget*>& get_aload(reg_t dst_reg, Op op, reg_t addr_reg, cst_t offset);
    vector<Gadget*>& get_jmp(reg_t jmp_reg);
    vector<Gadget*>& get_store(reg_t addr_reg, cst_t offset, reg_t src_reg);
    vector<Gadget*>& get_astore(reg_t addr_reg, cst_t offset, Op op, reg_t src_reg);
    
    // Destructor
    ~GadgetDB();
};


#endif
