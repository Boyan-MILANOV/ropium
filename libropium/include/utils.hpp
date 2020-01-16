#ifndef UTILS_H
#define UTILS_H

#include <string>
#include <cstdint>
#include <vector>
#include "expression.hpp"

using std::string;
using std::vector;

/* ======== Raw gadgets interface ======== */
class RawGadget{
public:
    RawGadget(){};
    RawGadget(string r, uint64_t a):raw(r), addr(a){}
    string raw;
    uint64_t addr;
};

// Read gadgets from file
vector<RawGadget>* raw_gadgets_from_file(string filename);
// Write gadgets to file from ROPgadget output
bool ropgadget_to_file(string filename, string bin);

/* ========= Support for hashing tuples ========== */
#include <tuple>
// function has to live in the std namespace 
// so that it is picked up by argument-dependent name lookup (ADL).
namespace std{
    namespace
    {
        // Code from boost
        // Reciprocal of the golden ratio helps spread entropy
        //     and handles duplicates.
        // See Mike Seymour in magic-numbers-in-boosthash-combine:
        //     https://stackoverflow.com/questions/4948780

        template <class T>
        inline void hash_combine(std::size_t& seed, T const& v)
        {
            seed ^= hash<T>()(v) + 0x9e3779b9 + (seed<<6) + (seed>>2);
        }

        // Recursive template code derived from Matthieu M.
        template <class Tuple, size_t Index = std::tuple_size<Tuple>::value - 1>
        struct HashValueImpl
        {
          static void apply(size_t& seed, Tuple const& tuple)
          {
            HashValueImpl<Tuple, Index-1>::apply(seed, tuple);
            hash_combine(seed, get<Index>(tuple));
          }
        };

        template <class Tuple>
        struct HashValueImpl<Tuple,0>
        {
          static void apply(size_t& seed, Tuple const& tuple)
          {
            hash_combine(seed, get<0>(tuple));
          }
        };
    }

    template <typename ... TT>
    struct hash<std::tuple<TT...>> 
    {
        size_t
        operator()(std::tuple<TT...> const& tt) const
        {                                              
            size_t seed = 0;                             
            HashValueImpl<std::tuple<TT...> >::apply(seed, tt);    
            return seed;                                 
        }                                              

    };
}


/* ========= Convert tuples to array/vector ================= */
template<int... Indices>
struct indices {
    using next = indices<Indices..., sizeof...(Indices)>;
};

template<int Size>
struct build_indices {
    using type = typename build_indices<Size - 1>::type::next;
};

template<>
struct build_indices<0> {
    using type = indices<>;
};

template<typename T>
using Bare = typename std::remove_cv<typename std::remove_reference<T>::type>::type;

template<typename Tuple>
constexpr
typename build_indices<std::tuple_size<Bare<Tuple>>::value>::type
make_indices()
{ return {}; }

template<typename Tuple, int... Indices>
std::array<
  cst_t,
    std::tuple_size<Bare<Tuple>>::value
>
to_array(Tuple&& tuple, indices<Indices...>)
{
    using std::get;
    return {{ get<Indices>(std::forward<Tuple>(tuple))... }};
}

template<typename Tuple>
auto tuple_to_array(Tuple&& tuple)
-> decltype( to_array(std::declval<Tuple>(), make_indices<Tuple>()) )
{
    return to_array(std::forward<Tuple>(tuple), make_indices<Tuple>());
}

template<typename Tuple>
vector<cst_t> tuple_to_vector(Tuple&& tuple)
{
    auto array = tuple_to_array(tuple);
    vector<cst_t> res;
    for( auto& a : array ){
        res.push_back(a);
    }
    return res;
}

/* =============== Printing stuff =============== */
#define DEFAULT_ERROR_COLOR_ANSI  "\033[91m"
#define DEFAULT_BOLD_COLOR_ANSI  "\033[1m"
#define DEFAULT_SPECIAL_COLOR_ANSI  "\033[93m"
#define DEFAULT_PAYLOAD_COLOR_ANSI "\033[96m"
#define DEFAULT_EXPLOIT_DESCRIPTION_ANSI  "\033[95m"
#define DEFAULT_END_COLOR_ANSI "\033[0m"

string str_bold(string s);
string str_special(string s);

string value_to_hex_str(int octets, addr_t addr);
#endif
