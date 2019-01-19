#include "Exception.hpp"
#include <stdexcept>

void throw_exception(std::string s){
    throw std::runtime_error(ExceptionFormatter() << s >> ExceptionFormatter::to_str);
}
