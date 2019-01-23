#include "Exception.hpp"
#include <stdexcept>
#include <iostream>

using std::cout;

void throw_exception(std::string s){
    throw std::runtime_error(ExceptionFormatter() << s >> ExceptionFormatter::to_str);
}
