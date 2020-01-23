#ifndef EXCEPTION_H
#define EXCEPTION_H

#include <sstream>
#include <string>
#include <exception>

using std::string;

/* From stackoverflow */
class QuickFmt{
public:
    QuickFmt() {}
    ~QuickFmt() {}

    template <typename Type>
    QuickFmt & operator << (const Type & value)
    {
        stream_ << value;
        return *this;
    }

    std::string str() const         { return stream_.str(); }
    operator std::string () const   { return stream_.str(); }

    enum ConvertToString 
    {
        to_str
    };
    std::string operator >> (ConvertToString) { return stream_.str(); }

private:
    std::stringstream stream_;

    QuickFmt(const QuickFmt &);
    QuickFmt & operator = (QuickFmt &);
};

/* Generic exception 
 * This exception is thrown when an unexpected error or inconsistency occurs
 * and execution should not continue */
class runtime_exception: public std::exception {
    string _msg;
public:
    explicit runtime_exception(string msg): _msg(msg){};
    virtual const char * what () const throw () {
      return _msg.c_str();
   }
};

/* Expression exception */
class expression_exception: public std::exception {
    string _msg;
public:
    explicit expression_exception(string msg): _msg(msg){};
    virtual const char * what () const throw () {
      return _msg.c_str();
   }
};

class ir_exception: public std::exception {
    string _msg;
public:
    explicit ir_exception(string msg): _msg(msg){};
    virtual const char * what () const throw () {return _msg.c_str();}
};

class il_exception: public std::exception {
    string _msg;
public:
    explicit il_exception(string msg): _msg(msg){};
    virtual const char * what () const throw () {return _msg.c_str();}
};

class strategy_exception: public std::exception {
    string _msg;
public:
    explicit strategy_exception(string msg): _msg(msg){};
    virtual const char * what () const throw () {return _msg.c_str();}
};

/* Symbolic Exception */
class symbolic_exception: public std::exception {
    string _msg;
public:
    explicit symbolic_exception(string msg): _msg(msg){};
    virtual const char * what () const throw () {
      return _msg.c_str();
   }
}; 

class unsupported_instruction_exception: public std::exception {
    string _msg;
public:
    explicit unsupported_instruction_exception(string msg): _msg(msg){};
    virtual const char * what () const throw () {
      return _msg.c_str();
   }
}; 

class illegal_instruction_exception: public std::exception {
    string _msg;
public:
    explicit illegal_instruction_exception(string msg): _msg(msg){};
    virtual const char * what () const throw () {
      return _msg.c_str();
   }
}; 

/* Test exception */ 
class test_exception : public std::exception {
   const char * what () const throw () {
      return "Unit test failure";
   }
};

#endif
