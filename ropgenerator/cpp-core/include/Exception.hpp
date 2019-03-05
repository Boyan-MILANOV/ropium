#ifndef EXCEPTION_H
#define EXCEPTION_H
#include <sstream>
#include <string>
#include <exception>


class ExceptionFormatter{
public:
    ExceptionFormatter() {}
    ~ExceptionFormatter() {}

    template <typename Type>
    ExceptionFormatter & operator << (const Type & value)
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

    ExceptionFormatter(const ExceptionFormatter &);
    ExceptionFormatter & operator = (ExceptionFormatter &);
};

void throw_exception(std::string s);

/* Sigint */ 
struct SigIntException : public std::exception {
   const char * what () const throw () {
      return "SIGINT Exception";
   }
};


#endif 
