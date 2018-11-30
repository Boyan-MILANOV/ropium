# Declaration of variables
CC = g++
#CC_FLAGS = -std=c++11 -Wall -Wextra -pedantic 
CC_FLAGS = -std=c++11 -fpermissive 
 
# File names
SOURCES = $(wildcard *.cpp)
OBJECTS = $(SOURCES:.cpp=.o)
 
# To obtain object files
all: $(OBJECTS)	

%.o: %.cpp
	$(CC) -c $(CC_FLAGS) $< -o $@
 
# To remove generated files
clean:
	rm -f $(OBJECTS)
