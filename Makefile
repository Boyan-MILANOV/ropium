CC = gcc
CXX = g++

OUTDIR = ./bin
LIB_FILE = libropgenerator.so
BINDINGS_FILE = ropgenerator.so

## Basic default flags 
CFLAGS ?=
CXXFLAGS ?=
CXXFLAGS ?=
LDFLAGS ?=
LDLIBS ?=
LDLIBS += -lcapstone

## Flags for debug mode
DEBUG ?= 0
ifeq ($(DEBUG), 1)
	CFLAGS += -g -O0
	CXXFLAGS += -g -O0
	LDFLAGS += -g
else
	CFLAGS += -O2
	CXXFLAGS += -O2
endif

## Final C++ flags
CXXFLAGS += -std=c++11 -fPIC -I librop/include -I librop/dependencies/murmur3 -Wno-write-strings -Wno-sign-compare -Wno-reorder

# Source files
SRCDIR=./librop
SRCS=$(wildcard $(SRCDIR)/symbolic/*.cpp)
SRCS+=$(wildcard $(SRCDIR)/ir/*.cpp)
SRCS+=$(wildcard $(SRCDIR)/arch/*.cpp)
SRCS+=$(wildcard $(SRCDIR)/ropchain/*.cpp)
SRCS+=$(wildcard $(SRCDIR)/utils/*.cpp)
SRCS+=$(wildcard $(SRCDIR)/database/*.cpp)
OBJS=$(SRCS:.cpp=.o)

TESTDIR = ./tests
TESTSRCS = $(wildcard $(TESTDIR)/*.cpp)
TESTOBJS = $(TESTSRCS:.cpp=.o)

DEPDIR = ./librop/dependencies
DEPSRCS = $(DEPDIR)/murmur3/murmur3.c 
DEPOBJS = $(DEPSRCS:.c=.o)

INCLUDEDIR = ./librop/include

# Compile lib and tests 
all: lib tests

# librop
lib: $(OBJS) $(DEPOBJS)
	$(CXX) $(CXXFLAGS) $(LDFLAGS) -o $(OUTDIR)/libropgenerator.so -shared $(OBJS) $(DEPOBJS) $(LDLIBS)

# unit tests
tests: $(TESTOBJS) $(OBJS) $(DEPOBJS)
	$(CXX) $(CXXFLAGS) $(LDFLAGS) -o $(OUTDIR)/tests $(TESTOBJS) $(OBJS) $(DEPOBJS) $(LDLIBS)

# generic 
%.o : %.cpp
	$(CXX) $(CXXFLAGS) $(LDFLAGS) -c $< -o $@ $(LDLIBS)

%.o : %.c
	$(CC) $(CFLAGS) $(LDFLAGS) -c $< -o $@ $(LDLIBS)

# Installation (assuming Linux system) 
# If prefix not set, set default
ifeq ($(PREFIX),)
    PREFIX = /usr
endif

# Check if lib and binding files exist
ifneq (,$(wildcard ./bin/libropgenerator.so))
    INSTALL_LIB_RULE=install_lib
else
	INSTALL_LIB_RULE=
endif
ifneq (,$(wildcard ./bin/ropgenerator.so)) 
    INSTALL_BINDINGS_RULE=install_bindings
    PYTHONDIR=$(shell python3 -m site --user-site)/
else
	INSTALL_BINDINGS_RULE=
endif

# make install command
install: $(INSTALL_LIB_RULE) $(INSTALL_BINDINGS_RULE)
	@echo "ROPGenerator libraries were successfully installed."

install_lib:
	install -d $(DESTDIR)$(PREFIX)/lib/
	install -D $(OUTDIR)/libropgenerator.so $(DESTDIR)$(PREFIX)/lib/
	install -d $(DESTDIR)$(PREFIX)/include/
#	install -D $(INCLUDEDIR)/ropgenerator.hpp $(DESTDIR)$(PREFIX)/include/

install_bindings:
	install -d $(PYTHONDIR)
	install -D $(OUTDIR)/ropgenerator.so $(PYTHONDIR)

# make test command
test:
	$(OUTDIR)/tests

# cleaning 
cleanall: clean

clean:
	rm -f $(OBJS)
	rm -f $(DEPOBJS)
	rm -f $(TESTOBJS)
	rm -f $(BINDINGS_OBJS)
	rm -f `find . -type f -name "*.gch"`
	rm -f $(OUTDIR)/*

