CC = gcc
CXX = g++

OUTDIR = ./bin
LIB_FILE = libropium.so
LIB_HEADER_FILE = ropium.hpp
BINDINGS_FILE = ropium.so

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
	CXXFLAGS += -O2 -Wno-narrowing
endif

## Bindings
BINDINGS ?= 1
ifeq ($(BINDINGS), 1)
	CXXFLAGS += `python3-config --cflags` -DPYTHON_BINDINGS -Ibindings/python
	BINDINGS_DIR = ./bindings
	BINDINGS_SRCS = $(wildcard $(BINDINGS_DIR)/*.cpp)
	BINDINGS_OBJS = $(BINDINGS_SRCS:.cpp=.o)
	BINDINGS_RULE = bindings
	LDLIBS += `python3-config --libs`
else
	BINDINGS_RULE = 
endif

SRCDIR=./libropium

## Final C++ flags
CXXFLAGS += -std=c++11 -fpermissive -fPIC -I $(SRCDIR)/include -I $(SRCDIR)/dependencies/murmur3 -Wno-write-strings -Wno-sign-compare -Wno-reorder

# Source files
SRCS=$(wildcard $(SRCDIR)/symbolic/*.cpp)
SRCS+=$(wildcard $(SRCDIR)/ir/*.cpp)
SRCS+=$(wildcard $(SRCDIR)/arch/*.cpp)
SRCS+=$(wildcard $(SRCDIR)/ropchain/*.cpp)
SRCS+=$(wildcard $(SRCDIR)/utils/*.cpp)
SRCS+=$(wildcard $(SRCDIR)/database/*.cpp)
SRCS+=$(wildcard $(SRCDIR)/compiler/*.cpp)
OBJS=$(SRCS:.cpp=.o)

TESTDIR = ./tests
TESTSRCS = $(wildcard $(TESTDIR)/*.cpp)
TESTOBJS = $(TESTSRCS:.cpp=.o)

DEPDIR = $(SRCDIR)/dependencies
DEPSRCS = $(DEPDIR)/murmur3/murmur3.c 
DEPOBJS = $(DEPSRCS:.c=.o)

INCLUDEDIR = $(SRCDIR)/include

# Compile lib and tests 
all: lib tests $(BINDINGS_RULE)

# librop
lib: $(OBJS) $(DEPOBJS)
	$(CXX) $(CXXFLAGS) $(LDFLAGS) -o $(OUTDIR)/$(LIB_FILE) -shared $(OBJS) $(DEPOBJS) $(LDLIBS)

# unit tests
tests: $(TESTOBJS) $(OBJS) $(DEPOBJS)
	$(CXX) $(CXXFLAGS) $(LDFLAGS) -o $(OUTDIR)/tests $(TESTOBJS) $(OBJS) $(DEPOBJS) $(LDLIBS)

# bindings
bindings: $(BINDINGS_OBJS) $(OBJS) $(DEPOBJS)
	$(CXX) $(CXXFLAGS) $(LDFLAGS) -o $(OUTDIR)/$(BINDINGS_FILE) -shared $(BINDINGS_OBJS) $(OBJS) $(DEPOBJS) $(LDLIBS)

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

INSTALL_MESSAGE_RULE=
# Check if lib and binding files exist
ifneq (,$(wildcard ./bin/$(LIB_FILE)))
    INSTALL_LIB_RULE=install_lib
	INSTALL_MESSAGE_RULE=print_install_message
else
	INSTALL_LIB_RULE=
endif
ifneq (,$(wildcard ./bin/$(BINDINGS_FILE))) 
    INSTALL_BINDINGS_RULE=install_bindings
    PYTHONDIR=$(shell python3 -m site --user-site)/
	INSTALL_MESSAGE_RULE=print_install_message
else
	INSTALL_BINDINGS_RULE=
endif

# make install command
install: $(INSTALL_LIB_RULE) $(INSTALL_BINDINGS_RULE) install_cli_tool $(INSTALL_MESSAGE_RULE)

install_lib:
	install -d $(DESTDIR)$(PREFIX)/lib/
	install -D $(OUTDIR)/$(LIB_FILE) $(DESTDIR)$(PREFIX)/lib/
	install -d $(DESTDIR)$(PREFIX)/include/
	install -D $(INCLUDEDIR)/$(LIB_HEADER_FILE) $(DESTDIR)$(PREFIX)/include/

install_bindings:
	install -d $(PYTHONDIR)
	install -D $(OUTDIR)/$(BINDINGS_FILE) $(PYTHONDIR)

install_cli_tool:
	install -D cli-tool/ropium $(DESTDIR)$(PREFIX)/bin/

print_install_message:
	@echo "\nROPium was successfully installed."

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
