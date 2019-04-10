<p align="center" >
<img width=75% src="/ressources/ascii_screen.png"/><br /><br /><br />
</p>

# About

ROPGenerator is a tool that makes ROP-exploits easy. It automatically extracts and analyses gadgets from binaries and
lets you find ROP-chains with semantic queries. The tool supports *X86* and *X64* architectures, soon to be 
extended with *ARM*. 

Key features:

   - **Effortless**: ROPGenerator works out-of-the-box with a smooth Command Line Interface
   - **Automatic chaining**: ROPGenerator automatically combines gadgets to create complex ROP-chains
   - **Semantic queries**: ROPGenerator queries are quick and convenient to write : ``rax=rbx+8``, ``mem(rdi+0x20)=rax``, ``rsi=mem(rbx+16)/2``, ``strcpy(0x1234, "awesome!\x00")``, ``...``
   - **Advanced features**: ROPGenerator supports ROP-chains involving function calls, syscalls, strings, ... 
     
     
# Content
- [About](#about)
- [Installation](#installation)
- [Getting started](#getting-started)
   - [Load a binary](#load-a-binary)
   - [Find ROP-chains](#find-rop-chains)
   - [Call functions](#call-functions)
- [Contact](#contact)
- [Licence](#licence)
- [Special thanks](#special-thanks)

# Installation
First install [pybind11](https://github.com/pybind/pybind11): 

      sudo apt install python3-dev
      apt install cmake
      git clone https://github.com/pybind/pybind11 && cd pybind11 
      mkdir build
      cd build
      cmake ..
      make check -j 4

Then you need the latest [ROPgadget](https://github.com/JonathanSalwan/ROPgadget) release: 

      sudo pip install capstone
      git clone https://github.com/JonathanSalwan/ROPgadget && cd ROPgadget
      python setup.py install 

Finally install and run ROPGenerator:

      git clone https://github.com/Boyan-MILANOV/ropgenerator && cd ropgenerator
      python3 setup.py install --user
      ROPGenerator 

# Getting started
### Load a binary 
<p align="center">
  <img src="/ressources/load.gif" width="750" align="middle">
</p>

### Find ROP-chains
<p align="center">
  <img src="/ressources/find.gif" width="800" align="middle">
</p>

### Call functions
<p align="center">
  <img src="/ressources/function.gif" width="800" align="middle">
</p>

# Contact
**Boyan MILANOV** - bmilanov (at) quarkslab (dot) com 

# Licence
ROPGenrator is provided under the MIT licence.

# Special thanks
ROPGenerator uses the following awesome projects: 
   - [BARF](https://github.com/programa-stic/barf-project) : Binary Analysis and Reverse Engineering plateform
   - [LIEF](https://github.com/lief-project/LIEF) : Binary Parsing and Instrumentation library 
   - [ROPgadget](https://github.com/JonathanSalwan/ROPgadget) : Gadget extractor
   - [prompt-toolkit](https://github.com/prompt-toolkit/python-prompt-toolkit) : Python CLI interface library 
