<p align="center" >
<img width=75% src="/ressources/ascii_screen.png"/><br />
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

# Installation
Frist install [pybind11](https://github.com/pybind/pybind11): 

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
## Load & Analyze binary 
<p align="center">
  <img src="/ressources/load.gif" width="800" align="middle">
</p>

## Find ROP-chains
<p align="center">
  <img src="/ressources/find.gif" width="1100" align="middle">
</p>

