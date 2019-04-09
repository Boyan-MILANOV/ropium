<p align="center" >
<img src="/ressources/ascii_screen.png"/><br />
</p>

# About

ROPGenerator is a tool that makes ROP-exploits easy. It automatically extracts and analyses gadgets from binaries and
lets you find ROP-chains with semantic queries. The tool supports *X86* and *X64* architectures, soon to be 
extended with *ARM*. 

Key features:

   - **Automatic chaining**: ROPGenerator automatically combines gadgets to create complex ROP-chains
   - **Semantic queries**: ROPGenerator builds ROP-chains from simple queries: ``rax=rbx+8``, ``mem(rdi+0x20)=rax``, ``...``
   - **Functions**: ROPGenerator supports calling functions with different conventions: ``System V AMD64``, ``CDECL``,  ``...`` 
   - **Syscalls**: ROPGenerator can build chains for various syscalls: ``execve()``, ``setuid()``, ``mmap()``, ``...`` 
     
     
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

Finally install ROPGenerator:

      git clone https://github.com/Boyan-MILANOV/ropgenerator && cd ropgenerator
      python3 setup.py install --user


# Getting started
TODO
