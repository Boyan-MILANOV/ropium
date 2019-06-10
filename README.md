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
   - [Use constraints](#use-constraints)
   - [Call functions](#call-functions)
   - [Make syscalls](#make-syscalls)
   - [Alloc-Copy-Execute shellcode](#alloc-copy-execute-shellcode)
- [Docker](#docker)
- [Contact](#contact)
- [Licence](#licence)
- [Special thanks](#special-thanks)

# Installation
First install [pybind11](https://github.com/pybind/pybind11): 

      sudo apt install python3-dev
      sudo apt install cmake
      pip3 install pytest 
      pip3 install pybind11
      git clone https://github.com/pybind/pybind11 && cd pybind11 
      mkdir build && cd build
      cmake ..
      make check -j 4

Then install [BARF](https://github.com/programa-stic/barf-project):

      git clone https://github.com/programa-stic/barf-project && cd barf-project
      python3 setup.py install --user

You also need the latest [ROPgadget](https://github.com/JonathanSalwan/ROPgadget) release: 

      pip install capstone
      git clone https://github.com/JonathanSalwan/ROPgadget && cd ROPgadget
      python setup.py install --user 

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

### Use constraints
ROPGenerator support many options for ROP-chains, including: 
   - Bad bytes to avoid
   - Registers that shouldn't be clobbered 
   - Offset to add to gadget addresses 
   - Maximum length 
   - Output format (*raw*, *python code*, ...)

<p align="center">
  <img src="/ressources/options.gif" width="800" align="middle">
</p>

### Call functions
<p align="center">
  <img src="/ressources/function.gif" width="800" align="middle">
</p>

### Make syscalls
<p align="center">
  <img src="/ressources/syscall.gif" width="800" align="middle">
</p>

### Alloc-Copy-Execute shellcode
You can save shellcodes in ROPGenerator, then use them with advanced commands, such as **ace** which automatically delivers the shellcode in memory, makes the memory executable, and jumps to execute it

<p align="center">
  <img src="/ressources/ace.gif" width="800" align="middle">
</p>

# Docker

If needed you can run ROPGenerator in a docker container. The container can be generated from the *Dockerfile* as
follows:

```bash
# Create your docker image (this will take time!)
docker build . --tag boyan:ropgenerator

# Run the image in interactive mode and start ROPGenerator 
docker run -it boyan:ropgenerator bash
root@c7117e962741:/# ROPGenerator

▒▒▒▒▒▒▒╗░▒▒▒▒▒▒╗░▒▒▒▒▒▒  ═════════════════════════
▒▒╔══▒▒║▒▒╔═══▒▒╗▒▒╔══▒╗
▒▒▒▒▒▒╔╝▒▒║   ▒▒║▒▒▒▒▒▒║ G  E  N  E  R  A  T  O  R
▒▒╔══▒▒╗╚▒▒▒▒▒▒╔╝▒▒╔═══╝
╚═╝  ╚═╝ ╚═════╝ ╚═╝     ════════════════════ v2.0

(main)>                                               
```
The actual image is around 2 GB based on a Debian Stretch with a Python 3.7.3 installed. 

# Contact

**Boyan MILANOV** - bmilanov (at) quarkslab (dot) com 

# Licence
ROPGenerator is provided under the MIT licence.

# Special thanks
ROPGenerator uses the following awesome projects: 
   - [BARF](https://github.com/programa-stic/barf-project) : Binary Analysis and Reverse Engineering plateform
   - [LIEF](https://github.com/lief-project/LIEF) : Binary Parsing and Instrumentation library 
   - [ROPgadget](https://github.com/JonathanSalwan/ROPgadget) : Gadget extractor
   - [prompt-toolkit](https://github.com/prompt-toolkit/python-prompt-toolkit) : Python CLI interface library 
   
Contributors:
   - [migounette](https://github.com/migounette) : Docker container support
