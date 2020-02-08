# About
**ROPium** is a library/tool that makes ROP-exploits easy. It automatically extracts and analyses gadgets from binaries and
lets you find ROP-chains with semantic queries. ROPium supports *X86* and *X64* architectures, soon to be 
extended with *ARM*.

Key features:

   - **Effortless**: ROPium works out-of-the-box with a smooth Command Line Interface
   - **Scriptable**: It is easy to integrate ROPium in script thanks to its python API
   - **Automatic chaining**: ROPium automatically combines gadgets to create complex ROP-chains
   - **Semantic queries**: ROPium queries are quick and convenient to write : ``rax=rbx+8``, ``[rdi+0x20]=rax``, ``rsi=[rbx+16]``, ``0x08040212(1, 2, 3)``, ``...``

# Content
- [About](#about)
- [Installation](#installation)
- [Getting started](#getting-started)
   - [CLI tool](#cli-tool)
   - [Python API](#python-api)
- [Docker](#docker)
- [Contact](#contact)
- [Licence](#licence)
- [Special thanks](#special-thanks)

# Installation
First install the [Capstone](https://github.com/aquynh/capstone) disassembly framework: 

      sudo apt-get install libcapstone-dev

You also need the latest [ROPgadget](https://github.com/JonathanSalwan/ROPgadget) release: 

      git clone https://github.com/JonathanSalwan/ROPgadget && cd ROPgadget
      python setup.py install --user 

Finally install **ROPium**:

      git clone https://github.com/Boyan-MILANOV/ropium && cd ropium
      make
      make test
      sudo make install 

# Getting started

### CLI tool

Thanks to a Command-Line-Interface wrapper, you can use ROPium interactively to quickly build ropchains:  

<p align="center">
  <img src="/ressources/ropium.gif" width="800" align="middle">
</p>


### Python API

Do you need to integrate ropchains directly in your scripts ? Good news, ROPium has a python API !

Loading a binary and finding ropchains:
```Python
from ropium import *
rop = ROPium(ARCH.X64)
rop.load('/lib/x86_64-linux-gnu/libc-2.27.so')

chain = rop.compile('rbx = [rax + 0x20]')
```

Dumping a ropchain in various formats:
```Python
>>> print( chain.dump() )

0x000000000009a851 (sub rax, 0x10; ret)
0x0000000000130018 (mov rax, qword ptr [rax + 0x30]; ret)
0x0000000000052240 (push rax; pop rbx; ret)

>>> print(chain.dump('python'))

from struct import pack
off = 0x0
p = ''
p += pack('<Q', 0x000000000009a851+off) # sub rax, 0x10; ret
p += pack('<Q', 0x0000000000130018+off) # mov rax, qword ptr [rax + 0x30]; ret
p += pack('<Q', 0x0000000000052240+off) # push rax; pop rbx; ret

>>> print(chain.dump('raw'))

b'Q\xa8\t\x00\x00\x00\x00\x00\x18\x00\x13\x00\x00\x00\x00\x00@"\x05\x00\x00\x00\x00\x00'
```

Set constraints on ropchains:
```Python
# Bytes that should not appear in the ropchain
rop.bad_bytes = [0x00, 0x0a, 0x0b]

# Register that should not be clobbered by the ropchain
rop.keep_regs = ['rsi', 'rdx']

# Enable/Forbid ropchain to dereference registers that might hold invalid addresses
# Safe mode is 'True' by default
rop.safe_mem = False
```

# Docker

If needed you can run ROPium in a docker container. The container can be generated from the *Dockerfile* as
follows:

```bash
# Create your docker image (this will take time!)
docker build . --tag ropium

# Run the image in interactive mode, bind mounting the file to analyze
docker run --rm -it -v /FULL/HOST/PATH/FILE:/tmp/FILE:ro ropium

(ropium)> load -a X86 /tmp/FILE
```
The actual image is around 200 MB based on a Debian Stretch with a Python 3.7.3 installed. 

# Contact

**Boyan MILANOV** - boyan.milanov (at) hotmail (dot) fr

# Licence
ROPium is provided under the MIT licence.

# Special thanks
Contributors:
   -  Docker container support: [migounette](https://github.com/migounette), [clslgrnc](https://github.com/clslgrnc)

ROPium uses the following awesome projects: 
   - [capstone](https://github.com/aquynh/capstone) : Disassembly Framework
   - [ROPgadget](https://github.com/JonathanSalwan/ROPgadget) : Gadget extractor
   - [prompt-toolkit](https://github.com/prompt-toolkit/python-prompt-toolkit) : Python CLI interface

